from __future__ import annotations

import base64
import json
from collections.abc import Callable
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from typing import Literal, cast

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ValidationError

import athena_context.presentation as presentation_module
import wc013_support
from athena_context.api.evaluation_domain import DemoEvaluationResult
from athena_context.cli import main
from athena_context.contracts import (
    ArgusPresentationPhase,
    AthenaValidationError,
    ClauseScope,
    DemoFaultRunReceipt,
    EvidenceSnapshot,
    ManifestFinding,
    PresentationAttestation,
    ResourceEvidenceRecord,
    canonicalize_json,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.contracts.manifest import FindingVerdict
from athena_context.fixtures import CANONICAL_PRIVATE_KEY
from athena_context.presentation import (
    PresentationSignatureVerifier,
    VerifiedDemoEvaluationResult,
    argus_signed_envelope,
    attest_argus_presentation,
    project_argus_presentation,
    verify_demo_evaluation_result,
    verify_presentation_attestation,
)
from wc013_support import (
    PUBLISHER,
    SUBSCRIPTION_ID,
    TENANT_ID,
    DemoHarness,
    build_harness,
    key_anchor,
    key_resolver,
)

SYNTHETIC_KEY_ID = "synthetic-key://athena-argus-demo/rs256-v1"
_ORIGINAL_RESOURCE_ITEMS = wc013_support._golden_resource_items


class DeterministicPresentationSigner:
    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key

    def sign_preimage(self, canonical_preimage: bytes) -> str:
        signature = self._private_key.sign(
            canonical_preimage,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("ascii")


class RsaPresentationVerifier(PresentationSignatureVerifier):
    def __init__(self, public_key: rsa.RSAPublicKey) -> None:
        self._public_key = public_key

    def verify_preimage(
        self,
        canonical_preimage: bytes,
        signature: bytes,
    ) -> bool:
        try:
            self._public_key.verify(
                signature,
                canonical_preimage,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature:
            return False
        return True


class ExactSignatureVerifier(PresentationSignatureVerifier):
    def __init__(self, expected_signature: bytes) -> None:
        self._expected_signature = expected_signature

    def verify_preimage(
        self,
        canonical_preimage: bytes,
        signature: bytes,
    ) -> bool:
        del canonical_preimage
        return signature == self._expected_signature


def _result_with_operational_finding(
    source: DemoEvaluationResult,
    *,
    verdict: FindingVerdict,
    citation_count: int | None = None,
) -> DemoEvaluationResult:
    web_records = [
        record
        for record in source.snapshot.evidence_records
        if isinstance(record, ResourceEvidenceRecord)
        and record.tags.workload_role == "web-service"
    ]
    web_digests = {record.item_digest for record in web_records}
    references = tuple(
        sorted(
            (
                reference
                for reference in source.snapshot.evidence_refs
                if getattr(reference, "item_digest", None) in web_digests
            ),
            key=lambda reference: reference.canonical_json(),
        )
    )
    if citation_count is not None:
        references = references[:citation_count]
    scope = ClauseScope(
        governanceScopeType="clause",
        manifestId=source.publication.manifest_id,
        profileId=source.publication.profile_id,
        clausePath="/constraints/web-service-operational-state",
        ownerRef="synthetic-operations-owner",
    )
    finding = ManifestFinding(
        clauseId="web-service-operational-state",
        findingKind="operationalState",
        verdict=verdict,
        manifestId=source.publication.manifest_id,
        manifestVersion=source.publication.manifest_version,
        profileId=source.publication.profile_id,
        resolvedProfileDigest=source.publication.resolved_profile_digest,
        governanceScope=scope,
        evidenceRefs=list(references),
    )
    draft = DemoEvaluationResult.model_construct(
        publication=source.publication,
        snapshot=source.snapshot,
        findings=(finding,),
        evaluated_at=source.evaluated_at,
        citation_count=len(references),
        result_digest="sha256:" + "0" * 64,
    )
    return DemoEvaluationResult(
        publication=source.publication,
        snapshot=source.snapshot,
        findings=(finding,),
        evaluated_at=source.evaluated_at,
        citation_count=len(references),
        result_digest=compute_artifact_digest(draft._digest_payload()),
    )


def _build_source(
    monkeypatch: pytest.MonkeyPatch,
    *,
    web_states: tuple[str, ...],
    verdict: FindingVerdict,
    profile_id: str = "production",
    citation_count: int | None = None,
) -> tuple[DemoHarness, DemoEvaluationResult]:
    def resource_items(observed_at: datetime) -> list[dict[str, object]]:
        items = _ORIGINAL_RESOURCE_ITEMS(observed_at)
        web_index = 0
        for item in items:
            tags = item.get("tags")
            if (
                isinstance(tags, dict)
                and tags.get("workloadRole") == "web-service"
            ):
                item["state"] = web_states[web_index]
                web_index += 1
        assert web_index == len(web_states)
        return items

    monkeypatch.setattr(
        wc013_support,
        "_golden_resource_items",
        resource_items,
    )
    harness = build_harness(profile_id=profile_id)
    source = harness.service.evaluate(
        PUBLISHER,
        f"argus-{profile_id}-{'-'.join(web_states)}",
        harness.command,
    )
    return harness, _result_with_operational_finding(
        source,
        verdict=verdict,
        citation_count=citation_count,
    )


def _snapshot_verifier(
    harness: DemoHarness,
) -> Callable[[EvidenceSnapshot, datetime], EvidenceSnapshot]:
    public_key = CANONICAL_PRIVATE_KEY.public_key()
    resolver = key_resolver(public_key)
    anchor = key_anchor(public_key)

    def verify(
        snapshot: EvidenceSnapshot,
        as_of: datetime,
    ) -> EvidenceSnapshot:
        return snapshot.validate_for_evaluation(
            as_of=as_of,
            expected_artifact_digest=(
                snapshot.compatibility.artifact_digest
            ),
            publication_resolver=harness.store.resolve_publication,
            identity_evidence=snapshot.identity_evidence,
            key_resolver=resolver,
            trusted_key_anchor=anchor,
            envelope_resolver=harness.store.resolve_envelope,
        )

    return verify


def _verified(
    harness: DemoHarness,
    result: DemoEvaluationResult,
) -> VerifiedDemoEvaluationResult:
    return verify_demo_evaluation_result(
        result,
        result_verifier=lambda supplied: supplied,
        snapshot_verifier=_snapshot_verifier(harness),
    )


def _web_records(result: DemoEvaluationResult) -> list[ResourceEvidenceRecord]:
    return [
        record
        for record in result.snapshot.evidence_records
        if isinstance(record, ResourceEvidenceRecord)
        and record.tags.workload_role == "web-service"
    ]


def _resource_name(resource_id: str) -> str:
    return resource_id.rstrip("/").rsplit("/", 1)[-1]


def _resource_group(resource_id: str) -> str:
    parts = resource_id.strip("/").split("/")
    index = [part.casefold() for part in parts].index("resourcegroups")
    return parts[index + 1]


def _receipt(
    result: DemoEvaluationResult,
    *,
    phase: ArgusPresentationPhase,
) -> DemoFaultRunReceipt:
    web_records = _web_records(result)
    target = (
        next(
            (
                record
                for record in web_records
                if record.state in {"stopped", "deallocated"}
            ),
            web_records[0],
        )
    )
    target_name = _resource_name(target.resource_id)
    eligible_names = sorted(_resource_name(record.resource_id) for record in web_records)
    completed_at = result.snapshot.collected_at - timedelta(seconds=1)
    action: Literal["inject", "status", "reset"]
    before_state: Literal[
        "PowerState/running",
        "PowerState/stopped",
        "PowerState/deallocated",
    ]
    after_state: Literal[
        "PowerState/running",
        "PowerState/stopped",
        "PowerState/deallocated",
    ]
    if phase == "baseline":
        action = "status"
        before_state = "PowerState/running"
        after_state = "PowerState/running"
    elif phase == "faulted":
        action = "inject"
        before_state = "PowerState/running"
        after_state = (
            "PowerState/deallocated"
            if target.state == "deallocated"
            else "PowerState/stopped"
        )
    else:
        action = "reset"
        before_state = "PowerState/stopped"
        after_state = "PowerState/running"
    return DemoFaultRunReceipt(
        schemaVersion="athena.demoFaultRun.v1",
        faultRunId="operator-run:001",
        faultKind="web-node-power-state",
        action=action,
        resourceGroup=_resource_group(target.resource_id),
        prefix=target_name.rsplit("-", 1)[0],
        targetVmName=target_name,
        targetVmResourceId=target.resource_id,
        eligibleWebVmNames=tuple(eligible_names),
        beforePowerState=before_state,
        afterPowerState=after_state,
        startedAt=completed_at - timedelta(seconds=1),
        completedAt=completed_at,
        outcome="confirmed",
    )


@pytest.mark.parametrize(
    ("phase", "states", "source_verdict", "service_state", "presentation_verdict"),
    [
        (
            "baseline",
            ("running", "running", "running"),
            "pass",
            "healthy",
            "pass",
        ),
        (
            "faulted",
            ("stopped", "running", "running"),
            "observation",
            "degraded-redundancy",
            "fail",
        ),
        (
            "recovered",
            ("running", "running", "running"),
            "pass",
            "recovered",
            "resolved",
        ),
    ],
)
def test_projects_and_attests_all_frozen_phases(
    monkeypatch: pytest.MonkeyPatch,
    phase: ArgusPresentationPhase,
    states: tuple[str, ...],
    source_verdict: FindingVerdict,
    service_state: str,
    presentation_verdict: str,
) -> None:
    harness, result = _build_source(
        monkeypatch,
        web_states=states,
        verdict=source_verdict,
    )
    receipt = _receipt(result, phase=phase)
    payload = project_argus_presentation(
        _verified(harness, result),
        receipt=receipt,
        phase=phase,
        synthetic_key_id=SYNTHETIC_KEY_ID,
    )
    signer = DeterministicPresentationSigner(CANONICAL_PRIVATE_KEY)
    attestation = attest_argus_presentation(payload, signer=signer)

    assert payload.phase == phase
    assert payload.runtime_state.web_tier.service_state == service_state
    assert payload.findings[0].verdict == presentation_verdict
    assert payload.athena.result_digest == sha256_hex(payload.canonical_preimage())
    assert payload.canonical_json() == canonicalize_json(
        json.loads(payload.canonical_json())
    )
    assert verify_presentation_attestation(
        payload,
        attestation,
        verifier=RsaPresentationVerifier(
            CANONICAL_PRIVATE_KEY.public_key()
        ),
    )
    envelope = argus_signed_envelope(payload, attestation)
    assert envelope["detachedSignature"] == attestation.detached_signature
    assert ("faultRun" in cast(dict[str, object], envelope["payload"])) == (
        phase != "baseline"
    )

    serialized = payload.canonical_json()
    for unsafe_value in (
        TENANT_ID,
        SUBSCRIPTION_ID,
        receipt.resource_group,
        receipt.fault_run_id,
        receipt.target_vm_name,
        receipt.target_vm_resource_id,
        result.snapshot.snapshot_id,
        result.publication.manifest_id,
        result.publication.profile_id,
        result.snapshot.snapshot_attestation.key_vault_key_id,
    ):
        assert unsafe_value not in serialized
    assert all(
        reference.startswith("synthetic-evidence-")
        for reference in payload.findings[0].evidence_refs
    )
    if phase == "baseline":
        serialized_payload = json.loads(serialized)
        assert set(serialized_payload) == {
            "schemaVersion",
            "scenarioId",
            "phase",
            "workload",
            "athena",
            "runtimeState",
            "findings",
            "argus",
        }
        serialized_payload["tenantId"] = TENANT_ID
        with pytest.raises(ValidationError, match="Extra inputs"):
            type(payload).model_validate_json(json.dumps(serialized_payload))
        serialized_payload.pop("tenantId")
        serialized_payload["athena"]["resultDigest"] = "sha256:" + "0" * 64
        with pytest.raises(ValidationError, match="resultDigest"):
            type(payload).model_validate_json(json.dumps(serialized_payload))


@pytest.mark.parametrize("fault_state", ["stopped", "deallocated"])
def test_faulted_projection_accepts_only_one_confirmed_failed_node(
    monkeypatch: pytest.MonkeyPatch,
    fault_state: str,
) -> None:
    harness, result = _build_source(
        monkeypatch,
        web_states=(fault_state, "running", "running"),
        verdict="observation",
    )
    payload = project_argus_presentation(
        _verified(harness, result),
        receipt=_receipt(result, phase="faulted"),
        phase="faulted",
        synthetic_key_id=SYNTHETIC_KEY_ID,
    )

    assert payload.runtime_state.web_tier.running_nodes == 2
    assert payload.runtime_state.web_tier.faulted_nodes == 1
    assert payload.fault_run is not None
    assert payload.fault_run.after_power_state == "stopped"


@pytest.mark.parametrize("profile_id", ["production", "development", "training"])
def test_projection_redacts_all_three_profile_identifiers(
    monkeypatch: pytest.MonkeyPatch,
    profile_id: str,
) -> None:
    harness, result = _build_source(
        monkeypatch,
        web_states=("running", "running", "running"),
        verdict="pass",
        profile_id=profile_id,
    )
    payload = project_argus_presentation(
        _verified(harness, result),
        receipt=_receipt(result, phase="baseline"),
        phase="baseline",
        synthetic_key_id=SYNTHETIC_KEY_ID,
    )

    assert payload.workload.profile_id.startswith("synthetic-profile-")
    assert profile_id not in payload.canonical_json()
    assert payload.findings[0].verdict == "pass"


def test_projection_is_deterministic_and_signature_tampering_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness, result = _build_source(
        monkeypatch,
        web_states=("stopped", "running", "running"),
        verdict="observation",
    )
    verified = _verified(harness, result)
    receipt = _receipt(result, phase="faulted")
    first = project_argus_presentation(
        verified,
        receipt=receipt,
        phase="faulted",
        synthetic_key_id=SYNTHETIC_KEY_ID,
    )
    second = project_argus_presentation(
        verified,
        receipt=receipt,
        phase="faulted",
        synthetic_key_id=SYNTHETIC_KEY_ID,
    )
    signer = DeterministicPresentationSigner(CANONICAL_PRIVATE_KEY)
    first_attestation = attest_argus_presentation(first, signer=signer)
    second_attestation = attest_argus_presentation(second, signer=signer)
    tampered = first_attestation.model_copy(
        update={"detached_signature": "AA"}
    )

    assert first.canonical_json() == second.canonical_json()
    assert first_attestation == second_attestation
    assert not verify_presentation_attestation(
        first,
        cast(PresentationAttestation, tampered),
        verifier=RsaPresentationVerifier(
            CANONICAL_PRIVATE_KEY.public_key()
        ),
    )


def test_alphanumeric_only_unpadded_base64url_signature_verifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = b"\x00"
    detached_signature = (
        base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    )
    harness, result = _build_source(
        monkeypatch,
        web_states=("running", "running", "running"),
        verdict="pass",
    )
    payload = project_argus_presentation(
        _verified(harness, result),
        receipt=_receipt(result, phase="baseline"),
        phase="baseline",
        synthetic_key_id=SYNTHETIC_KEY_ID,
    )
    attestation = PresentationAttestation(
        schemaVersion="athena.argus.presentationAttestation.v1",
        resultDigest=payload.athena.result_digest,
        signatureAlgorithm="RS256",
        keyVaultKeyId=SYNTHETIC_KEY_ID,
        detachedSignature=detached_signature,
    )

    assert detached_signature == "AA"
    assert verify_presentation_attestation(
        payload,
        attestation,
        verifier=ExactSignatureVerifier(signature),
    )


def test_rs256_sized_signature_round_trips_through_detached_base64url() -> None:
    signature = bytes(range(256))
    signer_value = base64.b64encode(signature).decode("ascii")

    detached_signature = presentation_module._base64url_signature(signer_value)

    assert len(signature) == 256
    assert "=" not in detached_signature
    assert presentation_module._decode_signature(detached_signature) == signature


@pytest.mark.parametrize(
    "detached_signature",
    ("A", "AA==", "AA+A", "AA/A", "AA\u00e5"),
)
def test_detached_signature_invalid_alphabet_or_length_fails_closed(
    detached_signature: str,
) -> None:
    with pytest.raises(
        AthenaValidationError,
        match="invalid base64 signature bytes",
    ):
        presentation_module._decode_signature(detached_signature)


def test_unverified_result_and_non_exact_verifier_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness, result = _build_source(
        monkeypatch,
        web_states=("running", "running", "running"),
        verdict="pass",
    )
    forged = object.__new__(VerifiedDemoEvaluationResult)
    with pytest.raises(
        AthenaValidationError,
        match="VerifiedDemoEvaluationResult",
    ):
        project_argus_presentation(
            cast(VerifiedDemoEvaluationResult, forged),
            receipt=_receipt(result, phase="baseline"),
            phase="baseline",
            synthetic_key_id=SYNTHETIC_KEY_ID,
        )
    with pytest.raises(
        AthenaValidationError,
        match="exact supplied result",
    ):
        verify_demo_evaluation_result(
            result,
            result_verifier=lambda supplied: supplied.model_copy(),
            snapshot_verifier=_snapshot_verifier(harness),
        )
    verified = _verified(harness, result)
    result.findings[0].verdict = "observation"
    with pytest.raises(AthenaValidationError, match="result digest"):
        project_argus_presentation(
            verified,
            receipt=_receipt(result, phase="baseline"),
            phase="baseline",
            synthetic_key_id=SYNTHETIC_KEY_ID,
        )


@pytest.mark.parametrize(
    ("states", "verdict", "error"),
    [
        (
            ("unknown", "running", "running"),
            "unknown",
            "unknown web-service",
        ),
        (
            ("stopped", "deallocated", "stopped"),
            "violation",
            "do not agree",
        ),
    ],
)
def test_unknown_and_insufficient_web_state_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    states: tuple[str, ...],
    verdict: FindingVerdict,
    error: str,
) -> None:
    harness, result = _build_source(
        monkeypatch,
        web_states=states,
        verdict=verdict,
    )
    with pytest.raises(AthenaValidationError, match=error):
        project_argus_presentation(
            _verified(harness, result),
            receipt=_receipt(result, phase="faulted"),
            phase="faulted",
            synthetic_key_id=SYNTHETIC_KEY_ID,
        )


def test_receipt_phase_citation_and_identifier_mismatches_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness, result = _build_source(
        monkeypatch,
        web_states=("stopped", "running", "running"),
        verdict="observation",
        citation_count=1,
    )
    with pytest.raises(AthenaValidationError, match="cite every exact"):
        project_argus_presentation(
            _verified(harness, result),
            receipt=_receipt(result, phase="faulted"),
            phase="faulted",
            synthetic_key_id=SYNTHETIC_KEY_ID,
        )

    harness, result = _build_source(
        monkeypatch,
        web_states=("running", "running", "running"),
        verdict="pass",
    )
    with pytest.raises(AthenaValidationError, match="do not agree"):
        project_argus_presentation(
            _verified(harness, result),
            receipt=_receipt(result, phase="recovered"),
            phase="baseline",
            synthetic_key_id=SYNTHETIC_KEY_ID,
        )
    with pytest.raises(ValidationError, match="keyVaultKeyId"):
        project_argus_presentation(
            _verified(harness, result),
            receipt=_receipt(result, phase="baseline"),
            phase="baseline",
            synthetic_key_id=(
                "https://real-demo-vault.vault.azure.net/keys/presentation/1"
            ),
        )
    receipt = _receipt(result, phase="baseline")
    stale_receipt = receipt.model_copy(
        update={
            "started_at": (
                result.snapshot.collected_at
                - (result.snapshot.expires_at - result.snapshot.collected_at)
                - timedelta(seconds=2)
            ),
            "completed_at": (
                result.snapshot.collected_at
                - (result.snapshot.expires_at - result.snapshot.collected_at)
                - timedelta(seconds=1)
            ),
        }
    )
    with pytest.raises(AthenaValidationError, match="freshness window"):
        project_argus_presentation(
            _verified(harness, result),
            receipt=stale_receipt,
            phase="baseline",
            synthetic_key_id=SYNTHETIC_KEY_ID,
        )


def test_malformed_fault_receipt_is_rejected() -> None:
    with pytest.raises(ValidationError, match="eligibleWebVmNames"):
        DemoFaultRunReceipt.model_validate(
            {
                "schemaVersion": "athena.demoFaultRun.v1",
                "faultRunId": "synthetic-run-001",
                "faultKind": "web-node-power-state",
                "action": "inject",
                "resourceGroup": "rg-athena-demo",
                "prefix": "athena-web",
                "targetVmName": "athena-web-01",
                "targetVmResourceId": (
                    "/subscriptions/11111111-1111-4111-8111-111111111111/"
                    "resourceGroups/rg-athena-demo/providers/Microsoft.Compute/"
                    "virtualMachines/athena-web-01"
                ),
                "eligibleWebVmNames": ["athena-web-02", "athena-web-01"],
                "beforePowerState": "PowerState/running",
                "afterPowerState": "PowerState/stopped",
                "startedAt": "2026-08-20T12:00:00.000Z",
                "completedAt": "2026-08-20T12:00:01.000Z",
                "outcome": "confirmed",
            }
        )


def test_cli_exports_canonical_payload_and_detached_attestation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    harness, result = _build_source(
        monkeypatch,
        web_states=("running", "running", "running"),
        verdict="pass",
    )
    receipt = _receipt(result, phase="baseline")
    result_path = tmp_path / "result.json"
    receipt_path = tmp_path / "receipt.json"
    payload_path = tmp_path / "presentation.json"
    attestation_path = tmp_path / "presentation.attestation.json"
    result_path.write_text(result.canonical_json(), encoding="utf-8")
    receipt_path.write_text(receipt.canonical_json(), encoding="utf-8")
    stdout = StringIO()
    stderr = StringIO()

    exit_code = main(
        [
            "argus-presentation-export",
            "--result",
            str(result_path),
            "--receipt",
            str(receipt_path),
            "--phase",
            "baseline",
            "--synthetic-key-id",
            SYNTHETIC_KEY_ID,
            "--output",
            str(payload_path),
            "--attestation-output",
            str(attestation_path),
        ],
        presentation_result_verifier=lambda supplied: supplied,
        presentation_snapshot_verifier=_snapshot_verifier(harness),
        presentation_signer=DeterministicPresentationSigner(
            CANONICAL_PRIVATE_KEY
        ),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    assert "ARGUS presentation export passed" in stdout.getvalue()
    payload_text = payload_path.read_text(encoding="utf-8").rstrip("\n")
    attestation_text = attestation_path.read_text(
        encoding="utf-8"
    ).rstrip("\n")
    assert payload_text == canonicalize_json(json.loads(payload_text))
    assert attestation_text == canonicalize_json(json.loads(attestation_text))

    second_stderr = StringIO()
    assert (
        main(
            [
                "argus-presentation-export",
                "--result",
                str(result_path),
                "--receipt",
                str(receipt_path),
                "--phase",
                "baseline",
                "--synthetic-key-id",
                SYNTHETIC_KEY_ID,
                "--output",
                str(payload_path),
                "--attestation-output",
                str(attestation_path),
            ],
            presentation_result_verifier=lambda supplied: supplied,
            presentation_snapshot_verifier=_snapshot_verifier(harness),
            presentation_signer=DeterministicPresentationSigner(
                CANONICAL_PRIVATE_KEY
            ),
            stderr=second_stderr,
        )
        == 1
    )
    assert "must not already exist" in second_stderr.getvalue()


def test_cli_export_without_trusted_dependencies_fails_closed(
    tmp_path: Path,
) -> None:
    stderr = StringIO()
    exit_code = main(
        [
            "argus-presentation-export",
            "--result",
            str(tmp_path / "result.json"),
            "--receipt",
            str(tmp_path / "receipt.json"),
            "--phase",
            "baseline",
            "--synthetic-key-id",
            SYNTHETIC_KEY_ID,
            "--output",
            str(tmp_path / "presentation.json"),
            "--attestation-output",
            str(tmp_path / "presentation.attestation.json"),
        ],
        stderr=stderr,
    )

    assert exit_code == 1
    assert "trusted result verifier, snapshot verifier, and signer are required" in (
        stderr.getvalue()
    )
