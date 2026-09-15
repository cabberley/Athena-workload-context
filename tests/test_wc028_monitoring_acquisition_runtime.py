from __future__ import annotations

import base64
import hashlib
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from urllib.parse import unquote

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel, ConfigDict, ValidationError

import athena_context.monitoring_acquisition_runtime as runtime_module
from athena_context import cli
from athena_context.artifacts import (
    ArtifactAlreadyExistsError,
    ArtifactReadResult,
    ArtifactWriteReceipt,
)
from athena_context.contracts import (
    MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
    MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
    MONITORING_IDENTITY_PROOF_AUDIENCE,
    MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS,
    MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
    MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
    TrustedKeyRecord,
    compute_artifact_digest,
    sha256_hex,
)
from athena_context.monitoring_acquisition_runtime import (
    AzureManagedIdentityJsonTransport,
    AzureMonitoringAcquisitionPort,
    AzureMonitoringCredentialBoundClient,
    MonitoringAcquisitionJobError,
    MonitoringEvidenceCommitPort,
    MonitoringRuntimeTrustedKey,
    Wc028MonitoringAcquisitionJobConfiguration,
    _build_acquisition_receipt_verifier,
    _coverage_descriptor,
    _result,
    _validate_acquisition_authority_preflight,
    _validate_monitoring_intent_key_lifecycle,
    load_wc028_monitoring_acquisition_job_configuration,
)

NOW = datetime(2026, 9, 14, 5, 30, tzinfo=UTC)
SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
TENANT_ID = "33333333-3333-3333-3333-333333333333"
COLLECTOR_PRINCIPAL_ID = "44444444-4444-4444-4444-444444444444"
CONTEXT_PRINCIPAL_ID = "55555555-5555-5555-5555-555555555555"
COLLECTOR_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-monitoring/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
    "athena-demo-monitoring-monitoring-collector-id"
)
CONTEXT_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-context/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/athena-context-id"
)
SOURCE_STORAGE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-context/"
    "providers/Microsoft.Storage/storageAccounts/athenacontextsource"
)
CHANGE_EVIDENCE_STORAGE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-change/"
    "providers/Microsoft.Storage/storageAccounts/athenachangeevidence"
)
EVIDENCE_STORAGE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-monitoring/"
    "providers/Microsoft.Storage/storageAccounts/athenamonitoring"
)
WORKLOAD_RESOURCE_GROUP_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-workload"
)
WORKSPACE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-monitoring/"
    "providers/Microsoft.OperationalInsights/workspaces/athena-hackathon-law"
)
NETWORK_WATCHER_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/"
    "providers/Microsoft.Network/networkWatchers/NetworkWatcher_australiaeast"
)
IP_FLOW_ROLE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/"
    "providers/Microsoft.Authorization/roleDefinitions/"
    "3728cdf6-4efd-5282-bdfc-63b7872fd801"
)
RESOURCE_HEALTH_ROLE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-workload/"
    "providers/Microsoft.Authorization/roleDefinitions/"
    "0790d6f2-9553-5b63-84ac-56596b7e4072"
)
VM_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-workload/"
    "providers/Microsoft.Compute/virtualMachines/vm-web-01"
)
BACKEND_VM_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-workload/"
    "providers/Microsoft.Compute/virtualMachines/vm-db-01"
)
NSG_RULE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-workload/"
    "providers/Microsoft.Network/networkSecurityGroups/nsg-web/securityRules/deny-db"
)
CORRELATION_ID = "66666666-6666-6666-6666-666666666666"
PATH_ID = f"path-{'7' * 32}"
COLLECTOR_KEY_ID = (
    "https://synthetic-monitoring-kv.vault.azure.net/keys/"
    "monitoring-evidence-signing/11111111111111111111111111111111"
)
INTENT_KEY_ID = (
    "https://synthetic-context-kv.vault.azure.net/keys/"
    "monitoring-intent-signing/22222222222222222222222222222222"
)
DIGEST_A = f"sha256:{'a' * 64}"
DIGEST_B = f"sha256:{'b' * 64}"
DIGEST_C = f"sha256:{'c' * 64}"
ACCESS_TOKEN = "synthetic-verified-token"


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _configuration_payload() -> dict[str, object]:
    return {
        "schemaVersion": "athena.wc028MonitoringAcquisitionJobConfiguration.v1",
        "managedIdentityClientId": CLIENT_ID,
        "collectorIdentityResourceId": COLLECTOR_ID,
        "athenaContextIdentityResourceId": CONTEXT_ID,
        "sourceStorageAccountResourceId": SOURCE_STORAGE_ID,
        "evidenceStorageAccountResourceId": EVIDENCE_STORAGE_ID,
        "evidenceBlobEndpoint": "https://athenamonitoring.blob.core.windows.net",
        "evidenceContainerName": "monitoring-evidence",
        "changeEvidenceStorageAccountResourceId": CHANGE_EVIDENCE_STORAGE_ID,
        "changeEvidenceBlobEndpoint": ("https://athenachangeevidence.blob.core.windows.net"),
        "changeEvidenceContainerName": "change-evidence",
        "workspaceResourceId": WORKSPACE_ID,
        "workspaceCustomerId": TENANT_ID,
        "networkWatcherResourceId": NETWORK_WATCHER_ID,
        "monitoringIntentTrustedKey": {
            "keyVaultKeyId": INTENT_KEY_ID,
            "publicKeyFingerprint": DIGEST_A,
            "activatedAt": datetime(2026, 9, 1, tzinfo=UTC),
        },
        "collectorSigningKey": {
            "keyVaultKeyId": COLLECTOR_KEY_ID,
            "publicKeyFingerprint": DIGEST_B,
            "activatedAt": datetime(2026, 9, 1, tzinfo=UTC),
        },
        "monitoringIntent": {"schemaVersion": "synthetic"},
        "monitoringIntentReference": {"schemaVersion": "synthetic"},
        "monitoringIntentAttestation": {"schemaVersion": "synthetic"},
        "contextBinding": {
            "schemaVersion": "synthetic",
            "bindingDigest": DIGEST_A,
            "requiredCoverageScopeDigests": [DIGEST_B],
        },
        "acquisitionAuthority": {
            "schemaVersion": "athena.wc028MonitoringAcquisitionAuthority.v4",
            "monitoringReaderIdentityId": COLLECTOR_ID,
            "monitoringReaderPrincipalId": COLLECTOR_PRINCIPAL_ID,
            "monitoringReaderClientId": CLIENT_ID,
            "monitoringReaderTenantId": TENANT_ID,
            "athenaContextIdentityId": CONTEXT_ID,
            "athenaContextPrincipalId": CONTEXT_PRINCIPAL_ID,
            "receiptSigningKeyId": COLLECTOR_KEY_ID,
            "contextBindingDigest": DIGEST_A,
            "requiredCoverageScopeDigests": [DIGEST_B],
            "identityProofAudience": MONITORING_IDENTITY_PROOF_AUDIENCE,
            "identityProofTokenVersion": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
            "identityProofRequiredRole": MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
            "identityProofMaximumLifetimeSeconds": (
                MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
            ),
            "authorityDigest": DIGEST_C,
        },
        "monitoringCollectorContract": {
            "schemaVersion": MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            "collectorIdentityClientId": CLIENT_ID,
            "collectorIdentityResourceId": COLLECTOR_ID,
            "collectorTenantId": TENANT_ID,
            "monitoringReaderPrincipalId": COLLECTOR_PRINCIPAL_ID,
            "athenaContextIdentityId": CONTEXT_ID,
            "athenaContextPrincipalId": CONTEXT_PRINCIPAL_ID,
            "physicalIdentitySeparationEnforced": True,
            "workloadResourceGroupId": WORKLOAD_RESOURCE_GROUP_ID,
            "workspaceResourceId": WORKSPACE_ID,
            "evidenceStorageAccountResourceId": EVIDENCE_STORAGE_ID,
            "evidenceContainerName": "monitoring-evidence",
            "signingKeyResourceId": COLLECTOR_KEY_ID,
            "ipFlowVerifyRoleDefinitionId": IP_FLOW_ROLE_ID,
            "ipFlowVerifyScopeId": NETWORK_WATCHER_ID,
            "ipFlowVerifyAllowedOperations": [
                "Microsoft.Network/networkWatchers/ipFlowVerify/action",
                "Microsoft.Network/networkWatchers/ipFlowVerify/read",
            ],
            "resourceHealthRoleDefinitionId": RESOURCE_HEALTH_ROLE_ID,
            "resourceHealthScopeIds": [VM_ID],
            "resourceHealthAllowedOperations": [
                "Microsoft.ResourceHealth/AvailabilityStatuses/read"
            ],
            "identityProofAudience": MONITORING_IDENTITY_PROOF_AUDIENCE,
            "identityProofTokenVersion": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
            "identityProofRequiredRole": MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
            "identityProofMaximumLifetimeSeconds": (
                MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
            ),
            "handoffSchemaVersion": "athena.wc028MonitoringEvidenceHandoff.v2",
            "acquisitionReceiptSchemaVersion": MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
        },
        "approvedChangeScope": {"schemaVersion": "synthetic"},
        "expectedActiveContextAuthorityDigest": DIGEST_A,
        "expectedAcquisitionAuthorityDigest": DIGEST_C,
        "incidentRevision": 1,
        "trustDelaySeconds": 60,
        "requestLifetimeSeconds": 600,
        "httpTimeoutSeconds": 30,
        "httpRetryLimit": 2,
    }


def test_configuration_preserves_identity_and_storage_separation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", CLIENT_ID)
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(
        _configuration_payload()
    )

    assert configuration.collector_identity_resource_id == COLLECTOR_ID.casefold()
    assert configuration.athena_context_identity_resource_id == CONTEXT_ID.casefold()
    assert (
        configuration.source_storage_account_resource_id
        != configuration.evidence_storage_account_resource_id
    )

    shared_identity = _configuration_payload()
    shared_identity["athenaContextIdentityResourceId"] = COLLECTOR_ID
    with pytest.raises(ValidationError, match="identities must be separate"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(shared_identity)

    shared_storage = _configuration_payload()
    shared_storage["sourceStorageAccountResourceId"] = EVIDENCE_STORAGE_ID
    with pytest.raises(ValidationError, match="storage must be separate"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(shared_storage)


def test_configuration_rejects_source_identity_and_scope_substitution() -> None:
    substituted_identity = _configuration_payload()
    authority = cast(dict[str, object], substituted_identity["acquisitionAuthority"])
    authority["monitoringReaderIdentityId"] = CONTEXT_ID
    with pytest.raises(ValidationError, match="acquisition reader identity"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_identity)

    substituted_storage = _configuration_payload()
    contract = cast(
        dict[str, object],
        substituted_storage["monitoringCollectorContract"],
    )
    contract["evidenceStorageAccountResourceId"] = SOURCE_STORAGE_ID
    with pytest.raises(ValidationError, match="collector contract evidence storage"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_storage)

    substituted_endpoint = _configuration_payload()
    substituted_endpoint["evidenceBlobEndpoint"] = "https://unreviewedaccount.blob.core.windows.net"
    with pytest.raises(ValidationError, match="reviewed storage account"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_endpoint)

    substituted_change_endpoint = _configuration_payload()
    substituted_change_endpoint["changeEvidenceBlobEndpoint"] = (
        "https://unreviewedchange.blob.core.windows.net"
    )
    with pytest.raises(ValidationError, match="change evidence Blob endpoint"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_change_endpoint)

    downgraded_contract = _configuration_payload()
    contract = cast(
        dict[str, object],
        downgraded_contract["monitoringCollectorContract"],
    )
    contract["schemaVersion"] = "athena.wc024MonitoringCollectorContract.v2"
    contract["handoffSchemaVersion"] = "athena.wc024MonitoringEvidenceHandoff.v1"
    with pytest.raises(ValidationError, match="collector contract schema"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(downgraded_contract)

    substituted_ip_flow_role = _configuration_payload()
    contract = cast(
        dict[str, object],
        substituted_ip_flow_role["monitoringCollectorContract"],
    )
    contract["ipFlowVerifyRoleDefinitionId"] = RESOURCE_HEALTH_ROLE_ID
    with pytest.raises(ValidationError, match="IP Flow Verify role"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_ip_flow_role)

    substituted_resource_health_role = _configuration_payload()
    contract = cast(
        dict[str, object],
        substituted_resource_health_role["monitoringCollectorContract"],
    )
    contract["resourceHealthRoleDefinitionId"] = IP_FLOW_ROLE_ID
    with pytest.raises(ValidationError, match="Resource Health role"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_resource_health_role)


def test_configuration_rejects_deployment_binding_substitution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ATHENA_WC028_DEPLOYED_COLLECTOR_IDENTITY_PRINCIPAL_ID",
        CONTEXT_PRINCIPAL_ID,
    )

    with pytest.raises(ValidationError, match="DEPLOYED_COLLECTOR"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(_configuration_payload())

    monkeypatch.delenv("ATHENA_WC028_DEPLOYED_COLLECTOR_IDENTITY_PRINCIPAL_ID")
    monkeypatch.setenv(
        "ATHENA_WC028_DEPLOYED_MONITORING_INTENT_SIGNING_KEY_ID",
        COLLECTOR_KEY_ID,
    )
    with pytest.raises(ValidationError, match="MONITORING_INTENT_SIGNING_KEY"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(_configuration_payload())


def test_configuration_loader_is_bounded_and_unambiguous(tmp_path: Path) -> None:
    path = tmp_path / "configuration.json"
    path.write_text(
        json.dumps(
            _configuration_payload(),
            default=lambda value: value.isoformat().replace("+00:00", "Z"),
        ),
        encoding="utf-8",
    )
    expected_digest = sha256_hex(path.read_bytes())

    assert (
        load_wc028_monitoring_acquisition_job_configuration(
            path=path,
            expected_digest=expected_digest,
        ).managed_identity_client_id
        == CLIENT_ID
    )
    with pytest.raises(ValueError, match="either a config path or environment JSON"):
        load_wc028_monitoring_acquisition_job_configuration(
            path=path,
            environment_json="{}",
            expected_digest=expected_digest,
        )
    with pytest.raises(ValueError, match="pinned digest"):
        load_wc028_monitoring_acquisition_job_configuration(
            path=path,
            expected_digest=DIGEST_A,
        )

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (512 * 1024 + 1))
    with pytest.raises(ValueError, match="byte bound"):
        load_wc028_monitoring_acquisition_job_configuration(
            path=oversized,
            expected_digest=DIGEST_A,
        )


def test_authority_digest_and_freshness_fail_before_external_reads() -> None:
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(
        _configuration_payload()
    )
    context_binding = SimpleNamespace(
        binding_digest=DIGEST_A,
        required_coverage_scope_digests=(DIGEST_B,),
    )
    authority = SimpleNamespace(
        schema_version="athena.wc028MonitoringAcquisitionAuthority.v4",
        authority_digest=DIGEST_C,
        monitoring_reader_identity_id=COLLECTOR_ID.casefold(),
        monitoring_reader_principal_id=COLLECTOR_PRINCIPAL_ID,
        monitoring_reader_client_id=CLIENT_ID,
        monitoring_reader_tenant_id=TENANT_ID,
        athena_context_identity_id=CONTEXT_ID.casefold(),
        athena_context_principal_id=CONTEXT_PRINCIPAL_ID,
        collector_contract_digest=DIGEST_B,
        context_binding_digest=DIGEST_A,
        required_coverage_scope_digests=(DIGEST_B,),
        max_freshness_seconds=600,
        receipt_signing_key_id=COLLECTOR_KEY_ID,
        identity_proof_audience=MONITORING_IDENTITY_PROOF_AUDIENCE,
        identity_proof_token_version=MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        identity_proof_required_role=MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
        identity_proof_maximum_lifetime_seconds=(
            MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ),
    )
    contract = SimpleNamespace(
        schema_version=MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        handoff_schema_version="athena.wc028MonitoringEvidenceHandoff.v2",
        acquisition_receipt_schema_version=MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
        collector_identity_resource_id=COLLECTOR_ID.casefold(),
        collector_identity_client_id=CLIENT_ID,
        collector_tenant_id=TENANT_ID,
        monitoring_reader_principal_id=COLLECTOR_PRINCIPAL_ID,
        athena_context_identity_id=CONTEXT_ID.casefold(),
        athena_context_principal_id=CONTEXT_PRINCIPAL_ID,
        physical_identity_separation_enforced=True,
        workload_resource_group_id=WORKLOAD_RESOURCE_GROUP_ID.casefold(),
        workspace_resource_id=WORKSPACE_ID.casefold(),
        evidence_storage_account_resource_id=EVIDENCE_STORAGE_ID.casefold(),
        evidence_container_name="monitoring-evidence",
        signing_key_resource_id=COLLECTOR_KEY_ID,
        ip_flow_verify_scope_id=NETWORK_WATCHER_ID.casefold(),
        ip_flow_verify_allowed_operations=(
            "Microsoft.Network/networkWatchers/ipFlowVerify/action",
            "Microsoft.Network/networkWatchers/ipFlowVerify/read",
        ),
        resource_health_allowed_operations=("Microsoft.ResourceHealth/AvailabilityStatuses/read",),
        identity_proof_audience=MONITORING_IDENTITY_PROOF_AUDIENCE,
        identity_proof_token_version=MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        identity_proof_required_role=MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
        identity_proof_maximum_lifetime_seconds=(
            MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ),
        maximum_evidence_age_seconds=600,
        compute_artifact_digest_value=lambda: DIGEST_C,
    )

    with pytest.raises(MonitoringAcquisitionJobError, match="collector contract"):
        _validate_acquisition_authority_preflight(
            acquisition_authority=cast(Any, authority),
            configuration=configuration,
            collector_contract=cast(Any, contract),
            context_binding=cast(Any, context_binding),
        )

    authority.collector_contract_digest = DIGEST_C
    authority.max_freshness_seconds = 30
    with pytest.raises(MonitoringAcquisitionJobError, match="freshness"):
        _validate_acquisition_authority_preflight(
            acquisition_authority=cast(Any, authority),
            configuration=configuration,
            collector_contract=cast(Any, contract),
            context_binding=cast(Any, context_binding),
        )

    authority.max_freshness_seconds = 600
    authority.authority_digest = DIGEST_A
    with pytest.raises(MonitoringAcquisitionJobError, match="configured authority"):
        _validate_acquisition_authority_preflight(
            acquisition_authority=cast(Any, authority),
            configuration=configuration,
            collector_contract=cast(Any, contract),
            context_binding=cast(Any, context_binding),
        )


def test_receipt_verifier_reuses_hardened_identity_and_key_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(
        _configuration_payload()
    )
    authority = SimpleNamespace(
        authority_digest=DIGEST_C,
        max_freshness_seconds=600,
    )
    contract = SimpleNamespace(
        maximum_evidence_age_seconds=300,
        compute_artifact_digest_value=lambda: DIGEST_B,
    )
    resolver = cast(Any, lambda _anchor: None)
    captured: dict[str, object] = {}

    def verify(receipt: object, **kwargs: object) -> None:
        captured["receipt"] = receipt
        captured.update(kwargs)

    monkeypatch.setattr(
        runtime_module,
        "verify_monitoring_acquisition_receipt_attestation",
        verify,
    )
    receipt = object()
    receipt_verifier = _build_acquisition_receipt_verifier(
        acquisition_authority=cast(Any, authority),
        collector_contract=cast(Any, contract),
        trusted_key=configuration.collector_signing_key,
        key_resolver=resolver,
    )

    receipt_verifier(cast(Any, receipt), NOW)

    assert captured["receipt"] is receipt
    assert captured["as_of"] == NOW
    assert captured["trusted_key_anchor"] == configuration.collector_signing_key.anchor
    assert captured["key_resolver"] is resolver
    assert captured["reviewed_collector_contract"] is contract
    assert captured["expected_acquisition_authority_digest"] == DIGEST_C
    assert captured["maximum_receipt_age_seconds"] == 300


def test_monitoring_intent_key_lifecycle_is_enforced() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    fingerprint = sha256_hex(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    trusted_key = MonitoringRuntimeTrustedKey(
        keyVaultKeyId=INTENT_KEY_ID,
        publicKeyFingerprint=fingerprint,
        activatedAt=NOW - timedelta(days=2),
    )
    monitoring_intent = cast(
        Any,
        SimpleNamespace(published_at=NOW - timedelta(days=1)),
    )
    record = TrustedKeyRecord(
        anchor=trusted_key.anchor,
        public_key=public_key,
        enabled=True,
        activated_at=NOW - timedelta(days=2),
    )

    _validate_monitoring_intent_key_lifecycle(
        monitoring_intent=monitoring_intent,
        key_record=record,
        as_of=NOW,
    )

    not_active_at_publication = TrustedKeyRecord(
        anchor=trusted_key.anchor,
        public_key=public_key,
        enabled=True,
        activated_at=NOW,
    )
    with pytest.raises(MonitoringAcquisitionJobError, match="not trusted"):
        _validate_monitoring_intent_key_lifecycle(
            monitoring_intent=monitoring_intent,
            key_record=not_active_at_publication,
            as_of=NOW,
        )

    expired = TrustedKeyRecord(
        anchor=trusted_key.anchor,
        public_key=public_key,
        enabled=True,
        activated_at=NOW - timedelta(days=2),
        expires_at=NOW,
    )
    with pytest.raises(MonitoringAcquisitionJobError, match="not trusted"):
        _validate_monitoring_intent_key_lifecycle(
            monitoring_intent=monitoring_intent,
            key_record=expired,
            as_of=NOW,
        )


def test_job_composes_hardened_coordinator_transaction_and_commit_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(
        _configuration_payload()
    )
    monitoring_intent = object()
    intent_reference = object()
    intent_attestation = object()
    context_binding = SimpleNamespace(
        binding_digest=DIGEST_A,
        required_coverage_scope_digests=(DIGEST_B,),
    )
    change_scope = object()
    collector_contract = SimpleNamespace(
        schema_version=MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        handoff_schema_version="athena.wc028MonitoringEvidenceHandoff.v2",
        acquisition_receipt_schema_version=MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
        collector_identity_resource_id=COLLECTOR_ID.casefold(),
        collector_identity_client_id=CLIENT_ID,
        collector_tenant_id=TENANT_ID,
        monitoring_reader_principal_id=COLLECTOR_PRINCIPAL_ID,
        athena_context_identity_id=CONTEXT_ID.casefold(),
        athena_context_principal_id=CONTEXT_PRINCIPAL_ID,
        physical_identity_separation_enforced=True,
        workspace_resource_id=WORKSPACE_ID.casefold(),
        evidence_storage_account_resource_id=EVIDENCE_STORAGE_ID.casefold(),
        evidence_container_name="monitoring-evidence",
        signing_key_resource_id=COLLECTOR_KEY_ID,
        ip_flow_verify_scope_id=NETWORK_WATCHER_ID.casefold(),
        ip_flow_verify_allowed_operations=(
            "Microsoft.Network/networkWatchers/ipFlowVerify/action",
            "Microsoft.Network/networkWatchers/ipFlowVerify/read",
        ),
        resource_health_allowed_operations=("Microsoft.ResourceHealth/AvailabilityStatuses/read",),
        identity_proof_audience=MONITORING_IDENTITY_PROOF_AUDIENCE,
        identity_proof_token_version=MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        identity_proof_required_role=MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
        identity_proof_maximum_lifetime_seconds=(
            MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ),
        maximum_evidence_age_seconds=600,
        compute_artifact_digest_value=lambda: DIGEST_B,
    )
    acquisition_authority = SimpleNamespace(
        schema_version="athena.wc028MonitoringAcquisitionAuthority.v4",
        authority_digest=DIGEST_C,
        monitoring_reader_identity_id=COLLECTOR_ID.casefold(),
        monitoring_reader_principal_id=COLLECTOR_PRINCIPAL_ID,
        monitoring_reader_client_id=CLIENT_ID,
        monitoring_reader_tenant_id=TENANT_ID,
        athena_context_identity_id=CONTEXT_ID.casefold(),
        athena_context_principal_id=CONTEXT_PRINCIPAL_ID,
        collector_contract_digest=DIGEST_B,
        context_binding_digest=DIGEST_A,
        required_coverage_scope_digests=(DIGEST_B,),
        allowed_resource_ids=(
            WORKSPACE_ID.casefold(),
            VM_ID.casefold(),
            BACKEND_VM_ID.casefold(),
            NSG_RULE_ID.casefold(),
        ),
        max_freshness_seconds=600,
        receipt_signing_key_id=COLLECTOR_KEY_ID,
        deployment_identity_contract_digest=DIGEST_A,
        identity_proof_audience=MONITORING_IDENTITY_PROOF_AUDIENCE,
        identity_proof_token_version=MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        identity_proof_required_role=MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
        identity_proof_maximum_lifetime_seconds=(
            MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ),
    )
    embedded = {
        "PublishedMonitoringIntent": monitoring_intent,
        "PublishedMonitoringIntentAssetReference": intent_reference,
        "PublishedMonitoringIntentAttestation": intent_attestation,
        "PublishedRuntimeContextBinding": context_binding,
        "MonitoringCollectorContract": collector_contract,
        "ApprovedChangeScope": change_scope,
        "MonitoringAcquisitionAuthority": acquisition_authority,
    }
    captured: dict[str, object] = {}
    key_resolver = cast(Any, lambda _anchor: object())
    transaction = object()
    commit_port = object()
    acquisition_adapter = object()
    outcome = cast(Any, SimpleNamespace(committed=object(), correlation_request=object()))

    monkeypatch.setattr(
        runtime_module,
        "_embedded_model",
        lambda model, _payload: embedded[model.__name__],
    )
    monkeypatch.setattr(
        runtime_module,
        "validate_published_monitoring_intent_assets",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        runtime_module,
        "validate_monitoring_intent_activation_eligible",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        runtime_module,
        "_validate_monitoring_intent_key_lifecycle",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        runtime_module,
        "KeyVaultRsaPublicKeyVerifier",
        lambda **_kwargs: SimpleNamespace(
            public_key=object(),
            verify_preimage=lambda *_args: True,
        ),
    )
    monkeypatch.setattr(
        runtime_module,
        "TrustedKeyRecord",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        runtime_module,
        "KeyVaultTrustedKeyResolver",
        lambda **_kwargs: key_resolver,
    )
    monkeypatch.setattr(
        runtime_module,
        "KeyVaultRsaSigner",
        lambda **_kwargs: SimpleNamespace(sign_preimage=lambda _payload: "signature"),
    )
    monkeypatch.setattr(
        runtime_module,
        "KeyVaultChangeEvidenceSigner",
        lambda **_kwargs: object(),
    )

    def build_transaction(**kwargs: object) -> object:
        captured["transaction"] = kwargs
        return transaction

    monkeypatch.setattr(
        runtime_module,
        "MonitoringCollectionTransaction",
        build_transaction,
    )

    monkeypatch.setattr(
        runtime_module,
        "_utc_now_milliseconds",
        lambda: NOW,
    )
    monkeypatch.setattr(
        runtime_module,
        "AzureManagedIdentityJsonTransport",
        lambda **kwargs: captured.setdefault("transport", kwargs),
    )
    monkeypatch.setattr(
        runtime_module,
        "AzureMonitoringAcquisitionPort",
        lambda **kwargs: captured.setdefault("port", kwargs),
    )

    def build_acquisition_adapter(**kwargs: object) -> object:
        captured["adapter"] = kwargs
        return acquisition_adapter

    monkeypatch.setattr(runtime_module, "AzureMonitoringAdapter", build_acquisition_adapter)

    stores: list[tuple[dict[str, object], object]] = []

    def build_store(**kwargs: object) -> object:
        store = object()
        stores.append((dict(kwargs), store))
        return store

    monkeypatch.setattr(
        runtime_module,
        "AzureBlobChangeEvidenceReplayStore",
        build_store,
    )

    def build_commit_port(**kwargs: object) -> object:
        captured["commit"] = kwargs
        return commit_port

    monkeypatch.setattr(
        runtime_module,
        "MonitoringEvidenceCommitPort",
        build_commit_port,
    )

    class _Coordinator:
        def __init__(self, **kwargs: object) -> None:
            captured["coordinator"] = kwargs

        def execute(self, **kwargs: object) -> Any:
            captured["execute"] = kwargs
            return outcome

    monkeypatch.setattr(
        runtime_module,
        "MonitoringAcquisitionCoordinator",
        _Coordinator,
    )

    assert (
        runtime_module.run_wc028_monitoring_acquisition_job(configuration=configuration) is outcome
    )

    transaction_arguments = cast(dict[str, object], captured["transaction"])
    assert callable(transaction_arguments["acquisition_receipt_verifier"])
    coordinator_arguments = cast(dict[str, object], captured["coordinator"])
    assert coordinator_arguments["collection_transaction"] is transaction
    assert coordinator_arguments["receipt_signer"] is not None
    assert coordinator_arguments["acquisition_adapter"] is acquisition_adapter
    assert coordinator_arguments["expected_collector_contract_digest"] == DIGEST_B
    adapter_arguments = cast(dict[str, object], captured["adapter"])
    assert adapter_arguments["reviewed_collector_contract"] is collector_contract
    assert callable(adapter_arguments["client_factory"])
    commit_arguments = cast(dict[str, object], captured["commit"])
    assert commit_arguments["key_resolver"] is key_resolver
    assert commit_arguments["reviewed_collector_contract"] is collector_contract
    assert [item[0]["container_name"] for item in stores] == [
        "monitoring-evidence",
        "change-evidence",
    ]
    assert commit_arguments["monitoring_writer"] is stores[0][1]
    assert commit_arguments["change_writer"] is stores[1][1]
    execute_arguments = cast(dict[str, object], captured["execute"])
    assert execute_arguments["commit_port"] is commit_port
    assert "collector_contract_digest" not in execute_arguments
    assert execute_arguments["trusted_as_of"] == NOW + timedelta(seconds=60)


class _HttpResponse:
    def __init__(self, payload: bytes = b"{}", *, status: int = 200) -> None:
        self._payload = payload
        self.status = status

    def __enter__(self) -> _HttpResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, _: int) -> bytes:
        return self._payload


def test_transport_uses_managed_identity_bearer_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[Any] = []

    def open_request(request: Any, *, timeout: int) -> _HttpResponse:
        captured.append((request, timeout))
        return _HttpResponse()

    monkeypatch.setattr(runtime_module, "urlopen", open_request)
    transport = AzureManagedIdentityJsonTransport(
        timeout_seconds=17,
        retry_limit=0,
    )

    assert transport.request_json(
        method="GET",
        url="https://management.azure.com/subscriptions?api-version=2022-12-01",
        access_token="synthetic-verified-token",
    ) == ({}, 2)
    request, timeout = captured[0]
    authorization = request.get_header("Authorization")
    assert isinstance(authorization, str)
    assert authorization.startswith("Bearer ")
    assert len(authorization) == len("Bearer ") + len(ACCESS_TOKEN)
    assert timeout == 17


def test_transport_rejects_untrusted_hosts_and_nonstandard_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = AzureManagedIdentityJsonTransport(
        timeout_seconds=10,
        retry_limit=0,
    )

    with pytest.raises(MonitoringAcquisitionJobError, match="not allowlisted"):
        transport.request_json(
            method="GET",
            url="https://unreviewed.example.invalid/query",
            access_token="synthetic-verified-token",
        )

    monkeypatch.setattr(
        runtime_module,
        "urlopen",
        lambda *_args, **_kwargs: _HttpResponse(b'{"value":NaN}'),
    )
    with pytest.raises(MonitoringAcquisitionJobError, match="strict JSON"):
        transport.request_json(
            method="GET",
            url="https://management.azure.com/subscriptions?api-version=2022-12-01",
            access_token="synthetic-verified-token",
        )

    monkeypatch.setattr(
        runtime_module,
        "urlopen",
        lambda *_args, **_kwargs: _HttpResponse(b"x" * (256 * 1024 + 1)),
    )
    with pytest.raises(MonitoringAcquisitionJobError, match="byte bound"):
        transport.request_json(
            method="GET",
            url="https://management.azure.com/subscriptions?api-version=2022-12-01",
            access_token="synthetic-verified-token",
        )


def test_runtime_source_clients_use_the_adapter_managed_identity() -> None:
    class _Credential:
        def __init__(self) -> None:
            self.scopes: list[str] = []

        def get_token(self, scope: str) -> object:
            self.scopes.append(scope)
            return SimpleNamespace(token=f"synthetic-source-token-{len(self.scopes)}")

    class _Port:
        collector_identity_resource_id = COLLECTOR_ID.casefold()

        def __init__(self) -> None:
            self.tokens: list[str] = []

        def _call(self, request: object, *, access_token: str) -> object:
            self.tokens.append(access_token)
            return request

        query_log_analytics = _call
        query_activity_log = _call
        query_resource_graph_changes = _call
        query_resource_health = _call
        query_ip_flow_verify = _call

    credential = _Credential()
    port = _Port()
    client = AzureMonitoringCredentialBoundClient(
        credential=cast(Any, credential),
        reviewed_contract=cast(
            Any,
            SimpleNamespace(
                schema_version=MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
                collector_identity_resource_id=COLLECTOR_ID,
            ),
        ),
        acquisition_port=cast(Any, port),
    )
    request = cast(Any, object())

    assert client.query_log_analytics(request) is request
    assert client.query_activity_log(request) is request
    assert client.query_resource_graph_changes(request) is request
    assert client.query_resource_health(request) is request
    assert client.query_ip_flow_verify(request) is request
    assert credential.scopes == [
        "https://api.loganalytics.io/.default",
        "https://management.azure.com/.default",
        "https://management.azure.com/.default",
        "https://management.azure.com/.default",
        "https://management.azure.com/.default",
    ]
    assert port.tokens == [
        "synthetic-source-token-1",
        "synthetic-source-token-2",
        "synthetic-source-token-3",
        "synthetic-source-token-4",
        "synthetic-source-token-5",
    ]


class _Request:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def model_dump(self, **_: object) -> dict[str, object]:
        return self.payload


class _Transport:
    def __init__(self) -> None:
        self.calls = 0

    def request_json(self, **_: object) -> tuple[object, int]:
        self.calls += 1
        raise AssertionError("source query must not occur")


class _ResponseTransport:
    def __init__(self, *responses: object) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def request_json(self, **kwargs: object) -> tuple[object, int]:
        self.calls.append(dict(kwargs))
        payload = self._responses.pop(0)
        return payload, len(json.dumps(payload).encode("utf-8"))


def _port(transport: _Transport) -> AzureMonitoringAcquisitionPort:
    return AzureMonitoringAcquisitionPort(
        collector_identity_resource_id=COLLECTOR_ID.casefold(),
        workspace_resource_id=WORKSPACE_ID.casefold(),
        workspace_customer_id="33333333-3333-3333-3333-333333333333",
        network_watcher_resource_id=NETWORK_WATCHER_ID.casefold(),
        authorized_resource_ids=(
            WORKSPACE_ID.casefold(),
            VM_ID.casefold(),
            BACKEND_VM_ID.casefold(),
            NSG_RULE_ID.casefold(),
        ),
        transport=transport,
    )


def test_adapter_rejects_identity_and_workspace_before_source_query() -> None:
    transport = _Transport()
    request = {
        "monitoringReaderIdentityId": CONTEXT_ID,
        "schemaVersion": "athena.wc028LogAnalyticsQueryRequest.v2",
        "queryTargetResourceId": WORKSPACE_ID,
    }
    with pytest.raises(MonitoringAcquisitionJobError, match="another monitoring identity"):
        _port(transport).query_log_analytics(
            _Request(request),
            access_token=ACCESS_TOKEN,
        )
    assert transport.calls == 0

    request["monitoringReaderIdentityId"] = COLLECTOR_ID
    request["queryTargetResourceId"] = NETWORK_WATCHER_ID
    with pytest.raises(MonitoringAcquisitionJobError, match="reviewed workspace"):
        _port(transport).query_log_analytics(
            _Request(request),
            access_token=ACCESS_TOKEN,
        )
    assert transport.calls == 0

    with pytest.raises(MonitoringAcquisitionJobError, match="resource allowlist"):
        _port(transport).query_activity_log(
            cast(
                Any,
                _Request(
                    {
                        "monitoringReaderIdentityId": COLLECTOR_ID,
                        "resourceIds": [SOURCE_STORAGE_ID],
                    }
                ),
            ),
            access_token=ACCESS_TOKEN,
        )
    assert transport.calls == 0


def test_log_analytics_adapter_maps_one_exact_reviewed_execution() -> None:
    start = NOW - timedelta(minutes=5)
    columns = (
        "resourceId",
        "observedStart",
        "observedEnd",
        "heartbeatCount",
    )
    transport = _ResponseTransport(
        {
            "tables": [
                {
                    "columns": [{"name": item} for item in columns],
                    "rows": [[VM_ID, _iso(start), _iso(NOW), 3]],
                }
            ]
        }
    )
    port = _port(cast(Any, transport))

    result = port.query_log_analytics(
        cast(
            Any,
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "schemaVersion": "athena.wc028LogAnalyticsQueryRequest.v2",
                    "queryTargetResourceId": WORKSPACE_ID,
                    "expectedColumns": list(columns),
                    "table": "Heartbeat",
                    "query": "Heartbeat | summarize heartbeatCount=count()",
                    "windowStart": _iso(start),
                    "windowEnd": _iso(NOW),
                    "collectorExecutionTime": _iso(NOW),
                    "coverageScope": {"resourceIds": [VM_ID]},
                    "requestDigest": DIGEST_A,
                }
            ),
        ),
        access_token=ACCESS_TOKEN,
    )

    assert result.source_identity_id == COLLECTOR_ID.casefold()
    assert result.rows[0].resource_id == VM_ID.casefold()
    assert result.rows[0].heartbeat_count == 3
    assert transport.calls[0]["access_token"] == ACCESS_TOKEN
    assert cast(dict[str, object], transport.calls[0]["body"])["timespan"] == (
        f"{_iso(start)}/{_iso(NOW)}"
    )

    proof_transport = _ResponseTransport(
        {
            "tables": [
                {
                    "columns": [{"name": item} for item in columns],
                    "rows": [[VM_ID, _iso(start), _iso(NOW), 0]],
                },
                {
                    "columns": [
                        {"name": "rawInputRowCount"},
                        {"name": "ingestionCompleteThrough"},
                    ],
                    "rows": [[12, _iso(NOW)]],
                },
            ]
        }
    )
    proof_result = _port(cast(Any, proof_transport)).query_log_analytics(
        cast(
            Any,
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "schemaVersion": "athena.wc028LogAnalyticsQueryRequest.v2",
                    "queryTargetResourceId": WORKSPACE_ID,
                    "expectedColumns": list(columns),
                    "table": "Heartbeat",
                    "query": "Heartbeat | summarize heartbeatCount=count()",
                    "queryDigest": DIGEST_B,
                    "windowStart": _iso(start),
                    "windowEnd": _iso(NOW),
                    "collectorExecutionTime": _iso(NOW),
                    "coverageScope": {"resourceIds": [VM_ID]},
                    "requestDigest": DIGEST_A,
                }
            ),
        ),
        access_token=ACCESS_TOKEN,
    )

    assert proof_result.rows[0].heartbeat_count == 0
    assert proof_result.aggregate_completeness_proof is not None
    assert proof_result.aggregate_completeness_proof.raw_input_row_count == 12
    assert proof_result.aggregate_completeness_proof.request_digest == DIGEST_A
    assert proof_result.aggregate_completeness_proof.query_digest == DIGEST_B


def test_empty_traffic_analytics_preserves_pre_authorized_scope() -> None:
    start = NOW - timedelta(minutes=5)
    columns = (
        "subjectResourceCandidates",
        "pathId",
        "decision",
        "direction",
        "protocol",
        "sourceResourceCandidates",
        "destinationResourceCandidates",
        "sourceAddress",
        "destinationAddress",
        "sourcePort",
        "destinationPort",
        "enforcementResourceId",
        "ruleResourceId",
        "observedStart",
        "observedEnd",
    )
    coverage_scope = {
        "resourceIds": [VM_ID, BACKEND_VM_ID],
        "pathId": PATH_ID,
        "direction": "outbound",
        "fiveTupleDigest": DIGEST_A,
    }
    transport = _ResponseTransport(
        {
            "tables": [
                {
                    "columns": [{"name": item} for item in columns],
                    "rows": [],
                }
            ]
        }
    )

    result = _port(cast(Any, transport)).query_log_analytics(
        cast(
            Any,
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "schemaVersion": "athena.wc028LogAnalyticsQueryRequest.v2",
                    "queryTargetResourceId": WORKSPACE_ID,
                    "expectedColumns": list(columns),
                    "table": "NTANetAnalytics",
                    "query": "NTANetAnalytics | summarize synthetic=count()",
                    "queryDigest": DIGEST_B,
                    "windowStart": _iso(start),
                    "windowEnd": _iso(NOW),
                    "collectorExecutionTime": _iso(NOW),
                    "coverageScope": coverage_scope,
                    "requestDigest": DIGEST_C,
                }
            ),
        ),
        access_token=ACCESS_TOKEN,
    )

    assert result.rows == ()
    assert result.coverage_descriptor is not None
    assert result.coverage_descriptor.resource_ids == tuple(
        sorted((BACKEND_VM_ID.casefold(), VM_ID.casefold()))
    )
    assert result.coverage_descriptor.path_id == PATH_ID
    assert result.coverage_descriptor.direction == "outbound"
    assert result.coverage_descriptor.five_tuple_digest == DIGEST_A


def test_nonempty_traffic_analytics_adds_fixed_limitation_without_reauthorizing() -> None:
    start = NOW - timedelta(minutes=5)
    columns = (
        "subjectResourceCandidates",
        "pathId",
        "decision",
        "direction",
        "protocol",
        "sourceResourceCandidates",
        "destinationResourceCandidates",
        "sourceAddress",
        "destinationAddress",
        "sourcePort",
        "destinationPort",
        "enforcementResourceId",
        "ruleResourceId",
        "observedStart",
        "observedEnd",
    )
    transport = _ResponseTransport(
        {
            "tables": [
                {
                    "columns": [{"name": item} for item in columns],
                    "rows": [
                        [
                            [VM_ID],
                            PATH_ID,
                            "denied",
                            "outbound",
                            "Tcp",
                            [VM_ID],
                            [BACKEND_VM_ID],
                            "10.0.1.4",
                            "10.0.2.4",
                            49152,
                            1433,
                            NSG_RULE_ID.rsplit("/securityRules/", maxsplit=1)[0],
                            NSG_RULE_ID,
                            _iso(start),
                            _iso(NOW),
                        ]
                    ],
                }
            ]
        }
    )
    authority_scope = {
        "resourceIds": [VM_ID, BACKEND_VM_ID],
        "pathId": PATH_ID,
        "direction": "outbound",
        "fiveTupleDigest": DIGEST_A,
    }

    result = _port(cast(Any, transport)).query_log_analytics(
        cast(
            Any,
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "schemaVersion": "athena.wc028LogAnalyticsQueryRequest.v2",
                    "queryTargetResourceId": WORKSPACE_ID,
                    "expectedColumns": list(columns),
                    "table": "NTANetAnalytics",
                    "query": "NTANetAnalytics | summarize synthetic=count()",
                    "queryDigest": DIGEST_B,
                    "windowStart": _iso(start),
                    "windowEnd": _iso(NOW),
                    "collectorExecutionTime": _iso(NOW),
                    "coverageScope": authority_scope,
                    "requestDigest": DIGEST_C,
                }
            ),
        ),
        access_token=ACCESS_TOKEN,
    )

    assert len(result.rows) == 1
    assert result.rows[0].traffic_analytics_limitation == "aggregatedNotPacketCausal"
    assert result.coverage_descriptor is not None
    assert result.coverage_descriptor.five_tuple_digest == DIGEST_A


def test_connection_monitor_compares_typed_authority_scope() -> None:
    start = NOW - timedelta(minutes=5)
    columns = (
        "subjectResourceId",
        "pathId",
        "monitorResourceId",
        "sourceResourceId",
        "destinationResourceId",
        "sourceAddress",
        "destinationAddress",
        "direction",
        "protocol",
        "sourcePort",
        "destinationPort",
        "status",
        "testConfigurationReference",
        "testConfigurationDigest",
        "observedStart",
        "observedEnd",
    )
    tuple_payload = {
        "direction": "outbound",
        "protocol": "Tcp",
        "sourceResourceId": VM_ID.casefold(),
        "destinationResourceId": BACKEND_VM_ID.casefold(),
        "sourceAddress": "10.0.1.4",
        "destinationAddress": "10.0.2.4",
        "sourcePort": 49152,
        "destinationPort": 1433,
    }
    coverage_scope = {
        "resourceIds": [VM_ID, BACKEND_VM_ID],
        "pathId": PATH_ID,
        "direction": "outbound",
        "fiveTupleDigest": compute_artifact_digest(tuple_payload),
        "endpointTestReference": "synthetic-web-db-test",
        "endpointTestDigest": DIGEST_B,
    }
    transport = _ResponseTransport(
        {
            "tables": [
                {
                    "columns": [{"name": item} for item in columns],
                    "rows": [
                        [
                            VM_ID,
                            PATH_ID,
                            NETWORK_WATCHER_ID,
                            VM_ID,
                            BACKEND_VM_ID,
                            "10.0.1.4",
                            "10.0.2.4",
                            "outbound",
                            "Tcp",
                            49152,
                            1433,
                            "failed",
                            "synthetic-web-db-test",
                            DIGEST_B,
                            _iso(start),
                            _iso(NOW),
                        ]
                    ],
                }
            ]
        }
    )

    result = _port(cast(Any, transport)).query_log_analytics(
        cast(
            Any,
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "schemaVersion": "athena.wc028LogAnalyticsQueryRequest.v2",
                    "queryTargetResourceId": WORKSPACE_ID,
                    "expectedColumns": list(columns),
                    "table": "NWConnectionMonitorTestResult",
                    "query": "NWConnectionMonitorTestResult | take 1",
                    "queryDigest": DIGEST_A,
                    "windowStart": _iso(start),
                    "windowEnd": _iso(NOW),
                    "collectorExecutionTime": _iso(NOW),
                    "coverageScope": coverage_scope,
                    "requestDigest": DIGEST_C,
                }
            ),
        ),
        access_token=ACCESS_TOKEN,
    )

    assert len(result.rows) == 1
    assert result.coverage_descriptor is not None
    assert result.coverage_descriptor.resource_ids == tuple(
        sorted((BACKEND_VM_ID.casefold(), VM_ID.casefold()))
    )


def test_activity_and_resource_graph_adapters_preserve_exact_change_scope() -> None:
    occurred_at = NOW - timedelta(minutes=1)
    azure_occurred_at = _iso(occurred_at).replace("Z", ".9792776Z")
    activity_transport = _ResponseTransport(
        {
            "value": [
                {
                    "category": {"value": "Administrative"},
                    "operationName": {
                        "value": ("Microsoft.Network/networkSecurityGroups/securityRules/write")
                    },
                    "status": {"value": "Succeeded"},
                    "level": "Informational",
                    "resourceId": NSG_RULE_ID,
                    "correlationId": CORRELATION_ID,
                    "eventTimestamp": azure_occurred_at,
                }
            ]
        }
    )
    activity_result = _port(cast(Any, activity_transport)).query_activity_log(
        cast(
            Any,
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "resourceIds": [NSG_RULE_ID],
                    "categories": ["Administrative"],
                    "operationNames": [
                        "Microsoft.Network/networkSecurityGroups/securityRules/write"
                    ],
                    "resultTypes": ["Succeeded"],
                    "levels": ["Informational"],
                    "expectedColumns": [
                        "category",
                        "operationName",
                        "resultType",
                        "level",
                        "targetResourceId",
                        "correlationId",
                        "occurredAt",
                    ],
                    "windowStart": _iso(NOW - timedelta(minutes=10)),
                    "windowEnd": _iso(NOW),
                    "requestDigest": DIGEST_A,
                }
            ),
        ),
        access_token=ACCESS_TOKEN,
    )

    assert activity_result.rows[0].target_resource_id == NSG_RULE_ID.casefold()
    assert activity_result.rows[0].correlation_id == CORRELATION_ID
    assert activity_result.rows[0].occurred_at.microsecond == 979000
    assert NSG_RULE_ID.casefold() in unquote(cast(str, activity_transport.calls[0]["url"]))

    graph_change = {
        "properties": {
            "targetResourceId": NSG_RULE_ID,
            "changeAttributes": {
                "correlationId": CORRELATION_ID,
                "timestamp": azure_occurred_at,
                "operation": ("Microsoft.Network/networkSecurityGroups/securityRules/write"),
            },
            "changes": {
                "properties.access": {
                    "previousValue": "Allow",
                    "newValue": "Deny",
                }
            },
        }
    }
    graph_transport = _ResponseTransport(
        {
            "data": [graph_change],
            "resultTruncated": False,
        }
    )
    graph_result = _port(cast(Any, graph_transport)).query_resource_graph_changes(
        cast(
            Any,
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "resourceIds": [NSG_RULE_ID],
                    "expectedColumns": [
                        "targetResourceId",
                        "correlationId",
                        "occurredAt",
                        "operationName",
                        "resultType",
                        "change",
                    ],
                    "windowStart": _iso(NOW - timedelta(minutes=10)),
                    "windowEnd": _iso(NOW),
                    "requestDigest": DIGEST_B,
                }
            ),
        ),
        access_token=ACCESS_TOKEN,
    )

    assert graph_result.rows[0].target_resource_id == NSG_RULE_ID.casefold()
    assert graph_result.rows[0].occurred_at == activity_result.rows[0].occurred_at
    normalized_properties = cast(
        dict[str, object],
        graph_result.rows[0].change["properties"],
    )
    assert normalized_properties["targetResourceId"] == NSG_RULE_ID
    assert (
        cast(
            dict[str, object],
            normalized_properties["changeAttributes"],
        )["correlationId"]
        == CORRELATION_ID
    )
    assert cast(
        dict[str, object],
        cast(dict[str, object], normalized_properties["changes"])["properties.access"],
    ) == {
        "newValue": "Deny",
        "previousValue": "Allow",
    }
    graph_body = cast(dict[str, object], graph_transport.calls[0]["body"])
    assert graph_body["subscriptions"] == (SUBSCRIPTION_ID,)
    assert NSG_RULE_ID.casefold() in cast(str, graph_body["query"])


def test_resource_health_and_ip_flow_adapters_keep_source_uncertainty() -> None:
    observed_start = NOW - timedelta(minutes=2)
    health_transport = _ResponseTransport(
        {
            "value": [
                {
                    "properties": {
                        "occuredTime": _iso(observed_start - timedelta(minutes=2)),
                        "reportedTime": _iso(observed_start - timedelta(minutes=1)),
                        "availabilityState": "Available",
                        "context": "Platform",
                    }
                },
                {
                    "properties": {
                        "occuredTime": _iso(observed_start),
                        "reportedTime": _iso(NOW),
                        "availabilityState": "Unavailable",
                        "context": "Platform",
                        "reasonType": "Unplanned",
                        "healthEventCause": "PlatformInitiated",
                    }
                },
            ]
        },
        {
            "access": "Deny",
            "ruleName": "securityRules/deny-db",
        },
    )
    port = _port(cast(Any, health_transport))
    health_result = port.query_resource_health(
        cast(
            Any,
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "resourceIds": [VM_ID],
                    "eventStatuses": ["Active"],
                    "currentStatuses": ["Unavailable"],
                    "previousStatuses": ["Available"],
                    "reasonTypes": ["PlatformInitiated"],
                    "expectedColumns": [
                        "resourceId",
                        "eventStatus",
                        "currentStatus",
                        "previousStatus",
                        "reasonType",
                        "observedStart",
                        "observedEnd",
                    ],
                    "windowStart": _iso(NOW - timedelta(minutes=10)),
                    "windowEnd": _iso(NOW),
                    "requestDigest": DIGEST_A,
                }
            ),
        ),
        access_token=ACCESS_TOKEN,
    )

    assert health_result.rows[0].event_status == "Active"
    assert health_result.rows[0].previous_status == "Available"
    assert health_result.rows[0].current_status == "Unavailable"

    recently_resolved_health = _ResponseTransport(
        {
            "value": [
                {
                    "properties": {
                        "occuredTime": _iso(observed_start),
                        "reportedTime": _iso(NOW),
                        "availabilityState": "Available",
                        "context": "Platform",
                        "reasonType": "Unplanned",
                        "recentlyResolved": {
                            "unavailableOccuredTime": _iso(observed_start),
                            "resolvedTime": _iso(NOW),
                        },
                    }
                }
            ]
        }
    )
    recently_resolved_result = _port(cast(Any, recently_resolved_health)).query_resource_health(
        cast(
            Any,
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "resourceIds": [VM_ID],
                    "eventStatuses": ["Resolved"],
                    "currentStatuses": ["Available"],
                    "previousStatuses": ["Unavailable"],
                    "reasonTypes": ["PlatformInitiated"],
                    "expectedColumns": [
                        "resourceId",
                        "eventStatus",
                        "currentStatus",
                        "previousStatus",
                        "reasonType",
                        "observedStart",
                        "observedEnd",
                    ],
                    "windowStart": _iso(NOW - timedelta(minutes=10)),
                    "windowEnd": _iso(NOW),
                    "requestDigest": DIGEST_A,
                }
            ),
        ),
        access_token=ACCESS_TOKEN,
    )
    assert recently_resolved_result.rows[0].event_status == "Resolved"
    assert recently_resolved_result.rows[0].previous_status == "Unavailable"
    assert recently_resolved_result.rows[0].current_status == "Available"

    flow_result = port.query_ip_flow_verify(
        cast(
            Any,
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "direction": "outbound",
                    "protocol": "Tcp",
                    "targetResourceId": VM_ID,
                    "sourceAddress": "10.0.1.4",
                    "destinationAddress": "10.0.2.4",
                    "sourcePort": 49152,
                    "destinationPort": 1433,
                    "checkedAt": _iso(NOW),
                    "requestDigest": DIGEST_B,
                }
            ),
        ),
        access_token=ACCESS_TOKEN,
    )

    assert flow_result.access == "Deny"
    assert flow_result.rule_resource_id == NSG_RULE_ID.casefold()
    assert flow_result.limitation == "pointInTimeNotHistorical"
    flow_body = cast(dict[str, object], health_transport.calls[1]["body"])
    assert flow_body == {
        "targetResourceId": VM_ID.casefold(),
        "direction": "Outbound",
        "protocol": "TCP",
        "localIPAddress": "10.0.1.4",
        "remoteIPAddress": "10.0.2.4",
        "localPort": "49152",
        "remotePort": "1433",
    }


def test_traffic_coverage_digest_preserves_source_and_destination_roles() -> None:
    descriptor = _coverage_descriptor(
        "NTANetAnalytics",
        [
            {
                "subjectResourceCandidates": [VM_ID],
                "sourceResourceCandidates": [VM_ID],
                "destinationResourceCandidates": [BACKEND_VM_ID],
                "pathId": PATH_ID,
                "direction": "outbound",
                "protocol": "Tcp",
                "sourceAddress": "10.0.1.4",
                "destinationAddress": "10.0.2.4",
                "sourcePort": 49152,
                "destinationPort": 1433,
            }
        ],
    )

    assert descriptor is not None
    assert descriptor["resourceIds"] == tuple(sorted((BACKEND_VM_ID.casefold(), VM_ID.casefold())))
    assert descriptor["fiveTupleDigest"] == compute_artifact_digest(
        {
            "direction": "outbound",
            "protocol": "Tcp",
            "sourceResourceId": VM_ID.casefold(),
            "destinationResourceId": BACKEND_VM_ID.casefold(),
            "sourceAddress": "10.0.1.4",
            "destinationAddress": "10.0.2.4",
            "sourcePort": 49152,
            "destinationPort": 1433,
        }
    )


class _StrictTupleResult(BaseModel):
    model_config = ConfigDict(strict=True)

    columns: tuple[str, ...]
    rows: tuple[dict[str, object], ...]


def test_adapter_result_uses_json_mode_for_pr94_strict_tuples() -> None:
    result = _result(
        _StrictTupleResult,
        {
            "columns": ("one", "two"),
            "rows": [{"one": 1, "two": 2}],
        },
    )

    assert result.columns == ("one", "two")
    assert result.rows == ({"one": 1, "two": 2},)


def test_ip_flow_rejects_unsupported_protocol_before_azure_call() -> None:
    transport = _Transport()
    with pytest.raises(MonitoringAcquisitionJobError, match="TCP or UDP"):
        _port(transport).query_ip_flow_verify(
            _Request(
                {
                    "monitoringReaderIdentityId": COLLECTOR_ID,
                    "direction": "inbound",
                    "protocol": "Icmp",
                }
            ),
            access_token=ACCESS_TOKEN,
        )
    assert transport.calls == 0


class _Writer:
    def __init__(self, *, collide: bool = False) -> None:
        self.collide = collide
        self.requests: list[Any] = []

    def create(self, request: Any) -> ArtifactWriteReceipt:
        self.requests.append(request)
        if self.collide:
            raise ArtifactAlreadyExistsError("synthetic collision")
        return ArtifactWriteReceipt(
            container_name="monitoring-evidence",
            blob_name=request.blob_name,
            version_id="2026-09-14T05:30:00.0000000Z",
            etag='"synthetic-etag"',
            last_modified=NOW,
            size_bytes=len(request.payload),
            payload_sha256=sha256_hex(request.payload),
        )


class _CurrentReader:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.requests: list[Any] = []

    def read_current(self, request: Any) -> ArtifactReadResult:
        self.requests.append(request)
        return ArtifactReadResult(
            container_name="monitoring-evidence",
            blob_name=request.blob_name,
            version_id="2026-09-14T05:30:00.0000000Z",
            payload=self._payload,
            size_bytes=len(self._payload),
            content_type="application/json",
            payload_sha256=sha256_hex(self._payload),
        )


class _Signer:
    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key

    def sign_preimage(self, canonical_preimage: bytes) -> str:
        return base64.b64encode(
            self._private_key.sign(
                canonical_preimage,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        ).decode("ascii")


@dataclass
class _CollectorContract:
    collector_identity_client_id: str
    signing_key_resource_id: str
    maximum_evidence_age_seconds: int = 600
    handoff_schema_version: str = "athena.wc024MonitoringEvidenceHandoff.v1"

    def compute_artifact_digest_value(self) -> str:
        return DIGEST_C


class _Bundle:
    collected_at = NOW

    def canonical_bytes(self) -> bytes:
        return b'{"schemaVersion":"synthetic-monitoring-bundle"}\n'


def _commit_port(
    writer: _Writer,
    *,
    change_writer: _Writer | None = None,
    current_reader: _CurrentReader | None = None,
) -> MonitoringEvidenceCommitPort:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    fingerprint = sha256_hex(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    trusted_key = MonitoringRuntimeTrustedKey(
        keyVaultKeyId=COLLECTOR_KEY_ID,
        publicKeyFingerprint=fingerprint,
        activatedAt=NOW - timedelta(days=1),
    )
    key_record = TrustedKeyRecord(
        anchor=trusted_key.anchor,
        public_key=public_key,
        enabled=True,
        activated_at=NOW - timedelta(days=1),
    )
    return MonitoringEvidenceCommitPort(
        monitoring_writer=writer,
        change_writer=writer if change_writer is None else change_writer,
        signer=_Signer(private_key),
        trusted_key=trusted_key,
        reviewed_collector_contract=cast(
            Any,
            _CollectorContract(
                collector_identity_client_id=CLIENT_ID,
                signing_key_resource_id=COLLECTOR_KEY_ID,
            ),
        ),
        key_record=key_record,
        monitoring_current_reader=current_reader,
        change_current_reader=current_reader,
    )


def test_commit_port_uses_exact_blob_name_and_verifies_trusted_key() -> None:
    writer = _Writer()
    prepared = SimpleNamespace(
        monitoring_bundle=_Bundle(),
        change_artifacts=(),
    )

    with _commit_port(writer).transaction(cast(Any, prepared)) as committed:
        handoff = committed.monitoring_handoff

    expected_digest = sha256_hex(_Bundle().canonical_bytes())
    expected_collection_id = f"wc024-{expected_digest.removeprefix('sha256:')[:12]}"
    assert writer.requests[0].blob_name == (
        f"wc024-monitoring/{expected_collection_id}/evidence.json"
    )
    assert handoff.collection_id == expected_collection_id
    assert handoff.collector_attestation.trust_anchor_ref == COLLECTOR_KEY_ID


def test_commit_port_fails_closed_on_immutable_collision() -> None:
    prepared = SimpleNamespace(
        monitoring_bundle=_Bundle(),
        change_artifacts=(),
    )
    with (
        pytest.raises(MonitoringAcquisitionJobError, match="already exists"),
        _commit_port(_Writer(collide=True)).transaction(cast(Any, prepared)),
    ):
        pass


def test_commit_port_recovers_only_an_identical_immutable_retry() -> None:
    bundle = _Bundle()
    prepared = SimpleNamespace(
        monitoring_bundle=bundle,
        change_artifacts=(),
    )
    reader = _CurrentReader(bundle.canonical_bytes())

    with _commit_port(
        _Writer(collide=True),
        current_reader=reader,
    ).transaction(cast(Any, prepared)) as committed:
        handoff = committed.monitoring_handoff

    assert len(reader.requests) == 1
    assert handoff.evidence.version == "2026-09-14T05:30:00.0000000Z"
    assert handoff.evidence.content_digest == sha256_hex(bundle.canonical_bytes())


def test_commit_port_keeps_change_artifacts_in_the_wc025_storage_domain() -> None:
    monitoring_writer = _Writer()
    change_writer = _Writer()
    evidence_id = "chg-" + hashlib.sha256(DIGEST_A.encode("utf-8")).hexdigest()[:12]
    artifact = SimpleNamespace(
        evidence=SimpleNamespace(
            evidence_id=evidence_id,
            deduplication_key=DIGEST_A,
            change_key=DIGEST_B,
        ),
        canonical_bytes=lambda: b'{"schemaVersion":"synthetic-change"}\n',
    )

    handoff = _commit_port(
        monitoring_writer,
        change_writer=change_writer,
    )._write_change_artifact(artifact)

    assert monitoring_writer.requests == []
    assert change_writer.requests[0].blob_name == (f"change-evidence/{'a' * 64}/evidence.json")
    assert handoff.evidence_id == evidence_id


def test_cli_runs_wc028_job_and_reports_exact_handoffs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = object()
    outcome = SimpleNamespace(
        committed=SimpleNamespace(
            monitoring_handoff=SimpleNamespace(collection_id="wc024-aaaaaaaaaaaa")
        ),
        correlation_request=SimpleNamespace(request_id="request-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
    )
    monkeypatch.setattr(
        cli,
        "load_wc028_monitoring_acquisition_job_configuration",
        lambda **_: configuration,
    )
    monkeypatch.setattr(
        cli,
        "run_wc028_monitoring_acquisition_job",
        lambda **_: outcome,
    )
    stdout = io.StringIO()
    stderr = io.StringIO()

    result = cli.main(
        ["wc028-monitoring-acquisition-job", "--config-json", "{}"],
        stdout=stdout,
        stderr=stderr,
    )

    assert result == 0
    assert "wc024-aaaaaaaaaaaa" in stdout.getvalue()
    assert "request-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" in stdout.getvalue()
    assert stderr.getvalue() == ""
