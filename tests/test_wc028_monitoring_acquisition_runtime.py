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

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import ValidationError

import athena_context.monitoring_acquisition_runtime as runtime_module
from athena_context import cli
from athena_context.artifacts import (
    ArtifactAlreadyExistsError,
    ArtifactNotFoundError,
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
    MonitoringAcquisitionJobError,
    MonitoringEvidenceCommitPort,
    MonitoringPersistenceCommitManifest,
    MonitoringRuntimeTrustedKey,
    Wc028MonitoringAcquisitionJobConfiguration,
    _build_acquisition_receipt_verifier,
    _monitoring_persistence_replay_payload,
    _validate_acquisition_authority_preflight,
    _validate_monitoring_intent_key_lifecycle,
    load_wc028_monitoring_acquisition_job_configuration,
)
from test_wc024_monitoring_contract import _acquisition_collector_contract
from test_wc028_monitoring_acquisition import (
    _acquisition_authority,
    _authority,
)

NOW = datetime(2026, 9, 14, 5, 30, tzinfo=UTC)
SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
TENANT_ID = "33333333-3333-3333-3333-333333333333"
COLLECTOR_PRINCIPAL_ID = "44444444-4444-4444-4444-444444444444"
CONTEXT_PRINCIPAL_ID = "55555555-5555-5555-5555-555555555555"
SUPPORT_CLIENT_ID = "66666666-6666-6666-6666-666666666666"
SUPPORT_PRINCIPAL_ID = "77777777-7777-7777-7777-777777777777"
COLLECTOR_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-monitoring/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
    "athena-demo-monitoring-monitoring-collector-id"
)
CONTEXT_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-context/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/athena-context-id"
)
SUPPORT_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-monitoring/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
    "athena-wc028-runtime-support-id"
)
SOURCE_STORAGE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-context/"
    "providers/Microsoft.Storage/storageAccounts/athenacontextsource"
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
EVIDENCE_CONTAINER_ID = f"{EVIDENCE_STORAGE_ID}/blobServices/default/containers/monitoring-evidence"
RESOURCE_LOG_ROLE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-workload/"
    "providers/Microsoft.Authorization/roleDefinitions/"
    "f33a4363-5d9a-5d50-9871-c08582234978"
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
CLEANUP_DIGEST = f"sha256:{'f' * 64}"
MONITORING_INTENT_ID = f"monitoring-intent-{'d' * 32}"
EXECUTION_ID = f"wc028-execution-{'e' * 32}"
PERSISTENCE_REPLAY_KEY = compute_artifact_digest(
    {
        "schemaVersion": "athena.wc028MonitoringPersistenceReplay.v1",
        "executionId": EXECUTION_ID,
        "acquisitionAuthorityDigest": DIGEST_C,
        "monitoringIntentDigest": DIGEST_A,
        "contextBindingDigest": DIGEST_A,
        "incidentRevision": 1,
        "legacyCollectorRbacCleanupDigest": CLEANUP_DIGEST,
    }
)


def _configuration_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringAcquisitionJobConfiguration.v2",
        "managedIdentityClientId": CLIENT_ID,
        "collectorIdentityResourceId": COLLECTOR_ID,
        "athenaContextIdentityResourceId": CONTEXT_ID,
        "runtimeSupportIdentityResourceId": SUPPORT_ID,
        "runtimeSupportIdentityClientId": SUPPORT_CLIENT_ID,
        "runtimeSupportIdentityPrincipalId": SUPPORT_PRINCIPAL_ID,
        "sourceStorageAccountResourceId": SOURCE_STORAGE_ID,
        "evidenceStorageAccountResourceId": EVIDENCE_STORAGE_ID,
        "evidenceBlobEndpoint": "https://athenamonitoring.blob.core.windows.net",
        "evidenceContainerName": "monitoring-evidence",
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
        "monitoringIntent": {
            "schemaVersion": "synthetic",
            "intentDigest": DIGEST_A,
        },
        "monitoringIntentReference": {"schemaVersion": "synthetic"},
        "monitoringIntentAttestation": {"schemaVersion": "synthetic"},
        "contextBinding": {
            "schemaVersion": "synthetic",
            "bindingDigest": DIGEST_A,
            "requiredCoverageScopeDigests": [DIGEST_B],
        },
        "acquisitionAuthority": {
            "schemaVersion": "athena.wc028MonitoringAcquisitionAuthority.v5",
            "monitoringReaderIdentityId": COLLECTOR_ID,
            "monitoringReaderPrincipalId": COLLECTOR_PRINCIPAL_ID,
            "monitoringReaderClientId": CLIENT_ID,
            "monitoringReaderTenantId": TENANT_ID,
            "athenaContextIdentityId": CONTEXT_ID,
            "athenaContextPrincipalId": CONTEXT_PRINCIPAL_ID,
            "receiptSigningKeyId": COLLECTOR_KEY_ID,
            "contextBindingDigest": DIGEST_A,
            "requiredCoverageScopeDigests": [DIGEST_B],
            "allowedSources": ["logAnalytics"],
            "allowedResourceIds": [VM_ID],
            "identityProofAudience": MONITORING_IDENTITY_PROOF_AUDIENCE,
            "identityProofTokenVersion": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
            "identityProofRequiredRole": MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
            "identityProofMaximumLifetimeSeconds": (
                MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
            ),
            "effectiveRbacInventoryDigest": DIGEST_B,
            "effectiveRbacSourceManifestDigest": DIGEST_C,
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
            "workspaceResourceContextAccessEnabled": True,
            "workspaceSkuName": "PerGB2018",
            "resourceIdColumn": "_ResourceId",
            "logQueryPreferHeader": "include-permissions=true",
            "flowTableAcquisitionMode": "unsupportedUnavailable",
            "signalReadScopeIds": [VM_ID],
            "resourceLogReaderRoleDefinitionId": RESOURCE_LOG_ROLE_ID,
            "resourceLogAllowedOperations": [
                "Microsoft.Insights/Logs/Heartbeat/Read",
                "Microsoft.Insights/Logs/Perf/Read",
                "Microsoft.Insights/Logs/InsightsMetrics/Read",
                "Microsoft.Insights/Logs/Syslog/Read",
                "Microsoft.Insights/Logs/VMConnection/Read",
            ],
            "resourceLogReadScopeIds": [VM_ID],
            "evidenceStorageAccountResourceId": EVIDENCE_STORAGE_ID,
            "evidenceContainerResourceId": EVIDENCE_CONTAINER_ID,
            "evidenceContainerName": "monitoring-evidence",
            "signingKeyResourceId": COLLECTOR_KEY_ID,
            "resourceHealthRoleDefinitionId": RESOURCE_HEALTH_ROLE_ID,
            "resourceHealthScopeIds": [VM_ID],
            "resourceHealthAllowedOperations": [
                "Microsoft.ResourceHealth/AvailabilityStatuses/current/read"
            ],
            "identityProofAudience": MONITORING_IDENTITY_PROOF_AUDIENCE,
            "identityProofTokenVersion": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
            "identityProofRequiredRole": MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
            "identityProofMaximumLifetimeSeconds": (
                MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
            ),
            "allowedReadOperations": [
                "Microsoft.Insights/Logs/Heartbeat/Read",
                "Microsoft.ResourceHealth/AvailabilityStatuses/current/read",
            ],
            "effectiveRbacInventory": {
                "inventoryDigest": DIGEST_B,
                "sourceManifestDigest": DIGEST_C,
            },
            "handoffSchemaVersion": "athena.wc028MonitoringEvidenceHandoff.v2",
            "acquisitionReceiptSchemaVersion": MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
        },
        "approvedChangeScope": {"schemaVersion": "synthetic"},
        "expectedActiveContextAuthorityDigest": DIGEST_A,
        "expectedAcquisitionAuthorityDigest": DIGEST_C,
        "incidentRevision": 1,
        "executionId": EXECUTION_ID,
        "legacyCollectorRbacCleanupDigest": CLEANUP_DIGEST,
        "trustDelaySeconds": 60,
        "requestLifetimeSeconds": 600,
    }
    payload["persistenceReplayKey"] = compute_artifact_digest(
        {
            "schemaVersion": "athena.wc028MonitoringPersistenceReplay.v1",
            "executionId": EXECUTION_ID,
            "acquisitionAuthorityDigest": DIGEST_C,
            "monitoringIntentDigest": DIGEST_A,
            "contextBindingDigest": DIGEST_A,
            "incidentRevision": 1,
            "legacyCollectorRbacCleanupDigest": CLEANUP_DIGEST,
        }
    )
    return payload


def test_configuration_preserves_identity_and_storage_separation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AZURE_CLIENT_ID", CLIENT_ID)
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(
        _configuration_payload()
    )

    assert configuration.collector_identity_resource_id == COLLECTOR_ID.casefold()
    assert configuration.athena_context_identity_resource_id == CONTEXT_ID.casefold()
    assert configuration.runtime_support_identity_resource_id == SUPPORT_ID.casefold()
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

    shared_support_identity = _configuration_payload()
    shared_support_identity["runtimeSupportIdentityResourceId"] = COLLECTOR_ID
    with pytest.raises(ValidationError, match="identities must be separate"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(shared_support_identity)

    shared_support_client = _configuration_payload()
    shared_support_client["runtimeSupportIdentityClientId"] = CLIENT_ID
    with pytest.raises(ValidationError, match="client and principal identities"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(shared_support_client)

    shared_support_principal = _configuration_payload()
    shared_support_principal["runtimeSupportIdentityPrincipalId"] = COLLECTOR_PRINCIPAL_ID
    with pytest.raises(ValidationError, match="client and principal identities"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(shared_support_principal)


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
    with pytest.raises(ValidationError, match="must not authorize IP Flow"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_ip_flow_role)

    substituted_resource_log_role = _configuration_payload()
    contract = cast(
        dict[str, object],
        substituted_resource_log_role["monitoringCollectorContract"],
    )
    contract["resourceLogReaderRoleDefinitionId"] = RESOURCE_HEALTH_ROLE_ID
    with pytest.raises(ValidationError, match="resource-log role"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_resource_log_role)

    substituted_resource_health_role = _configuration_payload()
    contract = cast(
        dict[str, object],
        substituted_resource_health_role["monitoringCollectorContract"],
    )
    contract["resourceHealthRoleDefinitionId"] = RESOURCE_LOG_ROLE_ID
    with pytest.raises(ValidationError, match="Resource Health role"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_resource_health_role)

    substituted_replay_key = _configuration_payload()
    substituted_replay_key["persistenceReplayKey"] = DIGEST_B
    with pytest.raises(ValidationError, match="persistenceReplayKey"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_replay_key)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("workspaceResourceId", WORKSPACE_ID),
        ("workspaceCustomerId", CLIENT_ID),
        ("networkWatcherResourceId", WORKLOAD_RESOURCE_GROUP_ID),
        ("changeEvidenceStorageAccountResourceId", SOURCE_STORAGE_ID),
        ("changeEvidenceBlobEndpoint", "https://athenacontextsource.blob.core.windows.net"),
        ("changeEvidenceContainerName", "change-evidence"),
        ("httpTimeoutSeconds", 30),
        ("httpRetryLimit", 2),
    ),
)
def test_configuration_rejects_obsolete_duplicate_client_settings(
    field_name: str,
    value: object,
) -> None:
    payload = _configuration_payload()
    payload[field_name] = value

    with pytest.raises(ValidationError, match="Extra inputs"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(payload)


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

    monkeypatch.delenv("ATHENA_WC028_DEPLOYED_MONITORING_INTENT_SIGNING_KEY_ID")
    monkeypatch.setenv("ATHENA_WC028_RUNTIME_SUPPORT_CLIENT_ID", CLIENT_ID)
    with pytest.raises(ValidationError, match="RUNTIME_SUPPORT_CLIENT_ID"):
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


def test_current_contract_and_authority_pass_exact_preflight_scope_binding() -> None:
    context_binding, monitoring_intent, controls = _authority(required_control_names={"heartbeat"})
    collector_contract = _acquisition_collector_contract()
    acquisition_authority = _acquisition_authority(
        context_binding=context_binding,
        controls=controls,
        collector_contract=collector_contract,
    )
    payload = _configuration_payload()
    evidence_storage_id = collector_contract.evidence_storage_account_resource_id
    evidence_storage_name = evidence_storage_id.rsplit("/", maxsplit=1)[-1]
    payload.update(
        {
            "managedIdentityClientId": collector_contract.collector_identity_client_id,
            "collectorIdentityResourceId": collector_contract.collector_identity_resource_id,
            "athenaContextIdentityResourceId": collector_contract.athena_context_identity_id,
            "evidenceStorageAccountResourceId": evidence_storage_id,
            "evidenceBlobEndpoint": (f"https://{evidence_storage_name}.blob.core.windows.net"),
            "monitoringIntent": monitoring_intent.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            "contextBinding": context_binding.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            "acquisitionAuthority": acquisition_authority.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            "monitoringCollectorContract": collector_contract.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            ),
            "expectedActiveContextAuthorityDigest": (
                context_binding.publication_authority.authority_digest
            ),
            "expectedAcquisitionAuthorityDigest": acquisition_authority.authority_digest,
        }
    )
    signing_key = cast(dict[str, object], payload["collectorSigningKey"])
    signing_key["keyVaultKeyId"] = collector_contract.signing_key_resource_id
    payload["persistenceReplayKey"] = compute_artifact_digest(
        {
            "schemaVersion": "athena.wc028MonitoringPersistenceReplay.v1",
            "executionId": EXECUTION_ID,
            "acquisitionAuthorityDigest": acquisition_authority.authority_digest,
            "monitoringIntentDigest": monitoring_intent.intent_digest,
            "contextBindingDigest": context_binding.binding_digest,
            "incidentRevision": 1,
            "legacyCollectorRbacCleanupDigest": CLEANUP_DIGEST,
        }
    )
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(payload)

    _validate_acquisition_authority_preflight(
        acquisition_authority=acquisition_authority,
        configuration=configuration,
        collector_contract=collector_contract,
        context_binding=context_binding,
        monitoring_intent=monitoring_intent,
    )


def test_authority_scope_digest_and_freshness_fail_before_external_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(
        _configuration_payload()
    )
    context_binding = SimpleNamespace(
        binding_digest=DIGEST_A,
        required_coverage_scope_digests=(DIGEST_B,),
    )
    monitoring_intent = SimpleNamespace(controls=())
    effective_rbac_inventory = SimpleNamespace(
        inventory_digest=DIGEST_B,
        source_manifest_digest=DIGEST_C,
    )
    authority = SimpleNamespace(
        schema_version="athena.wc028MonitoringAcquisitionAuthority.v5",
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
        required_control_ids=(),
        allowed_sources=(),
        allowed_resource_ids=(),
        max_freshness_seconds=600,
        receipt_signing_key_id=COLLECTOR_KEY_ID,
        identity_proof_audience=MONITORING_IDENTITY_PROOF_AUDIENCE,
        identity_proof_token_version=MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        identity_proof_required_role=MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
        identity_proof_maximum_lifetime_seconds=(
            MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ),
        effective_rbac_inventory_digest=DIGEST_B,
        effective_rbac_source_manifest_digest=DIGEST_C,
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
        evidence_container_resource_id=EVIDENCE_CONTAINER_ID.casefold(),
        evidence_container_name="monitoring-evidence",
        signing_key_resource_id=COLLECTOR_KEY_ID,
        flow_table_acquisition_mode="unsupportedUnavailable",
        ip_flow_verify_role_definition_id=None,
        ip_flow_verify_role_name=None,
        ip_flow_verify_scope_id=None,
        ip_flow_verify_allowed_operations=None,
        resource_log_allowed_operations=(
            "Microsoft.Insights/Logs/Heartbeat/Read",
            "Microsoft.Insights/Logs/Perf/Read",
            "Microsoft.Insights/Logs/InsightsMetrics/Read",
            "Microsoft.Insights/Logs/Syslog/Read",
            "Microsoft.Insights/Logs/VMConnection/Read",
        ),
        resource_health_allowed_operations=(
            "Microsoft.ResourceHealth/AvailabilityStatuses/current/read",
        ),
        identity_proof_audience=MONITORING_IDENTITY_PROOF_AUDIENCE,
        identity_proof_token_version=MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        identity_proof_required_role=MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
        identity_proof_maximum_lifetime_seconds=(
            MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ),
        effective_rbac_inventory=effective_rbac_inventory,
        maximum_evidence_age_seconds=600,
        compute_artifact_digest_value=lambda: DIGEST_C,
    )
    monkeypatch.setattr(
        runtime_module,
        "compute_monitoring_acquisition_authority_scope",
        lambda _controls, _contract: ((), ()),
    )

    with pytest.raises(MonitoringAcquisitionJobError, match="collector contract"):
        _validate_acquisition_authority_preflight(
            acquisition_authority=cast(Any, authority),
            configuration=configuration,
            collector_contract=cast(Any, contract),
            context_binding=cast(Any, context_binding),
            monitoring_intent=cast(Any, monitoring_intent),
        )

    authority.collector_contract_digest = DIGEST_C
    authority.allowed_sources = ("activityLog", "resourceGraph")
    monkeypatch.setattr(
        runtime_module,
        "compute_monitoring_acquisition_authority_scope",
        lambda _controls, _contract: (("activityLog", "resourceGraph"), ()),
    )
    with pytest.raises(MonitoringAcquisitionJobError, match="does not authorize runtime"):
        _validate_acquisition_authority_preflight(
            acquisition_authority=cast(Any, authority),
            configuration=configuration,
            collector_contract=cast(Any, contract),
            context_binding=cast(Any, context_binding),
            monitoring_intent=cast(Any, monitoring_intent),
        )

    authority.allowed_sources = ()
    monkeypatch.setattr(
        runtime_module,
        "compute_monitoring_acquisition_authority_scope",
        lambda _controls, _contract: ((), ()),
    )
    authority.allowed_resource_ids = (VM_ID.casefold(),)
    with pytest.raises(MonitoringAcquisitionJobError, match="exactly bind contract scope"):
        _validate_acquisition_authority_preflight(
            acquisition_authority=cast(Any, authority),
            configuration=configuration,
            collector_contract=cast(Any, contract),
            context_binding=cast(Any, context_binding),
            monitoring_intent=cast(Any, monitoring_intent),
        )

    authority.allowed_resource_ids = ()
    authority.max_freshness_seconds = 30
    with pytest.raises(MonitoringAcquisitionJobError, match="freshness"):
        _validate_acquisition_authority_preflight(
            acquisition_authority=cast(Any, authority),
            configuration=configuration,
            collector_contract=cast(Any, contract),
            context_binding=cast(Any, context_binding),
            monitoring_intent=cast(Any, monitoring_intent),
        )

    authority.max_freshness_seconds = 600
    authority.authority_digest = DIGEST_A
    with pytest.raises(MonitoringAcquisitionJobError, match="configured authority"):
        _validate_acquisition_authority_preflight(
            acquisition_authority=cast(Any, authority),
            configuration=configuration,
            collector_contract=cast(Any, contract),
            context_binding=cast(Any, context_binding),
            monitoring_intent=cast(Any, monitoring_intent),
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
        evidence_container_resource_id=EVIDENCE_CONTAINER_ID.casefold(),
        evidence_container_name="monitoring-evidence",
        signing_key_resource_id=COLLECTOR_KEY_ID,
        flow_table_acquisition_mode="unsupportedUnavailable",
        ip_flow_verify_role_definition_id=None,
        ip_flow_verify_role_name=None,
        ip_flow_verify_scope_id=None,
        ip_flow_verify_allowed_operations=None,
        resource_log_allowed_operations=(
            "Microsoft.Insights/Logs/Heartbeat/Read",
            "Microsoft.Insights/Logs/Perf/Read",
            "Microsoft.Insights/Logs/InsightsMetrics/Read",
            "Microsoft.Insights/Logs/Syslog/Read",
            "Microsoft.Insights/Logs/VMConnection/Read",
        ),
        resource_health_allowed_operations=(
            "Microsoft.ResourceHealth/AvailabilityStatuses/current/read",
        ),
        identity_proof_audience=MONITORING_IDENTITY_PROOF_AUDIENCE,
        identity_proof_token_version=MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        identity_proof_required_role=MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
        identity_proof_maximum_lifetime_seconds=(
            MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ),
        effective_rbac_inventory=SimpleNamespace(
            inventory_digest=DIGEST_B,
            source_manifest_digest=DIGEST_C,
        ),
        maximum_evidence_age_seconds=600,
        compute_artifact_digest_value=lambda: DIGEST_B,
    )
    acquisition_authority = SimpleNamespace(
        schema_version="athena.wc028MonitoringAcquisitionAuthority.v5",
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
        required_control_ids=(),
        allowed_sources=(),
        allowed_resource_ids=(),
        max_freshness_seconds=600,
        receipt_signing_key_id=COLLECTOR_KEY_ID,
        deployment_identity_contract_digest=DIGEST_A,
        identity_proof_audience=MONITORING_IDENTITY_PROOF_AUDIENCE,
        identity_proof_token_version=MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        identity_proof_required_role=MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
        identity_proof_maximum_lifetime_seconds=(
            MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
        ),
        effective_rbac_inventory_digest=DIGEST_B,
        effective_rbac_source_manifest_digest=DIGEST_C,
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
    verifier_calls: list[dict[str, object]] = []
    resolver_calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        runtime_module,
        "_embedded_model",
        lambda model, _payload: embedded[model.__name__],
    )
    monkeypatch.setattr(
        runtime_module,
        "_validate_acquisition_authority_preflight",
        lambda **kwargs: captured.setdefault("preflight", kwargs),
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

    def build_verifier(**kwargs: object) -> object:
        verifier_calls.append(dict(kwargs))
        return SimpleNamespace(
            public_key=object(),
            verify_preimage=lambda *_args: True,
        )

    monkeypatch.setattr(runtime_module, "KeyVaultRsaPublicKeyVerifier", build_verifier)
    monkeypatch.setattr(
        runtime_module,
        "TrustedKeyRecord",
        lambda **_kwargs: object(),
    )

    def build_resolver(**kwargs: object) -> object:
        resolver_calls.append(dict(kwargs))
        return key_resolver

    monkeypatch.setattr(runtime_module, "KeyVaultTrustedKeyResolver", build_resolver)
    monkeypatch.setattr(
        runtime_module,
        "KeyVaultRsaSigner",
        lambda **_kwargs: SimpleNamespace(sign_preimage=lambda _payload: "signature"),
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
    assert isinstance(
        transaction_arguments["change_signer"],
        runtime_module._UnsupportedChangeEvidenceSigner,
    )
    with pytest.raises(MonitoringAcquisitionJobError, match="does not authorize"):
        cast(Any, transaction_arguments["change_signer"]).sign_preimage(b"unexpected")
    assert verifier_calls[0]["managed_identity_client_id"] == SUPPORT_CLIENT_ID
    assert verifier_calls[1]["managed_identity_client_id"] == CLIENT_ID
    assert resolver_calls[0]["managed_identity_client_id"] == SUPPORT_CLIENT_ID
    assert resolver_calls[1]["managed_identity_client_id"] == CLIENT_ID
    coordinator_arguments = cast(dict[str, object], captured["coordinator"])
    assert coordinator_arguments["collection_transaction"] is transaction
    assert coordinator_arguments["receipt_signer"] is not None
    assert coordinator_arguments["acquisition_adapter"] is acquisition_adapter
    assert coordinator_arguments["expected_collector_contract_digest"] == DIGEST_B
    adapter_arguments = cast(dict[str, object], captured["adapter"])
    assert adapter_arguments["reviewed_collector_contract"] is collector_contract
    assert set(adapter_arguments) == {"reviewed_collector_contract"}
    preflight_arguments = cast(dict[str, object], captured["preflight"])
    assert preflight_arguments["monitoring_intent"] is monitoring_intent
    commit_arguments = cast(dict[str, object], captured["commit"])
    assert commit_arguments["key_resolver"] is key_resolver
    assert commit_arguments["reviewed_collector_contract"] is collector_contract
    assert [item[0]["container_name"] for item in stores] == ["monitoring-evidence"]
    assert commit_arguments["monitoring_writer"] is stores[0][1]
    assert commit_arguments["monitoring_current_reader"] is stores[0][1]
    assert commit_arguments["persistence_replay_key"] == configuration.persistence_replay_key
    assert "change_writer" not in commit_arguments
    execute_arguments = cast(dict[str, object], captured["execute"])
    assert execute_arguments["commit_port"] is commit_port
    assert "collector_contract_digest" not in execute_arguments
    assert execute_arguments["trusted_as_of"] == NOW + timedelta(seconds=60)


class _MemoryStore:
    def __init__(
        self,
        *,
        container_name: str,
        fail_once_on_suffix: str | None = None,
    ) -> None:
        self.container_name = container_name
        self.fail_once_on_suffix = fail_once_on_suffix
        self.create_requests: list[Any] = []
        self.read_requests: list[Any] = []
        self.blobs: dict[str, ArtifactReadResult] = {}

    def create(self, request: Any) -> ArtifactWriteReceipt:
        self.create_requests.append(request)
        if self.fail_once_on_suffix is not None and request.blob_name.endswith(
            self.fail_once_on_suffix
        ):
            self.fail_once_on_suffix = None
            raise RuntimeError("synthetic staged persistence failure")
        if request.blob_name in self.blobs:
            raise ArtifactAlreadyExistsError("synthetic create-only collision")
        version_id = f"synthetic-version-{len(self.blobs) + 1}"
        result = ArtifactReadResult(
            container_name=self.container_name,
            blob_name=request.blob_name,
            version_id=version_id,
            payload=request.payload,
            size_bytes=len(request.payload),
            content_type="application/json",
            payload_sha256=sha256_hex(request.payload),
        )
        self.blobs[request.blob_name] = result
        return ArtifactWriteReceipt(
            container_name=self.container_name,
            blob_name=request.blob_name,
            version_id=version_id,
            etag=f'"synthetic-etag-{len(self.blobs)}"',
            last_modified=NOW,
            size_bytes=len(request.payload),
            payload_sha256=sha256_hex(request.payload),
        )

    def read_current(self, request: Any) -> ArtifactReadResult:
        self.read_requests.append(request)
        try:
            return self.blobs[request.blob_name]
        except KeyError as exc:
            raise ArtifactNotFoundError("synthetic Blob is absent") from exc


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
    handoff_schema_version: str = "athena.wc028MonitoringEvidenceHandoff.v2"

    def compute_artifact_digest_value(self) -> str:
        return DIGEST_C


class _Bundle:
    collected_at = NOW
    monitoring_contract_digest = DIGEST_C
    acquisition_receipt = SimpleNamespace(receipt_digest=DIGEST_B)

    def __init__(
        self,
        payload: bytes = b'{"schemaVersion":"synthetic-monitoring-bundle"}\n',
    ) -> None:
        self._payload = payload

    def canonical_bytes(self) -> bytes:
        return self._payload


def _prepared(
    *,
    change_artifacts: tuple[object, ...] = (),
    bundle_payload: bytes = b'{"schemaVersion":"synthetic-monitoring-bundle"}\n',
) -> SimpleNamespace:
    return SimpleNamespace(
        intent_id=MONITORING_INTENT_ID,
        intent_digest=DIGEST_A,
        context_binding_digest=DIGEST_B,
        monitoring_bundle=_Bundle(bundle_payload),
        change_artifacts=change_artifacts,
    )


def _commit_port(
    monitoring_store: _MemoryStore,
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
        monitoring_writer=monitoring_store,
        monitoring_current_reader=monitoring_store,
        persistence_replay_key=PERSISTENCE_REPLAY_KEY,
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
    )


def test_commit_port_publishes_replay_manifest_last() -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    prepared = _prepared()
    prepared_digest = compute_artifact_digest(
        _monitoring_persistence_replay_payload(cast(Any, prepared))
    )
    replay_key = PERSISTENCE_REPLAY_KEY
    manifest_name = f"wc024-monitoring/commits/{replay_key.removeprefix('sha256:')}/manifest.json"

    with _commit_port(store).transaction(cast(Any, prepared)) as committed:
        assert manifest_name not in store.blobs

    written_names = [item.blob_name for item in store.create_requests]
    assert written_names[-1] == manifest_name
    manifest = MonitoringPersistenceCommitManifest.model_validate_json(
        store.blobs[manifest_name].payload
    )
    assert manifest.replay_key == replay_key
    assert manifest.collection_id == f"wc024-{replay_key.removeprefix('sha256:')[:12]}"
    assert manifest.prepared_digest == prepared_digest
    assert manifest.monitoring_handoff == committed.monitoring_handoff


def test_commit_port_leaves_no_commit_marker_when_correlation_fails() -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    prepared = _prepared()
    manifest_name = (
        f"wc024-monitoring/commits/{PERSISTENCE_REPLAY_KEY.removeprefix('sha256:')}/manifest.json"
    )

    with (
        pytest.raises(RuntimeError, match="synthetic correlation failure"),
        _commit_port(store).transaction(cast(Any, prepared)),
    ):
        raise RuntimeError("synthetic correlation failure")

    assert manifest_name not in store.blobs


def test_commit_port_replays_durable_manifest_without_new_writes() -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    port = _commit_port(store)
    with port.transaction(cast(Any, _prepared())) as first:
        pass
    create_count = len(store.create_requests)

    with port.transaction(cast(Any, _prepared())) as replayed:
        pass

    assert replayed == first
    assert len(store.create_requests) == create_count


def test_commit_port_recovers_partial_write_before_manifest() -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        fail_once_on_suffix="/manifest.json",
    )
    prepared = _prepared()
    port = _commit_port(store)

    with (
        pytest.raises(RuntimeError, match="staged persistence failure"),
        port.transaction(cast(Any, prepared)),
    ):
        pass
    assert len(store.blobs) == 1

    with port.transaction(cast(Any, prepared)) as committed:
        pass

    assert committed.monitoring_handoff.evidence.name in store.blobs
    assert any(name.endswith("/manifest.json") for name in store.blobs)


def test_commit_port_rejects_changed_reacquisition_under_same_replay_identity() -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        fail_once_on_suffix="/manifest.json",
    )
    port = _commit_port(store)

    with (
        pytest.raises(RuntimeError, match="staged persistence failure"),
        port.transaction(cast(Any, _prepared())),
    ):
        pass

    with (
        pytest.raises(MonitoringAcquisitionJobError, match="already exists"),
        port.transaction(
            cast(
                Any,
                _prepared(bundle_payload=b'{"schemaVersion":"different-monitoring-bundle"}\n'),
            )
        ),
    ):
        pass

    assert not any(name.endswith("/manifest.json") for name in store.blobs)


def test_commit_port_rejects_conflicting_existing_artifact() -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    prepared = _prepared()
    collection_id = f"wc024-{PERSISTENCE_REPLAY_KEY.removeprefix('sha256:')[:12]}"
    bundle_name = f"wc024-monitoring/{collection_id}/evidence.json"
    conflicting = b'{"schemaVersion":"conflicting"}\n'
    store.blobs[bundle_name] = ArtifactReadResult(
        container_name=store.container_name,
        blob_name=bundle_name,
        version_id="synthetic-conflict-version",
        payload=conflicting,
        size_bytes=len(conflicting),
        content_type="application/json",
        payload_sha256=sha256_hex(conflicting),
    )

    with (
        pytest.raises(MonitoringAcquisitionJobError, match="already exists"),
        _commit_port(store).transaction(cast(Any, prepared)),
    ):
        pass


def test_commit_port_rejects_unreviewed_change_artifacts_before_write() -> None:
    monitoring_store = _MemoryStore(container_name="monitoring-evidence")
    evidence_id = "chg-" + hashlib.sha256(DIGEST_A.encode("utf-8")).hexdigest()[:12]
    artifact = SimpleNamespace(
        evidence=SimpleNamespace(
            evidence_id=evidence_id,
            deduplication_key=DIGEST_A,
            change_key=DIGEST_B,
        ),
        canonical_bytes=lambda: b'{"schemaVersion":"synthetic-change"}\n',
    )
    prepared = _prepared(change_artifacts=(artifact,))

    with (
        pytest.raises(MonitoringAcquisitionJobError, match="change persistence"),
        _commit_port(monitoring_store).transaction(cast(Any, prepared)),
    ):
        pass

    assert monitoring_store.create_requests == []


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
