from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from azure.core.exceptions import AzureError, ServiceRequestError
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
    _validate_runtime_support_effective_rbac,
    load_wc028_monitoring_acquisition_job_configuration,
)
from athena_context.monitoring_collection import build_collected_correlation_request
from test_wc024_monitoring_contract import _acquisition_collector_contract
from test_wc028_monitoring_acquisition import (
    _AcquisitionPort,
    _authority,
    _execute,
    _trust_synthetic_managed_identity_key,
)

NOW = datetime(2026, 9, 14, 5, 30, tzinfo=UTC)
SUBSCRIPTION_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
TENANT_ID = "33333333-3333-3333-3333-333333333333"
IDENTITY_PROOF_AUDIENCE = f"api://{TENANT_ID}/athena-monitoring-identity-proof"
COLLECTOR_PRINCIPAL_ID = "44444444-4444-4444-4444-444444444444"
CONTEXT_PRINCIPAL_ID = "55555555-5555-5555-5555-555555555555"
SUPPORT_CLIENT_ID = "66666666-6666-6666-6666-666666666666"
SUPPORT_PRINCIPAL_ID = "77777777-7777-7777-7777-777777777777"
ATTESTOR_CLIENT_ID = "88888888-8888-8888-8888-888888888888"
ATTESTOR_PRINCIPAL_ID = "99999999-9999-9999-9999-999999999999"
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
ATTESTOR_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-monitoring/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
    "athena-wc028-runtime-support-rbac-attestor-id"
)
REGISTRY_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-shared/"
    "providers/Microsoft.ContainerRegistry/registries/athenademoacr"
)
MONITORING_INTENT_KEY_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-context/"
    "providers/Microsoft.KeyVault/vaults/synthetic-context-kv/"
    "keys/monitoring-intent-signing"
)
MONITORING_INTENT_VAULT_RESOURCE_ID = MONITORING_INTENT_KEY_RESOURCE_ID.rsplit(
    "/keys/",
    maxsplit=1,
)[0]
ACR_PULL_ROLE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/"
    "7f951dda-4ed3-4680-a7ca-43fe172d538d"
)
SUPPORT_KEY_READER_ROLE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/"
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)
MANAGEMENT_GROUP_SCOPE = "/providers/Microsoft.Management/managementGroups/synthetic-athena-root"
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
EVIDENCE_BLOB_SERVICE_ID = f"{EVIDENCE_STORAGE_ID}/blobServices/default"
EVIDENCE_IMMUTABILITY_POLICY_ID = f"{EVIDENCE_CONTAINER_ID}/immutabilityPolicies/default"
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


def _digest_json_value(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _digest_json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_digest_json_value(item) for item in value]
    return value


def _with_digest(payload: dict[str, object], field_name: str) -> dict[str, object]:
    return {
        **payload,
        field_name: compute_artifact_digest(_digest_json_value(payload)),
    }


def _storage_readiness_payload() -> dict[str, object]:
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringEvidenceStorageReadiness.v1",
        "storageAccountResourceId": EVIDENCE_STORAGE_ID.casefold(),
        "blobServiceResourceId": EVIDENCE_BLOB_SERVICE_ID.casefold(),
        "containerResourceId": EVIDENCE_CONTAINER_ID.casefold(),
        "immutabilityPolicyResourceId": EVIDENCE_IMMUTABILITY_POLICY_ID.casefold(),
        "versioningEnabled": True,
        "containerPublicAccess": "None",
        "immutabilityPolicyState": "Locked",
        "immutabilityRetentionDays": 30,
        "allowProtectedAppendWrites": False,
        "allowProtectedAppendWritesAll": False,
    }
    readiness_preimage = runtime_module._monitoring_evidence_storage_readiness_preimage(
        storage_account_resource_id=cast(
            str,
            payload["storageAccountResourceId"],
        ),
        blob_service_resource_id=cast(str, payload["blobServiceResourceId"]),
        container_resource_id=cast(str, payload["containerResourceId"]),
        immutability_policy_resource_id=cast(
            str,
            payload["immutabilityPolicyResourceId"],
        ),
        container_public_access=cast(str, payload["containerPublicAccess"]),
        immutability_policy_state=cast(
            str,
            payload["immutabilityPolicyState"],
        ),
        immutability_retention_days=cast(
            int,
            payload["immutabilityRetentionDays"],
        ),
    )
    payload["readbackBindingId"] = runtime_module._arm_template_guid(readiness_preimage)
    payload["readinessDigest"] = sha256_hex(readiness_preimage.encode("utf-8"))
    return payload


def _refresh_storage_readiness(
    readiness: dict[str, object],
) -> dict[str, object]:
    refreshed = copy.deepcopy(readiness)
    refreshed.pop("readinessDigest", None)
    readiness_preimage = runtime_module._monitoring_evidence_storage_readiness_preimage(
        storage_account_resource_id=cast(
            str,
            refreshed["storageAccountResourceId"],
        ),
        blob_service_resource_id=cast(
            str,
            refreshed["blobServiceResourceId"],
        ),
        container_resource_id=cast(str, refreshed["containerResourceId"]),
        immutability_policy_resource_id=cast(
            str,
            refreshed["immutabilityPolicyResourceId"],
        ),
        container_public_access=cast(
            str,
            refreshed["containerPublicAccess"],
        ),
        immutability_policy_state=cast(
            str,
            refreshed["immutabilityPolicyState"],
        ),
        immutability_retention_days=cast(
            int,
            refreshed["immutabilityRetentionDays"],
        ),
    )
    refreshed["readbackBindingId"] = runtime_module._arm_template_guid(readiness_preimage)
    refreshed["readinessDigest"] = sha256_hex(readiness_preimage.encode("utf-8"))
    return refreshed


def _runtime_support_rbac_inventory(
    *,
    subscription_id: str = SUBSCRIPTION_ID,
    tenant_id: str = TENANT_ID,
    support_identity_resource_id: str = SUPPORT_ID,
    registry_resource_id: str = REGISTRY_ID,
    monitoring_intent_key_resource_id: str = MONITORING_INTENT_KEY_RESOURCE_ID,
    collected_at: datetime | None = None,
    expires_at: datetime | None = None,
    collection_run_suffix: str = "a" * 32,
    source_manifest_digest: str = DIGEST_B,
) -> dict[str, object]:
    registry_id = registry_resource_id.casefold()
    key_id = monitoring_intent_key_resource_id.casefold()
    acr_role_id = (
        f"/subscriptions/{subscription_id}/providers/"
        "microsoft.authorization/roledefinitions/"
        "7f951dda-4ed3-4680-a7ca-43fe172d538d"
    )
    key_role_id = (
        f"/subscriptions/{subscription_id}/providers/"
        "microsoft.authorization/roledefinitions/"
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    )
    support_principal_id = SUPPORT_PRINCIPAL_ID.casefold()
    target_scopes = tuple(
        sorted(
            {
                MANAGEMENT_GROUP_SCOPE.casefold(),
                *runtime_module._resource_scope_ancestry(registry_id),
                *runtime_module._resource_scope_ancestry(key_id),
            }
        )
    )
    principal_evidence = _with_digest(
        {
            "principalId": support_principal_id,
            "queryFilter": "atScope() and assignedTo(principalId)",
            "targetScopeIds": target_scopes,
            "firstReadTargetDigests": tuple(DIGEST_A for _ in target_scopes),
            "secondReadTargetDigests": tuple(DIGEST_A for _ in target_scopes),
            "roleAssignmentRawPageDigests": (DIGEST_A,),
            "transitiveGroupIds": (),
            "transitiveGroupRawPageDigests": (DIGEST_B,),
            "allPagesRetrieved": True,
        },
        "evidenceDigest",
    )
    role_definitions = [
        _with_digest(
            {
                "roleDefinitionId": acr_role_id,
                "roleDefinitionName": "AcrPull",
                "actions": ("microsoft.containerregistry/registries/pull/read",),
                "notActions": (),
                "dataActions": (),
                "notDataActions": (),
                "rawDefinitionDigest": DIGEST_A,
            },
            "definitionDigest",
        ),
        _with_digest(
            {
                "roleDefinitionId": key_role_id,
                "roleDefinitionName": "Athena WC028 Monitoring Intent Key Reader",
                "actions": (),
                "notActions": (),
                "dataActions": ("microsoft.keyvault/vaults/keys/read",),
                "notDataActions": (),
                "rawDefinitionDigest": DIGEST_B,
            },
            "definitionDigest",
        ),
    ]
    role_definitions.sort(key=lambda item: cast(str, item["roleDefinitionId"]))
    grants = [
        _with_digest(
            {
                "assignedPrincipalId": support_principal_id,
                "assignedPrincipalType": "ServicePrincipal",
                "effectivePrincipalId": support_principal_id,
                "roleDefinitionId": acr_role_id,
                "roleDefinitionName": "AcrPull",
                "assignmentScopeIds": (registry_id,),
                "inheritance": "direct",
                "groupDerived": False,
            },
            "grantDigest",
        ),
        _with_digest(
            {
                "assignedPrincipalId": support_principal_id,
                "assignedPrincipalType": "ServicePrincipal",
                "effectivePrincipalId": support_principal_id,
                "roleDefinitionId": key_role_id,
                "roleDefinitionName": "Athena WC028 Monitoring Intent Key Reader",
                "assignmentScopeIds": (key_id,),
                "inheritance": "direct",
                "groupDerived": False,
            },
            "grantDigest",
        ),
    ]
    grants.sort(key=lambda item: cast(str, item["grantDigest"]))
    raw_snapshot_payload = {
        "supportPrincipalEvidenceDigest": principal_evidence["evidenceDigest"],
        "roleDefinitionRawPageDigests": [DIGEST_A],
        "denyAssignmentRawPageDigests": [DIGEST_B],
        "pimScheduleInstanceRawPageDigests": [DIGEST_C],
        "roleDefinitionRawDigests": [item["rawDefinitionDigest"] for item in role_definitions],
        "denyAssignmentRawDigests": [],
        "pimScheduleInstanceRawDigests": [],
    }
    raw_snapshot_digest = compute_artifact_digest(raw_snapshot_payload)
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028RuntimeSupportEffectiveRbacInventory.v1",
        "collectionRunId": f"runtime-support-rbac-{collection_run_suffix}",
        "tenantId": tenant_id,
        "subscriptionId": subscription_id,
        "supportIdentityResourceId": support_identity_resource_id.casefold(),
        "supportClientId": SUPPORT_CLIENT_ID,
        "supportPrincipalId": support_principal_id,
        "attestorIdentityResourceId": ATTESTOR_ID.casefold().replace(
            SUBSCRIPTION_ID,
            subscription_id,
        ),
        "attestorClientId": ATTESTOR_CLIENT_ID,
        "attestorPrincipalId": ATTESTOR_PRINCIPAL_ID,
        "attestorTenantId": tenant_id,
        "collectedAt": collected_at or NOW - timedelta(minutes=1),
        "expiresAt": expires_at or NOW + timedelta(minutes=10),
        "managementGroupAncestry": (MANAGEMENT_GROUP_SCOPE.casefold(),),
        "ancestorScopeCollectionComplete": True,
        "subscriptionDescendantCollectionComplete": True,
        "groupMembershipCollectionComplete": True,
        "roleDefinitionCollectionComplete": True,
        "denyAssignmentCollectionComplete": True,
        "pimScheduleInstanceCollectionComplete": True,
        "supportSecurityGroupIds": (),
        "supportGrants": tuple(grants),
        "supportPrincipalEvidence": principal_evidence,
        "roleDefinitions": tuple(role_definitions),
        "denyAssignments": (),
        "activePimScheduleInstances": (),
        "roleDefinitionRawPageDigests": (DIGEST_A,),
        "denyAssignmentRawPageDigests": (DIGEST_B,),
        "pimScheduleInstanceRawPageDigests": (DIGEST_C,),
        "firstRawSnapshotDigest": raw_snapshot_digest,
        "secondRawSnapshotDigest": raw_snapshot_digest,
        "repeatedReadStable": True,
        "assignmentCount": 2,
        "sourceReference": {
            "name": (
                "wc028-runtime-support-rbac/"
                f"runtime-support-rbac-{collection_run_suffix}/"
                "effective-rbac-inventory.json"
            ),
            "version": "2026-09-14T05:29:00.0000000Z",
            "contentDigest": source_manifest_digest,
        },
        "sourceManifestDigest": source_manifest_digest,
    }
    return _with_digest(payload, "inventoryDigest")


def _refresh_support_rbac_inventory(
    inventory: dict[str, object],
) -> dict[str, object]:
    refreshed = copy.deepcopy(inventory)
    principal_evidence = cast(
        dict[str, object],
        refreshed["supportPrincipalEvidence"],
    )
    principal_evidence.pop("evidenceDigest", None)
    principal_evidence.update(_with_digest(principal_evidence, "evidenceDigest"))
    grants = cast(list[dict[str, object]], list(refreshed["supportGrants"]))
    refreshed_grants = []
    for grant in grants:
        grant.pop("grantDigest", None)
        refreshed_grants.append(_with_digest(grant, "grantDigest"))
    refreshed_grants.sort(key=lambda item: cast(str, item["grantDigest"]))
    refreshed["supportGrants"] = tuple(refreshed_grants)
    roles = cast(list[dict[str, object]], list(refreshed["roleDefinitions"]))
    refreshed_roles = []
    for role in roles:
        role.pop("definitionDigest", None)
        refreshed_roles.append(_with_digest(role, "definitionDigest"))
    refreshed_roles.sort(key=lambda item: cast(str, item["roleDefinitionId"]))
    refreshed["roleDefinitions"] = tuple(refreshed_roles)
    denies = cast(list[dict[str, object]], list(refreshed["denyAssignments"]))
    refreshed_denies = []
    for deny in denies:
        deny.pop("denyAssignmentDigest", None)
        refreshed_denies.append(_with_digest(deny, "denyAssignmentDigest"))
    refreshed_denies.sort(key=lambda item: cast(str, item["denyAssignmentId"]))
    refreshed["denyAssignments"] = tuple(refreshed_denies)
    pim_instances = cast(
        list[dict[str, object]],
        list(refreshed["activePimScheduleInstances"]),
    )
    refreshed_pim_instances = []
    for instance in pim_instances:
        instance.pop("instanceDigest", None)
        refreshed_pim_instances.append(_with_digest(instance, "instanceDigest"))
    refreshed_pim_instances.sort(key=lambda item: cast(str, item["scheduleInstanceId"]))
    refreshed["activePimScheduleInstances"] = tuple(refreshed_pim_instances)
    raw_snapshot_payload = {
        "supportPrincipalEvidenceDigest": principal_evidence["evidenceDigest"],
        "roleDefinitionRawPageDigests": list(
            cast(tuple[str, ...], refreshed["roleDefinitionRawPageDigests"])
        ),
        "denyAssignmentRawPageDigests": list(
            cast(tuple[str, ...], refreshed["denyAssignmentRawPageDigests"])
        ),
        "pimScheduleInstanceRawPageDigests": list(
            cast(tuple[str, ...], refreshed["pimScheduleInstanceRawPageDigests"])
        ),
        "roleDefinitionRawDigests": [item["rawDefinitionDigest"] for item in refreshed_roles],
        "denyAssignmentRawDigests": [item["rawAssignmentDigest"] for item in refreshed_denies],
        "pimScheduleInstanceRawDigests": [
            item["rawInstanceDigest"] for item in refreshed_pim_instances
        ],
    }
    raw_snapshot_digest = compute_artifact_digest(raw_snapshot_payload)
    refreshed["firstRawSnapshotDigest"] = raw_snapshot_digest
    refreshed["secondRawSnapshotDigest"] = raw_snapshot_digest
    refreshed["assignmentCount"] = sum(
        len(cast(tuple[str, ...], item["assignmentScopeIds"])) for item in refreshed_grants
    )
    refreshed.pop("inventoryDigest", None)
    return _with_digest(refreshed, "inventoryDigest")


_SUPPORT_RBAC_INVENTORY = _runtime_support_rbac_inventory()
_STORAGE_READINESS = _storage_readiness_payload()
PERSISTENCE_REPLAY_KEY = compute_artifact_digest(
    {
        "schemaVersion": "athena.wc028MonitoringPersistenceReplay.v3",
        "executionId": EXECUTION_ID,
        "acquisitionAuthorityDigest": DIGEST_C,
        "monitoringIntentDigest": DIGEST_A,
        "monitoringIntentReferenceDigest": DIGEST_C,
        "contextBindingDigest": DIGEST_A,
        "incidentRevision": 1,
        "legacyCollectorRbacCleanupDigest": CLEANUP_DIGEST,
        "monitoringEvidenceStorageReadinessDigest": (_STORAGE_READINESS["readinessDigest"]),
        "trustDelaySeconds": 60,
        "requestLifetimeSeconds": 600,
    }
)


def _refresh_configuration_replay_key(payload: dict[str, object]) -> None:
    acquisition_authority = cast(
        dict[str, object],
        payload["acquisitionAuthority"],
    )
    monitoring_intent = cast(dict[str, object], payload["monitoringIntent"])
    context_binding = cast(dict[str, object], payload["contextBinding"])
    payload["persistenceReplayKey"] = compute_artifact_digest(
        {
            "schemaVersion": "athena.wc028MonitoringPersistenceReplay.v3",
            "executionId": payload["executionId"],
            "acquisitionAuthorityDigest": payload["expectedAcquisitionAuthorityDigest"],
            "monitoringIntentDigest": monitoring_intent["intentDigest"],
            "monitoringIntentReferenceDigest": cast(
                dict[str, object],
                payload["monitoringIntentReference"],
            )["referenceDigest"],
            "contextBindingDigest": context_binding["bindingDigest"],
            "incidentRevision": payload["incidentRevision"],
            "legacyCollectorRbacCleanupDigest": payload["legacyCollectorRbacCleanupDigest"],
            "monitoringEvidenceStorageReadinessDigest": cast(
                dict[str, object],
                payload["monitoringEvidenceStorageReadiness"],
            )["readinessDigest"],
            "trustDelaySeconds": payload["trustDelaySeconds"],
            "requestLifetimeSeconds": payload["requestLifetimeSeconds"],
        }
    )
    assert acquisition_authority["authorityDigest"] == payload["expectedAcquisitionAuthorityDigest"]


def _configuration_payload() -> dict[str, object]:
    support_rbac_inventory = copy.deepcopy(_SUPPORT_RBAC_INVENTORY)
    payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringAcquisitionJobConfiguration.v4",
        "managedIdentityClientId": CLIENT_ID,
        "collectorIdentityResourceId": COLLECTOR_ID,
        "athenaContextIdentityResourceId": CONTEXT_ID,
        "runtimeSupportIdentityResourceId": SUPPORT_ID,
        "runtimeSupportIdentityClientId": SUPPORT_CLIENT_ID,
        "runtimeSupportIdentityPrincipalId": SUPPORT_PRINCIPAL_ID,
        "registryResourceId": REGISTRY_ID,
        "runtimeSupportAcrPullRoleDefinitionId": ACR_PULL_ROLE_ID,
        "monitoringIntentSigningKeyResourceId": MONITORING_INTENT_KEY_RESOURCE_ID,
        "runtimeSupportMonitoringIntentKeyReaderRoleDefinitionId": (SUPPORT_KEY_READER_ROLE_ID),
        "runtimeSupportEffectiveRbacInventory": support_rbac_inventory,
        "sourceStorageAccountResourceId": SOURCE_STORAGE_ID,
        "evidenceStorageAccountResourceId": EVIDENCE_STORAGE_ID,
        "evidenceBlobEndpoint": "https://athenamonitoring.blob.core.windows.net",
        "evidenceContainerName": "monitoring-evidence",
        "monitoringEvidenceStorageReadiness": copy.deepcopy(_STORAGE_READINESS),
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
        "monitoringIntentReference": {
            "schemaVersion": "synthetic",
            "referenceDigest": DIGEST_C,
        },
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
            "identityProofAudience": IDENTITY_PROOF_AUDIENCE,
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
            "resourceHealthAllowedOperations": ["Microsoft.ResourceGraph/resources/read"],
            "identityProofAudience": IDENTITY_PROOF_AUDIENCE,
            "identityProofTokenVersion": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
            "identityProofRequiredRole": MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
            "identityProofMaximumLifetimeSeconds": (
                MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
            ),
            "allowedReadOperations": [
                "Microsoft.Insights/Logs/Heartbeat/Read",
                "Microsoft.ResourceGraph/resources/read",
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
    _refresh_configuration_replay_key(payload)
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
    with pytest.raises(ValidationError, match="client/principal identities"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(shared_support_client)

    shared_support_principal = _configuration_payload()
    shared_support_principal["runtimeSupportIdentityPrincipalId"] = COLLECTOR_PRINCIPAL_ID
    with pytest.raises(ValidationError, match="client/principal identities"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(shared_support_principal)


def test_configuration_accepts_tenant_bound_identity_proof_audience() -> None:
    payload = _configuration_payload()
    tenant_id = "99999999-9999-4999-8999-999999999999"
    audience = f"api://{tenant_id}/athena-monitoring-identity-proof"
    authority = cast(dict[str, object], payload["acquisitionAuthority"])
    authority["monitoringReaderTenantId"] = tenant_id
    authority["identityProofAudience"] = audience
    contract = cast(dict[str, object], payload["monitoringCollectorContract"])
    contract["collectorTenantId"] = tenant_id
    contract["rbacAttestorTenantId"] = tenant_id
    contract["identityProofAudience"] = audience
    support_inventory = cast(
        dict[str, object],
        payload["runtimeSupportEffectiveRbacInventory"],
    )
    support_inventory["tenantId"] = tenant_id
    support_inventory["attestorTenantId"] = tenant_id
    payload["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(
        support_inventory
    )

    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(payload)

    assert configuration.monitoring_collector_contract["identityProofAudience"] == audience
    assert configuration.acquisition_authority["identityProofAudience"] == audience


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

    substituted_window = _configuration_payload()
    substituted_window["trustDelaySeconds"] = 120
    substituted_window["requestLifetimeSeconds"] = 700
    with pytest.raises(ValidationError, match="persistenceReplayKey"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_window)

    substituted_reference = _configuration_payload()
    intent_reference = cast(
        dict[str, object],
        substituted_reference["monitoringIntentReference"],
    )
    intent_reference["referenceDigest"] = DIGEST_B
    with pytest.raises(ValidationError, match="persistenceReplayKey"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_reference)


def test_configuration_rejects_zero_cleanup_evidence() -> None:
    payload = _configuration_payload()
    payload["legacyCollectorRbacCleanupDigest"] = f"sha256:{'0' * 64}"

    with pytest.raises(ValidationError, match="non-zero SHA-256 digest"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(payload)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("versioningEnabled", False),
        ("containerPublicAccess", "Blob"),
        ("immutabilityPolicyState", "Disabled"),
        ("immutabilityRetentionDays", 0),
        ("allowProtectedAppendWrites", True),
        ("allowProtectedAppendWritesAll", True),
    ),
)
def test_configuration_rejects_unprotected_monitoring_evidence_storage(
    field_name: str,
    value: object,
) -> None:
    payload = _configuration_payload()
    readiness = cast(
        dict[str, object],
        payload["monitoringEvidenceStorageReadiness"],
    )
    readiness[field_name] = value
    payload["monitoringEvidenceStorageReadiness"] = _refresh_storage_readiness(readiness)
    _refresh_configuration_replay_key(payload)

    with pytest.raises(ValidationError):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(payload)


def test_configuration_rejects_storage_readiness_boundary_or_digest_substitution() -> None:
    substituted_container = _configuration_payload()
    readiness = cast(
        dict[str, object],
        substituted_container["monitoringEvidenceStorageReadiness"],
    )
    readiness["containerResourceId"] = (
        f"{EVIDENCE_BLOB_SERVICE_ID}/containers/unreviewed".casefold()
    )
    substituted_container["monitoringEvidenceStorageReadiness"] = _refresh_storage_readiness(
        readiness
    )
    _refresh_configuration_replay_key(substituted_container)
    with pytest.raises(ValidationError, match="exact WC-024 evidence resources"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_container)

    substituted_digest = _configuration_payload()
    readiness = cast(
        dict[str, object],
        substituted_digest["monitoringEvidenceStorageReadiness"],
    )
    readiness["readinessDigest"] = DIGEST_A
    _refresh_configuration_replay_key(substituted_digest)
    with pytest.raises(ValidationError, match="readinessDigest"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_digest)

    substituted_binding = _configuration_payload()
    readiness = cast(
        dict[str, object],
        substituted_binding["monitoringEvidenceStorageReadiness"],
    )
    readiness["readbackBindingId"] = "abababab-abab-abab-abab-abababababab"
    with pytest.raises(ValidationError, match="readbackBindingId"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(substituted_binding)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("managedIdentityClientId", "00000000-0000-0000-0000-000000000000"),
        (
            "runtimeSupportIdentityClientId",
            "00000000-0000-0000-0000-000000000000",
        ),
        (
            "runtimeSupportIdentityPrincipalId",
            "00000000-0000-0000-0000-000000000000",
        ),
        ("executionId", f"wc028-execution-{'0' * 32}"),
        ("expectedActiveContextAuthorityDigest", f"sha256:{'0' * 64}"),
        ("expectedAcquisitionAuthorityDigest", f"sha256:{'0' * 64}"),
        ("persistenceReplayKey", f"sha256:{'0' * 64}"),
    ),
)
def test_configuration_rejects_nil_guids_and_zero_runtime_sentinels(
    field_name: str,
    value: str,
) -> None:
    payload = _configuration_payload()
    payload[field_name] = value

    with pytest.raises(ValidationError, match="non-nil|non-zero|must be non-zero"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(payload)


def test_configuration_rejects_zero_nested_evidence_and_nil_subscription() -> None:
    zero_key_fingerprint = _configuration_payload()
    trusted_key = cast(
        dict[str, object],
        zero_key_fingerprint["monitoringIntentTrustedKey"],
    )
    trusted_key["publicKeyFingerprint"] = f"sha256:{'0' * 64}"
    with pytest.raises(ValidationError, match="non-zero"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(zero_key_fingerprint)

    zero_intent_digest = _configuration_payload()
    monitoring_intent = cast(
        dict[str, object],
        zero_intent_digest["monitoringIntent"],
    )
    monitoring_intent["intentDigest"] = f"sha256:{'0' * 64}"
    with pytest.raises(ValidationError, match="zero evidence sentinel"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(zero_intent_digest)

    nil_subscription = _configuration_payload()
    nil_subscription["collectorIdentityResourceId"] = COLLECTOR_ID.replace(
        SUBSCRIPTION_ID,
        "00000000-0000-0000-0000-000000000000",
    )
    with pytest.raises(ValidationError, match="subscription"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(nil_subscription)


def test_configuration_rejects_inconsistent_attestor_identity_tuples() -> None:
    attestor_client_overlap = _configuration_payload()
    inventory = cast(
        dict[str, object],
        attestor_client_overlap["runtimeSupportEffectiveRbacInventory"],
    )
    inventory["attestorClientId"] = CLIENT_ID
    attestor_client_overlap["runtimeSupportEffectiveRbacInventory"] = (
        _refresh_support_rbac_inventory(inventory)
    )
    with pytest.raises(ValidationError, match="client/principal identities"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(attestor_client_overlap)

    attestor_resource_overlap = _configuration_payload()
    inventory = cast(
        dict[str, object],
        attestor_resource_overlap["runtimeSupportEffectiveRbacInventory"],
    )
    inventory["attestorIdentityResourceId"] = COLLECTOR_ID.casefold()
    attestor_resource_overlap["runtimeSupportEffectiveRbacInventory"] = (
        _refresh_support_rbac_inventory(inventory)
    )
    with pytest.raises(ValidationError, match="dedicated effective RBAC evidence"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(attestor_resource_overlap)


def test_configuration_rejects_zero_support_evidence_digest() -> None:
    payload = _configuration_payload()
    inventory = cast(
        dict[str, object],
        payload["runtimeSupportEffectiveRbacInventory"],
    )
    inventory["roleDefinitionRawPageDigests"] = (f"sha256:{'0' * 64}",)

    with pytest.raises(ValidationError, match="raw page digests"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(payload)


@pytest.mark.parametrize(
    "principal_digest_field",
    (
        "targetReads",
        "roleAssignmentPages",
        "groupPages",
    ),
)
def test_configuration_rejects_rehashed_zero_principal_evidence_digests(
    principal_digest_field: str,
) -> None:
    payload = _configuration_payload()
    inventory = cast(
        dict[str, object],
        payload["runtimeSupportEffectiveRbacInventory"],
    )
    principal_evidence = cast(
        dict[str, object],
        inventory["supportPrincipalEvidence"],
    )
    zero_digest = f"sha256:{'0' * 64}"
    if principal_digest_field == "targetReads":
        first_reads = list(cast(tuple[str, ...], principal_evidence["firstReadTargetDigests"]))
        first_reads[0] = zero_digest
        principal_evidence["firstReadTargetDigests"] = tuple(first_reads)
        principal_evidence["secondReadTargetDigests"] = tuple(first_reads)
    elif principal_digest_field == "roleAssignmentPages":
        principal_evidence["roleAssignmentRawPageDigests"] = (zero_digest,)
    else:
        principal_evidence["transitiveGroupRawPageDigests"] = (zero_digest,)
    payload["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(inventory)

    with pytest.raises(ValidationError, match="evidence digests must be non-zero"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(payload)


def test_resource_scope_ancestry_includes_every_nested_arm_parent() -> None:
    assert runtime_module._resource_scope_ancestry(MONITORING_INTENT_KEY_RESOURCE_ID) == tuple(
        sorted(
            {
                f"/subscriptions/{SUBSCRIPTION_ID}".casefold(),
                (
                    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-context"
                ).casefold(),
                MONITORING_INTENT_VAULT_RESOURCE_ID.casefold(),
                MONITORING_INTENT_KEY_RESOURCE_ID.casefold(),
            }
        )
    )


def test_runtime_support_rbac_requires_key_vault_and_key_target_evidence() -> None:
    payload = _configuration_payload()
    inventory = cast(
        dict[str, object],
        payload["runtimeSupportEffectiveRbacInventory"],
    )
    principal_evidence = cast(
        dict[str, object],
        inventory["supportPrincipalEvidence"],
    )
    target_scopes = tuple(
        scope
        for scope in cast(tuple[str, ...], principal_evidence["targetScopeIds"])
        if scope != MONITORING_INTENT_VAULT_RESOURCE_ID.casefold()
    )
    principal_evidence["targetScopeIds"] = target_scopes
    principal_evidence["firstReadTargetDigests"] = tuple(DIGEST_A for _ in target_scopes)
    principal_evidence["secondReadTargetDigests"] = tuple(DIGEST_A for _ in target_scopes)
    payload["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(inventory)

    with pytest.raises(ValidationError, match="hierarchy-complete dedicated"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(payload)


def test_runtime_support_rbac_rejects_vault_level_key_roles() -> None:
    broader_expected_role = _configuration_payload()
    broader_inventory = cast(
        dict[str, object],
        broader_expected_role["runtimeSupportEffectiveRbacInventory"],
    )
    broader_grants = cast(
        list[dict[str, object]],
        list(broader_inventory["supportGrants"]),
    )
    key_grant = next(
        item
        for item in broader_grants
        if item["roleDefinitionId"] == SUPPORT_KEY_READER_ROLE_ID.casefold()
    )
    key_grant["assignmentScopeIds"] = (MONITORING_INTENT_VAULT_RESOURCE_ID.casefold(),)
    broader_inventory["supportGrants"] = tuple(broader_grants)
    broader_expected_role["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(
        broader_inventory
    )
    with pytest.raises(ValidationError, match="exact direct governed"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(broader_expected_role)

    unexpected_role = _configuration_payload()
    unexpected_inventory = cast(
        dict[str, object],
        unexpected_role["runtimeSupportEffectiveRbacInventory"],
    )
    unexpected_role_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
        "microsoft.authorization/roledefinitions/"
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    ).casefold()
    unexpected_grants = cast(
        list[dict[str, object]],
        list(unexpected_inventory["supportGrants"]),
    )
    unexpected_key_grant = next(
        item
        for item in unexpected_grants
        if item["roleDefinitionId"] == SUPPORT_KEY_READER_ROLE_ID.casefold()
    )
    unexpected_key_grant.update(
        {
            "roleDefinitionId": unexpected_role_id,
            "roleDefinitionName": "Synthetic Broad Vault Reader",
            "assignmentScopeIds": (MONITORING_INTENT_VAULT_RESOURCE_ID.casefold(),),
        }
    )
    unexpected_inventory["supportGrants"] = tuple(unexpected_grants)
    unexpected_roles = cast(
        list[dict[str, object]],
        list(unexpected_inventory["roleDefinitions"]),
    )
    unexpected_key_role = next(
        item
        for item in unexpected_roles
        if item["roleDefinitionId"] == SUPPORT_KEY_READER_ROLE_ID.casefold()
    )
    unexpected_key_role.update(
        {
            "roleDefinitionId": unexpected_role_id,
            "roleDefinitionName": "Synthetic Broad Vault Reader",
            "actions": ("microsoft.keyvault/vaults/read",),
            "dataActions": (),
        }
    )
    unexpected_inventory["roleDefinitions"] = tuple(unexpected_roles)
    unexpected_role["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(
        unexpected_inventory
    )
    with pytest.raises(ValidationError, match="arbitrary effective Azure privileges"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(unexpected_role)


def test_runtime_support_rbac_rejects_inherited_and_group_privileges() -> None:
    inherited = _configuration_payload()
    inherited_inventory = cast(
        dict[str, object],
        inherited["runtimeSupportEffectiveRbacInventory"],
    )
    inherited_grants = cast(
        list[dict[str, object]],
        list(inherited_inventory["supportGrants"]),
    )
    inherited_grants[0]["inheritance"] = "inherited"
    inherited_inventory["supportGrants"] = tuple(inherited_grants)
    inherited["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(
        inherited_inventory
    )
    _refresh_configuration_replay_key(inherited)
    with pytest.raises(ValidationError, match="exact direct governed"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(inherited)

    group_derived = _configuration_payload()
    group_inventory = cast(
        dict[str, object],
        group_derived["runtimeSupportEffectiveRbacInventory"],
    )
    group_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    group_inventory["supportSecurityGroupIds"] = (group_id,)
    principal_evidence = cast(
        dict[str, object],
        group_inventory["supportPrincipalEvidence"],
    )
    principal_evidence["transitiveGroupIds"] = (group_id,)
    group_grants = cast(
        list[dict[str, object]],
        list(group_inventory["supportGrants"]),
    )
    group_grants[0].update(
        {
            "assignedPrincipalId": group_id,
            "assignedPrincipalType": "Group",
            "groupDerived": True,
        }
    )
    group_inventory["supportGrants"] = tuple(group_grants)
    group_derived["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(
        group_inventory
    )
    _refresh_configuration_replay_key(group_derived)
    with pytest.raises(ValidationError, match="hierarchy-complete dedicated"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(group_derived)


def test_runtime_support_rbac_rejects_conditions_pim_and_applicable_denies() -> None:
    conditioned = _configuration_payload()
    conditioned_inventory = cast(
        dict[str, object],
        conditioned["runtimeSupportEffectiveRbacInventory"],
    )
    conditioned_grants = cast(
        list[dict[str, object]],
        list(conditioned_inventory["supportGrants"]),
    )
    conditioned_grants[0]["condition"] = "@Resource[synthetic] StringEquals 'denied'"
    conditioned_grants[0]["conditionVersion"] = "2.0"
    conditioned_inventory["supportGrants"] = tuple(conditioned_grants)
    conditioned["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(
        conditioned_inventory
    )
    _refresh_configuration_replay_key(conditioned)
    with pytest.raises(ValidationError, match="exact direct governed"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(conditioned)

    pim = _configuration_payload()
    pim_inventory = cast(
        dict[str, object],
        pim["runtimeSupportEffectiveRbacInventory"],
    )
    pim_inventory["activePimScheduleInstances"] = (
        {
            "scheduleInstanceId": (
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/roleAssignmentScheduleInstances/"
                "cccccccc-cccc-cccc-cccc-cccccccccccc"
            ).casefold(),
            "principalId": SUPPORT_PRINCIPAL_ID.casefold(),
            "roleDefinitionId": ACR_PULL_ROLE_ID.casefold(),
            "scopeId": REGISTRY_ID.casefold(),
            "assignmentType": "Activated",
            "startAt": NOW - timedelta(minutes=2),
            "endAt": NOW + timedelta(minutes=2),
            "rawInstanceDigest": DIGEST_A,
        },
    )
    pim["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(pim_inventory)
    _refresh_configuration_replay_key(pim)
    with pytest.raises(ValidationError, match="hierarchy-complete dedicated"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(pim)

    denied = _configuration_payload()
    denied_inventory = cast(
        dict[str, object],
        denied["runtimeSupportEffectiveRbacInventory"],
    )
    denied_inventory["denyAssignments"] = (
        {
            "denyAssignmentId": (
                f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                "Microsoft.Authorization/denyAssignments/"
                "dddddddd-dddd-dddd-dddd-dddddddddddd"
            ).casefold(),
            "scopeId": MONITORING_INTENT_VAULT_RESOURCE_ID.casefold(),
            "principalIds": (SUPPORT_PRINCIPAL_ID.casefold(),),
            "excludedPrincipalIds": (),
            "actions": (),
            "notActions": (),
            "dataActions": ("microsoft.keyvault/vaults/keys/read",),
            "notDataActions": (),
            "doNotApplyToChildScopes": False,
            "rawAssignmentDigest": DIGEST_A,
        },
    )
    denied["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(
        denied_inventory
    )
    _refresh_configuration_replay_key(denied)
    with pytest.raises(ValidationError, match="removes an exact required permission"):
        Wc028MonitoringAcquisitionJobConfiguration.model_validate(denied)


def test_runtime_support_rbac_must_be_fresh_before_job_execution() -> None:
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(
        _configuration_payload()
    )

    with pytest.raises(MonitoringAcquisitionJobError, match="stale before job execution"):
        _validate_runtime_support_effective_rbac(
            configuration=configuration,
            as_of=NOW + timedelta(minutes=11),
        )


def test_runtime_support_inventory_refresh_does_not_change_stable_replay_key() -> None:
    payload = _configuration_payload()
    stable_replay_key = payload["persistenceReplayKey"]
    inventory = cast(
        dict[str, object],
        payload["runtimeSupportEffectiveRbacInventory"],
    )
    inventory["collectionRunId"] = f"runtime-support-rbac-{'b' * 32}"
    inventory["collectedAt"] = NOW
    inventory["expiresAt"] = NOW + timedelta(minutes=10)
    inventory["sourceManifestDigest"] = DIGEST_C
    inventory["sourceReference"] = {
        "name": (
            "wc028-runtime-support-rbac/"
            f"runtime-support-rbac-{'b' * 32}/effective-rbac-inventory.json"
        ),
        "version": "2026-09-14T05:30:00.0000000Z",
        "contentDigest": DIGEST_C,
    }
    payload["runtimeSupportEffectiveRbacInventory"] = _refresh_support_rbac_inventory(inventory)

    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(payload)

    assert configuration.persistence_replay_key == stable_replay_key
    assert (
        configuration.runtime_support_effective_rbac_inventory.inventory_digest
        != _SUPPORT_RBAC_INVENTORY["inventoryDigest"]
    )


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


def test_configuration_requires_complete_deployment_binding_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ATHENA_WC028_DEPLOYED_LEGACY_COLLECTOR_RBAC_CLEANUP_DIGEST",
        CLEANUP_DIGEST,
    )

    with pytest.raises(ValidationError, match="one complete set"):
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


def test_current_nil_subscription_contract_is_rejected_at_startup() -> None:
    collector_contract = _acquisition_collector_contract()
    subscription_id = collector_contract.collector_identity_resource_id.strip("/").split("/")[1]
    registry_id = REGISTRY_ID.replace(SUBSCRIPTION_ID, subscription_id)

    with pytest.raises(ValueError, match="Azure subscription"):
        runtime_module._resource_scope_ancestry(registry_id)


def test_current_published_contract_remains_blocked_on_pr99_bootstrap() -> None:
    with pytest.raises(
        MonitoringAcquisitionJobError,
        match="blocked until PR #99 publishes the conditioned",
    ):
        runtime_module._require_pr99_conditioned_blob_contract(_acquisition_collector_contract())


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
        identity_proof_audience=IDENTITY_PROOF_AUDIENCE,
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
        resource_health_allowed_operations=("Microsoft.ResourceGraph/resources/read",),
        identity_proof_audience=IDENTITY_PROOF_AUDIENCE,
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
        resource_health_allowed_operations=("Microsoft.ResourceGraph/resources/read",),
        identity_proof_audience=IDENTITY_PROOF_AUDIENCE,
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
        identity_proof_audience=IDENTITY_PROOF_AUDIENCE,
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
        "_require_pr99_conditioned_blob_contract",
        lambda _contract: None,
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
        class _EmptyStore:
            @staticmethod
            def read_current(_request: object) -> object:
                raise ArtifactNotFoundError("synthetic Blob is absent")

        store = _EmptyStore()
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
    assert execute_arguments["stabilize_correlation_window"] is True


@pytest.mark.parametrize("partial_only", (False, True))
def test_job_probes_manifest_and_partial_recovery_before_current_support_freshness(
    monkeypatch: pytest.MonkeyPatch,
    persistence_case: _PersistenceCase,
    partial_only: bool,
) -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    with _commit_port(store, persistence_case).transaction(persistence_case.prepared) as committed:
        pass
    manifest_name, _, _ = runtime_module._monitoring_persistence_blob_names(PERSISTENCE_REPLAY_KEY)
    manifest = MonitoringPersistenceCommitManifest.model_validate_json(
        store.blobs[manifest_name].payload
    )
    receipt = persistence_case.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    expected_correlation = build_collected_correlation_request(
        persistence_case.prepared,
        committed,
        context_binding=persistence_case.context_binding,
        incident_revision=1,
        issued_at=receipt.execution_started_at,
        trusted_as_of=receipt.execution_started_at + timedelta(seconds=60),
        expires_at=receipt.execution_started_at + timedelta(seconds=600),
    )
    assert manifest.correlation_request_id == expected_correlation.request_id
    assert manifest.correlation_request_digest == expected_correlation.request_digest
    if partial_only:
        del store.blobs[manifest_name]
    expected_outcome = SimpleNamespace(
        committed=committed,
        correlation_request=expected_correlation,
    )
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(
        _configuration_payload()
    )
    context_binding = SimpleNamespace(binding_digest=DIGEST_A)
    collector_contract = SimpleNamespace(
        collector_identity_resource_id=COLLECTOR_ID.casefold(),
        compute_artifact_digest_value=lambda: DIGEST_B,
    )
    embedded = {
        "PublishedMonitoringIntent": object(),
        "PublishedMonitoringIntentAssetReference": object(),
        "PublishedMonitoringIntentAttestation": object(),
        "PublishedRuntimeContextBinding": context_binding,
        "MonitoringCollectorContract": collector_contract,
        "ApprovedChangeScope": object(),
        "MonitoringAcquisitionAuthority": object(),
    }
    monkeypatch.setattr(
        runtime_module,
        "_embedded_model",
        lambda model, _payload: embedded[model.__name__],
    )
    monkeypatch.setattr(
        runtime_module,
        "_validate_acquisition_authority_preflight",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        runtime_module,
        "_require_pr99_conditioned_blob_contract",
        lambda _contract: None,
    )
    freshness_calls: list[datetime | None] = []

    def reject_current_freshness_during_recovery(
        *,
        configuration: object,
        as_of: datetime | None,
    ) -> None:
        del configuration
        freshness_calls.append(as_of)
        if as_of is not None:
            raise AssertionError("current support-RBAC freshness must not gate durable recovery")

    monkeypatch.setattr(
        runtime_module,
        "_validate_runtime_support_effective_rbac",
        reject_current_freshness_during_recovery,
    )
    monkeypatch.setattr(runtime_module, "_utc_now_milliseconds", lambda: NOW)
    events: list[str] = []
    original_read_current = store.read_current

    def tracked_read_current(request: Any) -> ArtifactReadResult:
        events.append(f"blob:{request.blob_name}")
        return original_read_current(request)

    monkeypatch.setattr(store, "read_current", tracked_read_current)
    monkeypatch.setattr(
        runtime_module,
        "AzureBlobChangeEvidenceReplayStore",
        lambda **_kwargs: store,
    )

    def build_verifier(**kwargs: object) -> object:
        events.append("key:" + cast(str, kwargs["managed_identity_client_id"]))
        return SimpleNamespace(public_key=object())

    monkeypatch.setattr(runtime_module, "KeyVaultRsaPublicKeyVerifier", build_verifier)
    monkeypatch.setattr(runtime_module, "TrustedKeyRecord", lambda **_kwargs: object())
    monkeypatch.setattr(
        runtime_module,
        "KeyVaultTrustedKeyResolver",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        runtime_module,
        "KeyVaultRsaSigner",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        runtime_module,
        "_build_acquisition_receipt_verifier",
        lambda **_kwargs: lambda _receipt, _as_of: None,
    )

    class _RecoveryCommitPort:
        def __init__(self, **_kwargs: object) -> None:
            pass

        @staticmethod
        def recover(_probe: object) -> object:
            return expected_outcome

    monkeypatch.setattr(
        runtime_module,
        "MonitoringEvidenceCommitPort",
        _RecoveryCommitPort,
    )

    def reject_source_client(**_kwargs: object) -> object:
        raise AssertionError("source client must not be constructed during manifest recovery")

    monkeypatch.setattr(
        runtime_module,
        "AzureMonitoringAdapter",
        reject_source_client,
    )

    outcome = runtime_module.run_wc028_monitoring_acquisition_job(configuration=configuration)

    assert outcome is expected_outcome
    assert events[0] == f"blob:{manifest_name}"
    assert events.index(f"key:{CLIENT_ID}") > events.index(f"blob:{manifest_name}")
    assert f"key:{SUPPORT_CLIENT_ID}" not in events
    assert freshness_calls == []


def test_job_wraps_key_client_construction_and_read_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(
        _configuration_payload()
    )
    embedded = {
        "PublishedMonitoringIntent": object(),
        "PublishedMonitoringIntentAssetReference": object(),
        "PublishedMonitoringIntentAttestation": object(),
        "PublishedRuntimeContextBinding": SimpleNamespace(binding_digest=DIGEST_A),
        "MonitoringCollectorContract": SimpleNamespace(
            collector_identity_resource_id=COLLECTOR_ID.casefold(),
            compute_artifact_digest_value=lambda: DIGEST_B,
        ),
        "ApprovedChangeScope": object(),
        "MonitoringAcquisitionAuthority": object(),
    }
    monkeypatch.setattr(
        runtime_module,
        "_embedded_model",
        lambda model, _payload: embedded[model.__name__],
    )
    monkeypatch.setattr(
        runtime_module,
        "_validate_acquisition_authority_preflight",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        runtime_module,
        "_require_pr99_conditioned_blob_contract",
        lambda _contract: None,
    )
    monkeypatch.setattr(runtime_module, "_utc_now_milliseconds", lambda: NOW)
    monkeypatch.setattr(
        runtime_module,
        "AzureBlobChangeEvidenceReplayStore",
        lambda **_kwargs: _MemoryStore(container_name="monitoring-evidence"),
    )

    def fail_key_read(**_kwargs: object) -> object:
        raise AzureError("synthetic Key Vault client failure")

    monkeypatch.setattr(
        runtime_module,
        "KeyVaultRsaPublicKeyVerifier",
        fail_key_read,
    )

    with pytest.raises(
        MonitoringAcquisitionJobError,
        match="Azure client or transport operation failed",
    ):
        runtime_module.run_wc028_monitoring_acquisition_job(configuration=configuration)


def test_new_acquisition_recaptures_support_freshness_after_slow_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = Wc028MonitoringAcquisitionJobConfiguration.model_validate(
        _configuration_payload()
    )
    embedded = {
        "PublishedMonitoringIntent": object(),
        "PublishedMonitoringIntentAssetReference": object(),
        "PublishedMonitoringIntentAttestation": object(),
        "PublishedRuntimeContextBinding": SimpleNamespace(binding_digest=DIGEST_A),
        "MonitoringCollectorContract": SimpleNamespace(
            collector_identity_resource_id=COLLECTOR_ID.casefold(),
            compute_artifact_digest_value=lambda: DIGEST_B,
        ),
        "ApprovedChangeScope": object(),
        "MonitoringAcquisitionAuthority": object(),
    }
    monkeypatch.setattr(
        runtime_module,
        "_embedded_model",
        lambda model, _payload: embedded[model.__name__],
    )
    monkeypatch.setattr(
        runtime_module,
        "_validate_acquisition_authority_preflight",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        runtime_module,
        "_require_pr99_conditioned_blob_contract",
        lambda _contract: None,
    )
    clock = {"now": NOW}

    class _SlowEmptyStore:
        read_count = 0

        @classmethod
        def read_current(cls, _request: object) -> object:
            cls.read_count += 1
            clock["now"] += timedelta(minutes=4)
            raise ArtifactNotFoundError("synthetic Blob is absent")

    monkeypatch.setattr(
        runtime_module,
        "AzureBlobChangeEvidenceReplayStore",
        lambda **_kwargs: _SlowEmptyStore(),
    )
    monkeypatch.setattr(
        runtime_module,
        "_utc_now_milliseconds",
        lambda: clock["now"],
    )

    def reject_key_client(**_kwargs: object) -> object:
        raise AssertionError("key clients must not be built with expired support RBAC")

    monkeypatch.setattr(
        runtime_module,
        "KeyVaultRsaPublicKeyVerifier",
        reject_key_client,
    )

    with pytest.raises(
        MonitoringAcquisitionJobError,
        match="support effective RBAC evidence is stale",
    ):
        runtime_module.run_wc028_monitoring_acquisition_job(configuration=configuration)

    assert _SlowEmptyStore.read_count == 3
    assert clock["now"] == NOW + timedelta(minutes=12)


class _MemoryStore:
    def __init__(
        self,
        *,
        container_name: str,
        fail_once_on_suffix: str | None = None,
        ambiguous_once_on_suffix: str | None = None,
    ) -> None:
        self.container_name = container_name
        self.fail_once_on_suffix = fail_once_on_suffix
        self.ambiguous_once_on_suffix = ambiguous_once_on_suffix
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
        if self.ambiguous_once_on_suffix is not None and request.blob_name.endswith(
            self.ambiguous_once_on_suffix
        ):
            self.ambiguous_once_on_suffix = None
            raise ServiceRequestError("synthetic ambiguous create transport failure")
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


@dataclass(frozen=True)
class _PersistenceCase:
    prepared: Any
    context_binding: Any
    collector_contract: Any
    configuration: Any


@pytest.fixture
def persistence_case(monkeypatch: pytest.MonkeyPatch) -> _PersistenceCase:
    cast(Any, _trust_synthetic_managed_identity_key).__wrapped__(monkeypatch)
    outcome, _, _ = _execute(_AcquisitionPort())
    context_binding, _, _ = _authority()
    receipt = outcome.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    collector_contract = _acquisition_collector_contract()
    subscription_id = SUBSCRIPTION_ID
    support_identity_resource_id = SUPPORT_ID
    registry_resource_id = REGISTRY_ID.casefold()
    monitoring_intent_key_resource_id = MONITORING_INTENT_KEY_RESOURCE_ID.casefold()
    support_inventory = (
        runtime_module.MonitoringRuntimeSupportEffectiveRbacInventory.model_validate(
            _runtime_support_rbac_inventory(
                subscription_id=subscription_id,
                tenant_id=cast(str, collector_contract.collector_tenant_id),
                support_identity_resource_id=support_identity_resource_id,
                registry_resource_id=registry_resource_id,
                monitoring_intent_key_resource_id=monitoring_intent_key_resource_id,
                collected_at=receipt.execution_started_at - timedelta(minutes=1),
                expires_at=receipt.execution_completed_at + timedelta(minutes=10),
            )
        )
    )
    return _PersistenceCase(
        prepared=outcome.prepared,
        context_binding=context_binding,
        collector_contract=collector_contract,
        configuration=SimpleNamespace(
            persistence_replay_key=PERSISTENCE_REPLAY_KEY,
            execution_id=EXECUTION_ID,
            expected_acquisition_authority_digest=(receipt.acquisition_authority_digest),
            legacy_collector_rbac_cleanup_digest=CLEANUP_DIGEST,
            incident_revision=1,
            trust_delay_seconds=60,
            request_lifetime_seconds=600,
            runtime_support_effective_rbac_inventory=support_inventory,
            monitoring_evidence_storage_readiness=(
                runtime_module.MonitoringEvidenceStorageReadiness.model_validate(_STORAGE_READINESS)
            ),
            evidence_storage_account_resource_id=EVIDENCE_STORAGE_ID.casefold(),
            evidence_container_name="monitoring-evidence",
            runtime_support_identity_resource_id=(support_inventory.support_identity_resource_id),
            runtime_support_identity_client_id=support_inventory.support_client_id,
            runtime_support_identity_principal_id=(support_inventory.support_principal_id),
            registry_resource_id=registry_resource_id,
            runtime_support_acr_pull_role_definition_id=(ACR_PULL_ROLE_ID.casefold()),
            monitoring_intent_signing_key_resource_id=(monitoring_intent_key_resource_id),
            runtime_support_monitoring_intent_key_reader_role_definition_id=(
                SUPPORT_KEY_READER_ROLE_ID.casefold()
            ),
            collector_identity_resource_id=(
                collector_contract.collector_identity_resource_id.casefold()
            ),
            athena_context_identity_resource_id=cast(
                str,
                collector_contract.athena_context_identity_id,
            ).casefold(),
            managed_identity_client_id=(collector_contract.collector_identity_client_id),
        ),
    )


def _commit_port(
    monitoring_store: _MemoryStore,
    case: _PersistenceCase,
    *,
    private_key: rsa.RSAPrivateKey | None = None,
    signer: object | None = None,
    storage_readiness_verifier: (
        Callable[
            [runtime_module.MonitoringEvidenceStorageReadiness],
            runtime_module.MonitoringEvidenceStorageReadiness,
        ]
        | None
    ) = None,
) -> MonitoringEvidenceCommitPort:
    private_key = private_key or rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    fingerprint = sha256_hex(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    trusted_key = MonitoringRuntimeTrustedKey(
        keyVaultKeyId=case.collector_contract.signing_key_resource_id,
        publicKeyFingerprint=fingerprint,
        activatedAt=datetime(2020, 1, 1, tzinfo=UTC),
    )
    key_record = TrustedKeyRecord(
        anchor=trusted_key.anchor,
        public_key=public_key,
        enabled=True,
        activated_at=datetime(2020, 1, 1, tzinfo=UTC),
    )
    return MonitoringEvidenceCommitPort(
        monitoring_writer=monitoring_store,
        monitoring_current_reader=monitoring_store,
        persistence_replay_key=PERSISTENCE_REPLAY_KEY,
        signer=cast(Any, signer or _Signer(private_key)),
        trusted_key=trusted_key,
        reviewed_collector_contract=case.collector_contract,
        configuration=case.configuration,
        context_binding=case.context_binding,
        monitoring_intent_reference=case.prepared.monitoring_intent_reference,
        acquisition_receipt_verifier=lambda _receipt, _as_of: None,
        storage_readiness_verifier=(
            storage_readiness_verifier
            or (
                lambda expected: (
                    runtime_module.MonitoringEvidenceStorageReadiness.model_validate_json(
                        expected.model_dump_json(by_alias=True)
                    )
                )
            )
        ),
        key_record=key_record,
    )


def _rehash_recovery_state_without_resigning(
    state: runtime_module.MonitoringPersistenceRecoveryState,
    **updates: object,
) -> runtime_module.MonitoringPersistenceRecoveryState:
    state = state.model_copy(update=updates)
    state_digest = compute_artifact_digest(
        state.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
            exclude={"state_digest", "collector_attestation"},
        )
    )
    state = state.model_copy(update={"state_digest": state_digest})
    signed_payload = state.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={"collector_attestation"},
    )
    attestation = state.collector_attestation.model_copy(
        update={
            "signed_preimage_digest": compute_artifact_digest(
                runtime_module._monitoring_recovery_state_preimage(signed_payload)
            )
        }
    )
    return state.model_copy(update={"collector_attestation": attestation})


def test_commit_port_publishes_replay_manifest_last(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    prepared = persistence_case.prepared
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    prepared_digest = compute_artifact_digest(
        _monitoring_persistence_replay_payload(cast(Any, prepared))
    )
    replay_key = PERSISTENCE_REPLAY_KEY
    manifest_name = f"wc024-monitoring/commits/{replay_key.removeprefix('sha256:')}/manifest.json"

    with _commit_port(
        store,
        persistence_case,
        private_key=private_key,
    ).transaction(prepared) as committed:
        assert manifest_name not in store.blobs

    written_names = [item.blob_name for item in store.create_requests]
    assert written_names[0].endswith("/recovery.json")
    assert written_names[-1] == manifest_name
    recovery_state = runtime_module.MonitoringPersistenceRecoveryState.model_validate_json(
        store.blobs[written_names[0]].payload
    )
    signed_payload = recovery_state.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={"collector_attestation"},
    )
    private_key.public_key().verify(
        base64.b64decode(
            recovery_state.collector_attestation.signature,
            validate=True,
        ),
        runtime_module.canonicalize_json(
            runtime_module._monitoring_recovery_state_preimage(signed_payload)
        ).encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    manifest = MonitoringPersistenceCommitManifest.model_validate_json(
        store.blobs[manifest_name].payload
    )
    assert manifest.replay_key == replay_key
    assert manifest.collection_id == f"wc024-{replay_key.removeprefix('sha256:')[:12]}"
    assert manifest.prepared_digest == prepared_digest
    assert manifest.monitoring_handoff == committed.monitoring_handoff
    receipt = prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    expected_correlation = build_collected_correlation_request(
        prepared,
        committed,
        context_binding=persistence_case.context_binding,
        incident_revision=1,
        issued_at=receipt.execution_started_at,
        trusted_as_of=receipt.execution_started_at + timedelta(seconds=60),
        expires_at=receipt.execution_started_at + timedelta(seconds=600),
    )
    assert manifest.correlation_request_id == expected_correlation.request_id
    assert manifest.correlation_request_digest == expected_correlation.request_digest


def test_first_durable_write_revalidates_storage_protection(
    persistence_case: _PersistenceCase,
) -> None:
    unsafe_readiness = (
        persistence_case.configuration.monitoring_evidence_storage_readiness.model_copy(
            update={"versioning_enabled": False}
        )
    )
    unsafe_configuration = SimpleNamespace(
        **{
            **vars(persistence_case.configuration),
            "monitoring_evidence_storage_readiness": unsafe_readiness,
        }
    )
    unsafe_case = replace(
        persistence_case,
        configuration=unsafe_configuration,
    )
    store = _MemoryStore(container_name="monitoring-evidence")

    with (
        pytest.raises(
            MonitoringAcquisitionJobError,
            match="storage readiness failed runtime revalidation",
        ),
        _commit_port(store, unsafe_case).transaction(unsafe_case.prepared),
    ):
        pass

    assert store.create_requests == []
    assert store.blobs == {}


def test_first_durable_write_requires_matching_live_storage_readback(
    persistence_case: _PersistenceCase,
) -> None:
    changed_payload = _storage_readiness_payload()
    changed_payload["immutabilityRetentionDays"] = 31
    changed_readiness = runtime_module.MonitoringEvidenceStorageReadiness.model_validate(
        _refresh_storage_readiness(changed_payload)
    )
    store = _MemoryStore(container_name="monitoring-evidence")

    with (
        pytest.raises(
            MonitoringAcquisitionJobError,
            match="live monitoring evidence storage protection changed",
        ),
        _commit_port(
            store,
            persistence_case,
            storage_readiness_verifier=lambda _expected: changed_readiness,
        ).transaction(persistence_case.prepared),
    ):
        pass

    assert store.create_requests == []
    assert store.blobs == {}


def test_recovery_state_and_manifest_reject_zero_startup_sentinels(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    with _commit_port(store, persistence_case).transaction(persistence_case.prepared):
        pass
    manifest_name, recovery_name, _ = runtime_module._monitoring_persistence_blob_names(
        PERSISTENCE_REPLAY_KEY
    )
    state_payload = cast(
        dict[str, object],
        json.loads(store.blobs[recovery_name].payload),
    )
    state_payload["runtimeSupportIdentityPrincipalId"] = runtime_module._NIL_GUID
    with pytest.raises(ValidationError, match="non-nil GUID"):
        runtime_module.MonitoringPersistenceRecoveryState.model_validate_json(
            runtime_module.canonicalize_json(state_payload)
        )

    state_payload = cast(
        dict[str, object],
        json.loads(store.blobs[recovery_name].payload),
    )
    state_payload["runtimeSupportEffectiveRbacInventoryDigest"] = f"sha256:{'0' * 64}"
    with pytest.raises(ValidationError, match="non-zero SHA-256"):
        runtime_module.MonitoringPersistenceRecoveryState.model_validate_json(
            runtime_module.canonicalize_json(state_payload)
        )

    manifest_payload = cast(
        dict[str, object],
        json.loads(store.blobs[manifest_name].payload),
    )
    manifest_payload["executionId"] = f"wc028-execution-{'0' * 32}"
    with pytest.raises(ValidationError, match="executionId must be non-zero"):
        MonitoringPersistenceCommitManifest.model_validate_json(
            runtime_module.canonicalize_json(manifest_payload)
        )


def test_commit_port_leaves_no_commit_marker_when_correlation_fails(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    prepared = persistence_case.prepared
    manifest_name = (
        f"wc024-monitoring/commits/{PERSISTENCE_REPLAY_KEY.removeprefix('sha256:')}/manifest.json"
    )

    with (
        pytest.raises(RuntimeError, match="synthetic correlation failure"),
        _commit_port(store, persistence_case).transaction(prepared),
    ):
        raise RuntimeError("synthetic correlation failure")

    assert manifest_name not in store.blobs


def test_commit_port_replays_durable_manifest_without_new_writes(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    port = _commit_port(store, persistence_case)
    with port.transaction(persistence_case.prepared) as first:
        pass
    create_count = len(store.create_requests)

    with port.transaction(persistence_case.prepared) as replayed:
        pass

    assert replayed == first
    assert len(store.create_requests) == create_count


def test_commit_port_recovers_partial_write_before_manifest(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        fail_once_on_suffix="/manifest.json",
    )
    prepared = persistence_case.prepared
    port = _commit_port(store, persistence_case)

    with (
        pytest.raises(RuntimeError, match="staged persistence failure"),
        port.transaction(prepared),
    ):
        pass
    assert len(store.blobs) == 2

    with port.transaction(prepared) as committed:
        pass

    assert committed.monitoring_handoff.evidence.name in store.blobs
    assert any(name.endswith("/manifest.json") for name in store.blobs)


def test_commit_port_recovers_ambiguous_create_by_exact_known_name(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        ambiguous_once_on_suffix="/evidence.json",
    )

    with _commit_port(store, persistence_case).transaction(persistence_case.prepared) as committed:
        pass

    assert committed.monitoring_handoff.evidence.name in store.blobs
    assert any(name.endswith("/manifest.json") for name in store.blobs)


@pytest.mark.parametrize(
    ("failure_kind", "message"),
    (
        ("collision", "already exists"),
        ("transport", "conflicting immutable bytes"),
    ),
)
def test_create_recovery_rejects_identical_bytes_under_wrong_blob_name(
    persistence_case: _PersistenceCase,
    failure_kind: str,
    message: str,
) -> None:
    payload = b'{"schemaVersion":"synthetic"}\n'
    expected_name = "wc024-monitoring/commits/synthetic/recovery.json"

    class _FailingWriter:
        @staticmethod
        def create(_request: object) -> object:
            if failure_kind == "collision":
                raise ArtifactAlreadyExistsError("synthetic collision")
            raise ServiceRequestError("synthetic ambiguous create")

    class _WrongNameReader:
        @staticmethod
        def read_current(_request: object) -> ArtifactReadResult:
            return ArtifactReadResult(
                container_name="monitoring-evidence",
                blob_name="wc024-monitoring/commits/different/recovery.json",
                version_id="synthetic-version",
                payload=payload,
                size_bytes=len(payload),
                content_type="application/json",
                payload_sha256=sha256_hex(payload),
            )

    with pytest.raises(MonitoringAcquisitionJobError, match=message):
        _commit_port(
            _MemoryStore(container_name="monitoring-evidence"),
            persistence_case,
        )._write(
            writer=cast(Any, _FailingWriter()),
            current_reader=cast(Any, _WrongNameReader()),
            blob_name=expected_name,
            payload=payload,
        )


def test_commit_port_wraps_azure_signing_failure(
    persistence_case: _PersistenceCase,
) -> None:
    class _FailingSigner:
        @staticmethod
        def sign_preimage(_payload: bytes) -> str:
            raise AzureError("synthetic Key Vault signing failure")

    store = _MemoryStore(container_name="monitoring-evidence")

    with (
        pytest.raises(
            MonitoringAcquisitionJobError,
            match="recovery-state signing failed before persistence",
        ),
        _commit_port(
            store,
            persistence_case,
            signer=_FailingSigner(),
        ).transaction(persistence_case.prepared),
    ):
        pass
    assert store.blobs == {}


@pytest.mark.parametrize("remove_evidence", (False, True))
def test_restart_recovers_signed_state_without_reacquisition_byte_identically(
    persistence_case: _PersistenceCase,
    remove_evidence: bool,
) -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        fail_once_on_suffix="/manifest.json",
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    first_port = _commit_port(
        store,
        persistence_case,
        private_key=private_key,
    )
    first_committed = None
    with (
        pytest.raises(RuntimeError, match="staged persistence failure"),
        first_port.transaction(persistence_case.prepared) as committed,
    ):
        first_committed = committed
    assert first_committed is not None
    manifest_name, recovery_name, evidence_name = runtime_module._monitoring_persistence_blob_names(
        PERSISTENCE_REPLAY_KEY
    )
    assert manifest_name not in store.blobs
    assert evidence_name in store.blobs
    if remove_evidence:
        del store.blobs[evidence_name]

    receipt = persistence_case.prepared.monitoring_bundle.acquisition_receipt
    assert receipt is not None
    expected_correlation = build_collected_correlation_request(
        persistence_case.prepared,
        first_committed,
        context_binding=persistence_case.context_binding,
        incident_revision=1,
        issued_at=receipt.execution_started_at,
        trusted_as_of=receipt.execution_started_at + timedelta(seconds=60),
        expires_at=receipt.execution_started_at + timedelta(seconds=600),
    )
    restarted_port = _commit_port(
        store,
        persistence_case,
        private_key=private_key,
    )
    recovered = restarted_port.recover(
        runtime_module._probe_monitoring_persistence(
            reader=store,
            replay_key=PERSISTENCE_REPLAY_KEY,
        )
    )

    assert recovered is not None
    assert recovered.committed == first_committed
    assert recovered.correlation_request == expected_correlation
    assert recovered.correlation_request.canonical_bytes() == (
        expected_correlation.canonical_bytes()
    )
    assert manifest_name in store.blobs
    assert recovery_name in store.blobs
    assert evidence_name in store.blobs


def test_restart_uses_signed_original_support_inventory_after_current_refresh(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        fail_once_on_suffix="/manifest.json",
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    first_committed = None
    with (
        pytest.raises(RuntimeError, match="staged persistence failure"),
        _commit_port(
            store,
            persistence_case,
            private_key=private_key,
        ).transaction(persistence_case.prepared) as committed,
    ):
        first_committed = committed
    assert first_committed is not None
    original_inventory = persistence_case.configuration.runtime_support_effective_rbac_inventory
    refreshed_inventory = (
        runtime_module.MonitoringRuntimeSupportEffectiveRbacInventory.model_validate(
            _runtime_support_rbac_inventory(
                subscription_id=original_inventory.subscription_id,
                tenant_id=original_inventory.tenant_id,
                support_identity_resource_id=(original_inventory.support_identity_resource_id),
                registry_resource_id=(persistence_case.configuration.registry_resource_id),
                monitoring_intent_key_resource_id=(
                    persistence_case.configuration.monitoring_intent_signing_key_resource_id
                ),
                collected_at=original_inventory.expires_at + timedelta(minutes=1),
                expires_at=original_inventory.expires_at + timedelta(minutes=10),
                collection_run_suffix="b" * 32,
                source_manifest_digest=DIGEST_C,
            )
        )
    )
    refreshed_configuration = SimpleNamespace(
        **{
            **vars(persistence_case.configuration),
            "runtime_support_effective_rbac_inventory": refreshed_inventory,
        }
    )
    refreshed_case = replace(
        persistence_case,
        configuration=refreshed_configuration,
    )

    recovered = _commit_port(
        store,
        refreshed_case,
        private_key=private_key,
    ).recover(
        runtime_module._probe_monitoring_persistence(
            reader=store,
            replay_key=PERSISTENCE_REPLAY_KEY,
        )
    )

    assert recovered is not None
    assert recovered.committed == first_committed
    assert refreshed_inventory.inventory_digest != original_inventory.inventory_digest


def test_partial_recovery_rejects_changed_storage_readiness_before_write(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        fail_once_on_suffix="/manifest.json",
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with (
        pytest.raises(RuntimeError, match="staged persistence failure"),
        _commit_port(
            store,
            persistence_case,
            private_key=private_key,
        ).transaction(persistence_case.prepared),
    ):
        pass
    manifest_name, _, evidence_name = runtime_module._monitoring_persistence_blob_names(
        PERSISTENCE_REPLAY_KEY
    )
    del store.blobs[evidence_name]
    readiness_payload = _storage_readiness_payload()
    readiness_payload["immutabilityRetentionDays"] = 31
    changed_readiness = runtime_module.MonitoringEvidenceStorageReadiness.model_validate(
        _refresh_storage_readiness(readiness_payload)
    )
    changed_configuration = SimpleNamespace(
        **{
            **vars(persistence_case.configuration),
            "monitoring_evidence_storage_readiness": changed_readiness,
        }
    )
    changed_case = replace(
        persistence_case,
        configuration=changed_configuration,
    )

    with pytest.raises(
        MonitoringAcquisitionJobError,
        match="does not match the reviewed runtime configuration",
    ):
        _commit_port(
            store,
            changed_case,
            private_key=private_key,
        ).recover(
            runtime_module._probe_monitoring_persistence(
                reader=store,
                replay_key=PERSISTENCE_REPLAY_KEY,
            )
        )

    assert evidence_name not in store.blobs
    assert manifest_name not in store.blobs


@pytest.mark.parametrize("manifest_on_reconcile", (False, True))
def test_probe_reconciles_concurrent_state_and_manifest_publication(
    persistence_case: _PersistenceCase,
    manifest_on_reconcile: bool,
) -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with _commit_port(
        store,
        persistence_case,
        private_key=private_key,
    ).transaction(persistence_case.prepared):
        pass
    manifest_name, recovery_name, evidence_name = runtime_module._monitoring_persistence_blob_names(
        PERSISTENCE_REPLAY_KEY
    )

    class _InterleavedReader:
        def __init__(self) -> None:
            self.requests: list[str] = []
            self.manifest_reads = 0
            self.state_reads = 0

        def read_current(self, request: Any) -> ArtifactReadResult:
            self.requests.append(request.blob_name)
            if request.blob_name == manifest_name:
                self.manifest_reads += 1
                if self.manifest_reads == 1 or not manifest_on_reconcile:
                    raise ArtifactNotFoundError("synthetic manifest is not visible yet")
            elif request.blob_name == recovery_name:
                self.state_reads += 1
                if self.state_reads == 1:
                    raise ArtifactNotFoundError("synthetic state is not visible yet")
            return store.blobs[request.blob_name]

    reader = _InterleavedReader()
    probe = runtime_module._probe_monitoring_persistence(
        reader=reader,
        replay_key=PERSISTENCE_REPLAY_KEY,
    )

    assert probe.recovery_state_result == store.blobs[recovery_name]
    assert probe.evidence_result == store.blobs[evidence_name]
    assert probe.manifest_result == (store.blobs[manifest_name] if manifest_on_reconcile else None)
    assert reader.requests == [
        manifest_name,
        recovery_name,
        evidence_name,
        manifest_name,
        recovery_name,
    ]
    recovered = _commit_port(
        store,
        persistence_case,
        private_key=private_key,
    ).recover(probe)
    assert recovered is not None


def test_transaction_rejects_evidence_collision_not_seen_with_signed_state(
    persistence_case: _PersistenceCase,
) -> None:
    manifest_name, recovery_name, evidence_name = runtime_module._monitoring_persistence_blob_names(
        PERSISTENCE_REPLAY_KEY
    )

    class _LateOrphanStore(_MemoryStore):
        injected = False

        def create(self, request: Any) -> ArtifactWriteReceipt:
            if request.blob_name == evidence_name and not self.injected:
                self.injected = True
                self.blobs[evidence_name] = ArtifactReadResult(
                    container_name=self.container_name,
                    blob_name=evidence_name,
                    version_id="preexisting-orphan-version",
                    payload=request.payload,
                    size_bytes=len(request.payload),
                    content_type="application/json",
                    payload_sha256=sha256_hex(request.payload),
                )
            return super().create(request)

    store = _LateOrphanStore(container_name="monitoring-evidence")

    with (
        pytest.raises(
            MonitoringAcquisitionJobError,
            match="pre-existed its signed recovery state",
        ),
        _commit_port(store, persistence_case).transaction(persistence_case.prepared),
    ):
        pass

    assert recovery_name in store.blobs
    assert store.blobs[evidence_name].version_id == "preexisting-orphan-version"
    assert manifest_name not in store.blobs


def test_restart_rejects_evidence_without_collector_signed_recovery_binding(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        fail_once_on_suffix="/manifest.json",
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with (
        pytest.raises(RuntimeError, match="staged persistence failure"),
        _commit_port(
            store,
            persistence_case,
            private_key=private_key,
        ).transaction(persistence_case.prepared),
    ):
        pass
    manifest_name, recovery_name, evidence_name = runtime_module._monitoring_persistence_blob_names(
        PERSISTENCE_REPLAY_KEY
    )
    del store.blobs[recovery_name]
    store.read_requests.clear()

    with pytest.raises(
        MonitoringAcquisitionJobError,
        match="without its collector-signed recovery binding",
    ):
        _commit_port(
            store,
            persistence_case,
            private_key=private_key,
        ).recover(
            runtime_module._probe_monitoring_persistence(
                reader=store,
                replay_key=PERSISTENCE_REPLAY_KEY,
            )
        )

    assert evidence_name in store.blobs
    assert manifest_name not in store.blobs
    assert [item.blob_name for item in store.read_requests] == [
        manifest_name,
        recovery_name,
        evidence_name,
        manifest_name,
        recovery_name,
        manifest_name,
        recovery_name,
    ]


@pytest.mark.parametrize("incident_override", ("alternate", "missing"))
def test_restart_rejects_rehashed_unsigned_incident_observation_override(
    persistence_case: _PersistenceCase,
    incident_override: str,
) -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        fail_once_on_suffix="/manifest.json",
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with (
        pytest.raises(RuntimeError, match="staged persistence failure"),
        _commit_port(
            store,
            persistence_case,
            private_key=private_key,
        ).transaction(persistence_case.prepared),
    ):
        pass
    manifest_name, recovery_name, _ = runtime_module._monitoring_persistence_blob_names(
        PERSISTENCE_REPLAY_KEY
    )
    recovery_state = runtime_module.MonitoringPersistenceRecoveryState.model_validate_json(
        store.blobs[recovery_name].payload
    )
    if incident_override == "alternate":
        alternate_ids = [
            item.observation_id
            for item in persistence_case.prepared.monitoring_bundle.observations
            if item.observation_id != persistence_case.prepared.previous_health_observation_id
            and runtime_module.MonitoringEvidenceCommitPort._observation_health_state(item)
            == "healthy"
        ]
        assert alternate_ids
        replacement_observation_id = alternate_ids[0]
    else:
        replacement_observation_id = f"obs-{'f' * 32}"
    recovery_state = _rehash_recovery_state_without_resigning(
        recovery_state,
        previous_health_observation_id=replacement_observation_id,
    )
    tampered_state = recovery_state.canonical_bytes()
    store.blobs[recovery_name] = replace(
        store.blobs[recovery_name],
        payload=tampered_state,
        size_bytes=len(tampered_state),
        payload_sha256=sha256_hex(tampered_state),
    )

    with pytest.raises(
        MonitoringAcquisitionJobError,
        match="recovery-state attestation failed verification",
    ):
        _commit_port(
            store,
            persistence_case,
            private_key=private_key,
        ).recover(
            runtime_module._probe_monitoring_persistence(
                reader=store,
                replay_key=PERSISTENCE_REPLAY_KEY,
            )
        )

    assert manifest_name not in store.blobs


@pytest.mark.parametrize(
    "binding_field",
    (
        "execution",
        "replay",
        "cleanup",
        "revision",
        "timing",
        "support-inventory",
        "storage-readiness",
        "support-identity",
    ),
)
def test_restart_rejects_rehashed_unsigned_recovery_binding_fields(
    persistence_case: _PersistenceCase,
    binding_field: str,
) -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        fail_once_on_suffix="/manifest.json",
    )
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with (
        pytest.raises(RuntimeError, match="staged persistence failure"),
        _commit_port(
            store,
            persistence_case,
            private_key=private_key,
        ).transaction(persistence_case.prepared),
    ):
        pass
    manifest_name, recovery_name, _ = runtime_module._monitoring_persistence_blob_names(
        PERSISTENCE_REPLAY_KEY
    )
    state = runtime_module.MonitoringPersistenceRecoveryState.model_validate_json(
        store.blobs[recovery_name].payload
    )
    if binding_field == "execution":
        updates: dict[str, object] = {"execution_id": f"wc028-execution-{'b' * 32}"}
    elif binding_field == "replay":
        updates = {
            "replay_key": DIGEST_A,
            "replay_preimage_digest": DIGEST_A,
            "collection_id": (f"wc024-{DIGEST_A.removeprefix('sha256:')[:12]}"),
        }
    elif binding_field == "cleanup":
        updates = {"legacy_collector_rbac_cleanup_digest": DIGEST_A}
    elif binding_field == "revision":
        updates = {"incident_revision": 2}
    elif binding_field == "timing":
        updates = {
            "trusted_as_of": state.trusted_as_of + timedelta(seconds=1),
            "expires_at": state.expires_at + timedelta(seconds=1),
        }
    elif binding_field == "support-inventory":
        updates = {"runtime_support_effective_rbac_inventory_digest": DIGEST_A}
    elif binding_field == "storage-readiness":
        updates = {"monitoring_evidence_storage_readiness_digest": DIGEST_A}
    else:
        updates = {"runtime_support_identity_client_id": ("abababab-abab-abab-abab-abababababab")}
    tampered = _rehash_recovery_state_without_resigning(state, **updates)
    tampered_bytes = tampered.canonical_bytes()
    store.blobs[recovery_name] = replace(
        store.blobs[recovery_name],
        payload=tampered_bytes,
        size_bytes=len(tampered_bytes),
        payload_sha256=sha256_hex(tampered_bytes),
    )

    with pytest.raises(
        MonitoringAcquisitionJobError,
        match="recovery-state attestation failed verification",
    ):
        _commit_port(
            store,
            persistence_case,
            private_key=private_key,
        ).recover(
            runtime_module._probe_monitoring_persistence(
                reader=store,
                replay_key=PERSISTENCE_REPLAY_KEY,
            )
        )

    assert manifest_name not in store.blobs


def test_manifest_probe_rejects_tampering_before_other_recovery_reads(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    with _commit_port(store, persistence_case).transaction(persistence_case.prepared):
        pass
    manifest_name, recovery_name, evidence_name = runtime_module._monitoring_persistence_blob_names(
        PERSISTENCE_REPLAY_KEY
    )
    manifest = MonitoringPersistenceCommitManifest.model_validate_json(
        store.blobs[manifest_name].payload
    )
    replacement_digest = DIGEST_A
    if manifest.correlation_request_digest == replacement_digest:
        replacement_digest = DIGEST_B
    tampered = store.blobs[manifest_name].payload.replace(
        manifest.correlation_request_digest.encode("ascii"),
        replacement_digest.encode("ascii"),
    )
    store.blobs[manifest_name] = replace(
        store.blobs[manifest_name],
        payload=tampered,
        size_bytes=len(tampered),
        payload_sha256=sha256_hex(tampered),
    )
    store.read_requests.clear()

    with pytest.raises(MonitoringAcquisitionJobError, match="commit manifest is invalid"):
        runtime_module._probe_monitoring_persistence(
            reader=store,
            replay_key=PERSISTENCE_REPLAY_KEY,
        )

    assert [item.blob_name for item in store.read_requests] == [manifest_name]
    assert recovery_name in store.blobs
    assert evidence_name in store.blobs


def test_commit_port_rejects_changed_reacquisition_under_same_replay_identity(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(
        container_name="monitoring-evidence",
        fail_once_on_suffix="/manifest.json",
    )
    port = _commit_port(store, persistence_case)

    with (
        pytest.raises(RuntimeError, match="staged persistence failure"),
        port.transaction(persistence_case.prepared),
    ):
        pass

    changed_bundle = persistence_case.prepared.monitoring_bundle.model_copy(
        update={"workload_id": "synthetic-different-workload"}
    )
    changed_prepared = replace(
        persistence_case.prepared,
        monitoring_bundle=changed_bundle,
    )
    with (
        pytest.raises(MonitoringAcquisitionJobError, match="does not match"),
        port.transaction(changed_prepared),
    ):
        pass

    assert not any(name.endswith("/manifest.json") for name in store.blobs)


def test_commit_port_rejects_conflicting_existing_artifact(
    persistence_case: _PersistenceCase,
) -> None:
    store = _MemoryStore(container_name="monitoring-evidence")
    prepared = persistence_case.prepared
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
        pytest.raises(MonitoringAcquisitionJobError, match="does not match"),
        _commit_port(store, persistence_case).transaction(prepared),
    ):
        pass


def test_commit_port_rejects_unreviewed_change_artifacts_before_write(
    persistence_case: _PersistenceCase,
) -> None:
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
    prepared = replace(
        persistence_case.prepared,
        change_artifacts=(cast(Any, artifact),),
    )

    with (
        pytest.raises(MonitoringAcquisitionJobError, match="change persistence"),
        _commit_port(monitoring_store, persistence_case).transaction(prepared),
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


def test_cli_reports_wrapped_wc028_dependency_failure_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "load_wc028_monitoring_acquisition_job_configuration",
        lambda **_: object(),
    )

    def fail_job(**_kwargs: object) -> object:
        try:
            raise ServiceRequestError("synthetic transport details")
        except ServiceRequestError as exc:
            raise MonitoringAcquisitionJobError(
                "WC-028 Azure client or transport operation failed"
            ) from exc

    monkeypatch.setattr(cli, "run_wc028_monitoring_acquisition_job", fail_job)
    stdout = io.StringIO()
    stderr = io.StringIO()

    result = cli.main(
        ["wc028-monitoring-acquisition-job", "--config-json", "{}"],
        stdout=stdout,
        stderr=stderr,
    )

    assert result == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "wc028-monitoring-acquisition-job failed: "
        "WC-028 Azure client or transport operation failed\n"
    )
    assert "Traceback" not in stderr.getvalue()
    assert "synthetic transport details" not in stderr.getvalue()
