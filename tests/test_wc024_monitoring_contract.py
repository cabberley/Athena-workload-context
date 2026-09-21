from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid5

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import BaseModel, ValidationError

from athena_context.contracts import (
    MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
    MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
    MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION,
    MONITORING_EFFECTIVE_RBAC_INVENTORY_SCHEMA_VERSION,
    MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
    MONITORING_IDENTITY_PROOF_AUDIENCE,
    MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS,
    MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
    MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
    MonitoringAcquisitionExchange,
    MonitoringAcquisitionReceipt,
    MonitoringAcquisitionWireAttempt,
    MonitoringCollectorContract,
    MonitoringEffectiveRbacInventory,
    MonitoringEffectiveRbacInventoryAttestation,
    MonitoringEvidenceAttestation,
    MonitoringEvidenceHandoff,
    MonitoringIdentityProof,
    MonitoringRuntimeReplayBinding,
    MonitoringSelectedIncident,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    VersionPinnedBlobReference,
    canonicalize_json,
    compute_artifact_digest,
    monitoring_acquisition_receipt_preimage,
    monitoring_effective_rbac_inventory_attestation_preimage,
    monitoring_handoff_preimage,
    monitoring_runtime_replay_key_preimage,
    sha256_hex,
    verify_monitoring_acquisition_receipt_attestation,
    verify_monitoring_evidence_handoff_attestation,
)
from athena_context.monitoring_incident import (
    build_selected_incident,
)

COLLECTOR_CONTRACT_MODULE = (
    Path(__file__).parents[1]
    / "infra"
    / "wc024-monitoring-foundation"
    / "modules"
    / "monitoring-collector-contract.bicep"
)
EFFECTIVE_RBAC_INVENTORY_EXAMPLE = (
    Path(__file__).parents[1]
    / "infra"
    / "wc024-monitoring-foundation"
    / "effective-rbac-inventory.example.json"
)
LEGACY_EFFECTIVE_RBAC_INVENTORY_V2_EXAMPLE = (
    Path(__file__).parents[1]
    / "infra"
    / "wc024-monitoring-foundation"
    / "effective-rbac-inventory.v2.example.json"
)
MONITORING_FOUNDATION_MAIN = (
    Path(__file__).parents[1] / "infra" / "wc024-monitoring-foundation" / "main.bicep"
)


REVIEWED_VM_NAMES = (
    "athena-hackathon-client-01",
    "athena-hackathon-ecp-01",
    "athena-hackathon-ecp-02",
    "athena-hackathon-ecp-03",
    "athena-hackathon-iris-01",
    "athena-hackathon-mid-01",
    "athena-hackathon-mid-02",
    "athena-hackathon-sqlvm-01",
    "athena-hackathon-web-01",
    "athena-hackathon-web-02",
    "athena-hackathon-web-03",
)
REVIEWED_WORKLOAD_VNET_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
    "rg-athena-demo-workload/providers/Microsoft.Network/virtualNetworks/"
    "athena-hackathon-vnet"
)
REVIEWED_SIGNING_KEY_URI = (
    "https://athenademomonkv.vault.azure.net/keys/monitoring-evidence-signing/"
    "0123456789abcdef0123456789abcdef"
)
SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
MONITORING_RESOURCE_GROUP_ROOT = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-monitoring"
)
WORKLOAD_RESOURCE_GROUP_ROOT = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-workload"
)
WORKSPACE_ID = (
    f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.OperationalInsights/"
    "workspaces/athena-hackathon-law"
)
RESOURCE_CONTEXT_TABLES = (
    "Heartbeat",
    "Perf",
    "InsightsMetrics",
    "Syslog",
    "VMConnection",
)
RESOURCE_CONTEXT_TABLE_PLANS = tuple(
    {
        "table": table,
        "plan": "Analytics",
        "tableResourceId": f"{WORKSPACE_ID}/tables/{table}",
    }
    for table in RESOURCE_CONTEXT_TABLES
)
READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
)
SIGNAL_READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/2fda1d90-37da-55d9-8ac3-132fb7bdca5d"
)
RESOURCE_LOG_READER_ROLE_DEFINITION_ID = (
    f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Authorization/"
    "roleDefinitions/f33a4363-5d9a-5d50-9871-c08582234978"
)
LOG_ANALYTICS_DATA_READER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/3b03c2da-16b3-4a49-8834-0f8130efdd3b"
)
IP_FLOW_VERIFY_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/"
    "providers/Microsoft.Authorization/"
    "roleDefinitions/3728cdf6-4efd-5282-bdfc-63b7872fd801"
)
NETWORK_WATCHER_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/"
    "providers/Microsoft.Network/networkWatchers/NetworkWatcher_australiaeast"
)
IP_FLOW_VERIFY_OPERATIONS = (
    "Microsoft.Network/networkWatchers/ipFlowVerify/action",
    "Microsoft.Network/networkWatchers/ipFlowVerify/read",
)
RESOURCE_HEALTH_ROLE_DEFINITION_ID = (
    f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Authorization/"
    "roleDefinitions/0790d6f2-9553-5b63-84ac-56596b7e4072"
)
PREVIOUS_RESOURCE_HEALTH_OPERATIONS = ("Microsoft.ResourceHealth/availabilityStatuses/read",)
PREVIOUS_PERMISSION_ATTESTED_RESOURCE_HEALTH_OPERATIONS = (
    "Microsoft.ResourceGraph/resources/read",
)
RESOURCE_GRAPH_QUERY_ROLE_DEFINITION_ID = (
    f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Authorization/"
    "roleDefinitions/5687977f-aa06-5699-8e18-1a54a074b532"
)
RESOURCE_GRAPH_QUERY_SCOPE_ID = WORKLOAD_RESOURCE_GROUP_ROOT
RESOURCE_GRAPH_QUERY_OPERATIONS = ("Microsoft.ResourceGraph/resources/read",)
RESOURCE_HEALTH_ROLE_OPERATIONS = ("Microsoft.ResourceHealth/availabilityStatuses/read",)
RESOURCE_HEALTH_OPERATIONS = (
    *RESOURCE_GRAPH_QUERY_OPERATIONS,
    *RESOURCE_HEALTH_ROLE_OPERATIONS,
)
CURRENT_RBAC_TARGET_QUERY_MODE = (
    "assignedToPrincipalIncludingInheritedGroupsAndDescendants"
)
PREVIOUS_RESOURCE_LOG_OPERATIONS = (
    "Microsoft.Insights/logs/Heartbeat/read",
    "Microsoft.Insights/logs/NTANetAnalytics/read",
    "Microsoft.Insights/logs/NWConnectionMonitorTestResult/read",
    "Microsoft.Insights/logs/VMConnection/read",
)
RESOURCE_LOG_OPERATIONS = (
    "Microsoft.Insights/Logs/Heartbeat/Read",
    "Microsoft.Insights/Logs/Perf/Read",
    "Microsoft.Insights/Logs/InsightsMetrics/Read",
    "Microsoft.Insights/Logs/Syslog/Read",
    "Microsoft.Insights/Logs/VMConnection/Read",
)
MEASURED_RBAC_FIELDS = (
    "signalReaderRoleName",
    "resourceLogReaderRoleDefinitionId",
    "resourceLogReaderRoleName",
    "resourceLogAllowedOperations",
    "resourceLogReadScopeIds",
    "ipFlowVerifyRoleName",
    "resourceHealthRoleName",
    "signingKeyArmResourceId",
    "signingKeyCryptoUserRoleDefinitionId",
    "evidenceBlobServiceResourceId",
    "evidenceContainerResourceId",
    "evidenceImmutabilityPolicyResourceId",
    "evidenceContainerPublicAccess",
    "evidenceWriterRoleDefinitionId",
    "evidenceWriterRoleName",
    "evidenceWriterAllowedDataActions",
    "evidenceWriterAssignmentCondition",
    "evidenceWriterAssignmentConditionVersion",
    "evidenceBlobVersioningEnabled",
    "evidenceContainerHasImmutabilityPolicy",
    "evidenceContainerImmutabilityPolicyState",
    "evidenceContainerImmutabilityPeriodDays",
    "evidenceContainerProtectedAppendWritesEnabled",
    "evidenceContainerProtectedAppendWritesAllEnabled",
    "evidenceStorageReadbackBindingId",
    "evidenceStorageReadinessDigest",
    "legacyCollectorRbacCleanupSchemaVersion",
    "legacyCollectorRbacCleanupDigest",
    "effectiveRbacInventory",
    "workspaceResourceContextAccessEnabled",
    "workspaceSkuName",
    "resourceContextTablePlans",
    "resourceIdColumn",
    "logQueryPreferHeader",
    "flowTableAcquisitionMode",
    "rbacAttestorIdentityResourceId",
    "rbacAttestorIdentityClientId",
    "rbacAttestorPrincipalId",
    "rbacAttestorTenantId",
    "rbacAttestorRoleDefinitionId",
    "rbacAttestorRoleName",
    "rbacAttestorScopeId",
    "rbacAttestorAllowedOperations",
    "rbacAttestorIdentitySeparationEnforced",
    "collectorRuntimeResourceId",
    "rbacAttestorRuntimeResourceId",
    "runtimeSupportIdentityResourceId",
    "runtimeSupportIdentityPrincipalId",
    "runtimeSupportStorageReaderRoleDefinitionId",
    "runtimeSupportStorageReaderRoleName",
    "runtimeSupportStorageReaderAllowedOperations",
    "runtimeSupportStorageReaderRoleAssignmentId",
    "runtimeSupportStorageReaderScopeId",
    "rbacInventoryBootstrapHandoffId",
    "rbacInventoryBootstrapDeploymentId",
    "rbacInventoryBootstrapTemplateHash",
    "rbacInventoryBootstrapContractInputsBindingId",
    "rbacInventoryVerifierIdentityResourceId",
    "rbacInventoryVerifierIdentityClientId",
    "rbacInventoryVerifierIdentityPrincipalId",
    "rbacInventoryVerifierIdentityTenantId",
    "rbacInventoryReviewerKeyVaultResourceId",
    "rbacInventoryReviewerKeyArmResourceId",
    "rbacInventoryVerifierRoleDefinitionId",
    "rbacInventoryVerifierRoleName",
    "rbacInventoryVerifierRoleScopeId",
    "rbacInventoryVerifierAllowedDataActions",
    "rbacInventoryVerifierRoleAssignmentId",
    "rbacInventoryReviewerPrincipalId",
    "rbacInventoryReviewerKeyId",
    "rbacInventoryReviewerPublicKeyModulus",
    "rbacInventoryReviewerPublicKeyExponent",
    "rbacInventoryReviewerPublicKeyFingerprint",
    "effectiveRbacInventoryAttestation",
    "identityProofApplicationId",
    "identityProofApplicationObjectId",
    "identityProofServicePrincipalId",
    "identityProofAppRoleId",
    "identityProofAppRoleAssignmentId",
    "identityProofAssignedPrincipalId",
)
V9_ONLY_CONTRACT_FIELDS = (
    "collectorRuntimeResourceId",
    "rbacAttestorRuntimeResourceId",
    "runtimeSupportIdentityResourceId",
    "runtimeSupportIdentityPrincipalId",
    "runtimeSupportStorageReaderRoleDefinitionId",
    "runtimeSupportStorageReaderRoleName",
    "runtimeSupportStorageReaderAllowedOperations",
    "runtimeSupportStorageReaderRoleAssignmentId",
    "runtimeSupportStorageReaderScopeId",
    "rbacInventoryBootstrapHandoffId",
    "rbacInventoryBootstrapDeploymentId",
    "rbacInventoryBootstrapTemplateHash",
    "rbacInventoryBootstrapContractInputsBindingId",
    "rbacInventoryVerifierIdentityResourceId",
    "rbacInventoryVerifierIdentityClientId",
    "rbacInventoryVerifierIdentityPrincipalId",
    "rbacInventoryVerifierIdentityTenantId",
    "rbacInventoryReviewerKeyVaultResourceId",
    "rbacInventoryReviewerKeyArmResourceId",
    "rbacInventoryVerifierRoleDefinitionId",
    "rbacInventoryVerifierRoleName",
    "rbacInventoryVerifierRoleScopeId",
    "rbacInventoryVerifierAllowedDataActions",
    "rbacInventoryVerifierRoleAssignmentId",
    "rbacInventoryReviewerPrincipalId",
    "rbacInventoryReviewerKeyId",
    "rbacInventoryReviewerPublicKeyModulus",
    "rbacInventoryReviewerPublicKeyExponent",
    "rbacInventoryReviewerPublicKeyFingerprint",
    "effectiveRbacInventoryAttestation",
    "evidenceBlobServiceResourceId",
    "evidenceImmutabilityPolicyResourceId",
    "evidenceContainerPublicAccess",
    "evidenceWriterRoleName",
    "evidenceWriterAllowedDataActions",
    "evidenceWriterAssignmentCondition",
    "evidenceWriterAssignmentConditionVersion",
    "evidenceBlobVersioningEnabled",
    "evidenceContainerHasImmutabilityPolicy",
    "evidenceContainerImmutabilityPolicyState",
    "evidenceContainerImmutabilityPeriodDays",
    "evidenceContainerProtectedAppendWritesEnabled",
    "evidenceContainerProtectedAppendWritesAllEnabled",
    "evidenceStorageReadbackBindingId",
    "evidenceStorageReadinessDigest",
    "legacyCollectorRbacCleanupSchemaVersion",
    "legacyCollectorRbacCleanupDigest",
)
V10_ONLY_CONTRACT_FIELDS = (
    "resourceGraphQueryRoleDefinitionId",
    "resourceGraphQueryRoleName",
    "resourceGraphQueryScopeId",
)
V8_ONLY_CONTRACT_FIELDS = (
    "workspaceResourceContextAccessEnabled",
    "workspaceSkuName",
    "resourceContextTablePlans",
    "resourceIdColumn",
    "logQueryPreferHeader",
    "flowTableAcquisitionMode",
    "rbacAttestorIdentityResourceId",
    "rbacAttestorIdentityClientId",
    "rbacAttestorPrincipalId",
    "rbacAttestorTenantId",
    "rbacAttestorRoleDefinitionId",
    "rbacAttestorRoleName",
    "rbacAttestorScopeId",
    "rbacAttestorAllowedOperations",
    "rbacAttestorIdentitySeparationEnforced",
    "collectorRuntimeResourceId",
    "rbacAttestorRuntimeResourceId",
    "rbacInventoryReviewerPrincipalId",
    "rbacInventoryReviewerKeyId",
    "rbacInventoryReviewerPublicKeyModulus",
    "rbacInventoryReviewerPublicKeyExponent",
    "rbacInventoryReviewerPublicKeyFingerprint",
    "effectiveRbacInventoryAttestation",
    "identityProofApplicationId",
    "identityProofApplicationObjectId",
    "identityProofServicePrincipalId",
    "identityProofAppRoleId",
    "identityProofAppRoleAssignmentId",
    "identityProofAssignedPrincipalId",
)
SIGNAL_READER_ROLE_NAME = "Athena WC016 Approved Signal Reader synthetic00000"
RESOURCE_LOG_READER_ROLE_NAME = "Athena WC-028 VM Resource Log Reader"
IP_FLOW_VERIFY_ROLE_NAME = "Athena WC-028 Network Watcher IP Flow Verify"
RESOURCE_GRAPH_QUERY_ROLE_NAME = "Athena WC-028 Resource Graph Query Submitter"
RESOURCE_HEALTH_ROLE_NAME = "Athena WC-028 VM Resource Health Reader"
EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID = (
    f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.Storage/storageAccounts/"
    "athenademomonstore"
)
EVIDENCE_CONTAINER_RESOURCE_ID = (
    f"{EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID}/blobServices/default/containers/monitoring-evidence"
)
EVIDENCE_BLOB_SERVICE_RESOURCE_ID = f"{EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID}/blobServices/default"
EVIDENCE_IMMUTABILITY_POLICY_RESOURCE_ID = (
    f"{EVIDENCE_CONTAINER_RESOURCE_ID}/immutabilityPolicies/default"
)
PREVIOUS_EVIDENCE_WRITER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe"
)
_ARM_TEMPLATE_GUID_NAMESPACE = UUID("11fb06fb-712d-4ddd-98c7-e71bbd588830")
EVIDENCE_WRITER_ROLE_DEFINITION_GUID = str(
    uuid5(
        _ARM_TEMPLATE_GUID_NAMESPACE,
        "-".join(
            (
                f"/subscriptions/{SUBSCRIPTION_ID}",
                "athena-wc028-monitoring-evidence-create-only",
                EVIDENCE_CONTAINER_RESOURCE_ID.casefold(),
            )
        ),
    )
)
EVIDENCE_WRITER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    f"roleDefinitions/{EVIDENCE_WRITER_ROLE_DEFINITION_GUID}"
)
EVIDENCE_WRITER_ROLE_NAME = "Athena WC028 Monitoring Evidence Create-Only Writer"
EVIDENCE_WRITER_DATA_ACTIONS = (
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action",
)
EVIDENCE_WRITER_ASSIGNMENT_CONDITION = (
    "(((!(ActionMatches"
    "{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'}"
    " AND NOT SubOperationMatches{'Blob.List'}))"
    " AND !(ActionMatches"
    "{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action'}))"
    " OR (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name]"
    " StringEquals 'monitoring-evidence' AND ("
    "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path]"
    " StringLike 'wc024-monitoring/commits/*/manifest.json' OR "
    "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path]"
    " StringLike 'wc024-monitoring/commits/*/recovery.json' OR "
    "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path]"
    " StringLike 'wc024-monitoring/wc024-*/evidence.json')))"
    " AND (!(ActionMatches"
    "{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'}"
    " AND SubOperationMatches{'Blob.List'})))"
)
STORAGE_READBACK_OPERATIONS = (
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/blobServices/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/read",
)
STORAGE_READBACK_ROLE_NAME = "Athena WC028 Monitoring Storage Protection Reader"
LEGACY_COLLECTOR_RBAC_CLEANUP_DIGEST = "sha256:" + ("9" * 64)
SIGNING_KEY_ARM_RESOURCE_ID = (
    f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.KeyVault/vaults/"
    "athenademomonkv/keys/monitoring-evidence-signing"
)
SIGNING_KEY_VAULT_RESOURCE_ID = SIGNING_KEY_ARM_RESOURCE_ID.rsplit(
    "/keys/",
    maxsplit=1,
)[0]
SIGNING_KEY_CRYPTO_USER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/12338af0-0e69-4776-bea7-57ae8d297424"
)
COLLECTOR_TENANT_ID = "00000000-0000-0000-0000-000000000003"
RBAC_ATTESTOR_ID = (
    f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.ManagedIdentity/"
    "userAssignedIdentities/athena-demo-monitoring-monitoring-rbac-attestor-id"
)
RBAC_ATTESTOR_CLIENT_ID = "44444444-4444-4444-4444-444444444444"
RBAC_ATTESTOR_PRINCIPAL_ID = "55555555-5555-5555-5555-555555555555"
RBAC_ATTESTOR_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    "roleDefinitions/2a8d9aea-2688-5841-a7e4-82f23d0f1bac"
)
RBAC_ATTESTOR_ROLE_NAME = "Athena WC-028 Effective RBAC Attestor"
RBAC_ATTESTOR_OPERATIONS = (
    "Microsoft.Authorization/denyAssignments/read",
    "Microsoft.Authorization/roleAssignmentScheduleInstances/read",
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/roleDefinitions/read",
    "Microsoft.App/jobs/read",
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.Management/getEntities/action",
    "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read",
    "Microsoft.ManagedIdentity/userAssignedIdentities/listAssociatedResources/action",
    "Microsoft.ManagedIdentity/userAssignedIdentities/read",
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Storage/storageAccounts/blobServices/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/read",
)
PREVIOUS_RBAC_ATTESTOR_OPERATIONS = RBAC_ATTESTOR_OPERATIONS[:4]
IDENTITY_PROOF_APPLICATION_ID = "66666666-6666-6666-6666-666666666661"
IDENTITY_PROOF_APPLICATION_OBJECT_ID = "66666666-6666-6666-6666-666666666662"
IDENTITY_PROOF_SERVICE_PRINCIPAL_ID = "66666666-6666-6666-6666-666666666663"
IDENTITY_PROOF_APP_ROLE_ID = "66666666-6666-6666-6666-666666666664"
IDENTITY_PROOF_APP_ROLE_ASSIGNMENT_ID = "66666666-6666-6666-6666-666666666665"
COLLECTOR_RUNTIME_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-wc013-live/"
    "providers/Microsoft.App/jobs/athena-wc028-monitoring-acquisition"
)
RUNTIME_SUPPORT_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-wc013-live/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
    "athena-wc028-monitoring-acquisition-support-id"
)
RUNTIME_SUPPORT_PRINCIPAL_ID = "66666666-6666-6666-6666-666666666670"
STORAGE_READBACK_ROLE_DEFINITION_GUID = str(
    uuid5(
        _ARM_TEMPLATE_GUID_NAMESPACE,
        "-".join(
            (
                f"/subscriptions/{SUBSCRIPTION_ID}",
                "athena-wc028-monitoring-storage-readback",
                EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID.casefold(),
            )
        ),
    )
)
STORAGE_READBACK_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    f"roleDefinitions/{STORAGE_READBACK_ROLE_DEFINITION_GUID}"
)
STORAGE_READBACK_ROLE_ASSIGNMENT_GUID = str(
    uuid5(
        _ARM_TEMPLATE_GUID_NAMESPACE,
        "-".join(
            (
                EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID.casefold(),
                RUNTIME_SUPPORT_ID.casefold(),
                STORAGE_READBACK_ROLE_DEFINITION_ID.casefold(),
            )
        ),
    )
)
STORAGE_READBACK_ROLE_ASSIGNMENT_ID = (
    f"{EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID}/providers/Microsoft.Authorization/"
    f"roleAssignments/{STORAGE_READBACK_ROLE_ASSIGNMENT_GUID}"
)
STORAGE_READINESS_PREIMAGE = "|".join(
    (
        "athena.wc028MonitoringEvidenceStorageReadiness.v1",
        EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID.casefold(),
        EVIDENCE_BLOB_SERVICE_RESOURCE_ID.casefold(),
        EVIDENCE_CONTAINER_RESOURCE_ID.casefold(),
        EVIDENCE_IMMUTABILITY_POLICY_RESOURCE_ID.casefold(),
        "true",
        "None",
        "Unlocked",
        "30",
        "false",
        "false",
    )
)
STORAGE_READBACK_BINDING_ID = str(uuid5(_ARM_TEMPLATE_GUID_NAMESPACE, STORAGE_READINESS_PREIMAGE))
STORAGE_READINESS_DIGEST = (
    "sha256:" + hashlib.sha256(STORAGE_READINESS_PREIMAGE.encode("utf-8")).hexdigest()
)
RBAC_ATTESTOR_RUNTIME_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-demo-monitoring/"
    "providers/Microsoft.App/jobs/athena-wc028-rbac-attestor"
)
RBAC_INVENTORY_BOOTSTRAP_HANDOFF_ID = "88888888-8888-8888-8888-888888888888"
RBAC_INVENTORY_BOOTSTRAP_DEPLOYMENT_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Resources/"
    "deployments/wc024-monitoring-foundation-synthetic"
)
RBAC_INVENTORY_BOOTSTRAP_TEMPLATE_HASH = "synthetic-template-hash-123456789"
RBAC_INVENTORY_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID = "99999999-9999-9999-9999-999999999999"
RBAC_INVENTORY_VERIFIER_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-rbac-review/"
    "providers/Microsoft.ManagedIdentity/userAssignedIdentities/"
    "athena-wc028-rbac-review-verifier"
)
RBAC_INVENTORY_VERIFIER_CLIENT_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
RBAC_INVENTORY_VERIFIER_PRINCIPAL_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-rbac-review/"
    "providers/Microsoft.KeyVault/vaults/athenarbacevidencekv/keys/"
    "monitoring-rbac-inventory-review"
)
RBAC_INVENTORY_REVIEWER_KEY_VAULT_RESOURCE_ID = RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID.rsplit(
    "/keys/", maxsplit=1
)[0]
RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_GUID = str(
    uuid5(
        _ARM_TEMPLATE_GUID_NAMESPACE,
        "-".join(
            (
                f"/subscriptions/{SUBSCRIPTION_ID}",
                "athena-wc028-rbac-reviewer-key-reader",
                RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID.casefold(),
            )
        ),
    )
)
RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/providers/Microsoft.Authorization/"
    f"roleDefinitions/{RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_GUID}"
)
RBAC_INVENTORY_VERIFIER_ROLE_NAME = "Athena WC028 RBAC Reviewer Public Key Reader"
RBAC_INVENTORY_VERIFIER_DATA_ACTIONS = ("Microsoft.KeyVault/vaults/keys/read",)
RBAC_INVENTORY_VERIFIER_ROLE_ASSIGNMENT_GUID = str(
    uuid5(
        _ARM_TEMPLATE_GUID_NAMESPACE,
        "-".join(
            (
                RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID.casefold(),
                RBAC_INVENTORY_VERIFIER_ID.casefold(),
                RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_ID.casefold(),
            )
        ),
    )
)
RBAC_INVENTORY_VERIFIER_ROLE_ASSIGNMENT_ID = (
    f"{RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID}/providers/"
    "Microsoft.Authorization/roleAssignments/"
    f"{RBAC_INVENTORY_VERIFIER_ROLE_ASSIGNMENT_GUID}"
)
RBAC_INVENTORY_REVIEWER_PRINCIPAL_ID = "77777777-7777-7777-7777-777777777777"
RBAC_INVENTORY_REVIEWER_KEY_ID = (
    "https://athenarbacevidencekv.vault.azure.net/keys/"
    "monitoring-rbac-inventory-review/0123456789abcdef0123456789abcdef"
)
_RBAC_INVENTORY_REVIEWER_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items() if item is not None}
    return value


def _base64url_integer(value: int) -> str:
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def _rbac_inventory_reviewer_public_material(
    private_key: rsa.RSAPrivateKey = _RBAC_INVENTORY_REVIEWER_PRIVATE_KEY,
) -> tuple[str, str, str]:
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    fingerprint = sha256_hex(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return (
        _base64url_integer(numbers.n),
        _base64url_integer(numbers.e),
        fingerprint,
    )


def _managed_identity_attachment_evidence(
    *,
    identity_resource_id: str,
    associated_resource_id: str,
    associated_identity_resource_ids: tuple[str, ...],
    associated_identity_lifecycles: tuple[tuple[str, str], ...],
) -> dict[str, object]:
    normalized_identity_resource_id = identity_resource_id.casefold().rstrip("/")
    associated_page = compute_artifact_digest(
        {
            "identityResourceId": normalized_identity_resource_id,
            "associatedResourceIds": [associated_resource_id.casefold()],
        }
    )
    federated_page = compute_artifact_digest(
        {
            "identityResourceId": normalized_identity_resource_id,
            "federatedIdentityCredentialIds": [],
        }
    )
    normalized_associated_resource_id = associated_resource_id.casefold()
    normalized_associated_identity_resource_ids = tuple(
        sorted(item.casefold() for item in associated_identity_resource_ids)
    )
    normalized_lifecycles = tuple(
        {
            "identityResourceId": identity_id.casefold(),
            "lifecycle": lifecycle,
        }
        for identity_id, lifecycle in sorted(
            associated_identity_lifecycles,
            key=lambda item: item[0].casefold(),
        )
    )
    associated_resource_configuration_digest = compute_artifact_digest(
        {
            "resourceId": normalized_associated_resource_id,
            "identityResourceIds": list(normalized_associated_identity_resource_ids),
            "identityLifecycles": list(normalized_lifecycles),
        }
    )
    payload: dict[str, object] = {
        "identityResourceId": normalized_identity_resource_id,
        "associatedResourcesRequestPath": (
            f"{normalized_identity_resource_id}/listAssociatedResources"
            "?api-version=2021-09-30-preview"
        ),
        "federatedIdentityCredentialsRequestPath": (
            f"{normalized_identity_resource_id}/federatedIdentityCredentials?api-version=2023-01-31"
        ),
        "associatedResourceIds": (associated_resource_id.casefold(),),
        "federatedIdentityCredentialIds": (),
        "associatedResourceConfigurationRequestPaths": (
            f"{normalized_associated_resource_id}?api-version=2025-01-01",
        ),
        "associatedResourceIdentityResourceIds": (normalized_associated_identity_resource_ids),
        "associatedResourceIdentityLifecycles": normalized_lifecycles,
        "firstReadCompletedAt": datetime(2026, 9, 10, 1, 52, tzinfo=UTC),
        "secondReadCompletedAt": datetime(2026, 9, 10, 1, 53, tzinfo=UTC),
        "firstAssociatedResourceRawPageDigests": (associated_page,),
        "secondAssociatedResourceRawPageDigests": (associated_page,),
        "firstFederatedCredentialRawPageDigests": (federated_page,),
        "secondFederatedCredentialRawPageDigests": (federated_page,),
        "firstAssociatedResourceConfigurationDigests": (associated_resource_configuration_digest,),
        "secondAssociatedResourceConfigurationDigests": (associated_resource_configuration_digest,),
        "allPagesRetrieved": True,
    }
    return {
        **payload,
        "evidenceDigest": compute_artifact_digest(_json_value(payload)),
    }


def _unattached_managed_identity_evidence(
    identity_resource_id: str,
) -> dict[str, object]:
    normalized_identity_resource_id = identity_resource_id.casefold().rstrip("/")
    associated_page = compute_artifact_digest(
        {
            "identityResourceId": normalized_identity_resource_id,
            "associatedResourceIds": [],
        }
    )
    federated_page = compute_artifact_digest(
        {
            "identityResourceId": normalized_identity_resource_id,
            "federatedIdentityCredentialIds": [],
        }
    )
    payload: dict[str, object] = {
        "identityResourceId": normalized_identity_resource_id,
        "associatedResourcesRequestPath": (
            f"{normalized_identity_resource_id}/listAssociatedResources"
            "?api-version=2021-09-30-preview"
        ),
        "federatedIdentityCredentialsRequestPath": (
            f"{normalized_identity_resource_id}/federatedIdentityCredentials?api-version=2023-01-31"
        ),
        "associatedResourceIds": (),
        "federatedIdentityCredentialIds": (),
        "firstReadCompletedAt": datetime(2026, 9, 10, 1, 52, tzinfo=UTC),
        "secondReadCompletedAt": datetime(2026, 9, 10, 1, 53, tzinfo=UTC),
        "firstAssociatedResourceRawPageDigests": (associated_page,),
        "secondAssociatedResourceRawPageDigests": (associated_page,),
        "firstFederatedCredentialRawPageDigests": (federated_page,),
        "secondFederatedCredentialRawPageDigests": (federated_page,),
        "allPagesRetrieved": True,
    }
    return {
        **payload,
        "evidenceDigest": compute_artifact_digest(_json_value(payload)),
    }


def _reviewer_key_verifier_evidence() -> dict[str, object]:
    grant = _effective_rbac_grant(
        principal_id=RBAC_INVENTORY_VERIFIER_PRINCIPAL_ID,
        role_definition_id=RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_ID,
        role_definition_name=RBAC_INVENTORY_VERIFIER_ROLE_NAME,
        assignment_scope_ids=(RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID,),
    )
    principal_evidence = _effective_rbac_principal_evidence(
        principal_id=RBAC_INVENTORY_VERIFIER_PRINCIPAL_ID,
        target_scope_ids=(f"/subscriptions/{SUBSCRIPTION_ID}",),
        include_inherited=True,
    )
    attachment_evidence = _unattached_managed_identity_evidence(RBAC_INVENTORY_VERIFIER_ID)
    payload: dict[str, object] = {
        "identityResourceId": RBAC_INVENTORY_VERIFIER_ID.casefold(),
        "identityClientId": RBAC_INVENTORY_VERIFIER_CLIENT_ID,
        "identityPrincipalId": RBAC_INVENTORY_VERIFIER_PRINCIPAL_ID,
        "identityTenantId": COLLECTOR_TENANT_ID,
        "reviewerKeyArmResourceId": (RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID.casefold()),
        "roleDefinitionId": RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_ID.casefold(),
        "roleDefinitionName": RBAC_INVENTORY_VERIFIER_ROLE_NAME,
        "roleAssignmentId": RBAC_INVENTORY_VERIFIER_ROLE_ASSIGNMENT_ID.casefold(),
        "allowedDataActions": RBAC_INVENTORY_VERIFIER_DATA_ACTIONS,
        "assignmentCount": 1,
        "grant": grant,
        "principalEvidence": principal_evidence,
        "attachmentEvidence": attachment_evidence,
    }
    return {
        **payload,
        "evidenceDigest": compute_artifact_digest(_json_value(payload)),
    }


def _exclusive_data_plane_principal_evidence(
    *,
    collector_principal_id: str,
    scope_ids: tuple[str, ...],
) -> dict[str, object]:
    normalized_scopes = tuple(sorted(item.casefold() for item in scope_ids))
    assignment_collection_scope_id = f"/subscriptions/{SUBSCRIPTION_ID}"
    target_digests = (
        compute_artifact_digest(
            {
                "assignmentCollectionScopeId": assignment_collection_scope_id,
                "queryFilter": "none",
                "scopeIds": list(normalized_scopes),
            }
        ),
    )
    raw_page = compute_artifact_digest(
        {
            "assignmentCollectionScopeId": assignment_collection_scope_id,
            "page": "allSubscriptionRoleAssignments",
        }
    )
    storage_configuration_digest = compute_artifact_digest(
        {
            "allowSharedKeyAccess": False,
            "defaultToOAuthAuthentication": True,
        }
    )
    blob_service_configuration_digest = compute_artifact_digest(
        {
            "isVersioningEnabled": True,
        }
    )
    container_configuration_digest = compute_artifact_digest(
        {
            "hasImmutabilityPolicy": True,
        }
    )
    immutability_policy_configuration_digest = compute_artifact_digest(
        {
            "state": "Unlocked",
            "immutabilityPeriodSinceCreationInDays": 30,
            "allowProtectedAppendWrites": False,
            "allowProtectedAppendWritesAll": False,
        }
    )
    key_vault_configuration_digest = compute_artifact_digest(
        {
            "enableRbacAuthorization": True,
            "accessPolicyPrincipalIds": [],
        }
    )
    payload: dict[str, object] = {
        "assignmentCollectionScopeId": assignment_collection_scope_id,
        "scopeIds": normalized_scopes,
        "queryFilter": "none",
        "includeInherited": True,
        "includeAllDescendantScopes": True,
        "evidenceWriterAuthorizedPrincipalIds": (collector_principal_id.casefold(),),
        "signingKeyAuthorizedPrincipalIds": (collector_principal_id.casefold(),),
        "evidenceStorageSharedKeyAccessEnabled": False,
        "evidenceStorageDefaultToOAuthAuthentication": True,
        "evidenceBlobVersioningEnabled": True,
        "evidenceContainerPublicAccess": "None",
        "evidenceContainerHasImmutabilityPolicy": True,
        "evidenceContainerImmutabilityPolicyState": "Unlocked",
        "evidenceContainerImmutabilityPeriodDays": 30,
        "evidenceContainerProtectedAppendWritesEnabled": False,
        "evidenceContainerProtectedAppendWritesAllEnabled": False,
        "signingKeyVaultRbacAuthorizationEnabled": True,
        "signingKeyVaultAccessPolicyPrincipalIds": (),
        "firstReadCompletedAt": datetime(2026, 9, 10, 1, 52, tzinfo=UTC),
        "secondReadCompletedAt": datetime(2026, 9, 10, 1, 53, tzinfo=UTC),
        "firstReadTargetDigests": target_digests,
        "secondReadTargetDigests": target_digests,
        "firstRawPageDigests": (raw_page,),
        "secondRawPageDigests": (raw_page,),
        "firstResourceConfigurationDigests": tuple(
            sorted(
                (
                    blob_service_configuration_digest,
                    container_configuration_digest,
                    immutability_policy_configuration_digest,
                    key_vault_configuration_digest,
                    storage_configuration_digest,
                )
            )
        ),
        "secondResourceConfigurationDigests": tuple(
            sorted(
                (
                    blob_service_configuration_digest,
                    container_configuration_digest,
                    immutability_policy_configuration_digest,
                    key_vault_configuration_digest,
                    storage_configuration_digest,
                )
            )
        ),
        "allPagesRetrieved": True,
    }
    return {
        **payload,
        "evidenceDigest": compute_artifact_digest(_json_value(payload)),
    }


def _effective_rbac_inventory_attestation(
    inventory: MonitoringEffectiveRbacInventory,
    *,
    private_key: rsa.RSAPrivateKey = _RBAC_INVENTORY_REVIEWER_PRIVATE_KEY,
    reviewer_principal_id: str = RBAC_INVENTORY_REVIEWER_PRINCIPAL_ID,
    reviewer_key_id: str = RBAC_INVENTORY_REVIEWER_KEY_ID,
    schema_version: str | None = None,
) -> MonitoringEffectiveRbacInventoryAttestation:
    modulus, exponent, fingerprint = _rbac_inventory_reviewer_public_material(private_key)
    attestation_schema_version = schema_version or (
        "athena.wc028MonitoringEffectiveRbacInventoryAttestation.v2"
        if inventory.schema_version == MONITORING_EFFECTIVE_RBAC_INVENTORY_SCHEMA_VERSION
        else "athena.wc028MonitoringEffectiveRbacInventoryAttestation.v1"
    )
    preimage = monitoring_effective_rbac_inventory_attestation_preimage(
        schema_version=attestation_schema_version,
        bootstrap_handoff_id=RBAC_INVENTORY_BOOTSTRAP_HANDOFF_ID,
        bootstrap_deployment_id=RBAC_INVENTORY_BOOTSTRAP_DEPLOYMENT_ID.casefold(),
        bootstrap_template_hash=RBAC_INVENTORY_BOOTSTRAP_TEMPLATE_HASH,
        bootstrap_contract_inputs_binding_id=(RBAC_INVENTORY_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID),
        reviewer_principal_id=reviewer_principal_id,
        reviewer_key_id=reviewer_key_id,
        public_key_fingerprint=fingerprint,
        inventory_digest=inventory.inventory_digest,
        source_manifest_digest=inventory.source_manifest_digest,
        legacy_collector_rbac_cleanup_schema_version=("athena.wc028LegacyCollectorRbacCleanup.v3"),
        legacy_collector_rbac_cleanup_digest=LEGACY_COLLECTOR_RBAC_CLEANUP_DIGEST,
    )
    signature = base64.b64encode(
        private_key.sign(
            canonicalize_json(preimage).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    ).decode("ascii")
    return MonitoringEffectiveRbacInventoryAttestation(
        schemaVersion=attestation_schema_version,
        signatureAlgorithm="RS256",
        bootstrapHandoffId=RBAC_INVENTORY_BOOTSTRAP_HANDOFF_ID,
        bootstrapDeploymentId=RBAC_INVENTORY_BOOTSTRAP_DEPLOYMENT_ID,
        bootstrapTemplateHash=RBAC_INVENTORY_BOOTSTRAP_TEMPLATE_HASH,
        bootstrapContractInputsBindingId=(RBAC_INVENTORY_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID),
        reviewerPrincipalId=reviewer_principal_id,
        reviewerKeyId=reviewer_key_id,
        publicKeyModulus=modulus,
        publicKeyExponent=exponent,
        publicKeyFingerprint=fingerprint,
        inventoryDigest=inventory.inventory_digest,
        sourceManifestDigest=inventory.source_manifest_digest,
        legacyCollectorRbacCleanupSchemaVersion=("athena.wc028LegacyCollectorRbacCleanup.v3"),
        legacyCollectorRbacCleanupDigest=LEGACY_COLLECTOR_RBAC_CLEANUP_DIGEST,
        signedPreimageDigest=compute_artifact_digest(preimage),
        signature=signature,
    )


REVIEWED_LOG_TABLES = (
    "Heartbeat",
    "Perf",
    "InsightsMetrics",
    "Syslog",
    "VMComputer",
    "VMConnection",
    "VMBoundPort",
    "VMProcess",
    "NTANetAnalytics",
    "NWConnectionMonitorDestinationListenerResult",
    "NWConnectionMonitorDNSResult",
    "NWConnectionMonitorPathResult",
    "NWConnectionMonitorTestResult",
)
LOG_ANALYTICS_ACCESS_CONDITION = (
    "((!(ActionMatches"
    "{'Microsoft.OperationalInsights/workspaces/tables/data/read'}"
    ")) OR ("
    + " OR ".join(
        "@Resource[Microsoft.OperationalInsights/workspaces/tables:name] "
        f"StringEquals '{table_name}'"
        for table_name in REVIEWED_LOG_TABLES
    )
    + "))"
)
SIGNAL_READ_SCOPE_IDS = tuple(
    f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Compute/virtualMachines/{vm_name}"
    for vm_name in REVIEWED_VM_NAMES
)
UNAPPROVED_PEER_VM_ID = (
    f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Compute/"
    "virtualMachines/athena-hackathon-peer-01"
)
RESOURCE_READ_SCOPE_IDS = (
    (
        f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.Insights/"
        "dataCollectionEndpoints/athena-hackathon-linux-dce"
    ),
    (
        f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.Insights/"
        "dataCollectionRules/athena-hackathon-linux-dcr"
    ),
    (
        f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.Insights/"
        "privateLinkScopes/athena-demo-monitoring-workload-ampls"
    ),
    (
        f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/Microsoft.Insights/"
        "privateLinkScopes/athena-demo-monitoring-collector-ampls"
    ),
    *(
        (
            f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Compute/"
            f"virtualMachines/{vm_name}/providers/Microsoft.Insights/"
            "dataCollectionRuleAssociations/athena-linux-dcr"
        )
        for vm_name in REVIEWED_VM_NAMES
    ),
    *(
        (
            f"{WORKLOAD_RESOURCE_GROUP_ROOT}/providers/Microsoft.Compute/"
            f"virtualMachines/{vm_name}/providers/Microsoft.Insights/"
            "dataCollectionRuleAssociations/configurationAccessEndpoint"
        )
        for vm_name in REVIEWED_VM_NAMES
    ),
    (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/NetworkWatcherRG/"
        "providers/Microsoft.Network/networkWatchers/NetworkWatcher_australiaeast/"
        "flowLogs/athena-hackathon-vnet-rg-athena-demo-workload-flowlog"
    ),
)


def test_bicep_and_python_share_one_canonical_vm_allowlist() -> None:
    source = MONITORING_FOUNDATION_MAIN.read_text(encoding="utf-8")
    block = source.split(
        "var reviewedApprovedVmNames = [",
        maxsplit=1,
    )[1].split("]", maxsplit=1)[0]
    bicep_names = tuple(line.strip().strip("'") for line in block.splitlines() if line.strip())

    assert bicep_names == REVIEWED_VM_NAMES


def test_acquisition_contract_resolves_and_separates_actual_context_uami() -> None:
    source = MONITORING_FOUNDATION_MAIN.read_text(encoding="utf-8")

    assert "param athenaContextIdentityResourceId string" in source
    assert (
        "resource athenaContextIdentity "
        "'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing"
    ) in source
    assert "collectorIdentityResourceId) != toLower(athenaContextIdentity.id)" in source
    assert (
        "collectorIdentityPrincipalId) != toLower(athenaContextIdentity.properties.principalId)"
    ) in source
    assert "physicalIdentitySeparationEnforced: acquisitionIdentitySeparation" in source
    assert "collectorTenantId: monitoringEvidenceSeams.outputs.collectorIdentityTenantId" in source
    assert "module monitoringRbacAttestor" in source
    assert (
        "rbacAttestorPrincipalId: monitoringEvidenceSeams.outputs.rbacAttestorIdentityPrincipalId"
    ) in source
    assert "flowTableAcquisitionMode: 'unsupportedUnavailable'" in (
        Path(__file__).parents[1]
        / "infra"
        / "wc024-monitoring-foundation"
        / "modules"
        / "monitoring-collector-contract.bicep"
    ).read_text(encoding="utf-8")
    assert "? reviewedApprovedVmNames" in source


def test_workload_vnet_id_is_canonicalized_before_digesting() -> None:
    canonical = _collector_contract()
    uppercase_payload = canonical.model_dump(
        mode="json",
        by_alias=True,
    )
    uppercase_payload["workloadVirtualNetworkResourceId"] = (
        canonical.workload_virtual_network_resource_id.upper()
    )

    normalized = MonitoringCollectorContract.model_validate_json(json.dumps(uppercase_payload))

    assert normalized.workload_virtual_network_resource_id == (
        canonical.workload_virtual_network_resource_id
    )
    assert normalized.compute_artifact_digest_value() == (canonical.compute_artifact_digest_value())


def _collector_contract() -> MonitoringCollectorContract:
    return MonitoringCollectorContract(
        schemaVersion=MONITORING_COLLECTOR_CONTRACT_SCHEMA_VERSION,
        collectorIdentityResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-monitoring/providers/Microsoft.ManagedIdentity/"
            "userAssignedIdentities/athena-demo-monitoring-monitoring-collector-id"
        ),
        collectorIdentityClientId="00000000-0000-0000-0000-000000000001",
        monitoringResourceGroupId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-athena-demo-monitoring"
        ),
        workloadResourceGroupId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/"
            "resourceGroups/rg-athena-demo-workload"
        ),
        workloadVirtualNetworkResourceId=REVIEWED_WORKLOAD_VNET_ID,
        approvedVmNames=REVIEWED_VM_NAMES,
        workspaceResourceId=WORKSPACE_ID,
        dataCollectionRuleResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-monitoring/providers/Microsoft.Insights/dataCollectionRules/"
            "athena-hackathon-linux-dcr"
        ),
        dataCollectionEndpointResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-monitoring/providers/Microsoft.Insights/"
            "dataCollectionEndpoints/athena-hackathon-linux-dce"
        ),
        authorizationMode="conditionedWorkspacePlusExactResourceContext",
        workspaceAccessControlMode="workspaceAndResourceContext",
        readerRoleDefinitionId=READER_ROLE_DEFINITION_ID,
        signalReaderRoleDefinitionId=SIGNAL_READER_ROLE_DEFINITION_ID,
        logAnalyticsDataReaderRoleDefinitionId=(LOG_ANALYTICS_DATA_READER_ROLE_DEFINITION_ID),
        logAnalyticsAllowedTables=REVIEWED_LOG_TABLES,
        logAnalyticsAccessCondition=LOG_ANALYTICS_ACCESS_CONDITION,
        resourceReadScopeIds=RESOURCE_READ_SCOPE_IDS,
        signalReadScopeIds=SIGNAL_READ_SCOPE_IDS,
        signingKeyResourceId=REVIEWED_SIGNING_KEY_URI,
        evidenceStorageAccountResourceId=(
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-monitoring/providers/Microsoft.Storage/storageAccounts/"
            "athenademomonstore"
        ),
        evidenceContainerName="monitoring-evidence",
        signalKinds=(
            "heartbeat",
            "perf",
            "insightsMetrics",
            "syslog",
            "disk",
            "guest",
            "vnetFlow",
            "trafficAnalytics",
        ),
        allowedReadOperations=(
            "Microsoft.OperationalInsights/workspaces/read",
            "Microsoft.OperationalInsights/workspaces/query/read",
            "Microsoft.OperationalInsights/workspaces/tables/data/read",
            "Microsoft.Compute/virtualMachines/instanceView/read",
            "Microsoft.Insights/Metrics/Read",
            "Microsoft.Insights/dataCollectionRules/read",
            "Microsoft.Insights/dataCollectionEndpoints/read",
            "Microsoft.Insights/dataCollectionRuleAssociations/read",
            "Microsoft.Insights/privateLinkScopes/read",
            "Microsoft.Network/networkWatchers/flowLogs/read",
        ),
        collectionMode="isolatedSignedCollector",
        handoffSchemaVersion=MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
        maximumEvidenceAgeSeconds=600,
        connectionMonitorMode="capabilityOnly",
        connectionMonitorDeploymentMode="capability-only",
    )


def _effective_rbac_grant(
    *,
    principal_id: str,
    role_definition_id: str,
    role_definition_name: str,
    assignment_scope_ids: tuple[str, ...],
    condition: str | None = None,
    condition_version: str | None = None,
    assigned_principal_id: str | None = None,
    assigned_principal_type: str = "ServicePrincipal",
    inheritance: str = "direct",
    group_derived: bool = False,
) -> dict[str, object]:
    assigned_principal_id = principal_id if assigned_principal_id is None else assigned_principal_id
    payload: dict[str, object] = {
        "assignedPrincipalId": assigned_principal_id,
        "assignedPrincipalType": assigned_principal_type,
        "effectivePrincipalId": principal_id,
        "roleDefinitionId": role_definition_id.casefold(),
        "roleDefinitionName": role_definition_name,
        "assignmentScopeIds": tuple(sorted(item.casefold() for item in assignment_scope_ids)),
        "inheritance": inheritance,
        "groupDerived": group_derived,
    }
    if condition is not None:
        payload["condition"] = condition
        payload["conditionVersion"] = condition_version
    return {
        **payload,
        "grantDigest": compute_artifact_digest(_json_value(payload)),
    }


def _effective_rbac_role_definition(
    *,
    role_definition_id: str,
    role_definition_name: str,
    actions: tuple[str, ...] = (),
    not_actions: tuple[str, ...] = (),
    data_actions: tuple[str, ...] = (),
    not_data_actions: tuple[str, ...] = (),
) -> dict[str, object]:
    normalized_payload: dict[str, object] = {
        "roleDefinitionId": role_definition_id.casefold(),
        "roleDefinitionName": role_definition_name,
        "actions": tuple(sorted(item.casefold() for item in actions)),
        "notActions": tuple(sorted(item.casefold() for item in not_actions)),
        "dataActions": tuple(sorted(item.casefold() for item in data_actions)),
        "notDataActions": tuple(sorted(item.casefold() for item in not_data_actions)),
    }
    payload = {
        **normalized_payload,
        "rawDefinitionDigest": compute_artifact_digest(
            {"rawRoleDefinition": _json_value(normalized_payload)}
        ),
    }
    return {
        **payload,
        "definitionDigest": compute_artifact_digest(_json_value(payload)),
    }


def _effective_rbac_principal_evidence(
    *,
    principal_id: str,
    target_scope_ids: tuple[str, ...],
    transitive_group_ids: tuple[str, ...] = (),
    query_filter: str = "assignedTo(principalId)",
    include_inherited: bool = False,
    target_bound: bool = True,
) -> dict[str, object]:
    targets = tuple(sorted(item.casefold() for item in target_scope_ids))
    target_reads: tuple[dict[str, object], ...] = ()
    target_digests: tuple[str, ...] = ()
    first_role_assignment_pages: tuple[str, ...] = ()
    second_role_assignment_pages: tuple[str, ...] = ()
    if target_bound:
        target_read_items = []
        for target in targets:
            raw_page_digest = compute_artifact_digest(
                {
                    "principalId": principal_id.casefold(),
                    "targetScopeId": target,
                    "page": "roleAssignments",
                }
            )
            target_digest = compute_artifact_digest(
                {
                    "principalId": principal_id.casefold(),
                    "targetScopeId": target,
                    "queryMode": CURRENT_RBAC_TARGET_QUERY_MODE,
                    "rawPageDigests": [raw_page_digest],
                }
            )
            target_read_items.append(
                {
                    "targetScopeId": target,
                    "queryMode": CURRENT_RBAC_TARGET_QUERY_MODE,
                    "targetDigest": target_digest,
                    "rawPageDigests": (raw_page_digest,),
                    "readCount": 2,
                    "allPagesRetrieved": True,
                    "bindingId": str(
                        uuid5(
                            _ARM_TEMPLATE_GUID_NAMESPACE,
                            "-".join(
                                (
                                    principal_id.casefold(),
                                    target,
                                    CURRENT_RBAC_TARGET_QUERY_MODE,
                                    target_digest,
                                    raw_page_digest,
                                    "2",
                                    "true",
                                )
                            ),
                        )
                    ),
                }
            )
        target_reads = tuple(target_read_items)
    else:
        target_digests = tuple(
            compute_artifact_digest(
                {
                    "principalId": principal_id.casefold(),
                    "targetScopeId": target,
                    "queryFilter": query_filter,
                }
            )
            for target in targets
        )
        first_role_assignment_pages = (
            compute_artifact_digest(
                {
                    "principalId": principal_id.casefold(),
                    "page": "roleAssignments",
                }
            ),
        )
        second_role_assignment_pages = first_role_assignment_pages
    first_transitive_group_pages = (
        compute_artifact_digest(
            {
                "principalId": principal_id.casefold(),
                "page": "transitiveGroups",
            }
        ),
    )
    second_transitive_group_pages = (
        compute_artifact_digest(
            {
                "principalId": principal_id.casefold(),
                "page": "transitiveGroups",
            }
        ),
    )
    payload: dict[str, object] = {
        "principalId": principal_id.casefold(),
        "transitiveGroupIds": tuple(sorted(item.casefold() for item in transitive_group_ids)),
        "firstTransitiveGroupRawPageDigests": first_transitive_group_pages,
        "secondTransitiveGroupRawPageDigests": second_transitive_group_pages,
        "allPagesRetrieved": True,
    }
    if target_bound:
        payload["targetReadEvidence"] = target_reads
    else:
        payload.update(
            {
                "queryFilter": query_filter,
                "targetScopeIds": targets,
                "firstReadTargetDigests": target_digests,
                "secondReadTargetDigests": target_digests,
                "firstRoleAssignmentRawPageDigests": first_role_assignment_pages,
                "secondRoleAssignmentRawPageDigests": second_role_assignment_pages,
            }
        )
        if include_inherited:
            payload.update(
                {
                    "includeInherited": True,
                    "includeGroups": True,
                    "includeAllDescendantScopes": True,
                }
            )
    return {
        **payload,
        "evidenceDigest": compute_artifact_digest(_json_value(payload)),
    }


def _principal_snapshot_fields(
    prefix: str,
    evidence: dict[str, object],
    *,
    first_read: bool,
) -> dict[str, object]:
    target_reads = evidence.get("targetReadEvidence")
    payload: dict[str, object] = {
        f"{prefix}PrincipalId": evidence["principalId"],
        f"{prefix}TransitiveGroupRawPageDigests": evidence[
            "firstTransitiveGroupRawPageDigests"
            if first_read
            else "secondTransitiveGroupRawPageDigests"
        ],
    }
    if target_reads is not None:
        payload[f"{prefix}TargetReadBindingIds"] = tuple(
            item["bindingId"] for item in tuple(target_reads)
        )
        return payload
    payload[f"{prefix}TargetReadDigests"] = evidence[
        "firstReadTargetDigests" if first_read else "secondReadTargetDigests"
    ]
    payload[f"{prefix}RoleAssignmentRawPageDigests"] = evidence[
        "firstRoleAssignmentRawPageDigests"
        if first_read
        else "secondRoleAssignmentRawPageDigests"
    ]
    return payload


def _management_group_hierarchy_evidence(
    *,
    ancestry: tuple[str, ...],
) -> dict[str, object]:
    subscription_scope = f"/subscriptions/{SUBSCRIPTION_ID}"
    parent_edges = []
    for index, parent_scope in enumerate(ancestry):
        edge_payload = {
            "childScopeId": (subscription_scope if index == 0 else ancestry[index - 1]),
            "parentScopeId": parent_scope,
        }
        parent_edges.append(
            {
                **edge_payload,
                "edgeDigest": compute_artifact_digest(_json_value(edge_payload)),
            }
        )
    raw_page_digest = compute_artifact_digest(
        _json_value(
            {
                "requestPath": (
                    "/providers/Microsoft.Management/getEntities?api-version=2020-05-01"
                    "&$select=Name,Type,ParentNameChain"
                ),
                "subscriptionScopeId": subscription_scope,
                "parentEdges": tuple(parent_edges),
            }
        )
    )
    payload: dict[str, object] = {
        "requestPath": (
            "/providers/Microsoft.Management/getEntities?api-version=2020-05-01"
            "&$select=Name,Type,ParentNameChain"
        ),
        "subscriptionScopeId": subscription_scope,
        "orderedAncestry": ancestry,
        "parentEdges": tuple(parent_edges),
        "firstReadCompletedAt": datetime(2026, 9, 10, 1, 52, tzinfo=UTC),
        "secondReadCompletedAt": datetime(2026, 9, 10, 1, 53, tzinfo=UTC),
        "firstRawPageDigests": (raw_page_digest,),
        "secondRawPageDigests": (raw_page_digest,),
        "allPagesRetrieved": True,
    }
    return {
        **payload,
        "evidenceDigest": compute_artifact_digest(_json_value(payload)),
    }


def _effective_rbac_inventory(payload: dict[str, object]) -> dict[str, object]:
    principal_id = str(payload["monitoringReaderPrincipalId"])
    evidence_writer_role_definition_id = str(payload["evidenceWriterRoleDefinitionId"])
    resource_health_operations = tuple(payload["resourceHealthAllowedOperations"])
    resource_graph_query_operations = (
        resource_health_operations[:1]
        if payload.get("resourceGraphQueryRoleDefinitionId") is not None
        else ()
    )
    resource_health_role_operations = (
        resource_health_operations[1:]
        if resource_graph_query_operations
        else resource_health_operations
    )
    conditioned_evidence_writer = (
        evidence_writer_role_definition_id.casefold()
        == EVIDENCE_WRITER_ROLE_DEFINITION_ID.casefold()
    )
    grants = [
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=str(payload["readerRoleDefinitionId"]),
            role_definition_name="Reader",
            assignment_scope_ids=tuple(payload["resourceReadScopeIds"]),
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=str(payload["signalReaderRoleDefinitionId"]),
            role_definition_name=SIGNAL_READER_ROLE_NAME,
            assignment_scope_ids=tuple(payload["signalReadScopeIds"]),
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=RESOURCE_LOG_READER_ROLE_DEFINITION_ID,
            role_definition_name=RESOURCE_LOG_READER_ROLE_NAME,
            assignment_scope_ids=SIGNAL_READ_SCOPE_IDS,
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=RESOURCE_HEALTH_ROLE_DEFINITION_ID,
            role_definition_name=RESOURCE_HEALTH_ROLE_NAME,
            assignment_scope_ids=SIGNAL_READ_SCOPE_IDS,
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=evidence_writer_role_definition_id,
            role_definition_name=(
                EVIDENCE_WRITER_ROLE_NAME
                if conditioned_evidence_writer
                else "Storage Blob Data Contributor"
            ),
            assignment_scope_ids=(EVIDENCE_CONTAINER_RESOURCE_ID,),
            condition=(
                EVIDENCE_WRITER_ASSIGNMENT_CONDITION if conditioned_evidence_writer else None
            ),
            condition_version="2.0" if conditioned_evidence_writer else None,
        ),
        _effective_rbac_grant(
            principal_id=principal_id,
            role_definition_id=SIGNING_KEY_CRYPTO_USER_ROLE_DEFINITION_ID,
            role_definition_name="Key Vault Crypto User",
            assignment_scope_ids=(SIGNING_KEY_ARM_RESOURCE_ID,),
        ),
    ]
    if payload.get("resourceGraphQueryRoleDefinitionId") is not None:
        grants.append(
            _effective_rbac_grant(
                principal_id=principal_id,
                role_definition_id=str(payload["resourceGraphQueryRoleDefinitionId"]),
                role_definition_name=str(payload["resourceGraphQueryRoleName"]),
                assignment_scope_ids=(str(payload["resourceGraphQueryScopeId"]),),
            )
        )
    ordered_grants = tuple(sorted(grants, key=lambda item: str(item["grantDigest"])))
    runtime_support_grants = (
        _effective_rbac_grant(
            principal_id=RUNTIME_SUPPORT_PRINCIPAL_ID,
            role_definition_id=STORAGE_READBACK_ROLE_DEFINITION_ID,
            role_definition_name=STORAGE_READBACK_ROLE_NAME,
            assignment_scope_ids=(EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID,),
        ),
    )
    reviewer_key_verifier_evidence = _reviewer_key_verifier_evidence()
    role_definition_items = [
                _effective_rbac_role_definition(
                    role_definition_id=str(payload["readerRoleDefinitionId"]),
                    role_definition_name="Reader",
                    actions=("*/read",),
                ),
                _effective_rbac_role_definition(
                    role_definition_id=str(payload["signalReaderRoleDefinitionId"]),
                    role_definition_name=SIGNAL_READER_ROLE_NAME,
                    actions=(
                        "Microsoft.Compute/virtualMachines/instanceView/read",
                        "Microsoft.Insights/metrics/read",
                    ),
                ),
                _effective_rbac_role_definition(
                    role_definition_id=RESOURCE_LOG_READER_ROLE_DEFINITION_ID,
                    role_definition_name=RESOURCE_LOG_READER_ROLE_NAME,
                    actions=RESOURCE_LOG_OPERATIONS,
                ),
                _effective_rbac_role_definition(
                    role_definition_id=RESOURCE_HEALTH_ROLE_DEFINITION_ID,
                    role_definition_name=RESOURCE_HEALTH_ROLE_NAME,
                    actions=resource_health_role_operations,
                ),
                _effective_rbac_role_definition(
                    role_definition_id=evidence_writer_role_definition_id,
                    role_definition_name=(
                        EVIDENCE_WRITER_ROLE_NAME
                        if conditioned_evidence_writer
                        else "Storage Blob Data Contributor"
                    ),
                    data_actions=(
                        EVIDENCE_WRITER_DATA_ACTIONS
                        if conditioned_evidence_writer
                        else ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/*",)
                    ),
                ),
                _effective_rbac_role_definition(
                    role_definition_id=SIGNING_KEY_CRYPTO_USER_ROLE_DEFINITION_ID,
                    role_definition_name="Key Vault Crypto User",
                    data_actions=(
                        "Microsoft.KeyVault/vaults/keys/read",
                        "Microsoft.KeyVault/vaults/keys/sign/action",
                    ),
                ),
                _effective_rbac_role_definition(
                    role_definition_id=RBAC_ATTESTOR_ROLE_DEFINITION_ID,
                    role_definition_name=RBAC_ATTESTOR_ROLE_NAME,
                    actions=tuple(
                        payload.get(
                            "rbacAttestorAllowedOperations",
                            RBAC_ATTESTOR_OPERATIONS,
                        )
                    ),
                ),
                _effective_rbac_role_definition(
                    role_definition_id=RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_ID,
                    role_definition_name=RBAC_INVENTORY_VERIFIER_ROLE_NAME,
                    data_actions=RBAC_INVENTORY_VERIFIER_DATA_ACTIONS,
                ),
                _effective_rbac_role_definition(
                    role_definition_id=STORAGE_READBACK_ROLE_DEFINITION_ID,
                    role_definition_name=STORAGE_READBACK_ROLE_NAME,
                    actions=STORAGE_READBACK_OPERATIONS,
                ),
    ]
    if payload.get("resourceGraphQueryRoleDefinitionId") is not None:
        role_definition_items.append(
            _effective_rbac_role_definition(
                role_definition_id=str(payload["resourceGraphQueryRoleDefinitionId"]),
                role_definition_name=str(payload["resourceGraphQueryRoleName"]),
                actions=resource_graph_query_operations,
            )
        )
    role_definitions = tuple(
        sorted(
            role_definition_items,
            key=lambda item: str(item["roleDefinitionId"]),
        )
    )
    workspace_id = str(payload["workspaceResourceId"]).casefold().rstrip("/")
    evidence_storage_account_id = (
        str(payload["evidenceStorageAccountResourceId"]).casefold().rstrip("/")
    )
    signing_key_id = str(payload["signingKeyArmResourceId"]).casefold().rstrip("/")
    signing_key_vault_id = signing_key_id.rsplit("/keys/", maxsplit=1)[0]
    network_watcher_resource_group_id = (
        f"/subscriptions/{SUBSCRIPTION_ID}/resourcegroups/networkwatcherrg"
    )
    management_group_ancestry = (
        f"/providers/microsoft.management/managementgroups/{COLLECTOR_TENANT_ID}",
    )
    protected_scope_ids = tuple(
        sorted(
            {
                f"/subscriptions/{SUBSCRIPTION_ID}",
                COLLECTOR_RUNTIME_RESOURCE_ID.casefold(),
                RBAC_ATTESTOR_RUNTIME_RESOURCE_ID.casefold(),
                RUNTIME_SUPPORT_ID.casefold(),
                RBAC_INVENTORY_VERIFIER_ID.casefold(),
                RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID.casefold(),
                RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID.casefold().rsplit(
                    "/keys/",
                    maxsplit=1,
                )[0],
                RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_ID.casefold(),
                RBAC_INVENTORY_VERIFIER_ROLE_ASSIGNMENT_ID.casefold(),
                STORAGE_READBACK_ROLE_DEFINITION_ID.casefold(),
                STORAGE_READBACK_ROLE_ASSIGNMENT_ID.casefold(),
                MONITORING_RESOURCE_GROUP_ROOT.casefold(),
                WORKLOAD_RESOURCE_GROUP_ROOT.casefold(),
                REVIEWED_WORKLOAD_VNET_ID.casefold(),
                workspace_id,
                *(
                    f"{workspace_id}/tables/{table_name.casefold()}"
                    for table_name in REVIEWED_LOG_TABLES
                ),
                evidence_storage_account_id,
                f"{evidence_storage_account_id}/blobservices/default",
                EVIDENCE_CONTAINER_RESOURCE_ID.casefold(),
                EVIDENCE_IMMUTABILITY_POLICY_RESOURCE_ID.casefold(),
                signing_key_vault_id,
                signing_key_id,
                network_watcher_resource_group_id,
                NETWORK_WATCHER_RESOURCE_ID.casefold(),
                *management_group_ancestry,
                *(
                    str(scope).casefold()
                    for grant in ordered_grants
                    for scope in tuple(grant["assignmentScopeIds"])
                ),
            }
        )
    )
    collector_principal_evidence = _effective_rbac_principal_evidence(
        principal_id=principal_id,
        target_scope_ids=(
            f"/subscriptions/{SUBSCRIPTION_ID}",
            *management_group_ancestry,
        ),
        include_inherited=True,
    )
    context_principal_evidence = _effective_rbac_principal_evidence(
        principal_id=str(payload["athenaContextPrincipalId"]),
        target_scope_ids=(
            f"/subscriptions/{SUBSCRIPTION_ID}",
            *management_group_ancestry,
        ),
        include_inherited=True,
    )
    runtime_support_principal_evidence = _effective_rbac_principal_evidence(
        principal_id=RUNTIME_SUPPORT_PRINCIPAL_ID,
        target_scope_ids=(
            f"/subscriptions/{SUBSCRIPTION_ID}",
            *management_group_ancestry,
        ),
        include_inherited=True,
    )
    hierarchy_evidence = _management_group_hierarchy_evidence(
        ancestry=management_group_ancestry,
    )
    collector_attachment_evidence = _managed_identity_attachment_evidence(
        identity_resource_id=str(payload["collectorIdentityResourceId"]),
        associated_resource_id=COLLECTOR_RUNTIME_RESOURCE_ID,
        associated_identity_resource_ids=(
            str(payload["collectorIdentityResourceId"]),
            RUNTIME_SUPPORT_ID,
        ),
        associated_identity_lifecycles=(
            (str(payload["collectorIdentityResourceId"]), "All"),
            (RUNTIME_SUPPORT_ID, "None"),
        ),
    )
    attestor_attachment_evidence = _managed_identity_attachment_evidence(
        identity_resource_id=RBAC_ATTESTOR_ID,
        associated_resource_id=RBAC_ATTESTOR_RUNTIME_RESOURCE_ID,
        associated_identity_resource_ids=(RBAC_ATTESTOR_ID,),
        associated_identity_lifecycles=((RBAC_ATTESTOR_ID, "All"),),
    )
    exclusive_principal_evidence = _exclusive_data_plane_principal_evidence(
        collector_principal_id=principal_id,
        scope_ids=(
            evidence_storage_account_id,
            f"{evidence_storage_account_id}/blobservices/default",
            EVIDENCE_CONTAINER_RESOURCE_ID,
            EVIDENCE_IMMUTABILITY_POLICY_RESOURCE_ID,
            signing_key_vault_id,
            signing_key_id,
        ),
    )
    role_definition_page_digest = compute_artifact_digest(
        {"page": "roleDefinitions", "roles": _json_value(role_definitions)}
    )
    deny_page_digest = compute_artifact_digest({"page": "denyAssignments", "items": []})
    pim_page_digest = compute_artifact_digest(
        {"page": "roleAssignmentScheduleInstances", "items": []}
    )
    normalized_record_digests = {
        "roleDefinitionRawDigests": tuple(item["rawDefinitionDigest"] for item in role_definitions),
        "denyAssignmentRawDigests": (),
        "pimScheduleInstanceRawDigests": (),
        "collectorIdentityAttachmentEvidenceDigest": (
            collector_attachment_evidence["evidenceDigest"]
        ),
        "rbacAttestorIdentityAttachmentEvidenceDigest": (
            attestor_attachment_evidence["evidenceDigest"]
        ),
        "exclusiveDataPlanePrincipalEvidenceDigest": (
            exclusive_principal_evidence["evidenceDigest"]
        ),
        "reviewerKeyVerifierEvidenceDigest": (reviewer_key_verifier_evidence["evidenceDigest"]),
        "managementGroupHierarchyEvidenceDigest": hierarchy_evidence["evidenceDigest"],
        "runtimeSupportPrincipalEvidenceDigest": (
            runtime_support_principal_evidence["evidenceDigest"]
        ),
    }
    first_raw_snapshot_digest = compute_artifact_digest(
        _json_value(
            {
                **_principal_snapshot_fields(
                    "collector",
                    collector_principal_evidence,
                    first_read=True,
                ),
                **_principal_snapshot_fields(
                    "athenaContext",
                    context_principal_evidence,
                    first_read=True,
                ),
                **_principal_snapshot_fields(
                    "runtimeSupport",
                    runtime_support_principal_evidence,
                    first_read=True,
                ),
                "roleDefinitionRawPageDigests": (role_definition_page_digest,),
                "denyAssignmentRawPageDigests": (deny_page_digest,),
                "pimScheduleInstanceRawPageDigests": (pim_page_digest,),
                **normalized_record_digests,
            }
        )
    )
    second_raw_snapshot_digest = compute_artifact_digest(
        _json_value(
            {
                **_principal_snapshot_fields(
                    "collector",
                    collector_principal_evidence,
                    first_read=False,
                ),
                **_principal_snapshot_fields(
                    "athenaContext",
                    context_principal_evidence,
                    first_read=False,
                ),
                **_principal_snapshot_fields(
                    "runtimeSupport",
                    runtime_support_principal_evidence,
                    first_read=False,
                ),
                "roleDefinitionRawPageDigests": (role_definition_page_digest,),
                "denyAssignmentRawPageDigests": (deny_page_digest,),
                "pimScheduleInstanceRawPageDigests": (pim_page_digest,),
                **normalized_record_digests,
            }
        )
    )
    inventory_payload: dict[str, object] = {
        "schemaVersion": MONITORING_EFFECTIVE_RBAC_INVENTORY_SCHEMA_VERSION,
        "collectionRunId": "monitoring-rbac-" + "a" * 32,
        "tenantId": COLLECTOR_TENANT_ID,
        "subscriptionId": SUBSCRIPTION_ID,
        "collectorPrincipalId": principal_id,
        "athenaContextPrincipalId": str(payload["athenaContextPrincipalId"]),
        "runtimeSupportPrincipalId": RUNTIME_SUPPORT_PRINCIPAL_ID,
        "attestorIdentityResourceId": RBAC_ATTESTOR_ID.casefold(),
        "attestorClientId": RBAC_ATTESTOR_CLIENT_ID,
        "attestorPrincipalId": RBAC_ATTESTOR_PRINCIPAL_ID,
        "attestorTenantId": COLLECTOR_TENANT_ID,
        "collectedAt": datetime(2026, 9, 10, 1, 55, tzinfo=UTC),
        "expiresAt": datetime(2026, 9, 10, 2, 10, tzinfo=UTC),
        "firstReadCompletedAt": datetime(2026, 9, 10, 1, 54, tzinfo=UTC),
        "secondReadCompletedAt": datetime(2026, 9, 10, 1, 55, tzinfo=UTC),
        "scopeCollectionMode": (
            "subscriptionAssignedToAllInheritedAndUnfilteredWithProtectedScopes"
        ),
        "protectedScopeIds": protected_scope_ids,
        "managementGroupAncestry": management_group_ancestry,
        "managementGroupHierarchyEvidence": hierarchy_evidence,
        "ancestorScopeCollectionComplete": True,
        "subscriptionDescendantCollectionComplete": True,
        "groupMembershipCollectionComplete": True,
        "roleDefinitionCollectionComplete": True,
        "denyAssignmentCollectionComplete": True,
        "denyAssignmentIncludeInherited": True,
        "pimScheduleInstanceCollectionComplete": True,
        "pimScheduleInstanceIncludeInherited": True,
        "signalReaderRoleActions": tuple(
            sorted(
                (
                    "microsoft.compute/virtualmachines/instanceview/read",
                    "microsoft.insights/metrics/read",
                )
            )
        ),
        "resourceLogReaderRoleActions": tuple(
            sorted(item.casefold() for item in RESOURCE_LOG_OPERATIONS)
        ),
        "resourceHealthRoleActions": tuple(
            item.casefold() for item in resource_health_role_operations
        ),
        "collectorSecurityGroupIds": (),
        "athenaContextSecurityGroupIds": (),
        "collectorGrants": ordered_grants,
        "athenaContextGrants": (),
        "runtimeSupportGrants": runtime_support_grants,
        "collectorIdentityAttachmentEvidence": collector_attachment_evidence,
        "rbacAttestorIdentityAttachmentEvidence": attestor_attachment_evidence,
        "reviewerKeyVerifierEvidence": reviewer_key_verifier_evidence,
        "exclusiveDataPlanePrincipalEvidence": exclusive_principal_evidence,
        "collectorPrincipalEvidence": collector_principal_evidence,
        "athenaContextPrincipalEvidence": context_principal_evidence,
        "runtimeSupportPrincipalEvidence": runtime_support_principal_evidence,
        "roleDefinitions": role_definitions,
        "denyAssignments": (),
        "activePimScheduleInstances": (),
        "firstRoleDefinitionRawPageDigests": (role_definition_page_digest,),
        "secondRoleDefinitionRawPageDigests": (role_definition_page_digest,),
        "firstDenyAssignmentRawPageDigests": (deny_page_digest,),
        "secondDenyAssignmentRawPageDigests": (deny_page_digest,),
        "firstPimScheduleInstanceRawPageDigests": (pim_page_digest,),
        "secondPimScheduleInstanceRawPageDigests": (pim_page_digest,),
        "firstRawSnapshotDigest": first_raw_snapshot_digest,
        "secondRawSnapshotDigest": second_raw_snapshot_digest,
        "repeatedReadStable": True,
        "assignmentCount": (
            sum(len(tuple(item["assignmentScopeIds"])) for item in ordered_grants)
            + sum(len(tuple(item["assignmentScopeIds"])) for item in runtime_support_grants)
            + 1
        ),
        "sourceReference": VersionPinnedBlobReference(
            name=("monitoring-rbac/monitoring-rbac-" + "a" * 32 + "/effective-rbac-inventory.json"),
            version="2026-09-10T01:55:00.0000000Z",
            contentDigest="sha256:" + "e" * 64,
        ),
        "sourceManifestDigest": "sha256:" + "e" * 64,
    }
    if payload.get("resourceGraphQueryRoleDefinitionId") is not None:
        inventory_payload["resourceGraphQueryRoleActions"] = tuple(
            item.casefold() for item in resource_graph_query_operations
        )
    return {
        **inventory_payload,
        "inventoryDigest": compute_artifact_digest(_json_value(inventory_payload)),
    }


def _recompute_effective_rbac_inventory(
    inventory: dict[str, object],
) -> None:
    grants = tuple(
        sorted(
            tuple(inventory["collectorGrants"]),
            key=lambda item: str(item["grantDigest"]),
        )
    )
    inventory["collectorGrants"] = grants
    context_grants = tuple(
        sorted(
            tuple(inventory["athenaContextGrants"]),
            key=lambda item: str(item["grantDigest"]),
        )
    )
    inventory["athenaContextGrants"] = context_grants
    runtime_support_grants = tuple(
        sorted(
            tuple(inventory.get("runtimeSupportGrants", ())),
            key=lambda item: str(item["grantDigest"]),
        )
    )
    if runtime_support_grants:
        inventory["runtimeSupportGrants"] = runtime_support_grants
    inventory["assignmentCount"] = sum(
        len(tuple(item["assignmentScopeIds"]))
        for item in (*grants, *context_grants, *runtime_support_grants)
    ) + (
        len(tuple(inventory["reviewerKeyVerifierEvidence"]["grant"]["assignmentScopeIds"]))
        if "reviewerKeyVerifierEvidence" in inventory
        else 0
    )
    if inventory.get("schemaVersion") in {
        "athena.wc028MonitoringEffectiveRbacInventory.v2",
        "athena.wc028MonitoringEffectiveRbacInventory.v3",
        "athena.wc028MonitoringEffectiveRbacInventory.v4",
        "athena.wc028MonitoringEffectiveRbacInventory.v5",
        MONITORING_EFFECTIVE_RBAC_INVENTORY_SCHEMA_VERSION,
    }:
        collector_evidence = inventory["collectorPrincipalEvidence"]
        context_evidence = inventory["athenaContextPrincipalEvidence"]
        assert isinstance(collector_evidence, dict)
        assert isinstance(context_evidence, dict)
        normalized_record_digests = {
            "roleDefinitionRawDigests": tuple(
                item["rawDefinitionDigest"] for item in tuple(inventory["roleDefinitions"])
            ),
            "denyAssignmentRawDigests": tuple(
                item["rawAssignmentDigest"] for item in tuple(inventory["denyAssignments"])
            ),
            "pimScheduleInstanceRawDigests": tuple(
                item["rawInstanceDigest"] for item in tuple(inventory["activePimScheduleInstances"])
            ),
        }
        if inventory["schemaVersion"] in {
            "athena.wc028MonitoringEffectiveRbacInventory.v4",
            "athena.wc028MonitoringEffectiveRbacInventory.v5",
            MONITORING_EFFECTIVE_RBAC_INVENTORY_SCHEMA_VERSION,
        }:
            runtime_support_evidence = inventory["runtimeSupportPrincipalEvidence"]
            normalized_record_digests.update(
                {
                    "collectorIdentityAttachmentEvidenceDigest": inventory[
                        "collectorIdentityAttachmentEvidence"
                    ]["evidenceDigest"],
                    "rbacAttestorIdentityAttachmentEvidenceDigest": inventory[
                        "rbacAttestorIdentityAttachmentEvidence"
                    ]["evidenceDigest"],
                    "exclusiveDataPlanePrincipalEvidenceDigest": inventory[
                        "exclusiveDataPlanePrincipalEvidence"
                    ]["evidenceDigest"],
                    "reviewerKeyVerifierEvidenceDigest": inventory["reviewerKeyVerifierEvidence"][
                        "evidenceDigest"
                    ],
                    "managementGroupHierarchyEvidenceDigest": inventory[
                        "managementGroupHierarchyEvidence"
                    ]["evidenceDigest"],
                    "runtimeSupportPrincipalEvidenceDigest": runtime_support_evidence[
                        "evidenceDigest"
                    ],
                }
            )
        if inventory["schemaVersion"] == "athena.wc028MonitoringEffectiveRbacInventory.v2":
            raw_snapshot_digest = compute_artifact_digest(
                _json_value(
                    {
                        "collectorPrincipalEvidenceDigest": (collector_evidence["evidenceDigest"]),
                        "athenaContextPrincipalEvidenceDigest": (
                            context_evidence["evidenceDigest"]
                        ),
                        "roleDefinitionRawPageDigests": (inventory["roleDefinitionRawPageDigests"]),
                        "denyAssignmentRawPageDigests": (inventory["denyAssignmentRawPageDigests"]),
                        "pimScheduleInstanceRawPageDigests": (
                            inventory["pimScheduleInstanceRawPageDigests"]
                        ),
                        **normalized_record_digests,
                    }
                )
            )
            inventory["firstRawSnapshotDigest"] = raw_snapshot_digest
            inventory["secondRawSnapshotDigest"] = raw_snapshot_digest
        else:
            first_snapshot_payload = {
                **_principal_snapshot_fields(
                    "collector",
                    collector_evidence,
                    first_read=True,
                ),
                **_principal_snapshot_fields(
                    "athenaContext",
                    context_evidence,
                    first_read=True,
                ),
                "roleDefinitionRawPageDigests": inventory["firstRoleDefinitionRawPageDigests"],
                "denyAssignmentRawPageDigests": inventory["firstDenyAssignmentRawPageDigests"],
                "pimScheduleInstanceRawPageDigests": inventory[
                    "firstPimScheduleInstanceRawPageDigests"
                ],
                **normalized_record_digests,
            }
            second_snapshot_payload = {
                **_principal_snapshot_fields(
                    "collector",
                    collector_evidence,
                    first_read=False,
                ),
                **_principal_snapshot_fields(
                    "athenaContext",
                    context_evidence,
                    first_read=False,
                ),
                "roleDefinitionRawPageDigests": inventory["secondRoleDefinitionRawPageDigests"],
                "denyAssignmentRawPageDigests": inventory["secondDenyAssignmentRawPageDigests"],
                "pimScheduleInstanceRawPageDigests": inventory[
                    "secondPimScheduleInstanceRawPageDigests"
                ],
                **normalized_record_digests,
            }
            if inventory["schemaVersion"] in {
                "athena.wc028MonitoringEffectiveRbacInventory.v4",
                "athena.wc028MonitoringEffectiveRbacInventory.v5",
                MONITORING_EFFECTIVE_RBAC_INVENTORY_SCHEMA_VERSION,
            }:
                runtime_support_evidence = inventory["runtimeSupportPrincipalEvidence"]
                first_snapshot_payload.update(
                    _principal_snapshot_fields(
                        "runtimeSupport",
                        runtime_support_evidence,
                        first_read=True,
                    )
                )
                second_snapshot_payload.update(
                    _principal_snapshot_fields(
                        "runtimeSupport",
                        runtime_support_evidence,
                        first_read=False,
                    )
                )
            inventory["firstRawSnapshotDigest"] = compute_artifact_digest(
                _json_value(first_snapshot_payload)
            )
            inventory["secondRawSnapshotDigest"] = compute_artifact_digest(
                _json_value(second_snapshot_payload)
            )
    inventory.pop("inventoryDigest", None)
    inventory["inventoryDigest"] = compute_artifact_digest(_json_value(inventory))


def _recompute_principal_evidence(evidence: dict[str, object]) -> None:
    evidence.pop("evidenceDigest", None)
    evidence["evidenceDigest"] = compute_artifact_digest(_json_value(evidence))


def _recompute_target_read_binding(
    evidence: dict[str, object],
    target_read: dict[str, object],
) -> None:
    raw_page_digests = tuple(str(item) for item in target_read["rawPageDigests"])
    target_read["bindingId"] = str(
        uuid5(
            _ARM_TEMPLATE_GUID_NAMESPACE,
            "-".join(
                (
                    str(evidence["principalId"]).casefold(),
                    str(target_read["targetScopeId"]).casefold(),
                    str(target_read["queryMode"]),
                    str(target_read["targetDigest"]),
                    ",".join(raw_page_digests),
                    str(target_read["readCount"]),
                    str(target_read["allPagesRetrieved"]).lower(),
                )
            ),
        )
    )


def _recompute_nested_evidence(evidence: dict[str, object]) -> None:
    evidence.pop("evidenceDigest", None)
    evidence["evidenceDigest"] = compute_artifact_digest(_json_value(evidence))


def _rebind_effective_rbac_inventory_attestation(
    contract_payload: dict[str, object],
) -> None:
    inventory_payload = contract_payload["effectiveRbacInventory"]
    assert isinstance(inventory_payload, dict)
    inventory = MonitoringEffectiveRbacInventory(**inventory_payload)
    contract_payload["effectiveRbacInventory"] = inventory.model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    contract_payload["effectiveRbacInventoryAttestation"] = _effective_rbac_inventory_attestation(
        inventory
    ).model_dump(
        mode="python",
        by_alias=True,
    )


def _deny_assignment(
    *,
    principal_id: str,
    actions: tuple[str, ...],
    excluded_principal_ids: tuple[str, ...] = (),
    scope_id: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "denyAssignmentId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/denyAssignments/"
            "66666666-6666-6666-6666-666666666666"
        ).casefold(),
        "scopeId": scope_id or f"/subscriptions/{SUBSCRIPTION_ID}",
        "principalIds": (principal_id,),
        "excludedPrincipalIds": tuple(sorted(excluded_principal_ids)),
        "actions": tuple(sorted(item.casefold() for item in actions)),
        "notActions": (),
        "dataActions": (),
        "notDataActions": (),
        "doNotApplyToChildScopes": False,
        "rawAssignmentDigest": "sha256:" + "6" * 64,
    }
    return {
        **payload,
        "denyAssignmentDigest": compute_artifact_digest(_json_value(payload)),
    }


def _pim_schedule_instance(
    *,
    principal_id: str,
    role_definition_id: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "scheduleInstanceId": (
            f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleAssignmentScheduleInstances/"
            "77777777-7777-7777-7777-777777777777"
        ).casefold(),
        "principalId": principal_id,
        "roleDefinitionId": role_definition_id.casefold(),
        "scopeId": f"/subscriptions/{SUBSCRIPTION_ID}",
        "assignmentType": "Activated",
        "startAt": datetime(2026, 9, 10, 1, 50, tzinfo=UTC),
        "endAt": datetime(2026, 9, 10, 2, 5, tzinfo=UTC),
        "rawInstanceDigest": "sha256:" + "7" * 64,
    }
    return {
        **payload,
        "instanceDigest": compute_artifact_digest(_json_value(payload)),
    }


def _previous_effective_rbac_inventory(
    payload: dict[str, object],
) -> dict[str, object]:
    inventory = _effective_rbac_inventory(payload)
    ip_flow_grant = _effective_rbac_grant(
        principal_id=str(payload["monitoringReaderPrincipalId"]),
        role_definition_id=IP_FLOW_VERIFY_ROLE_DEFINITION_ID,
        role_definition_name=IP_FLOW_VERIFY_ROLE_NAME,
        assignment_scope_ids=(NETWORK_WATCHER_RESOURCE_ID,),
    )
    inventory["schemaVersion"] = "athena.wc028MonitoringEffectiveRbacInventory.v1"
    inventory.pop("scopeCollectionMode")
    inventory["managementGroupAncestry"] = (
        "/providers/microsoft.management/managementgroups/synthetic-root",
    )
    inventory["ancestorScopeCollectionComplete"] = True
    inventory["resourceLogReaderRoleActions"] = tuple(
        sorted(item.casefold() for item in PREVIOUS_RESOURCE_LOG_OPERATIONS)
    )
    inventory["ipFlowVerifyRoleActions"] = tuple(
        sorted(item.casefold() for item in IP_FLOW_VERIFY_OPERATIONS)
    )
    inventory["resourceHealthRoleActions"] = tuple(
        item.casefold() for item in PREVIOUS_RESOURCE_HEALTH_OPERATIONS
    )
    inventory["collectorGrants"] = tuple(
        sorted(
            (
                *(
                    item
                    for item in tuple(inventory["collectorGrants"])
                    if item["roleDefinitionId"]
                    != RESOURCE_GRAPH_QUERY_ROLE_DEFINITION_ID.casefold()
                ),
                ip_flow_grant,
            ),
            key=lambda item: str(item["grantDigest"]),
        )
    )
    for field in (
        "attestorIdentityResourceId",
        "attestorClientId",
        "attestorPrincipalId",
        "attestorTenantId",
        "firstReadCompletedAt",
        "secondReadCompletedAt",
        "protectedScopeIds",
        "denyAssignmentCollectionComplete",
        "denyAssignmentIncludeInherited",
        "pimScheduleInstanceCollectionComplete",
        "pimScheduleInstanceIncludeInherited",
        "collectorPrincipalEvidence",
        "athenaContextPrincipalEvidence",
        "collectorIdentityAttachmentEvidence",
        "rbacAttestorIdentityAttachmentEvidence",
        "reviewerKeyVerifierEvidence",
        "exclusiveDataPlanePrincipalEvidence",
        "managementGroupHierarchyEvidence",
        "runtimeSupportPrincipalId",
        "runtimeSupportGrants",
        "runtimeSupportPrincipalEvidence",
        "resourceGraphQueryRoleActions",
        "roleDefinitions",
        "denyAssignments",
        "activePimScheduleInstances",
        "roleDefinitionRawPageDigests",
        "denyAssignmentRawPageDigests",
        "pimScheduleInstanceRawPageDigests",
        "firstRoleDefinitionRawPageDigests",
        "secondRoleDefinitionRawPageDigests",
        "firstDenyAssignmentRawPageDigests",
        "secondDenyAssignmentRawPageDigests",
        "firstPimScheduleInstanceRawPageDigests",
        "secondPimScheduleInstanceRawPageDigests",
        "firstRawSnapshotDigest",
        "secondRawSnapshotDigest",
        "repeatedReadStable",
    ):
        inventory.pop(field, None)
    _recompute_effective_rbac_inventory(inventory)
    return inventory


def _previous_permission_attested_effective_rbac_inventory(
    payload: dict[str, object],
) -> dict[str, object]:
    inventory = _effective_rbac_inventory(payload)
    previous_targets = tuple(
        item
        for item in tuple(inventory["protectedScopeIds"])
        if not str(item).startswith("/providers/microsoft.management/managementgroups/")
        and item
        not in {
            EVIDENCE_IMMUTABILITY_POLICY_RESOURCE_ID.casefold(),
            COLLECTOR_RUNTIME_RESOURCE_ID.casefold(),
            RBAC_ATTESTOR_RUNTIME_RESOURCE_ID.casefold(),
            RUNTIME_SUPPORT_ID.casefold(),
            RBAC_INVENTORY_VERIFIER_ID.casefold(),
            RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID.casefold(),
            RBAC_INVENTORY_REVIEWER_KEY_VAULT_RESOURCE_ID.casefold(),
            RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_ID.casefold(),
            RBAC_INVENTORY_VERIFIER_ROLE_ASSIGNMENT_ID.casefold(),
            STORAGE_READBACK_ROLE_DEFINITION_ID.casefold(),
            STORAGE_READBACK_ROLE_ASSIGNMENT_ID.casefold(),
        }
    )
    collector_evidence = _effective_rbac_principal_evidence(
        principal_id=str(payload["monitoringReaderPrincipalId"]),
        target_scope_ids=previous_targets,
        query_filter="atScope() and assignedTo(principalId)",
        target_bound=False,
    )
    context_evidence = _effective_rbac_principal_evidence(
        principal_id=str(payload["athenaContextPrincipalId"]),
        target_scope_ids=previous_targets,
        query_filter="atScope() and assignedTo(principalId)",
        target_bound=False,
    )
    role_definitions = tuple(
        item
        for item in tuple(inventory["roleDefinitions"])
        if item["roleDefinitionId"]
        not in {
            RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_ID.casefold(),
            STORAGE_READBACK_ROLE_DEFINITION_ID.casefold(),
        }
    )
    role_definition_page_digest = compute_artifact_digest(
        {"page": "roleDefinitions", "roles": _json_value(role_definitions)}
    )
    inventory.update(
        {
            "schemaVersion": "athena.wc028MonitoringEffectiveRbacInventory.v3",
            "scopeCollectionMode": "subscriptionAndDescendantAtScope",
            "managementGroupAncestry": (),
            "ancestorScopeCollectionComplete": False,
            "roleDefinitions": role_definitions,
            "collectorPrincipalEvidence": collector_evidence,
            "athenaContextPrincipalEvidence": context_evidence,
            "firstRoleDefinitionRawPageDigests": (role_definition_page_digest,),
            "secondRoleDefinitionRawPageDigests": (role_definition_page_digest,),
        }
    )
    for field in (
        "protectedScopeIds",
        "managementGroupHierarchyEvidence",
        "denyAssignmentIncludeInherited",
        "pimScheduleInstanceIncludeInherited",
        "collectorIdentityAttachmentEvidence",
        "rbacAttestorIdentityAttachmentEvidence",
        "reviewerKeyVerifierEvidence",
        "exclusiveDataPlanePrincipalEvidence",
        "runtimeSupportPrincipalId",
        "runtimeSupportGrants",
        "runtimeSupportPrincipalEvidence",
    ):
        inventory.pop(field, None)
    _recompute_effective_rbac_inventory(inventory)
    return inventory


def _previous_trust_hardened_effective_rbac_inventory(
    payload: dict[str, object],
) -> dict[str, object]:
    inventory = _effective_rbac_inventory(payload)
    _downgrade_target_read_evidence(inventory)
    inventory["schemaVersion"] = "athena.wc028MonitoringEffectiveRbacInventory.v4"
    inventory.pop("resourceGraphQueryRoleActions", None)
    _recompute_effective_rbac_inventory(inventory)
    return inventory


def _downgrade_principal_target_read_evidence(
    evidence: dict[str, object],
) -> dict[str, object]:
    target_reads = tuple(evidence.pop("targetReadEvidence"))
    legacy_payload: dict[str, object] = {
        **evidence,
        "queryFilter": "assignedTo(principalId)",
        "includeInherited": True,
        "includeGroups": True,
        "includeAllDescendantScopes": True,
        "targetScopeIds": tuple(item["targetScopeId"] for item in target_reads),
        "firstReadTargetDigests": tuple(item["targetDigest"] for item in target_reads),
        "secondReadTargetDigests": tuple(item["targetDigest"] for item in target_reads),
        "firstRoleAssignmentRawPageDigests": tuple(
            sorted(
                digest
                for item in target_reads
                for digest in tuple(item["rawPageDigests"])
            )
        ),
        "secondRoleAssignmentRawPageDigests": tuple(
            sorted(
                digest
                for item in target_reads
                for digest in tuple(item["rawPageDigests"])
            )
        ),
    }
    _recompute_principal_evidence(legacy_payload)
    return legacy_payload


def _downgrade_target_read_evidence(inventory: dict[str, object]) -> None:
    for field in (
        "collectorPrincipalEvidence",
        "athenaContextPrincipalEvidence",
        "runtimeSupportPrincipalEvidence",
    ):
        evidence = inventory[field]
        assert isinstance(evidence, dict)
        inventory[field] = _downgrade_principal_target_read_evidence(evidence)
    verifier = inventory["reviewerKeyVerifierEvidence"]
    assert isinstance(verifier, dict)
    principal_evidence = verifier["principalEvidence"]
    assert isinstance(principal_evidence, dict)
    verifier["principalEvidence"] = _downgrade_principal_target_read_evidence(
        principal_evidence
    )
    _recompute_nested_evidence(verifier)


def _previous_target_unbound_effective_rbac_inventory(
    payload: dict[str, object],
) -> dict[str, object]:
    inventory = _effective_rbac_inventory(payload)
    _downgrade_target_read_evidence(inventory)
    inventory["schemaVersion"] = "athena.wc028MonitoringEffectiveRbacInventory.v5"
    _recompute_effective_rbac_inventory(inventory)
    return inventory


def _acquisition_collector_contract() -> MonitoringCollectorContract:
    payload = _collector_contract().model_dump(mode="python", by_alias=True)
    payload.update(
        {
            "schemaVersion": MONITORING_ACQUISITION_COLLECTOR_CONTRACT_SCHEMA_VERSION,
            "collectorTenantId": COLLECTOR_TENANT_ID,
            "monitoringReaderPrincipalId": "11111111-1111-1111-1111-111111111111",
            "athenaContextIdentityId": (
                f"{MONITORING_RESOURCE_GROUP_ROOT}/providers/"
                "Microsoft.ManagedIdentity/userAssignedIdentities/synthetic-athena-context"
            ),
            "athenaContextPrincipalId": "22222222-2222-2222-2222-222222222222",
            "physicalIdentitySeparationEnforced": True,
            "collectorRuntimeResourceId": COLLECTOR_RUNTIME_RESOURCE_ID,
            "rbacAttestorRuntimeResourceId": RBAC_ATTESTOR_RUNTIME_RESOURCE_ID,
            "runtimeSupportIdentityResourceId": RUNTIME_SUPPORT_ID,
            "runtimeSupportIdentityPrincipalId": RUNTIME_SUPPORT_PRINCIPAL_ID,
            "runtimeSupportStorageReaderRoleDefinitionId": (STORAGE_READBACK_ROLE_DEFINITION_ID),
            "runtimeSupportStorageReaderRoleName": STORAGE_READBACK_ROLE_NAME,
            "runtimeSupportStorageReaderAllowedOperations": STORAGE_READBACK_OPERATIONS,
            "runtimeSupportStorageReaderRoleAssignmentId": (STORAGE_READBACK_ROLE_ASSIGNMENT_ID),
            "runtimeSupportStorageReaderScopeId": EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID,
            "signalReaderRoleName": SIGNAL_READER_ROLE_NAME,
            "resourceLogReaderRoleDefinitionId": (RESOURCE_LOG_READER_ROLE_DEFINITION_ID),
            "resourceLogReaderRoleName": RESOURCE_LOG_READER_ROLE_NAME,
            "resourceLogAllowedOperations": RESOURCE_LOG_OPERATIONS,
            "resourceLogReadScopeIds": SIGNAL_READ_SCOPE_IDS,
            "workspaceResourceContextAccessEnabled": True,
            "workspaceSkuName": "PerGB2018",
            "resourceContextTablePlans": RESOURCE_CONTEXT_TABLE_PLANS,
            "resourceIdColumn": "_ResourceId",
            "logQueryPreferHeader": "include-permissions=true",
            "flowTableAcquisitionMode": "unsupportedUnavailable",
            "rbacAttestorIdentityResourceId": RBAC_ATTESTOR_ID,
            "rbacAttestorIdentityClientId": RBAC_ATTESTOR_CLIENT_ID,
            "rbacAttestorPrincipalId": RBAC_ATTESTOR_PRINCIPAL_ID,
            "rbacAttestorTenantId": COLLECTOR_TENANT_ID,
            "rbacAttestorRoleDefinitionId": RBAC_ATTESTOR_ROLE_DEFINITION_ID,
            "rbacAttestorRoleName": RBAC_ATTESTOR_ROLE_NAME,
            "rbacAttestorScopeId": f"/subscriptions/{SUBSCRIPTION_ID}",
            "rbacAttestorAllowedOperations": RBAC_ATTESTOR_OPERATIONS,
            "rbacAttestorIdentitySeparationEnforced": True,
            "identityProofAudience": MONITORING_IDENTITY_PROOF_AUDIENCE,
            "identityProofApplicationId": IDENTITY_PROOF_APPLICATION_ID,
            "identityProofApplicationObjectId": (IDENTITY_PROOF_APPLICATION_OBJECT_ID),
            "identityProofServicePrincipalId": (IDENTITY_PROOF_SERVICE_PRINCIPAL_ID),
            "identityProofAppRoleId": IDENTITY_PROOF_APP_ROLE_ID,
            "identityProofAppRoleAssignmentId": (IDENTITY_PROOF_APP_ROLE_ASSIGNMENT_ID),
            "identityProofAssignedPrincipalId": ("11111111-1111-1111-1111-111111111111"),
            "identityProofTokenVersion": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
            "identityProofRequiredRole": MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,
            "identityProofMaximumLifetimeSeconds": (
                MONITORING_IDENTITY_PROOF_MAXIMUM_LIFETIME_SECONDS
            ),
            "resourceGraphQueryRoleDefinitionId": RESOURCE_GRAPH_QUERY_ROLE_DEFINITION_ID,
            "resourceGraphQueryRoleName": RESOURCE_GRAPH_QUERY_ROLE_NAME,
            "resourceGraphQueryScopeId": RESOURCE_GRAPH_QUERY_SCOPE_ID,
            "resourceHealthRoleDefinitionId": RESOURCE_HEALTH_ROLE_DEFINITION_ID,
            "resourceHealthRoleName": RESOURCE_HEALTH_ROLE_NAME,
            "resourceHealthScopeIds": SIGNAL_READ_SCOPE_IDS,
            "resourceHealthAllowedOperations": RESOURCE_HEALTH_OPERATIONS,
            "allowedReadOperations": (
                *(
                    operation
                    for operation in payload["allowedReadOperations"]
                    if not operation.startswith("Microsoft.OperationalInsights/workspaces")
                ),
                *RESOURCE_HEALTH_OPERATIONS,
                *RESOURCE_LOG_OPERATIONS,
            ),
            "signingKeyArmResourceId": SIGNING_KEY_ARM_RESOURCE_ID,
            "signingKeyCryptoUserRoleDefinitionId": (SIGNING_KEY_CRYPTO_USER_ROLE_DEFINITION_ID),
            "evidenceBlobServiceResourceId": EVIDENCE_BLOB_SERVICE_RESOURCE_ID,
            "evidenceContainerResourceId": EVIDENCE_CONTAINER_RESOURCE_ID,
            "evidenceContainerPublicAccess": "None",
            "evidenceImmutabilityPolicyResourceId": (EVIDENCE_IMMUTABILITY_POLICY_RESOURCE_ID),
            "evidenceWriterRoleDefinitionId": EVIDENCE_WRITER_ROLE_DEFINITION_ID,
            "evidenceWriterRoleName": EVIDENCE_WRITER_ROLE_NAME,
            "evidenceWriterAllowedDataActions": EVIDENCE_WRITER_DATA_ACTIONS,
            "evidenceWriterAssignmentCondition": (EVIDENCE_WRITER_ASSIGNMENT_CONDITION),
            "evidenceWriterAssignmentConditionVersion": "2.0",
            "evidenceBlobVersioningEnabled": True,
            "evidenceContainerHasImmutabilityPolicy": True,
            "evidenceContainerImmutabilityPolicyState": "Unlocked",
            "evidenceContainerImmutabilityPeriodDays": 30,
            "evidenceContainerProtectedAppendWritesEnabled": False,
            "evidenceContainerProtectedAppendWritesAllEnabled": False,
            "evidenceStorageReadbackBindingId": STORAGE_READBACK_BINDING_ID,
            "evidenceStorageReadinessDigest": STORAGE_READINESS_DIGEST,
            "legacyCollectorRbacCleanupSchemaVersion": (
                "athena.wc028LegacyCollectorRbacCleanup.v3"
            ),
            "legacyCollectorRbacCleanupDigest": LEGACY_COLLECTOR_RBAC_CLEANUP_DIGEST,
            "handoffSchemaVersion": "athena.wc028MonitoringEvidenceHandoff.v2",
            "acquisitionReceiptSchemaVersion": MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
        }
    )
    inventory = MonitoringEffectiveRbacInventory(**_effective_rbac_inventory(payload))
    modulus, exponent, fingerprint = _rbac_inventory_reviewer_public_material()
    payload.update(
        {
            "rbacInventoryReviewerPrincipalId": (RBAC_INVENTORY_REVIEWER_PRINCIPAL_ID),
            "rbacInventoryBootstrapHandoffId": (RBAC_INVENTORY_BOOTSTRAP_HANDOFF_ID),
            "rbacInventoryBootstrapDeploymentId": (RBAC_INVENTORY_BOOTSTRAP_DEPLOYMENT_ID),
            "rbacInventoryBootstrapTemplateHash": (RBAC_INVENTORY_BOOTSTRAP_TEMPLATE_HASH),
            "rbacInventoryBootstrapContractInputsBindingId": (
                RBAC_INVENTORY_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID
            ),
            "rbacInventoryVerifierIdentityResourceId": (RBAC_INVENTORY_VERIFIER_ID),
            "rbacInventoryVerifierIdentityClientId": (RBAC_INVENTORY_VERIFIER_CLIENT_ID),
            "rbacInventoryVerifierIdentityPrincipalId": (RBAC_INVENTORY_VERIFIER_PRINCIPAL_ID),
            "rbacInventoryVerifierIdentityTenantId": COLLECTOR_TENANT_ID,
            "rbacInventoryReviewerKeyVaultResourceId": (
                RBAC_INVENTORY_REVIEWER_KEY_VAULT_RESOURCE_ID
            ),
            "rbacInventoryReviewerKeyArmResourceId": (RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID),
            "rbacInventoryVerifierRoleDefinitionId": (RBAC_INVENTORY_VERIFIER_ROLE_DEFINITION_ID),
            "rbacInventoryVerifierRoleName": RBAC_INVENTORY_VERIFIER_ROLE_NAME,
            "rbacInventoryVerifierRoleScopeId": (RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID),
            "rbacInventoryVerifierAllowedDataActions": (RBAC_INVENTORY_VERIFIER_DATA_ACTIONS),
            "rbacInventoryVerifierRoleAssignmentId": (RBAC_INVENTORY_VERIFIER_ROLE_ASSIGNMENT_ID),
            "rbacInventoryReviewerKeyId": RBAC_INVENTORY_REVIEWER_KEY_ID,
            "rbacInventoryReviewerPublicKeyModulus": modulus,
            "rbacInventoryReviewerPublicKeyExponent": exponent,
            "rbacInventoryReviewerPublicKeyFingerprint": fingerprint,
            "effectiveRbacInventory": inventory,
            "effectiveRbacInventoryAttestation": (_effective_rbac_inventory_attestation(inventory)),
        }
    )
    return MonitoringCollectorContract(**payload)


def _handoff_payload() -> dict[str, object]:
    return {
        "schemaVersion": MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
        "collectorContractDigest": _collector_contract().compute_artifact_digest_value(),
        "collectionId": "wc024-0123456789ab",
        "observedAt": datetime(2026, 9, 6, 6, 0, tzinfo=UTC),
        "evidence": VersionPinnedBlobReference(
            name="wc024-monitoring/wc024-0123456789ab/evidence.json",
            version="2026-09-06T06:00:00.0000000Z",
            contentDigest="sha256:" + "a" * 64,
        ),
    }


def _signed_handoff() -> MonitoringEvidenceHandoff:
    payload = _handoff_payload()
    signature = base64.b64encode(b"synthetic-signature").decode("ascii")
    evidence = payload["evidence"]
    assert isinstance(evidence, VersionPinnedBlobReference)
    attestation = MonitoringEvidenceAttestation(
        signatureAlgorithm="RS256",
        trustAnchorRef=REVIEWED_SIGNING_KEY_URI,
        signedPreimageDigest=compute_artifact_digest(
            {
                "domain": MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
                "handoff": {
                    **payload,
                    "evidence": evidence.model_dump(mode="json", by_alias=True),
                },
            }
        ),
        signature=signature,
    )
    return MonitoringEvidenceHandoff(**payload, collectorAttestation=attestation)


def test_collector_contract_is_exact_generic_and_deterministic() -> None:
    contract = _collector_contract()

    assert contract.canonical_json() == _collector_contract().canonical_json()
    assert contract.collection_mode == "isolatedSignedCollector"
    assert contract.connection_monitor_mode == "capabilityOnly"


def test_acquisition_collector_contract_authorizes_receipt_handoff() -> None:
    contract = _acquisition_collector_contract()

    assert contract.handoff_schema_version == "athena.wc028MonitoringEvidenceHandoff.v2"
    assert (
        contract.acquisition_receipt_schema_version == MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION
    )
    assert contract.ip_flow_verify_scope_id is None
    assert contract.ip_flow_verify_allowed_operations is None
    assert contract.flow_table_acquisition_mode == "unsupportedUnavailable"
    assert contract.identity_proof_audience == MONITORING_IDENTITY_PROOF_AUDIENCE
    assert contract.collector_runtime_resource_id == (COLLECTOR_RUNTIME_RESOURCE_ID.casefold())
    assert contract.rbac_attestor_runtime_resource_id == (
        RBAC_ATTESTOR_RUNTIME_RESOURCE_ID.casefold()
    )
    assert contract.runtime_support_identity_resource_id == RUNTIME_SUPPORT_ID.casefold()
    assert contract.rbac_inventory_verifier_identity_resource_id == (
        RBAC_INVENTORY_VERIFIER_ID.casefold()
    )
    assert contract.rbac_inventory_verifier_identity_principal_id == (
        RBAC_INVENTORY_VERIFIER_PRINCIPAL_ID
    )
    assert contract.rbac_inventory_reviewer_key_arm_resource_id == (
        RBAC_INVENTORY_REVIEWER_KEY_ARM_RESOURCE_ID.casefold()
    )
    assert contract.rbac_inventory_bootstrap_deployment_id == (
        RBAC_INVENTORY_BOOTSTRAP_DEPLOYMENT_ID.casefold()
    )
    assert contract.rbac_inventory_bootstrap_template_hash == (
        RBAC_INVENTORY_BOOTSTRAP_TEMPLATE_HASH
    )
    assert contract.rbac_inventory_bootstrap_contract_inputs_binding_id == (
        RBAC_INVENTORY_BOOTSTRAP_CONTRACT_INPUTS_BINDING_ID
    )
    assert contract.identity_proof_application_id == IDENTITY_PROOF_APPLICATION_ID
    assert contract.identity_proof_application_object_id == IDENTITY_PROOF_APPLICATION_OBJECT_ID
    assert contract.identity_proof_service_principal_id == IDENTITY_PROOF_SERVICE_PRINCIPAL_ID
    assert contract.identity_proof_app_role_id == IDENTITY_PROOF_APP_ROLE_ID
    assert contract.identity_proof_app_role_assignment_id == IDENTITY_PROOF_APP_ROLE_ASSIGNMENT_ID
    assert contract.identity_proof_assigned_principal_id == contract.monitoring_reader_principal_id
    assert "Microsoft.Network/networkWatchers/read" not in contract.allowed_read_operations
    assert contract.resource_graph_query_role_definition_id == (
        RESOURCE_GRAPH_QUERY_ROLE_DEFINITION_ID
    )
    assert contract.resource_graph_query_role_name == RESOURCE_GRAPH_QUERY_ROLE_NAME
    assert contract.resource_graph_query_scope_id == RESOURCE_GRAPH_QUERY_SCOPE_ID.casefold()
    assert contract.resource_health_scope_ids == SIGNAL_READ_SCOPE_IDS
    assert contract.resource_health_allowed_operations == RESOURCE_HEALTH_OPERATIONS
    assert "resourceGraphQueryAllowedOperations" not in contract.model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    assert "Microsoft.ResourceHealth/availabilityStatuses/current/read" not in (
        contract.allowed_read_operations
    )
    assert contract.workspace_access_control_mode == "workspaceAndResourceContext"
    assert contract.workspace_resource_context_access_enabled is True
    assert contract.workspace_sku_name == "PerGB2018"
    assert tuple(item.table for item in contract.resource_context_table_plans or ()) == (
        RESOURCE_CONTEXT_TABLES
    )
    assert contract.resource_id_column == "_ResourceId"
    assert contract.log_query_prefer_header == "include-permissions=true"
    assert contract.resource_log_allowed_operations == RESOURCE_LOG_OPERATIONS
    assert contract.rbac_attestor_identity_resource_id == RBAC_ATTESTOR_ID.casefold()
    assert contract.rbac_attestor_principal_id == RBAC_ATTESTOR_PRINCIPAL_ID
    assert contract.rbac_attestor_allowed_operations == RBAC_ATTESTOR_OPERATIONS
    assert contract.evidence_blob_service_resource_id is not None
    assert contract.evidence_blob_service_resource_id.casefold() == (
        EVIDENCE_BLOB_SERVICE_RESOURCE_ID.casefold()
    )
    assert contract.evidence_immutability_policy_resource_id is not None
    assert contract.evidence_immutability_policy_resource_id.casefold() == (
        EVIDENCE_IMMUTABILITY_POLICY_RESOURCE_ID.casefold()
    )
    assert contract.evidence_writer_role_name == EVIDENCE_WRITER_ROLE_NAME
    assert contract.evidence_writer_allowed_data_actions == EVIDENCE_WRITER_DATA_ACTIONS
    assert contract.evidence_writer_assignment_condition == (EVIDENCE_WRITER_ASSIGNMENT_CONDITION)
    assert contract.evidence_writer_assignment_condition_version == "2.0"
    assert contract.evidence_blob_versioning_enabled is True
    assert contract.evidence_container_has_immutability_policy is True
    assert contract.evidence_container_immutability_policy_state == "Unlocked"
    assert contract.evidence_container_immutability_period_days == 30
    assert contract.evidence_container_protected_append_writes_enabled is False
    assert contract.evidence_container_protected_append_writes_all_enabled is False
    assert contract.legacy_collector_rbac_cleanup_digest == (LEGACY_COLLECTOR_RBAC_CLEANUP_DIGEST)
    assert contract.effective_rbac_inventory is not None
    assert contract.effective_rbac_inventory.reviewer_key_verifier_evidence is not None
    assert (
        contract.effective_rbac_inventory.reviewer_key_verifier_evidence.allowed_data_actions
        == RBAC_INVENTORY_VERIFIER_DATA_ACTIONS
    )
    assert not (
        contract.effective_rbac_inventory.reviewer_key_verifier_evidence.attachment_evidence.associated_resource_ids
    )
    assert (
        contract.effective_rbac_inventory.schema_version
        == MONITORING_EFFECTIVE_RBAC_INVENTORY_SCHEMA_VERSION
    )
    assert contract.effective_rbac_inventory.protected_scope_ids
    collector_target_reads = (
        contract.effective_rbac_inventory.collector_principal_evidence.target_read_evidence
    )
    assert collector_target_reads is not None
    assert all(
        item.query_mode == CURRENT_RBAC_TARGET_QUERY_MODE for item in collector_target_reads
    )
    assert tuple(item.target_scope_id for item in collector_target_reads) == tuple(
        sorted(
            (
                f"/subscriptions/{SUBSCRIPTION_ID}",
                f"/providers/microsoft.management/managementgroups/{COLLECTOR_TENANT_ID}",
            )
        )
    )
    assert contract.effective_rbac_inventory_attestation is not None
    assert (
        contract.effective_rbac_inventory_attestation.reviewer_principal_id
        == RBAC_INVENTORY_REVIEWER_PRINCIPAL_ID
    )
    assert not any(
        operation.startswith("Microsoft.OperationalInsights/workspaces")
        for operation in contract.allowed_read_operations
    )
    assert all(
        item.role_definition_name != "Log Analytics Data Reader"
        for item in contract.effective_rbac_inventory.collector_grants
    )


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        (
            "evidenceWriterRoleDefinitionId",
            PREVIOUS_EVIDENCE_WRITER_ROLE_DEFINITION_ID,
            "exact reviewed definitions",
        ),
        (
            "evidenceWriterAssignmentCondition",
            "(!(ActionMatches{'synthetic'}))",
            "known-name Blob read",
        ),
        (
            "legacyCollectorRbacCleanupDigest",
            "sha256:" + ("0" * 64),
            "cleanup digest must be non-zero",
        ),
        (
            "evidenceBlobVersioningEnabled",
            False,
            "Input should be True",
        ),
        (
            "evidenceContainerHasImmutabilityPolicy",
            False,
            "Input should be True",
        ),
        (
            "rbacInventoryVerifierIdentityPrincipalId",
            RBAC_INVENTORY_REVIEWER_PRINCIPAL_ID,
            "omitted an exact scope, runtime, or exclusive principal",
        ),
        (
            "rbacInventoryVerifierAllowedDataActions",
            ("Microsoft.KeyVault/vaults/keys/sign/action",),
            "literal_error",
        ),
    ),
)
def test_current_contract_rejects_broad_or_untruthful_persistence(
    field_name: str,
    value: object,
    message: str,
) -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    payload[field_name] = value

    with pytest.raises(ValidationError, match=message):
        MonitoringCollectorContract(**payload)


def test_current_contract_rejects_runtime_support_as_inventory_reviewer() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = _acquisition_collector_contract().effective_rbac_inventory
    assert inventory is not None
    payload["rbacInventoryReviewerPrincipalId"] = RUNTIME_SUPPORT_PRINCIPAL_ID
    payload["effectiveRbacInventoryAttestation"] = _effective_rbac_inventory_attestation(
        inventory,
        reviewer_principal_id=RUNTIME_SUPPORT_PRINCIPAL_ID,
    )

    with pytest.raises(
        ValidationError,
        match="attestation does not match its reviewed authority",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_inventory_requires_exact_blob_list_deny_condition() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    grants = []
    for item in tuple(inventory["collectorGrants"]):
        grant = dict(item)
        if grant["roleDefinitionId"] == EVIDENCE_WRITER_ROLE_DEFINITION_ID.casefold():
            grant.pop("condition")
            grant.pop("conditionVersion")
            grant.pop("grantDigest")
            grant["grantDigest"] = compute_artifact_digest(_json_value(grant))
        grants.append(grant)
    inventory["collectorGrants"] = tuple(grants)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="does not match exact deployed assignments",
    ):
        MonitoringCollectorContract(**payload)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        (
            "identityProofAudience",
            "api://00000000-0000-0000-0000-000000000004/athena-monitoring-identity-proof",
        ),
        (
            "identityProofAssignedPrincipalId",
            "77777777-7777-7777-7777-777777777777",
        ),
        (
            "identityProofServicePrincipalId",
            IDENTITY_PROOF_APPLICATION_ID,
        ),
    ),
)
def test_current_collector_contract_rejects_unbound_identity_proof_authority(
    field_name: str,
    value: str,
) -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    payload[field_name] = value

    with pytest.raises(
        ValidationError,
        match="deployed identity-proof authority",
    ):
        MonitoringCollectorContract(**payload)


def test_effective_rbac_inventory_example_matches_reviewed_contract() -> None:
    inventory = MonitoringEffectiveRbacInventory.model_validate_json(
        EFFECTIVE_RBAC_INVENTORY_EXAMPLE.read_text(encoding="utf-8")
    )

    assert inventory == _acquisition_collector_contract().effective_rbac_inventory


def test_legacy_v2_effective_rbac_inventory_is_parse_only() -> None:
    legacy_inventory = MonitoringEffectiveRbacInventory.model_validate_json(
        LEGACY_EFFECTIVE_RBAC_INVENTORY_V2_EXAMPLE.read_text(encoding="utf-8")
    )
    assert legacy_inventory.schema_version == "athena.wc028MonitoringEffectiveRbacInventory.v2"
    assert legacy_inventory.resource_health_role_actions == (
        "microsoft.resourcehealth/availabilitystatuses/read",
    )

    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    payload["effectiveRbacInventory"] = legacy_inventory.model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    with pytest.raises(
        ValidationError,
        match=(
            "version-bound effective RBAC inventory|current effective RBAC inventory|"
            "does not match exact deployed assignments|"
            "attestation does not match"
        ),
    ):
        MonitoringCollectorContract(**payload)


def _legacy_v3_acquisition_collector_contract() -> MonitoringCollectorContract:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload["schemaVersion"] = "athena.wc028MonitoringCollectorContract.v3"
    payload["allowedReadOperations"] = _collector_contract().allowed_read_operations
    for field in (
        "collectorTenantId",
        "ipFlowVerifyRoleDefinitionId",
        "ipFlowVerifyScopeId",
        "ipFlowVerifyAllowedOperations",
        "identityProofAudience",
        "identityProofTokenVersion",
        "identityProofRequiredRole",
        "identityProofMaximumLifetimeSeconds",
        "resourceHealthRoleDefinitionId",
        "resourceHealthScopeIds",
        "resourceHealthAllowedOperations",
        "acquisitionReceiptSchemaVersion",
        *MEASURED_RBAC_FIELDS,
        *V10_ONLY_CONTRACT_FIELDS,
    ):
        payload.pop(field, None)
    return MonitoringCollectorContract(**payload)


def test_legacy_v3_acquisition_collector_contract_remains_readable() -> None:
    legacy = _legacy_v3_acquisition_collector_contract()

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v3"
    assert legacy.ip_flow_verify_role_definition_id is None


def test_legacy_v4_acquisition_collector_contract_remains_readable() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload["schemaVersion"] = "athena.wc028MonitoringCollectorContract.v4"
    payload["acquisitionReceiptSchemaVersion"] = "athena.wc028MonitoringAcquisitionReceipt.v3"
    payload["allowedReadOperations"] = (
        *_collector_contract().allowed_read_operations,
        *IP_FLOW_VERIFY_OPERATIONS,
    )
    payload.update(
        {
            "ipFlowVerifyRoleDefinitionId": IP_FLOW_VERIFY_ROLE_DEFINITION_ID,
            "ipFlowVerifyScopeId": NETWORK_WATCHER_RESOURCE_ID,
            "ipFlowVerifyAllowedOperations": IP_FLOW_VERIFY_OPERATIONS,
        }
    )
    for field in (
        "identityProofAudience",
        "identityProofTokenVersion",
        "identityProofRequiredRole",
        "identityProofMaximumLifetimeSeconds",
        "resourceHealthRoleDefinitionId",
        "resourceHealthScopeIds",
        "resourceHealthAllowedOperations",
        *MEASURED_RBAC_FIELDS,
        *V10_ONLY_CONTRACT_FIELDS,
    ):
        payload.pop(field, None)

    legacy = MonitoringCollectorContract(**payload)

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v4"
    assert legacy.identity_proof_audience is None


def test_legacy_v5_acquisition_collector_contract_remains_readable() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload["schemaVersion"] = "athena.wc028MonitoringCollectorContract.v5"
    payload["acquisitionReceiptSchemaVersion"] = "athena.wc028MonitoringAcquisitionReceipt.v4"
    payload["allowedReadOperations"] = (
        *_collector_contract().allowed_read_operations,
        *IP_FLOW_VERIFY_OPERATIONS,
    )
    payload.update(
        {
            "ipFlowVerifyRoleDefinitionId": IP_FLOW_VERIFY_ROLE_DEFINITION_ID,
            "ipFlowVerifyScopeId": NETWORK_WATCHER_RESOURCE_ID,
            "ipFlowVerifyAllowedOperations": IP_FLOW_VERIFY_OPERATIONS,
        }
    )
    for field in (
        "resourceHealthRoleDefinitionId",
        "resourceHealthScopeIds",
        "resourceHealthAllowedOperations",
        *MEASURED_RBAC_FIELDS,
        *V10_ONLY_CONTRACT_FIELDS,
    ):
        payload.pop(field, None)

    legacy = MonitoringCollectorContract(**payload)

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v5"
    assert legacy.resource_health_role_definition_id is None


def test_legacy_v6_acquisition_collector_contract_remains_readable() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload["schemaVersion"] = "athena.wc028MonitoringCollectorContract.v6"
    payload["acquisitionReceiptSchemaVersion"] = "athena.wc028MonitoringAcquisitionReceipt.v4"
    payload["allowedReadOperations"] = (
        *_collector_contract().allowed_read_operations,
        *IP_FLOW_VERIFY_OPERATIONS,
        *PREVIOUS_RESOURCE_HEALTH_OPERATIONS,
    )
    payload.update(
        {
            "ipFlowVerifyRoleDefinitionId": IP_FLOW_VERIFY_ROLE_DEFINITION_ID,
            "ipFlowVerifyScopeId": NETWORK_WATCHER_RESOURCE_ID,
            "ipFlowVerifyAllowedOperations": IP_FLOW_VERIFY_OPERATIONS,
            "resourceHealthAllowedOperations": PREVIOUS_RESOURCE_HEALTH_OPERATIONS,
        }
    )
    for field in (*MEASURED_RBAC_FIELDS, *V10_ONLY_CONTRACT_FIELDS):
        payload.pop(field, None)

    legacy = MonitoringCollectorContract(**payload)

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v6"
    assert legacy.resource_health_role_definition_id == (RESOURCE_HEALTH_ROLE_DEFINITION_ID)
    assert legacy.effective_rbac_inventory is None


def test_legacy_v7_measured_rbac_contract_remains_readable() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload.update(
        {
            "schemaVersion": "athena.wc028MonitoringCollectorContract.v7",
            "acquisitionReceiptSchemaVersion": ("athena.wc028MonitoringAcquisitionReceipt.v5"),
            "ipFlowVerifyRoleDefinitionId": IP_FLOW_VERIFY_ROLE_DEFINITION_ID,
            "ipFlowVerifyRoleName": IP_FLOW_VERIFY_ROLE_NAME,
            "ipFlowVerifyScopeId": NETWORK_WATCHER_RESOURCE_ID,
            "ipFlowVerifyAllowedOperations": IP_FLOW_VERIFY_OPERATIONS,
            "resourceLogAllowedOperations": PREVIOUS_RESOURCE_LOG_OPERATIONS,
            "resourceHealthAllowedOperations": PREVIOUS_RESOURCE_HEALTH_OPERATIONS,
            "evidenceWriterRoleDefinitionId": (PREVIOUS_EVIDENCE_WRITER_ROLE_DEFINITION_ID),
            "allowedReadOperations": (
                *(
                    operation
                    for operation in _collector_contract().allowed_read_operations
                    if not operation.startswith("Microsoft.OperationalInsights/workspaces")
                ),
                *IP_FLOW_VERIFY_OPERATIONS,
                *PREVIOUS_RESOURCE_HEALTH_OPERATIONS,
                *PREVIOUS_RESOURCE_LOG_OPERATIONS,
            ),
        }
    )
    for field in (
        *V8_ONLY_CONTRACT_FIELDS,
        *V9_ONLY_CONTRACT_FIELDS,
        *V10_ONLY_CONTRACT_FIELDS,
    ):
        payload.pop(field, None)
    payload["effectiveRbacInventory"] = _previous_effective_rbac_inventory(payload)

    legacy = MonitoringCollectorContract(**payload)

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v7"
    assert legacy.ip_flow_verify_scope_id == NETWORK_WATCHER_RESOURCE_ID
    assert legacy.effective_rbac_inventory is not None
    assert (
        legacy.effective_rbac_inventory.schema_version
        == "athena.wc028MonitoringEffectiveRbacInventory.v1"
    )


def test_legacy_v8_permission_attested_contract_remains_readable() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload.update(
        {
            "schemaVersion": "athena.wc028MonitoringCollectorContract.v8",
            "acquisitionReceiptSchemaVersion": ("athena.wc028MonitoringAcquisitionReceipt.v5"),
            "rbacAttestorAllowedOperations": PREVIOUS_RBAC_ATTESTOR_OPERATIONS,
            "evidenceWriterRoleDefinitionId": (PREVIOUS_EVIDENCE_WRITER_ROLE_DEFINITION_ID),
            "resourceHealthAllowedOperations": (
                PREVIOUS_PERMISSION_ATTESTED_RESOURCE_HEALTH_OPERATIONS
            ),
            "allowedReadOperations": (
                *(
                    operation
                    for operation in _collector_contract().allowed_read_operations
                    if not operation.startswith("Microsoft.OperationalInsights/workspaces")
                ),
                *PREVIOUS_PERMISSION_ATTESTED_RESOURCE_HEALTH_OPERATIONS,
                *RESOURCE_LOG_OPERATIONS,
            ),
        }
    )
    for field in (*V9_ONLY_CONTRACT_FIELDS, *V10_ONLY_CONTRACT_FIELDS):
        payload.pop(field, None)
    payload["effectiveRbacInventory"] = _previous_permission_attested_effective_rbac_inventory(
        payload
    )

    legacy = MonitoringCollectorContract(**payload)

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v8"
    assert legacy.acquisition_receipt_schema_version == (
        "athena.wc028MonitoringAcquisitionReceipt.v5"
    )
    assert legacy.effective_rbac_inventory is not None
    assert (
        legacy.effective_rbac_inventory.schema_version
        == "athena.wc028MonitoringEffectiveRbacInventory.v3"
    )


def _legacy_v9_trust_hardened_contract() -> MonitoringCollectorContract:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    payload.update(
        {
            "schemaVersion": "athena.wc028MonitoringCollectorContract.v9",
            "resourceHealthAllowedOperations": (
                PREVIOUS_PERMISSION_ATTESTED_RESOURCE_HEALTH_OPERATIONS
            ),
            "allowedReadOperations": (
                *(
                    operation
                    for operation in _collector_contract().allowed_read_operations
                    if not operation.startswith("Microsoft.OperationalInsights/workspaces")
                ),
                *PREVIOUS_PERMISSION_ATTESTED_RESOURCE_HEALTH_OPERATIONS,
                *RESOURCE_LOG_OPERATIONS,
            ),
        }
    )
    for field in V10_ONLY_CONTRACT_FIELDS:
        payload.pop(field, None)
    inventory = MonitoringEffectiveRbacInventory(
        **_previous_trust_hardened_effective_rbac_inventory(payload)
    )
    payload["effectiveRbacInventory"] = inventory
    payload["effectiveRbacInventoryAttestation"] = _effective_rbac_inventory_attestation(inventory)
    return MonitoringCollectorContract(**payload)


def test_legacy_v9_trust_hardened_contract_remains_readable() -> None:
    legacy = _legacy_v9_trust_hardened_contract()

    assert legacy.schema_version == "athena.wc028MonitoringCollectorContract.v9"
    assert legacy.resource_graph_query_role_definition_id is None
    assert legacy.resource_health_allowed_operations == (
        PREVIOUS_PERMISSION_ATTESTED_RESOURCE_HEALTH_OPERATIONS
    )
    assert legacy.effective_rbac_inventory is not None
    assert (
        legacy.effective_rbac_inventory.schema_version
        == "athena.wc028MonitoringEffectiveRbacInventory.v4"
    )


def test_v10_contract_rejects_v9_graph_only_inventory_topology() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    legacy = _legacy_v9_trust_hardened_contract()
    payload["effectiveRbacInventory"] = legacy.effective_rbac_inventory
    payload["effectiveRbacInventoryAttestation"] = legacy.effective_rbac_inventory_attestation

    with pytest.raises(
        ValidationError,
        match="does not match exact deployed assignments|version-bound effective RBAC inventory",
    ):
        MonitoringCollectorContract(**payload)


def test_v10_contract_rejects_v5_unbound_ancestor_evidence() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    previous_inventory = MonitoringEffectiveRbacInventory(
        **_previous_target_unbound_effective_rbac_inventory(payload)
    )
    assert (
        previous_inventory.schema_version
        == "athena.wc028MonitoringEffectiveRbacInventory.v5"
    )
    payload["effectiveRbacInventory"] = previous_inventory

    with pytest.raises(
        ValidationError,
        match="version-bound effective RBAC inventory",
    ):
        MonitoringCollectorContract(**payload)


def test_v10_contract_rejects_v1_inventory_attestation_domain() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    inventory = MonitoringEffectiveRbacInventory(**payload["effectiveRbacInventory"])
    payload["effectiveRbacInventoryAttestation"] = _effective_rbac_inventory_attestation(
        inventory,
        schema_version="athena.wc028MonitoringEffectiveRbacInventoryAttestation.v1",
    )

    with pytest.raises(
        ValidationError,
        match="attestation does not match its reviewed authority",
    ):
        MonitoringCollectorContract(**payload)


def test_v9_contract_rejects_v2_inventory_attestation_domain() -> None:
    payload = _legacy_v9_trust_hardened_contract().model_dump(
        mode="python",
        by_alias=True,
        exclude_none=True,
    )
    inventory = MonitoringEffectiveRbacInventory(**payload["effectiveRbacInventory"])
    payload["effectiveRbacInventoryAttestation"] = _effective_rbac_inventory_attestation(
        inventory,
        schema_version="athena.wc028MonitoringEffectiveRbacInventoryAttestation.v2",
    )

    with pytest.raises(
        ValidationError,
        match="attestation does not match its reviewed authority",
    ):
        MonitoringCollectorContract(**payload)


def test_receipt_verifier_rejects_v9_contract_before_receipt_evaluation() -> None:
    with pytest.raises(
        ValueError,
        match="production acquisition verification requires",
    ):
        verify_monitoring_acquisition_receipt_attestation(
            MonitoringAcquisitionReceipt.model_construct(),
            as_of=datetime(2026, 9, 21, tzinfo=UTC),
            trusted_key_anchor=TrustedKeyAnchor.from_key_vault_key_id(
                REVIEWED_SIGNING_KEY_URI,
                public_key_fingerprint="sha256:" + ("0" * 64),
            ),
            key_resolver=lambda _anchor: None,
            reviewed_collector_contract=_legacy_v9_trust_hardened_contract(),
            expected_acquisition_authority_digest="sha256:" + ("1" * 64),
            maximum_receipt_age_seconds=600,
            expected_runtime_replay_binding=MonitoringRuntimeReplayBinding.model_construct(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("ipFlowVerifyRoleDefinitionId", READER_ROLE_DEFINITION_ID),
        ("ipFlowVerifyScopeId", f"{NETWORK_WATCHER_RESOURCE_ID}/flowLogs/synthetic"),
        (
            "ipFlowVerifyAllowedOperations",
            ("Microsoft.Network/networkWatchers/ipFlowVerify/read",) * 2,
        ),
        (
            "allowedReadOperations",
            _collector_contract().allowed_read_operations,
        ),
        ("collectorTenantId", None),
        ("identityProofAudience", "api://unreviewed-proof"),
        ("identityProofRequiredRole", None),
        ("identityProofMaximumLifetimeSeconds", None),
        ("resourceGraphQueryRoleDefinitionId", READER_ROLE_DEFINITION_ID),
        ("resourceGraphQueryScopeId", f"/subscriptions/{SUBSCRIPTION_ID}"),
        ("resourceHealthRoleDefinitionId", READER_ROLE_DEFINITION_ID),
        ("resourceHealthScopeIds", SIGNAL_READ_SCOPE_IDS[:-1]),
        (
            "resourceHealthScopeIds",
            (*SIGNAL_READ_SCOPE_IDS[:-1], UNAPPROVED_PEER_VM_ID),
        ),
        (
            "resourceHealthAllowedOperations",
            ("Microsoft.ResourceHealth/availabilityStatuses/current/read",),
        ),
        (
            "resourceHealthAllowedOperations",
            RESOURCE_HEALTH_ROLE_OPERATIONS,
        ),
        (
            "resourceHealthAllowedOperations",
            RESOURCE_GRAPH_QUERY_OPERATIONS,
        ),
        ("resourceHealthAllowedOperations", ("Microsoft.ResourceHealth/events/read",)),
        ("workspaceAccessControlMode", "workspaceOnly"),
        ("workspaceResourceContextAccessEnabled", None),
        ("workspaceSkuName", None),
        (
            "resourceContextTablePlans",
            tuple(
                {
                    **item,
                    "plan": "Basic" if item["table"] == "Heartbeat" else "Analytics",
                }
                for item in RESOURCE_CONTEXT_TABLE_PLANS
            ),
        ),
        ("resourceIdColumn", None),
        ("logQueryPreferHeader", None),
        ("flowTableAcquisitionMode", None),
        (
            "resourceLogAllowedOperations",
            ("Microsoft.Insights/Logs/*/Read",) * 5,
        ),
        ("rbacAttestorIdentityResourceId", None),
        ("rbacAttestorRoleDefinitionId", READER_ROLE_DEFINITION_ID),
        ("rbacAttestorAllowedOperations", RBAC_ATTESTOR_OPERATIONS[:-1]),
        ("effectiveRbacInventory", None),
        ("acquisitionReceiptSchemaVersion", None),
    ),
)
def test_acquisition_contract_rejects_missing_or_incorrect_permission_policy(
    field: str,
    value: object,
) -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    payload[field] = value

    with pytest.raises(ValidationError):
        MonitoringCollectorContract(**payload)


@pytest.mark.parametrize(
    ("role_definition_id", "role_definition_name", "assignment_scope_ids"),
    (
        (
            RESOURCE_GRAPH_QUERY_ROLE_DEFINITION_ID,
            RESOURCE_GRAPH_QUERY_ROLE_NAME,
            (f"/subscriptions/{SUBSCRIPTION_ID}",),
        ),
        (
            RESOURCE_GRAPH_QUERY_ROLE_DEFINITION_ID,
            RESOURCE_GRAPH_QUERY_ROLE_NAME,
            (SIGNAL_READ_SCOPE_IDS[0],),
        ),
        (
            RESOURCE_HEALTH_ROLE_DEFINITION_ID,
            RESOURCE_HEALTH_ROLE_NAME,
            (*SIGNAL_READ_SCOPE_IDS[:-1], UNAPPROVED_PEER_VM_ID),
        ),
    ),
)
def test_effective_rbac_rejects_inexact_resource_health_authorization_scopes(
    role_definition_id: str,
    role_definition_name: str,
    assignment_scope_ids: tuple[str, ...],
) -> None:
    contract = _acquisition_collector_contract()
    payload = contract.model_dump(mode="python", by_alias=True)
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    replacement = _effective_rbac_grant(
        principal_id=str(contract.monitoring_reader_principal_id),
        role_definition_id=role_definition_id,
        role_definition_name=role_definition_name,
        assignment_scope_ids=assignment_scope_ids,
    )
    inventory["collectorGrants"] = tuple(
        replacement
        if item["roleDefinitionId"] == role_definition_id.casefold()
        else item
        for item in tuple(inventory["collectorGrants"])
    )
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="does not match exact deployed assignments",
    ):
        MonitoringCollectorContract(**payload)


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("resourceGraphQueryRoleActions", ()),
        (
            "resourceHealthRoleActions",
            tuple(item.casefold() for item in RESOURCE_GRAPH_QUERY_OPERATIONS),
        ),
    ),
)
def test_effective_rbac_rejects_missing_query_or_availability_permission(
    field_name: str,
    value: object,
) -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory[field_name] = value
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError):
        MonitoringCollectorContract(**payload)


def test_acquisition_contract_rejects_unexpected_effective_rbac_paths() -> None:
    base_contract = _acquisition_collector_contract()
    principal_id = str(base_contract.monitoring_reader_principal_id)
    group_id = "33333333-3333-3333-3333-333333333333"
    cases = (
        (
            _effective_rbac_grant(
                principal_id=principal_id,
                role_definition_id=(
                    f"/subscriptions/{SUBSCRIPTION_ID}/providers/"
                    "Microsoft.Authorization/roleDefinitions/"
                    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
                ),
                role_definition_name="Owner",
                assignment_scope_ids=(f"/subscriptions/{SUBSCRIPTION_ID}",),
                inheritance="inherited",
            ),
            (),
        ),
        (
            _effective_rbac_grant(
                principal_id=principal_id,
                assigned_principal_id=group_id,
                assigned_principal_type="Group",
                group_derived=True,
                role_definition_id=READER_ROLE_DEFINITION_ID,
                role_definition_name="Reader",
                assignment_scope_ids=(WORKLOAD_RESOURCE_GROUP_ROOT,),
            ),
            (group_id,),
        ),
        (
            _effective_rbac_grant(
                principal_id=principal_id,
                role_definition_id=READER_ROLE_DEFINITION_ID,
                role_definition_name="Reader",
                assignment_scope_ids=(WORKLOAD_RESOURCE_GROUP_ROOT,),
                condition="synthetic-unreviewed-condition",
                condition_version="2.0",
            ),
            (),
        ),
    )
    for extra_grant, security_group_ids in cases:
        payload = base_contract.model_dump(mode="python", by_alias=True)
        inventory = payload["effectiveRbacInventory"]
        assert isinstance(inventory, dict)
        inventory["collectorGrants"] = (
            *tuple(inventory["collectorGrants"]),
            extra_grant,
        )
        inventory["collectorSecurityGroupIds"] = security_group_ids
        _recompute_effective_rbac_inventory(inventory)

        with pytest.raises(
            ValidationError,
            match="effective RBAC",
        ):
            MonitoringCollectorContract(**payload)


def test_acquisition_contract_rejects_incomplete_effective_rbac_inventory() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["subscriptionDescendantCollectionComplete"] = False
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError):
        MonitoringCollectorContract(**payload)


def test_current_rbac_inventory_requires_tenant_root_management_group() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["managementGroupAncestry"] = ()
    inventory["ancestorScopeCollectionComplete"] = True
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="exact collectable scope evidence",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_inventory_rejects_broken_management_group_parent_chain() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    hierarchy = inventory["managementGroupHierarchyEvidence"]
    assert isinstance(hierarchy, dict)
    edges = [dict(item) for item in tuple(hierarchy["parentEdges"])]
    edge_payload = {
        "childScopeId": edges[0]["childScopeId"],
        "parentScopeId": (
            "/providers/microsoft.management/managementgroups/ffffffff-ffff-ffff-ffff-ffffffffffff"
        ),
    }
    edges[0] = {
        **edge_payload,
        "edgeDigest": compute_artifact_digest(_json_value(edge_payload)),
    }
    hierarchy["parentEdges"] = tuple(edges)
    _recompute_nested_evidence(hierarchy)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="hierarchy evidence is incomplete",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_inventory_requires_exact_runtime_support_storage_grant() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["runtimeSupportGrants"] = ()
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError):
        MonitoringCollectorContract(**payload)


def test_current_rbac_inventory_rejects_runtime_support_storage_deny() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["denyAssignments"] = (
        _deny_assignment(
            principal_id=RUNTIME_SUPPORT_PRINCIPAL_ID,
            actions=("Microsoft.Storage/storageAccounts/read",),
            scope_id=f"/subscriptions/{SUBSCRIPTION_ID}",
        ),
    )
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="runtime storage verification",
    ):
        MonitoringCollectorContract(**payload)


def test_context_identity_is_forbidden_on_canonical_flow_log_child_scope() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    context_grant = _effective_rbac_grant(
        principal_id=str(payload["athenaContextPrincipalId"]),
        role_definition_id=READER_ROLE_DEFINITION_ID,
        role_definition_name="Reader",
        assignment_scope_ids=(RESOURCE_READ_SCOPE_IDS[-1],),
    )
    inventory["athenaContextGrants"] = (context_grant,)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="effective RBAC inventory does not match exact deployed assignments",
    ):
        MonitoringCollectorContract(**payload)


@pytest.mark.parametrize(
    "scope_id",
    (
        RESOURCE_READ_SCOPE_IDS[0],
        SIGNAL_READ_SCOPE_IDS[0],
        WORKSPACE_ID,
        f"{WORKSPACE_ID}/tables/{REVIEWED_LOG_TABLES[0]}",
        REVIEWED_WORKLOAD_VNET_ID,
        EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID,
        f"{EVIDENCE_STORAGE_ACCOUNT_RESOURCE_ID}/blobServices/default",
        SIGNING_KEY_VAULT_RESOURCE_ID,
        NETWORK_WATCHER_RESOURCE_ID,
    ),
)
def test_context_identity_is_forbidden_on_each_distinct_acquisition_read_scope(
    scope_id: str,
) -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["athenaContextGrants"] = (
        _effective_rbac_grant(
            principal_id=str(payload["athenaContextPrincipalId"]),
            role_definition_id=READER_ROLE_DEFINITION_ID,
            role_definition_name="Reader",
            assignment_scope_ids=(scope_id,),
        ),
    )
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="effective RBAC inventory does not match exact deployed assignments",
    ):
        MonitoringCollectorContract(**payload)


def test_context_group_grant_is_forbidden_on_workspace_table_scope() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    group_id = "33333333-3333-3333-3333-333333333333"
    inventory["athenaContextSecurityGroupIds"] = (group_id,)
    context_evidence = inventory["athenaContextPrincipalEvidence"]
    assert isinstance(context_evidence, dict)
    context_evidence["transitiveGroupIds"] = (group_id,)
    _recompute_principal_evidence(context_evidence)
    inventory["athenaContextGrants"] = (
        _effective_rbac_grant(
            principal_id=str(payload["athenaContextPrincipalId"]),
            assigned_principal_id=group_id,
            assigned_principal_type="Group",
            role_definition_id=READER_ROLE_DEFINITION_ID,
            role_definition_name="Reader",
            assignment_scope_ids=(f"{WORKSPACE_ID}/tables/{REVIEWED_LOG_TABLES[0]}",),
            inheritance="direct",
            group_derived=True,
        ),
    )
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="effective RBAC inventory does not match exact deployed assignments",
    ):
        MonitoringCollectorContract(**payload)


def test_acquisition_contract_rejects_unbound_effective_rbac_source() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    source_reference = inventory["sourceReference"]
    assert isinstance(source_reference, dict)
    source_reference["contentDigest"] = "sha256:" + "f" * 64
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError, match="effective RBAC inventory"):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_requires_every_exact_target() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["protectedScopeIds"] = tuple(inventory["protectedScopeIds"])[:-1]
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="omitted an exact scope, runtime, or exclusive principal",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_requires_exact_target_query_mode() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorPrincipalEvidence"]
    assert isinstance(evidence, dict)
    target_reads = tuple(evidence["targetReadEvidence"])
    target_reads[0]["queryMode"] = "atScopeOnly"

    with pytest.raises(
        ValidationError,
        match="queryMode",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_legacy_unbound_target_fields() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorPrincipalEvidence"]
    assert isinstance(evidence, dict)
    evidence["queryFilter"] = "assignedTo(principalId)"
    _recompute_principal_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="uniquely bind target, query mode, and page evidence",
    ):
        MonitoringCollectorContract(**payload)


@pytest.mark.parametrize(
    "reused_field",
    ("targetScopeId", "targetDigest", "rawPageDigests", "bindingId"),
)
def test_current_rbac_attestation_rejects_reused_target_binding_material(
    reused_field: str,
) -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorPrincipalEvidence"]
    assert isinstance(evidence, dict)
    target_reads = list(evidence["targetReadEvidence"])
    target_reads[1][reused_field] = target_reads[0][reused_field]
    evidence["targetReadEvidence"] = tuple(target_reads)
    _recompute_principal_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="uniquely bind target, query mode, and page evidence",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_incorrect_target_binding_id() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorPrincipalEvidence"]
    assert isinstance(evidence, dict)
    target_reads = list(evidence["targetReadEvidence"])
    target_reads[0]["bindingId"] = "00000000-0000-0000-0000-000000000000"
    evidence["targetReadEvidence"] = tuple(target_reads)
    _recompute_principal_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="uniquely bind target, query mode, and page evidence",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_reordered_target_reads() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorPrincipalEvidence"]
    assert isinstance(evidence, dict)
    evidence["targetReadEvidence"] = tuple(
        reversed(tuple(evidence["targetReadEvidence"]))
    )
    _recompute_principal_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="uniquely bind target, query mode, and page evidence",
    ):
        MonitoringCollectorContract(**payload)


@pytest.mark.parametrize("scope_mutation", ("missing", "extra"))
def test_current_rbac_attestation_requires_exact_principal_target_set(
    scope_mutation: str,
) -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorPrincipalEvidence"]
    assert isinstance(evidence, dict)
    target_reads = list(evidence["targetReadEvidence"])
    if scope_mutation == "missing":
        target_reads = target_reads[1:]
    else:
        target_scope_id = (
            "/providers/microsoft.management/managementgroups/"
            "11111111-1111-1111-1111-111111111111"
        )
        raw_page_digest = compute_artifact_digest(
            {
                "principalId": evidence["principalId"],
                "targetScopeId": target_scope_id,
                "page": "roleAssignments",
            }
        )
        target_read: dict[str, object] = {
            "targetScopeId": target_scope_id,
            "queryMode": CURRENT_RBAC_TARGET_QUERY_MODE,
            "targetDigest": compute_artifact_digest(
                {
                    "principalId": evidence["principalId"],
                    "targetScopeId": target_scope_id,
                    "queryMode": CURRENT_RBAC_TARGET_QUERY_MODE,
                    "rawPageDigests": [raw_page_digest],
                }
            ),
            "rawPageDigests": (raw_page_digest,),
            "readCount": 2,
            "allPagesRetrieved": True,
        }
        _recompute_target_read_binding(evidence, target_read)
        target_reads.append(target_read)
        target_reads.sort(key=lambda item: str(item["targetScopeId"]))
    evidence["targetReadEvidence"] = tuple(target_reads)
    _recompute_principal_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="runtime and subscription-wide evidence is invalid",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_unapproved_collector_attachment() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorIdentityAttachmentEvidence"]
    assert isinstance(evidence, dict)
    evidence["associatedResourceIds"] = tuple(
        sorted(
            (
                COLLECTOR_RUNTIME_RESOURCE_ID.casefold(),
                COLLECTOR_RUNTIME_RESOURCE_ID.replace(
                    "athena-wc028-monitoring-acquisition",
                    "synthetic-unapproved-job",
                ).casefold(),
            )
        )
    )
    _recompute_nested_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="runtime configuration evidence is incomplete or unstable",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_extra_runtime_identity() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorIdentityAttachmentEvidence"]
    assert isinstance(evidence, dict)
    evidence["associatedResourceIdentityResourceIds"] = tuple(
        sorted(
            (
                *tuple(evidence["associatedResourceIdentityResourceIds"]),
                str(payload["athenaContextIdentityId"]).casefold(),
            )
        )
    )
    evidence["associatedResourceIdentityLifecycles"] = tuple(
        sorted(
            (
                *tuple(evidence["associatedResourceIdentityLifecycles"]),
                {
                    "identityResourceId": str(payload["athenaContextIdentityId"]).casefold(),
                    "lifecycle": "All",
                },
            ),
            key=lambda item: str(item["identityResourceId"]),
        )
    )
    evidence["firstAssociatedResourceConfigurationDigests"] = (
        compute_artifact_digest(
            {
                "resourceId": COLLECTOR_RUNTIME_RESOURCE_ID.casefold(),
                "identityResourceIds": list(evidence["associatedResourceIdentityResourceIds"]),
                "identityLifecycles": list(evidence["associatedResourceIdentityLifecycles"]),
            }
        ),
    )
    evidence["secondAssociatedResourceConfigurationDigests"] = evidence[
        "firstAssociatedResourceConfigurationDigests"
    ]
    _recompute_nested_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)
    _rebind_effective_rbac_inventory_attestation(payload)

    with pytest.raises(
        ValidationError,
        match="omitted an exact scope, runtime, or exclusive principal",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_requires_platform_only_support_identity() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorIdentityAttachmentEvidence"]
    assert isinstance(evidence, dict)
    lifecycles = [dict(item) for item in tuple(evidence["associatedResourceIdentityLifecycles"])]
    for item in lifecycles:
        if item["identityResourceId"] == RUNTIME_SUPPORT_ID.casefold():
            item["lifecycle"] = "All"
    evidence["associatedResourceIdentityLifecycles"] = tuple(lifecycles)
    _recompute_nested_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)
    _rebind_effective_rbac_inventory_attestation(payload)

    with pytest.raises(
        ValidationError,
        match="omitted an exact scope, runtime, or exclusive principal",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_persistent_verifier_attachment() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    verifier_evidence = inventory["reviewerKeyVerifierEvidence"]
    assert isinstance(verifier_evidence, dict)
    attachment = verifier_evidence["attachmentEvidence"]
    assert isinstance(attachment, dict)
    attachment["associatedResourceIds"] = (
        (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/rg-athena-rbac-review/"
            "providers/Microsoft.App/jobs/synthetic-unapproved-verifier"
        ).casefold(),
    )
    _recompute_nested_evidence(attachment)
    _recompute_nested_evidence(verifier_evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="unattached keys/get-only identity",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_federated_collector_credential() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorIdentityAttachmentEvidence"]
    assert isinstance(evidence, dict)
    evidence["federatedIdentityCredentialIds"] = (
        (
            f"{str(payload['collectorIdentityResourceId']).rstrip('/')}/"
            "federatedIdentityCredentials/synthetic-unapproved"
        ).casefold(),
    )
    _recompute_nested_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="runtime and subscription-wide evidence is invalid",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_filtered_attachment_inventory() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["collectorIdentityAttachmentEvidence"]
    assert isinstance(evidence, dict)
    evidence["associatedResourcesRequestPath"] = (
        f"{evidence['associatedResourcesRequestPath']}&$filter=resourceType eq 'Microsoft.App/jobs'"
    )
    _recompute_nested_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="exact unfiltered request paths",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_additional_evidence_writer() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["exclusiveDataPlanePrincipalEvidence"]
    assert isinstance(evidence, dict)
    evidence["evidenceWriterAuthorizedPrincipalIds"] = (
        str(payload["monitoringReaderPrincipalId"]),
        "88888888-8888-8888-8888-888888888888",
    )
    _recompute_nested_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)
    _rebind_effective_rbac_inventory_attestation(payload)

    with pytest.raises(
        ValidationError,
        match="omitted an exact scope, runtime, or exclusive principal",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_requires_unfiltered_all_principal_scan() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["exclusiveDataPlanePrincipalEvidence"]
    assert isinstance(evidence, dict)
    evidence["queryFilter"] = "atScope()"
    _recompute_nested_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError, match="Input should be 'none'"):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_nonexclusive_data_plane_auth_mode() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["exclusiveDataPlanePrincipalEvidence"]
    assert isinstance(evidence, dict)
    evidence["evidenceStorageSharedKeyAccessEnabled"] = True
    _recompute_nested_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError, match="Input should be False"):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_requires_complete_storage_readback_pages() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    evidence = inventory["exclusiveDataPlanePrincipalEvidence"]
    assert isinstance(evidence, dict)
    evidence["firstResourceConfigurationDigests"] = tuple(
        evidence["firstResourceConfigurationDigests"]
    )[:2]
    evidence["secondResourceConfigurationDigests"] = tuple(
        evidence["secondResourceConfigurationDigests"]
    )[:2]
    _recompute_nested_evidence(evidence)
    _recompute_effective_rbac_inventory(inventory)
    _rebind_effective_rbac_inventory_attestation(payload)

    with pytest.raises(
        ValidationError,
        match="omitted an exact scope, runtime, or exclusive principal",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_inventory_rejects_reviewer_signature_tampering() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    attestation = payload["effectiveRbacInventoryAttestation"]
    assert isinstance(attestation, dict)
    attestation["signature"] = base64.b64encode(b"synthetic-forged-reviewer-signature").decode(
        "ascii"
    )

    with pytest.raises(
        ValidationError,
        match="reviewer signature is invalid",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_inventory_requires_separately_governed_reviewer_vault() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory_payload = payload["effectiveRbacInventory"]
    assert isinstance(inventory_payload, dict)
    inventory = MonitoringEffectiveRbacInventory(**inventory_payload)
    same_vault_key_id = (
        "https://athenademomonkv.vault.azure.net/keys/"
        "monitoring-rbac-inventory-review/0123456789abcdef0123456789abcdef"
    )
    with pytest.raises(
        ValidationError,
        match="attestation authority or cleanup binding is invalid",
    ):
        _effective_rbac_inventory_attestation(
            inventory,
            reviewer_key_id=same_vault_key_id,
        )


def test_current_rbac_attestation_rejects_unstable_or_incomplete_pages() -> None:
    for field, value, expected in (
        ("secondRawSnapshotDigest", "sha256:" + "0" * 64, "stable"),
        ("denyAssignmentCollectionComplete", False, "literal_error"),
    ):
        payload = _acquisition_collector_contract().model_dump(
            mode="python",
            by_alias=True,
        )
        inventory = payload["effectiveRbacInventory"]
        assert isinstance(inventory, dict)
        inventory[field] = value
        if field == "secondRawSnapshotDigest":
            inventory.pop("inventoryDigest", None)
            inventory["inventoryDigest"] = compute_artifact_digest(_json_value(inventory))
        else:
            _recompute_effective_rbac_inventory(inventory)

        with pytest.raises(ValidationError, match=expected):
            MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_requires_distinct_read_receipt_times() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["secondReadCompletedAt"] = inventory["firstReadCompletedAt"]
    inventory.pop("inventoryDigest")
    inventory["inventoryDigest"] = compute_artifact_digest(_json_value(inventory))

    with pytest.raises(ValidationError, match="read receipts are not distinct"):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_second_global_read_page_drift() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["secondRoleDefinitionRawPageDigests"] = ("sha256:" + "f" * 64,)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError, match="stable separate-attestor evidence"):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_reused_principal_target_page_digest() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    collector_evidence = inventory["collectorPrincipalEvidence"]
    assert isinstance(collector_evidence, dict)
    target_reads = tuple(collector_evidence["targetReadEvidence"])
    target_reads[1]["rawPageDigests"] = target_reads[0]["rawPageDigests"]
    _recompute_principal_evidence(collector_evidence)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="uniquely bind target, query mode, and page evidence",
    ):
        MonitoringCollectorContract(**payload)


def test_current_rbac_attestation_rejects_missing_roles_and_conditions() -> None:
    missing_role = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    missing_inventory = missing_role["effectiveRbacInventory"]
    assert isinstance(missing_inventory, dict)
    missing_inventory["roleDefinitions"] = tuple(missing_inventory["roleDefinitions"])[1:]
    _recompute_effective_rbac_inventory(missing_inventory)
    with pytest.raises(
        ValidationError,
        match="omitted a referenced full role definition",
    ):
        MonitoringCollectorContract(**missing_role)

    conditioned = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    conditioned_inventory = conditioned["effectiveRbacInventory"]
    assert isinstance(conditioned_inventory, dict)
    grant = dict(tuple(conditioned_inventory["collectorGrants"])[0])
    grant["condition"] = "synthetic unsupported condition"
    grant["conditionVersion"] = "2.0"
    grant.pop("grantDigest")
    grant["grantDigest"] = compute_artifact_digest(_json_value(grant))
    conditioned_inventory["collectorGrants"] = (
        grant,
        *tuple(conditioned_inventory["collectorGrants"])[1:],
    )
    _recompute_effective_rbac_inventory(conditioned_inventory)
    with pytest.raises(
        ValidationError,
        match="does not match exact deployed assignments",
    ):
        MonitoringCollectorContract(**conditioned)


def test_current_rbac_attestation_evaluates_wildcard_denies_and_active_pim() -> None:
    denied = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    denied_inventory = denied["effectiveRbacInventory"]
    assert isinstance(denied_inventory, dict)
    denied_inventory["denyAssignments"] = (
        _deny_assignment(
            principal_id=str(denied["monitoringReaderPrincipalId"]),
            actions=("*/read",),
        ),
    )
    _recompute_effective_rbac_inventory(denied_inventory)
    with pytest.raises(ValidationError, match="deny assignment removes"):
        MonitoringCollectorContract(**denied)

    pim = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    pim_inventory = pim["effectiveRbacInventory"]
    assert isinstance(pim_inventory, dict)
    pim_inventory["activePimScheduleInstances"] = (
        _pim_schedule_instance(
            principal_id=str(pim["monitoringReaderPrincipalId"]),
            role_definition_id=READER_ROLE_DEFINITION_ID,
        ),
    )
    _recompute_effective_rbac_inventory(pim_inventory)
    with pytest.raises(ValidationError, match="must not depend on active PIM"):
        MonitoringCollectorContract(**pim)


def test_current_rbac_attestation_treats_all_zero_principal_as_wildcard() -> None:
    denied = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    denied_inventory = denied["effectiveRbacInventory"]
    assert isinstance(denied_inventory, dict)
    denied_inventory["denyAssignments"] = (
        _deny_assignment(
            principal_id="00000000-0000-0000-0000-000000000000",
            actions=("*/read",),
        ),
    )
    _recompute_effective_rbac_inventory(denied_inventory)

    with pytest.raises(ValidationError, match="deny assignment removes"):
        MonitoringCollectorContract(**denied)


def test_current_rbac_attestation_honors_all_principals_exclusion() -> None:
    allowed = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    allowed_inventory = allowed["effectiveRbacInventory"]
    assert isinstance(allowed_inventory, dict)
    allowed_inventory["denyAssignments"] = (
        _deny_assignment(
            principal_id="00000000-0000-0000-0000-000000000000",
            actions=("*/read",),
            excluded_principal_ids=(
                str(allowed["monitoringReaderPrincipalId"]),
                RUNTIME_SUPPORT_PRINCIPAL_ID,
            ),
        ),
    )
    _recompute_effective_rbac_inventory(allowed_inventory)
    _rebind_effective_rbac_inventory_attestation(allowed)

    assert MonitoringCollectorContract(**allowed)


def test_current_rbac_attestation_honors_all_principals_group_exclusion() -> None:
    allowed = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = allowed["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    group_id = "33333333-3333-3333-3333-333333333333"
    inventory["collectorSecurityGroupIds"] = (group_id,)
    collector_evidence = inventory["collectorPrincipalEvidence"]
    assert isinstance(collector_evidence, dict)
    collector_evidence["transitiveGroupIds"] = (group_id,)
    _recompute_principal_evidence(collector_evidence)
    inventory["denyAssignments"] = (
        _deny_assignment(
            principal_id="00000000-0000-0000-0000-000000000000",
            actions=("*/read",),
            excluded_principal_ids=(group_id, RUNTIME_SUPPORT_PRINCIPAL_ID),
        ),
    )
    _recompute_effective_rbac_inventory(inventory)
    _rebind_effective_rbac_inventory_attestation(allowed)

    assert MonitoringCollectorContract(**allowed)


def test_current_rbac_attestation_rejects_all_principals_as_an_exclusion() -> None:
    invalid = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = invalid["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["denyAssignments"] = (
        _deny_assignment(
            principal_id=str(invalid["monitoringReaderPrincipalId"]),
            actions=("*/read",),
            excluded_principal_ids=("00000000-0000-0000-0000-000000000000",),
        ),
    )
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(
        ValidationError,
        match="All Principals cannot appear in excludedPrincipalIds",
    ):
        MonitoringCollectorContract(**invalid)


def test_current_rbac_attestation_conservatively_applies_returned_ancestor_deny() -> None:
    denied = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    denied_inventory = denied["effectiveRbacInventory"]
    assert isinstance(denied_inventory, dict)
    denied_inventory["denyAssignments"] = (
        _deny_assignment(
            principal_id=str(denied["monitoringReaderPrincipalId"]),
            actions=("*/read",),
            scope_id=(f"/providers/microsoft.management/managementgroups/{COLLECTOR_TENANT_ID}"),
        ),
    )
    _recompute_effective_rbac_inventory(denied_inventory)

    with pytest.raises(ValidationError, match="deny assignment removes"):
        MonitoringCollectorContract(**denied)


def test_current_rbac_attestation_requires_transitive_group_evidence() -> None:
    payload = _acquisition_collector_contract().model_dump(
        mode="python",
        by_alias=True,
    )
    inventory = payload["effectiveRbacInventory"]
    assert isinstance(inventory, dict)
    inventory["collectorSecurityGroupIds"] = ("33333333-3333-3333-3333-333333333333",)
    _recompute_effective_rbac_inventory(inventory)

    with pytest.raises(ValidationError, match="groups"):
        MonitoringCollectorContract(**payload)


def test_collector_contract_bicep_output_matches_the_production_contract() -> None:
    source = COLLECTOR_CONTRACT_MODULE.read_text(encoding="utf-8")
    output_fields = set(
        re.findall(
            r"^  (?P<field>[a-zA-Z][a-zA-Z0-9]*):",
            source.split("var collectorContract = {", maxsplit=1)[1].split("\n}", maxsplit=1)[0],
            flags=re.MULTILINE,
        )
    )
    bicep_output = _collector_contract().model_dump(by_alias=True, exclude_none=True)
    expected_fields = set(bicep_output)

    assert output_fields == expected_fields == set(bicep_output)
    assert MonitoringCollectorContract(**bicep_output) == _collector_contract()
    for operation in _collector_contract().allowed_read_operations:
        assert f"'{operation}'" in source
    assert "output collectorContract object = collectorContract" in source
    assert "athena.wc028MonitoringCollectorContract.v10" in source
    assert "athena.wc028MonitoringEvidenceHandoff.v2" in source


@pytest.mark.parametrize(
    "change",
    [
        {"signalKinds": ("heartbeat",) * 8},
        {"allowedReadOperations": ("Microsoft.Insights/Metrics/Read",) * 10},
        {"authorizationMode": "customRole"},
        {"workspaceAccessControlMode": "unknown"},
        {"logAnalyticsAllowedTables": ("Heartbeat",) * 13},
        {"logAnalyticsAccessCondition": "allow everything"},
        {"resourceReadScopeIds": RESOURCE_READ_SCOPE_IDS[:-1]},
        {"signalReadScopeIds": SIGNAL_READ_SCOPE_IDS[:-1]},
        {"maximumEvidenceAgeSeconds": 901},
        {"connectionMonitorMode": "configured"},
        {"unpublishedEndpointPath": "synthetic"},
    ],
)
def test_collector_contract_fails_closed_for_non_generic_configuration(
    change: dict[str, object],
) -> None:
    payload = _collector_contract().model_dump(by_alias=True)
    payload.update(change)

    with pytest.raises(ValidationError):
        MonitoringCollectorContract(**payload)


def test_signed_handoff_binds_exact_version_pinned_evidence() -> None:
    handoff = _signed_handoff()

    assert handoff.evidence.name == "wc024-monitoring/wc024-0123456789ab/evidence.json"
    assert monitoring_handoff_preimage(handoff)["domain"] == (
        MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION
    )


def test_signed_handoff_rejects_changed_reference_or_attestation_binding() -> None:
    payload = _signed_handoff().model_dump(by_alias=True)
    payload["evidence"]["contentDigest"] = "sha256:" + "b" * 64  # type: ignore[index]

    with pytest.raises(ValidationError):
        MonitoringEvidenceHandoff(**payload)


def test_reviewed_collector_contract_must_authorize_handoff_version() -> None:
    payload = _handoff_payload()
    payload["schemaVersion"] = "athena.wc028MonitoringEvidenceHandoff.v2"
    payload["acquisitionReceiptDigest"] = "sha256:" + "f" * 64
    evidence = payload["evidence"]
    assert isinstance(evidence, VersionPinnedBlobReference)
    handoff = MonitoringEvidenceHandoff(
        **payload,
        collectorAttestation=MonitoringEvidenceAttestation(
            signatureAlgorithm="RS256",
            trustAnchorRef=REVIEWED_SIGNING_KEY_URI,
            signedPreimageDigest=compute_artifact_digest(
                monitoring_handoff_preimage(
                    {
                        **payload,
                        "evidence": evidence.model_dump(
                            mode="json",
                            by_alias=True,
                        ),
                    }
                )
            ),
            signature=base64.b64encode(b"synthetic-signature").decode("ascii"),
        ),
    )
    _, contract, anchor, record = _trusted_signed_handoff()

    with pytest.raises(ValueError, match="schema is not authorized"):
        verify_monitoring_evidence_handoff_attestation(
            handoff,
            as_of=handoff.observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
        )
    with pytest.raises(ValueError, match="full reviewed collector contract"):
        verify_monitoring_evidence_handoff_attestation(
            handoff,
            as_of=handoff.observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            expected_collector_contract_digest=contract.compute_artifact_digest_value(),
            reviewed_maximum_evidence_age_seconds=(contract.maximum_evidence_age_seconds),
            reviewed_signing_key_resource_id=contract.signing_key_resource_id,
            expected_handoff_schema_version=("athena.wc028MonitoringEvidenceHandoff.v2"),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "workloadResourceGroupId",
            "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/"
            "rg-athena-demo-workload",
        ),
        (
            "workspaceResourceId",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-workload/providers/Microsoft.OperationalInsights/workspaces/"
            "athena-demo-monitoring-law",
        ),
        (
            "workloadVirtualNetworkResourceId",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
            "rg-athena-demo-workload/providers/Microsoft.Network/virtualNetworks/"
            "other-vnet",
        ),
        ("approvedVmNames", ("athena-hackathon-web-01",) * 11),
        ("signingKeyResourceId", "not-a-versioned-key-uri"),
        ("evidenceStorageAccountResourceId", "not-a-resource-id"),
    ],
)
def test_collector_contract_fails_closed_for_invalid_scope_or_resource_ids(
    field: str,
    value: str,
) -> None:
    payload = _collector_contract().model_dump(by_alias=True)
    payload[field] = value

    with pytest.raises(ValidationError):
        MonitoringCollectorContract(**payload)


def _trusted_signed_handoff() -> tuple[
    MonitoringEvidenceHandoff,
    MonitoringCollectorContract,
    TrustedKeyAnchor,
    TrustedKeyRecord,
]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    handoff = _signed_handoff()
    signature = base64.b64encode(
        private_key.sign(
            canonicalize_json(monitoring_handoff_preimage(handoff)).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    ).decode("ascii")
    attestation = handoff.collector_attestation.model_copy(update={"signature": signature})
    signed_handoff = handoff.model_copy(update={"collector_attestation": attestation})
    public_key = private_key.public_key()
    fingerprint = sha256_hex(
        public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    anchor = TrustedKeyAnchor.from_key_vault_key_id(
        attestation.trust_anchor_ref,
        public_key_fingerprint=fingerprint,
    )
    record = TrustedKeyRecord(
        anchor=anchor,
        public_key=public_key,
        enabled=True,
        activated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    return signed_handoff, _collector_contract(), anchor, record


def _selected_incident() -> MonitoringSelectedIncident:
    selected = build_selected_incident(
        incident_resource_id=SIGNAL_READ_SCOPE_IDS[0],
        previous_record_id="heartbeat-previous",
        current_record_ids=("heartbeat-current",),
        current_state="unhealthy",
    )
    return MonitoringSelectedIncident.model_validate(
        {
            "incidentResourceId": selected.incident_resource_id,
            "previousRecordId": selected.previous_record_id,
            "currentRecordIds": selected.current_record_ids,
            "currentState": selected.current_state,
            "transitionDigest": selected.transition_digest,
        }
    )


def test_signed_acquisition_receipt_reverifies_deployed_identity_policy() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    contract = _acquisition_collector_contract()
    reader_identity = contract.collector_identity_resource_id
    reader_principal = contract.monitoring_reader_principal_id
    reader_client = contract.collector_identity_client_id
    reader_tenant = contract.collector_tenant_id
    context_identity = contract.athena_context_identity_id
    context_principal = contract.athena_context_principal_id
    assert reader_principal is not None
    assert reader_tenant is not None
    assert context_identity is not None
    assert context_principal is not None
    effective_rbac_inventory = contract.effective_rbac_inventory
    assert effective_rbac_inventory is not None
    deployment_digest = compute_artifact_digest(
        {
            "monitoringReaderIdentityId": reader_identity.casefold(),
            "monitoringReaderPrincipalId": reader_principal,
            "monitoringReaderClientId": reader_client,
            "monitoringReaderTenantId": reader_tenant,
            "athenaContextIdentityId": context_identity.casefold(),
            "athenaContextPrincipalId": context_principal,
            "effectiveRbacInventoryDigest": effective_rbac_inventory.inventory_digest,
            "effectiveRbacSourceManifestDigest": (effective_rbac_inventory.source_manifest_digest),
        }
    )
    authority_digest = "sha256:" + "c" * 64
    collector_digest = contract.compute_artifact_digest_value()
    observed_at = datetime(2026, 9, 10, 2, 0, tzinfo=UTC)
    proof_payload: dict[str, object] = {
        "schemaVersion": "athena.wc028MonitoringIdentityProof.v1",
        "tokenVersion": MONITORING_IDENTITY_PROOF_TOKEN_VERSION,
        "tenantId": reader_tenant,
        "principalId": reader_principal,
        "clientId": reader_client,
        "subject": reader_principal,
        "issuer": f"https://sts.windows.net/{reader_tenant}/",
        "audience": MONITORING_IDENTITY_PROOF_AUDIENCE,
        "identityType": "app",
        "roles": [MONITORING_IDENTITY_PROOF_REQUIRED_ROLE],
        "tokenHash": "sha256:" + "6" * 64,
        "keyId": "synthetic-kid",
        "issuedAt": observed_at,
        "notBefore": observed_at,
        "expiresAt": observed_at.replace(hour=3),
        "verifiedAt": observed_at,
    }
    proof = MonitoringIdentityProof(
        **{
            **proof_payload,
            "roles": (MONITORING_IDENTITY_PROOF_REQUIRED_ROLE,),
        },
        proofDigest=compute_artifact_digest(proof_payload),
    )
    replay_payload = {
        "schemaVersion": "athena.wc028MonitoringPersistenceReplay.v3",
        "executionId": "wc028-execution-" + ("8" * 32),
        "acquisitionAuthorityDigest": authority_digest,
        "monitoringIntentDigest": "sha256:" + ("2" * 64),
        "monitoringIntentReferenceDigest": "sha256:" + ("7" * 64),
        "contextBindingDigest": "sha256:" + ("3" * 64),
        "incidentRevision": 1,
        "legacyCollectorRbacCleanupDigest": LEGACY_COLLECTOR_RBAC_CLEANUP_DIGEST,
        "monitoringEvidenceStorageReadinessDigest": STORAGE_READINESS_DIGEST,
        "issuedAt": observed_at,
        "trustedAsOf": observed_at.replace(minute=1),
        "expiresAt": observed_at.replace(minute=10),
        "trustDelaySeconds": 60,
        "requestLifetimeSeconds": 600,
    }
    runtime_replay_binding = MonitoringRuntimeReplayBinding(
        **replay_payload,
        persistenceReplayKey=compute_artifact_digest(
            monitoring_runtime_replay_key_preimage(replay_payload)
        ),
    )
    exchange = MonitoringAcquisitionExchange(
        sequence=1,
        source="ipFlowVerify",
        requestDigest="sha256:" + "d" * 64,
        resultDigest="sha256:" + "e" * 64,
        requestedAt=observed_at,
        receivedAt=observed_at,
        checkedAt=observed_at,
        identityProofDigest=proof.proof_digest,
        effectiveRbacInventoryDigest=effective_rbac_inventory.inventory_digest,
        effectiveRbacSourceManifestDigest=(effective_rbac_inventory.source_manifest_digest),
        effectiveRbacValidFrom=effective_rbac_inventory.collected_at,
        effectiveRbacValidUntil=effective_rbac_inventory.expires_at,
    )
    wire_attempt = MonitoringAcquisitionWireAttempt(
        sequence=1,
        exchangeSequence=1,
        source="ipFlowVerify",
        requestDigest=exchange.request_digest,
        logicalRequestDigest=exchange.request_digest,
        resultDigest=exchange.result_digest,
        exchangeResultDigest=exchange.result_digest,
        requestedAt=observed_at,
        receivedAt=observed_at,
        effectiveRbacInventoryDigest=effective_rbac_inventory.inventory_digest,
        effectiveRbacSourceManifestDigest=(effective_rbac_inventory.source_manifest_digest),
        effectiveRbacValidFrom=effective_rbac_inventory.collected_at,
        effectiveRbacValidUntil=effective_rbac_inventory.expires_at,
    )
    selected_incident = _selected_incident()
    payload: dict[str, object] = {
        "schemaVersion": MONITORING_ACQUISITION_RECEIPT_SCHEMA_VERSION,
        "authenticatedPrincipalId": reader_principal,
        "authenticatedClientId": reader_client,
        "authenticatedTenantId": reader_tenant,
        "monitoringReaderIdentityId": reader_identity,
        "athenaContextIdentityId": context_identity,
        "athenaContextPrincipalId": context_principal,
        "deploymentIdentityContractDigest": deployment_digest,
        "acquisitionAuthorityDigest": authority_digest,
        "collectorContractDigest": collector_digest,
        "intentId": "monitoring-intent-" + "1" * 32,
        "intentDigest": "sha256:" + "2" * 64,
        "contextBindingDigest": "sha256:" + "3" * 64,
        "collectionBatchDigest": "sha256:" + "4" * 64,
        "normalizedEvidenceDigest": "sha256:" + "5" * 64,
        "selectedIncident": selected_incident.model_dump(
            mode="json",
            by_alias=True,
        ),
        "effectiveRbacInventoryDigest": effective_rbac_inventory.inventory_digest,
        "effectiveRbacSourceManifestDigest": (effective_rbac_inventory.source_manifest_digest),
        "effectiveRbacValidFrom": effective_rbac_inventory.collected_at,
        "effectiveRbacValidUntil": effective_rbac_inventory.expires_at,
        "runtimeReplayBinding": runtime_replay_binding.model_dump(
            mode="json",
            by_alias=True,
        ),
        "executionStartedAt": observed_at,
        "executionCompletedAt": observed_at,
        "receiptIssuedAt": observed_at,
        "exchanges": [
            exchange.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        ],
        "wireAttempts": [
            wire_attempt.model_dump(
                mode="json",
                by_alias=True,
            )
        ],
        "identityProof": proof.model_dump(mode="json", by_alias=True),
    }
    receipt_digest = compute_artifact_digest(payload)
    signed_payload = {
        **payload,
        "receiptId": (
            f"monitoring-acquisition-receipt-{receipt_digest.removeprefix('sha256:')[:32]}"
        ),
        "receiptDigest": receipt_digest,
    }
    preimage = monitoring_acquisition_receipt_preimage(signed_payload)
    signature = base64.b64encode(
        private_key.sign(
            canonicalize_json(preimage).encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    ).decode("ascii")
    receipt = MonitoringAcquisitionReceipt(
        **{
            **signed_payload,
            "exchanges": (exchange,),
            "wireAttempts": (wire_attempt,),
            "identityProof": proof,
            "selectedIncident": selected_incident,
            "runtimeReplayBinding": runtime_replay_binding,
        },
        collectorAttestation=MonitoringEvidenceAttestation(
            signatureAlgorithm="RS256",
            trustAnchorRef=REVIEWED_SIGNING_KEY_URI,
            signedPreimageDigest=compute_artifact_digest(preimage),
            signature=signature,
        ),
    )
    mismatched_attempt = wire_attempt.model_copy(
        update={"exchange_result_digest": "sha256:" + ("f" * 64)}
    )
    with pytest.raises(
        ValidationError,
        match="wire attempts do not bind every logical exchange",
    ):
        MonitoringAcquisitionReceipt.model_validate(
            {
                **signed_payload,
                "exchanges": (exchange,),
                "wireAttempts": (mismatched_attempt,),
                "identityProof": proof,
                "selectedIncident": selected_incident,
                "runtimeReplayBinding": runtime_replay_binding,
                "collectorAttestation": receipt.collector_attestation,
            }
        )
    public_key = private_key.public_key()
    anchor = TrustedKeyAnchor.from_key_vault_key_id(
        REVIEWED_SIGNING_KEY_URI,
        public_key_fingerprint=sha256_hex(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ),
    )
    record = TrustedKeyRecord(
        anchor=anchor,
        public_key=public_key,
        enabled=True,
        activated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )

    verify_monitoring_acquisition_receipt_attestation(
        receipt,
        as_of=observed_at,
        trusted_key_anchor=anchor,
        key_resolver=lambda _anchor: record,
        reviewed_collector_contract=contract,
        expected_acquisition_authority_digest=authority_digest,
        maximum_receipt_age_seconds=600,
        expected_runtime_replay_binding=runtime_replay_binding,
    )
    legacy_v9_contract = _legacy_v9_trust_hardened_contract()
    with pytest.raises(
        ValueError,
        match="does not match deployed acquisition authority",
    ):
        verify_monitoring_acquisition_receipt_attestation(
            receipt.model_copy(
                update={
                    "collector_contract_digest": (
                        legacy_v9_contract.compute_artifact_digest_value()
                    )
                }
            ),
            as_of=observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
            expected_runtime_replay_binding=runtime_replay_binding,
        )
    mismatched_replay_payload = runtime_replay_binding.model_dump(
        mode="python",
        by_alias=True,
    )
    mismatched_replay_payload["incidentRevision"] = 2
    mismatched_replay_payload.pop("persistenceReplayKey")
    mismatched_replay_payload["persistenceReplayKey"] = compute_artifact_digest(
        monitoring_runtime_replay_key_preimage(mismatched_replay_payload)
    )
    with pytest.raises(ValueError, match="expected runtime replay v3"):
        verify_monitoring_acquisition_receipt_attestation(
            receipt,
            as_of=observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
            expected_runtime_replay_binding=MonitoringRuntimeReplayBinding(
                **mismatched_replay_payload
            ),
        )
    with pytest.raises(
        ValueError,
        match="outside measured effective RBAC lifetime",
    ):
        verify_monitoring_acquisition_receipt_attestation(
            receipt.model_copy(
                update={
                    "execution_completed_at": effective_rbac_inventory.expires_at,
                    "receipt_issued_at": effective_rbac_inventory.expires_at,
                }
            ),
            as_of=observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
            expected_runtime_replay_binding=runtime_replay_binding,
        )
    with pytest.raises(ValueError, match="does not match deployed acquisition authority"):
        verify_monitoring_acquisition_receipt_attestation(
            receipt.model_copy(update={"authenticated_principal_id": context_principal}),
            as_of=observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
            expected_runtime_replay_binding=runtime_replay_binding,
        )
    other_anchor = TrustedKeyAnchor.from_key_vault_key_id(
        "https://athenademomonkv.vault.azure.net/keys/other/0123456789abcdef0123456789abcdef",
        public_key_fingerprint=anchor.public_key_fingerprint,
    )
    with pytest.raises(ValueError, match="signing key is not authority-approved"):
        verify_monitoring_acquisition_receipt_attestation(
            receipt,
            as_of=observed_at,
            trusted_key_anchor=other_anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
            expected_runtime_replay_binding=runtime_replay_binding,
        )

    legacy_exchange = exchange.model_copy(
        update={
            "identity_proof_digest": None,
            "effective_rbac_inventory_digest": None,
            "effective_rbac_source_manifest_digest": None,
            "effective_rbac_valid_from": None,
            "effective_rbac_valid_until": None,
        }
    )
    legacy_payload = {
        key: value
        for key, value in payload.items()
        if key
        not in {
            "authenticatedClientId",
            "authenticatedTenantId",
            "monitoringReaderIdentityId",
            "athenaContextPrincipalId",
            "identityProof",
            "selectedIncident",
            "effectiveRbacInventoryDigest",
            "effectiveRbacSourceManifestDigest",
            "effectiveRbacValidFrom",
            "effectiveRbacValidUntil",
            "runtimeReplayBinding",
            "wireAttempts",
        }
    }
    legacy_payload.update(
        {
            "schemaVersion": "athena.wc028MonitoringAcquisitionReceipt.v1",
            "authenticatedPrincipalId": reader_identity,
            "exchanges": [
                legacy_exchange.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude_none=True,
                )
            ],
        }
    )
    legacy_digest = compute_artifact_digest(legacy_payload)
    legacy_signed_payload = {
        **legacy_payload,
        "receiptId": (
            f"monitoring-acquisition-receipt-{legacy_digest.removeprefix('sha256:')[:32]}"
        ),
        "receiptDigest": legacy_digest,
    }
    legacy_preimage = monitoring_acquisition_receipt_preimage(legacy_signed_payload)
    legacy_receipt = MonitoringAcquisitionReceipt(
        **{**legacy_signed_payload, "exchanges": (legacy_exchange,)},
        collectorAttestation=MonitoringEvidenceAttestation(
            signatureAlgorithm="RS256",
            trustAnchorRef=REVIEWED_SIGNING_KEY_URI,
            signedPreimageDigest=compute_artifact_digest(legacy_preimage),
            signature=base64.b64encode(
                private_key.sign(
                    canonicalize_json(legacy_preimage).encode("utf-8"),
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            ).decode("ascii"),
        ),
    )
    assert legacy_receipt.schema_version == "athena.wc028MonitoringAcquisitionReceipt.v1"
    with pytest.raises(ValueError, match="requires replay-bound acquisition receipt v6"):
        verify_monitoring_acquisition_receipt_attestation(
            legacy_receipt,
            as_of=observed_at,
            trusted_key_anchor=anchor,
            key_resolver=lambda _anchor: record,
            reviewed_collector_contract=contract,
            expected_acquisition_authority_digest=authority_digest,
            maximum_receipt_age_seconds=600,
            expected_runtime_replay_binding=runtime_replay_binding,
        )


def test_signed_handoff_requires_the_exact_active_collector_key() -> None:
    signed_handoff, contract, anchor, record = _trusted_signed_handoff()

    verify_monitoring_evidence_handoff_attestation(
        signed_handoff,
        as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
        reviewed_collector_contract=contract,
        trusted_key_anchor=anchor,
        key_resolver=lambda _: record,
    )

    with pytest.raises(ValueError, match="expected collector contract"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest="sha256:" + "b" * 64,
            reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
            reviewed_signing_key_resource_id=contract.signing_key_resource_id,
            expected_handoff_schema_version=MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="trusted key"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            reviewed_collector_contract=contract,
            trusted_key_anchor=TrustedKeyAnchor.from_key_vault_key_id(
                "https://athenademomonkv.vault.azure.net/keys/another-key/"
                "0123456789abcdef0123456789abcdef",
                public_key_fingerprint=anchor.public_key_fingerprint,
            ),
            key_resolver=lambda _: record,
        )

    wrong_record_anchor = TrustedKeyAnchor.from_key_vault_key_id(
        "https://athenademomonkv.vault.azure.net/keys/another-key/0123456789abcdef0123456789abcdef",
        public_key_fingerprint=anchor.public_key_fingerprint,
    )
    wrong_record = TrustedKeyRecord(
        anchor=wrong_record_anchor,
        public_key=record.public_key,
        enabled=True,
        activated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="key is not trusted"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            reviewed_collector_contract=contract,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: wrong_record,
        )

    payload = _signed_handoff().model_dump(by_alias=True)
    payload["evidence"]["name"] = "wc024-monitoring/other/evidence.json"  # type: ignore[index]

    with pytest.raises(ValidationError):
        MonitoringEvidenceHandoff(**payload)


def test_signed_handoff_binds_reviewed_signing_key_to_trusted_anchor() -> None:
    signed_handoff, contract, anchor, record = _trusted_signed_handoff()
    other_key_uri = (
        "https://athenademomonkv.vault.azure.net/keys/other-monitoring-key/"
        "0123456789abcdef0123456789abcdef"
    )

    with pytest.raises(ValueError, match="trusted key"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest=signed_handoff.collector_contract_digest,
            reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
            reviewed_signing_key_resource_id=other_key_uri,
            expected_handoff_schema_version=MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="expected collector contract"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            reviewed_collector_contract=contract.model_copy(
                update={"signing_key_resource_id": other_key_uri}
            ),
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="reviewed signing key"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest=signed_handoff.collector_contract_digest,
            reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )


def test_signed_handoff_rejects_key_retired_or_expired_at_trusted_as_of() -> None:
    signed_handoff, contract, anchor, record = _trusted_signed_handoff()

    for stale_record in (
        TrustedKeyRecord(
            anchor=anchor,
            public_key=record.public_key,
            enabled=True,
            activated_at=datetime(2026, 1, 1, tzinfo=UTC),
            retired_at=datetime(2026, 9, 6, 6, 5, tzinfo=UTC),
        ),
        TrustedKeyRecord(
            anchor=anchor,
            public_key=record.public_key,
            enabled=True,
            activated_at=datetime(2026, 1, 1, tzinfo=UTC),
            expires_at=datetime(2026, 9, 6, 6, 5, tzinfo=UTC),
        ),
    ):
        with pytest.raises(ValueError, match="key is not trusted"):
            verify_monitoring_evidence_handoff_attestation(
                signed_handoff,
                as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
                reviewed_collector_contract=contract,
                trusted_key_anchor=anchor,
                key_resolver=lambda _, stale_record=stale_record: stale_record,
            )


def test_signed_handoff_requires_trusted_as_of_and_reviewed_freshness() -> None:
    signed_handoff, contract, anchor, record = _trusted_signed_handoff()

    with pytest.raises(ValueError, match="reviewed handoff schema"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest=signed_handoff.collector_contract_digest,
            reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
            reviewed_signing_key_resource_id=contract.signing_key_resource_id,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="reviewed schema"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest=signed_handoff.collector_contract_digest,
            reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
            reviewed_signing_key_resource_id=contract.signing_key_resource_id,
            expected_handoff_schema_version=("athena.wc028MonitoringEvidenceHandoff.v2"),
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    verify_monitoring_evidence_handoff_attestation(
        signed_handoff,
        as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
        expected_collector_contract_digest=signed_handoff.collector_contract_digest,
        reviewed_maximum_evidence_age_seconds=contract.maximum_evidence_age_seconds,
        reviewed_signing_key_resource_id=contract.signing_key_resource_id,
        expected_handoff_schema_version=MONITORING_EVIDENCE_HANDOFF_SCHEMA_VERSION,
        trusted_key_anchor=anchor,
        key_resolver=lambda _: record,
    )

    with pytest.raises(ValueError, match="future"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 5, 59, 59, tzinfo=UTC),
            reviewed_collector_contract=contract,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="reviewed maximum age"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, 1, tzinfo=UTC),
            reviewed_collector_contract=contract,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="trusted UTC"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10),
            reviewed_collector_contract=contract,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )

    with pytest.raises(ValueError, match="reviewed maximum evidence age"):
        verify_monitoring_evidence_handoff_attestation(
            signed_handoff,
            as_of=datetime(2026, 9, 6, 6, 10, tzinfo=UTC),
            expected_collector_contract_digest=signed_handoff.collector_contract_digest,
            trusted_key_anchor=anchor,
            key_resolver=lambda _: record,
        )
