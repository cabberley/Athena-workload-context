import json
import shutil
import subprocess
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "infra" / "wc027-guidance-authority-publisher" / "main.bicep"
RUNTIME = ROOT / "infra" / "wc027-enrichment-feed-runtime" / "main.bicep"
REQUEST_PRODUCER = ROOT / "infra" / "wc027-guidance-publication-request-producer" / "main.bicep"
ROOT_DEPLOYMENT = ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"
BLOB_CREATOR = (
    ROOT
    / "infra"
    / "wc027-guidance-authority-publisher"
    / "modules"
    / "blob-create-rbac.bicep"
)
TABLE_CAS = (
    ROOT
    / "infra"
    / "wc027-guidance-authority-publisher"
    / "modules"
    / "table-cas-rbac.bicep"
)
KEY_SIGNER = (
    ROOT
    / "infra"
    / "wc027-guidance-authority-publisher"
    / "modules"
    / "key-signer-rbac.bicep"
)
ACR_PULL = (
    ROOT / "infra" / "wc027-enrichment-feed-runtime" / "modules" / "acr-pull-rbac.bicep"
)
DIGEST_PULL_READINESS = (
    ROOT
    / "infra"
    / "wc027-guidance-authority-publisher"
    / "Test-AcrDigestPullReadiness.ps1"
)


def _evaluate_registry_resource_id(resource_id: str) -> tuple[list[str], bool]:
    raw_segments = resource_id.split("/")
    segments = [*raw_segments, *([""] * 9)]
    valid = (
        len(raw_segments) == 9
        and not segments[0]
        and segments[1] == "subscriptions"
        and bool(segments[2])
        and segments[3] == "resourceGroups"
        and bool(segments[4])
        and segments[5] == "providers"
        and segments[6] == "Microsoft.ContainerRegistry"
        and segments[7] == "registries"
        and bool(segments[8])
        and not any(alias in resource_id for alias in ("//", "?", "#", "%"))
    )
    return segments, valid


def _repository_condition(repository_name: str) -> str:
    return (
        "((!(ActionMatches{'Microsoft.ContainerRegistry/registries/"
        "repositories/content/read'}) AND "
        "!(ActionMatches{'Microsoft.ContainerRegistry/registries/"
        "repositories/metadata/read'})) OR "
        "(@Request[Microsoft.ContainerRegistry/registries/repositories:name] "
        f"StringEqualsIgnoreCase '{repository_name}'))"
    )


def _publisher_image_pull_evidence() -> tuple[
    dict[str, dict[str, object]],
    dict[str, object],
    dict[str, dict[str, object]],
]:
    repository_name = "athena/wc027-guidance-authority-publisher"
    condition = _repository_condition(repository_name)
    registry_resource_id = (
        "/subscriptions/11111111-1111-1111-1111-111111111111/"
        "resourceGroups/rg-shared-acr/providers/"
        "Microsoft.ContainerRegistry/registries/athenashared"
    )
    principal_ids = [
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    ]
    assignment_ids = [
        (
            f"{registry_resource_id}/providers/"
            "Microsoft.Authorization/roleAssignments/"
            f"55555555-5555-4555-8555-55555555555{index}"
        )
        for index in range(3)
    ]
    identity_resource_id = (
        "/subscriptions/11111111-1111-1111-1111-111111111111/"
        "resourceGroups/rg-wc027/providers/Microsoft.ManagedIdentity/"
        "userAssignedIdentities/wc027-publisher-broker"
    )
    binding = {
        "registryResourceId": registry_resource_id,
        "registryServer": "athenashared.azurecr.io",
        "image": (
            "athenashared.azurecr.io/athena/"
            "wc027-guidance-authority-publisher@sha256:" + "a" * 64
        ),
        "repositoryName": repository_name,
        "roleAssignmentMode": "AbacRepositoryPermissions",
        "anonymousPullEnabled": False,
        "roleDefinitionId": "b93aa761-3e63-49ed-ac28-beffa264f7ac",
        "conditionVersion": "2.0",
        "condition": condition,
        "identityResourceId": identity_resource_id,
        "identityClientId": principal_ids[0],
        "identityPrincipalId": principal_ids[0],
        "roleAssignmentResourceId": assignment_ids[0],
    }
    request_repository_name = "athena/wc027-guidance-publication-request-producer"
    feed_repository_name = "athena/wc027-enrichment-feed-producer"
    bindings = {
        "publisher": binding,
        "request-producer": {
            "schemaVersion": "athena.wc027AcrPullBinding.v1",
            "registryResourceId": registry_resource_id,
            "image": (
                "athenashared.azurecr.io/"
                f"{request_repository_name}@sha256:" + "b" * 64
            ),
            "principalId": principal_ids[1],
            "roleAssignmentMode": "AbacRepositoryPermissions",
            "anonymousPullEnabled": False,
            "repositoryName": request_repository_name,
            "roleDefinitionId": "b93aa761-3e63-49ed-ac28-beffa264f7ac",
            "roleAssignmentResourceId": assignment_ids[1],
            "conditionVersion": "2.0",
            "condition": _repository_condition(request_repository_name),
        },
        "feed-producer": {
            "schemaVersion": "athena.wc027AcrPullBinding.v1",
            "registryResourceId": registry_resource_id,
            "image": (
                "athenashared.azurecr.io/"
                f"{feed_repository_name}@sha256:" + "c" * 64
            ),
            "principalId": principal_ids[2],
            "roleAssignmentMode": "AbacRepositoryPermissions",
            "anonymousPullEnabled": False,
            "repositoryName": feed_repository_name,
            "roleDefinitionId": "b93aa761-3e63-49ed-ac28-beffa264f7ac",
            "roleAssignmentResourceId": assignment_ids[2],
            "conditionVersion": "2.0",
            "condition": _repository_condition(feed_repository_name),
        },
    }
    evidence = {
        "schemaVersion": "athena.wc027AcrDigestPullReadiness.v1",
        "registryResourceId": binding["registryResourceId"],
        "registryServer": binding["registryServer"],
        "image": binding["image"],
        "repositoryName": binding["repositoryName"],
        "managedIdentityResourceId": binding["identityResourceId"],
        "managedIdentityClientId": binding["identityClientId"],
        "managedIdentityPrincipalId": binding["identityPrincipalId"],
        "roleAssignmentMode": binding["roleAssignmentMode"],
        "anonymousPullEnabled": binding["anonymousPullEnabled"],
        "roleDefinitionId": binding["roleDefinitionId"],
        "roleAssignmentResourceId": binding["roleAssignmentResourceId"],
        "conditionVersion": binding["conditionVersion"],
        "condition": binding["condition"],
        "effectiveAccess": {
            "schemaVersion": "athena.wc027AcrEffectiveAccessEvidence.v1",
            "verified": True,
            "tenantId": "10101010-1010-4010-8010-101010101010",
            "tenantSubscriptionHierarchyComplete": True,
            "governedSubscriptionIds": [
                "11111111-1111-1111-1111-111111111111"
            ],
            "anonymousPullEnabled": False,
            "expectedAssignmentCount": 3,
            "pullCapableAssignmentCount": 3,
            "roleDefinitionsResolved": True,
            "exactAssignmentReadbacksComplete": True,
            "directAssignmentsComplete": True,
            "inheritedAssignmentsComplete": True,
            "transitiveGroupsComplete": True,
            "directMembershipTraversalComplete": True,
            "convergedMembershipReadbacks": True,
            "roleAssignmentScheduleInstancesComplete": True,
            "roleAssignmentSchedulesComplete": True,
            "roleEligibilityScheduleInstancesComplete": True,
            "roleEligibilitySchedulesComplete": True,
            "roleManagementPendingRequestsComplete": True,
            "convergedPimReadbacks": True,
            "convergedRoleDefinitionReadbacks": True,
            "siblingRegistriesChecked": True,
            "acrEscalationPathsChecked": True,
            "completeness": {
                "classicRoleAssignments": True,
                "pimRoleAssignmentScheduleInstances": True,
                "pimRoleAssignmentSchedules": True,
                "pimRoleEligibilityScheduleInstances": True,
                "pimRoleEligibilitySchedules": True,
                "pimPendingGrantRequests": True,
                "pimConvergedReadbacks": True,
                "roleDefinitionReadbacks": True,
                "transitiveGroups": True,
                "siblingRegistries": True,
                "acrEscalationPaths": True,
                "exactAssignmentReadbacks": True,
                "paginationBudgets": True,
            },
            "paginationBudgets": {
                "tenantHierarchyMaxPages": 64,
                "governedSubscriptionMaxCount": 4096,
                "graphMembershipMaxPagesPerObject": 16,
                "transitiveGroupMaxCountPerPrincipal": 4096,
                "classicRoleAssignmentMaxPagesPerQuery": 64,
                "classicRoleAssignmentMaxApiCalls": 16_384,
                "classicRoleAssignmentMaxItems": 65_536,
                "pimRoleManagementMaxPagesPerQuery": 64,
                "pimRoleManagementMaxApiCalls": 98_304,
                "pimRoleManagementMaxItems": 262_144,
            },
            "evidenceDigest": "sha256:" + "d" * 64,
            "expectedAssignmentIds": assignment_ids,
            "principalIds": principal_ids,
            "registryResourceIds": [registry_resource_id],
            "reviewedAssignments": [
                {
                    "label": "publisher",
                    "principalId": principal_ids[0],
                    "assignmentResourceId": assignment_ids[0],
                    "registryResourceId": registry_resource_id,
                    "repositoryName": repository_name,
                    "roleAssignmentMode": "AbacRepositoryPermissions",
                    "roleDefinitionId": "b93aa761-3e63-49ed-ac28-beffa264f7ac",
                    "conditionVersion": "2.0",
                    "condition": condition,
                },
                {
                    "label": "request-producer",
                    "principalId": principal_ids[1],
                    "assignmentResourceId": assignment_ids[1],
                    "registryResourceId": registry_resource_id,
                    "repositoryName": request_repository_name,
                    "roleAssignmentMode": "AbacRepositoryPermissions",
                    "roleDefinitionId": "b93aa761-3e63-49ed-ac28-beffa264f7ac",
                    "conditionVersion": "2.0",
                    "condition": _repository_condition(request_repository_name),
                },
                {
                    "label": "feed-producer",
                    "principalId": principal_ids[2],
                    "assignmentResourceId": assignment_ids[2],
                    "registryResourceId": registry_resource_id,
                    "repositoryName": feed_repository_name,
                    "roleAssignmentMode": "AbacRepositoryPermissions",
                    "roleDefinitionId": "b93aa761-3e63-49ed-ac28-beffa264f7ac",
                    "conditionVersion": "2.0",
                    "condition": _repository_condition(feed_repository_name),
                },
            ],
            "extraPullCapableAssignmentIds": [],
            "verifiedAt": "2026-09-17T04:40:00.000Z",
        },
        "attempts": 3,
        "maxAttempts": 10,
        "verifiedAt": "2026-09-17T04:40:01.000Z",
        "success": True,
    }
    return bindings, evidence, deepcopy(bindings)


def _evaluate_publisher_image_pull_evidence(
    source: str,
    *,
    bindings: dict[str, dict[str, object]],
    evidence: dict[str, object],
    live_bindings: dict[str, dict[str, object]],
) -> bool:
    binding = bindings["publisher"]
    required_predicates = (
        "wc027ParsedPublisherImagePullEvidence.schemaVersion == "
        "'athena.wc027AcrDigestPullReadiness.v1'",
        "wc027ParsedPublisherImagePullEvidence.success == true",
        "wc027ParsedPublisherImagePullEvidence.registryResourceId == "
        "wc027ParsedPublisherConfiguration.imagePull.registryResourceId",
        "wc027ParsedPublisherImagePullEvidence.image == wc027PublisherImage",
        "wc027ParsedPublisherConfiguration.imagePull.image == wc027PublisherImage",
        "wc027ParsedPublisherImagePullEvidence.anonymousPullEnabled == false",
        "wc027ParsedPublisherImagePullEvidence.anonymousPullEnabled == "
        "wc027ParsedPublisherConfiguration.imagePull.anonymousPullEnabled",
        "wc027ParsedPublisherImagePullEvidence.repositoryName == "
        "wc027ParsedPublisherConfiguration.imagePull.repositoryName",
        "wc027ParsedPublisherImagePullEvidence.managedIdentityResourceId",
        "wc027ParsedPublisherImagePullEvidence.roleAssignmentMode == "
        "wc027ParsedPublisherConfiguration.imagePull.roleAssignmentMode",
        "wc027ParsedPublisherImagePullEvidence.roleDefinitionId == "
        "wc027ParsedPublisherConfiguration.imagePull.roleDefinitionId",
        "wc027ParsedPublisherImagePullEvidence.conditionVersion == "
        "wc027ParsedPublisherConfiguration.imagePull.conditionVersion",
        "wc027ParsedPublisherImagePullEvidence.condition == "
        "wc027ParsedPublisherConfiguration.imagePull.condition",
        "wc027ParsedPublisherImagePullEvidence.managedIdentityPrincipalId",
        "wc027ParsedPublisherImagePullEvidence.roleAssignmentResourceId",
        "wc027PublisherImagePullConditionValid",
        "wc027PublisherImagePullIdentityMatches",
        "resource wc027PublisherImagePullIdentity "
        "'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing",
        "wc027PublisherImagePullIdentity!.properties.clientId",
        "wc027PublisherImagePullIdentity!.properties.principalId",
        "wc027ParsedEffectiveAcrAccess.schemaVersion == "
        "'athena.wc027AcrEffectiveAccessEvidence.v1'",
        "length(items(wc027ParsedEffectiveAcrAccess)) == 33",
        "wc027ParsedEffectiveAcrAccess.expectedAssignmentCount == 3",
        "wc027ParsedEffectiveAcrAccess.pullCapableAssignmentCount == 3",
        "wc027ParsedEffectiveAcrAccess.roleDefinitionsResolved == true",
        "wc027ParsedEffectiveAcrAccess.exactAssignmentReadbacksComplete == true",
        "wc027ParsedEffectiveAcrAccess.inheritedAssignmentsComplete == true",
        "wc027ParsedEffectiveAcrAccess.transitiveGroupsComplete == true",
        "wc027ParsedEffectiveAcrAccess.directMembershipTraversalComplete == true",
        "wc027ParsedEffectiveAcrAccess.convergedMembershipReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.roleAssignmentScheduleInstancesComplete == true",
        "wc027ParsedEffectiveAcrAccess.roleAssignmentSchedulesComplete == true",
        "wc027ParsedEffectiveAcrAccess.roleEligibilityScheduleInstancesComplete == true",
        "wc027ParsedEffectiveAcrAccess.roleEligibilitySchedulesComplete == true",
        "wc027ParsedEffectiveAcrAccess.roleManagementPendingRequestsComplete == true",
        "wc027ParsedEffectiveAcrAccess.convergedPimReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.convergedRoleDefinitionReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.siblingRegistriesChecked == true",
        "wc027ParsedEffectiveAcrAccess.acrEscalationPathsChecked == true",
        "length(items(wc027ParsedEffectiveAcrAccess.completeness)) == 13",
        "wc027ParsedEffectiveAcrAccess.completeness.classicRoleAssignments == true",
        (
            "wc027ParsedEffectiveAcrAccess.completeness."
            "pimRoleAssignmentScheduleInstances == true"
        ),
        "wc027ParsedEffectiveAcrAccess.completeness.pimRoleAssignmentSchedules == true",
        (
            "wc027ParsedEffectiveAcrAccess.completeness."
            "pimRoleEligibilityScheduleInstances == true"
        ),
        "wc027ParsedEffectiveAcrAccess.completeness.pimRoleEligibilitySchedules == true",
        "wc027ParsedEffectiveAcrAccess.completeness.pimPendingGrantRequests == true",
        "wc027ParsedEffectiveAcrAccess.completeness.pimConvergedReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.completeness.roleDefinitionReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.completeness.transitiveGroups == true",
        "wc027ParsedEffectiveAcrAccess.completeness.siblingRegistries == true",
        "wc027ParsedEffectiveAcrAccess.completeness.acrEscalationPaths == true",
        "wc027ParsedEffectiveAcrAccess.completeness.exactAssignmentReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.completeness.paginationBudgets == true",
        "length(items(wc027ParsedEffectiveAcrAccess.paginationBudgets)) == 10",
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "tenantHierarchyMaxPages == 64"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "governedSubscriptionMaxCount == 4096"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "graphMembershipMaxPagesPerObject == 16"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "transitiveGroupMaxCountPerPrincipal == 4096"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "classicRoleAssignmentMaxPagesPerQuery == 64"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "classicRoleAssignmentMaxApiCalls == 16384"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "classicRoleAssignmentMaxItems == 65536"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "pimRoleManagementMaxPagesPerQuery == 64"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "pimRoleManagementMaxApiCalls == 98304"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "pimRoleManagementMaxItems == 262144"
        ),
        "wc027ParsedEffectiveAcrAccess.tenantSubscriptionHierarchyComplete == true",
        "wc027EffectiveAcrEvidenceFresh",
        "wc027EffectiveAcrEvidenceDigestValid",
        "wc027RequestProducerImagePullPrincipalMatches",
        "wc027RequestProducerImagePullRegistryMatchesImage",
        "wc027RequestProducerImagePullAssignmentInDeploymentBinding",
        "wc027FeedProducerImagePullPrincipalMatches",
        "wc027FeedProducerImagePullRegistryMatchesImage",
        "wc027FeedProducerImagePullAssignmentInDeploymentBinding",
        "wc027ParsedRequestProducerImagePullBinding.roleAssignmentMode == "
        "wc027ParsedFeedProducerImagePullBinding.roleAssignmentMode",
        "wc027ParsedRequestProducerImagePullBinding.roleAssignmentMode == "
        "wc027ParsedPublisherConfiguration.imagePull.roleAssignmentMode",
        "wc027ReviewedRequestProducerAcrAssignmentValid",
        "wc027ReviewedFeedProducerAcrAssignmentValid",
        "wc027ReviewedPublisherAcrAssignmentValid",
        "length(items(wc027ReviewedRequestProducerAcrAssignment)) == 9",
        "length(items(wc027ReviewedFeedProducerAcrAssignment)) == 9",
        "length(items(wc027ReviewedPublisherAcrAssignment)) == 9",
        "wc027EffectiveAcrSummarySetsValid",
        "empty(wc027ParsedEffectiveAcrAccess.extraPullCapableAssignmentIds)",
        "wc027ParsedPublisherImagePullEvidence.attempts >= 1",
        "wc027ParsedPublisherImagePullEvidence.maxAttempts <= 20",
    )
    if any(predicate not in source for predicate in required_predicates):
        return False
    effective_access = evidence.get("effectiveAccess")
    if not isinstance(effective_access, dict):
        return False
    if set(effective_access) != {
        "schemaVersion",
        "verified",
        "tenantId",
        "tenantSubscriptionHierarchyComplete",
        "governedSubscriptionIds",
        "anonymousPullEnabled",
        "expectedAssignmentCount",
        "pullCapableAssignmentCount",
        "roleDefinitionsResolved",
        "exactAssignmentReadbacksComplete",
        "directAssignmentsComplete",
        "inheritedAssignmentsComplete",
        "transitiveGroupsComplete",
        "directMembershipTraversalComplete",
        "convergedMembershipReadbacks",
        "roleAssignmentScheduleInstancesComplete",
        "roleAssignmentSchedulesComplete",
        "roleEligibilityScheduleInstancesComplete",
        "roleEligibilitySchedulesComplete",
        "roleManagementPendingRequestsComplete",
        "convergedPimReadbacks",
        "convergedRoleDefinitionReadbacks",
        "siblingRegistriesChecked",
        "acrEscalationPathsChecked",
        "completeness",
        "paginationBudgets",
        "expectedAssignmentIds",
        "principalIds",
        "registryResourceIds",
        "reviewedAssignments",
        "extraPullCapableAssignmentIds",
        "evidenceDigest",
        "verifiedAt",
    }:
        return False
    completeness = effective_access.get("completeness")
    pagination_budgets = effective_access.get("paginationBudgets")
    if not isinstance(completeness, dict) or not isinstance(
        pagination_budgets,
        dict,
    ):
        return False
    reviewed_assignments = effective_access.get("reviewedAssignments")
    if not isinstance(reviewed_assignments, list):
        return False
    if any(
        not isinstance(item, dict)
        or set(item)
        != {
            "label",
            "principalId",
            "assignmentResourceId",
            "registryResourceId",
            "repositoryName",
            "roleAssignmentMode",
            "roleDefinitionId",
            "conditionVersion",
            "condition",
        }
        for item in reviewed_assignments
    ):
        return False

    def exact_string_set(value: object, expected: set[str]) -> bool:
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item for item in value
        ):
            return False
        normalized = [item.casefold() for item in value]
        return len(normalized) == len(set(normalized)) and set(normalized) == {
            item.casefold() for item in expected
        }

    if not (
        exact_string_set(
            effective_access.get("expectedAssignmentIds"),
            {
                str(item["assignmentResourceId"])
                for item in reviewed_assignments
            },
        )
        and exact_string_set(
            effective_access.get("principalIds"),
            {str(item["principalId"]) for item in reviewed_assignments},
        )
        and exact_string_set(
            effective_access.get("registryResourceIds"),
            {str(item["registryResourceId"]) for item in reviewed_assignments},
        )
    ):
        return False
    publisher_assignments = [
        item
        for item in reviewed_assignments
        if isinstance(item, dict) and item.get("label") == "publisher"
    ]
    if len(publisher_assignments) != 1:
        return False
    publisher_assignment = publisher_assignments[0]
    live_publisher = live_bindings["publisher"]
    if (
        binding.get("identityResourceId")
        != live_publisher.get("identityResourceId")
        or binding.get("identityClientId")
        != live_publisher.get("identityClientId")
        or binding.get("identityPrincipalId")
        != live_publisher.get("identityPrincipalId")
    ):
        return False
    if not (
        bindings["request-producer"].get("roleAssignmentMode")
        == bindings["feed-producer"].get("roleAssignmentMode")
        == binding.get("roleAssignmentMode")
    ):
        return False
    reviewed_by_label = {
        str(item.get("label")): item
        for item in reviewed_assignments
        if isinstance(item, dict)
    }
    for label in ("request-producer", "feed-producer"):
        expected = bindings[label]
        live = live_bindings[label]
        reviewed = reviewed_by_label.get(label)
        if (
            reviewed is None
            or expected.get("schemaVersion") != "athena.wc027AcrPullBinding.v1"
            or expected.get("anonymousPullEnabled") is not False
            or expected.get("principalId") != live.get("principalId")
            or expected.get("registryResourceId")
            != live.get("registryResourceId")
            or expected.get("image") != live.get("image")
            or expected.get("roleAssignmentResourceId")
            != live.get("roleAssignmentResourceId")
            or reviewed.get("principalId") != expected.get("principalId")
            or reviewed.get("assignmentResourceId")
            != expected.get("roleAssignmentResourceId")
            or reviewed.get("registryResourceId")
            != expected.get("registryResourceId")
            or reviewed.get("repositoryName") != expected.get("repositoryName")
            or reviewed.get("roleAssignmentMode")
            != expected.get("roleAssignmentMode")
            or reviewed.get("roleDefinitionId")
            != expected.get("roleDefinitionId")
            or reviewed.get("conditionVersion")
            != expected.get("conditionVersion")
            or reviewed.get("condition") != expected.get("condition")
        ):
            return False
    try:
        effective_verified_at = datetime.fromisoformat(
            str(effective_access.get("verifiedAt", "")).replace("Z", "+00:00")
        )
        pull_verified_at = datetime.fromisoformat(
            str(evidence.get("verifiedAt", "")).replace("Z", "+00:00")
        )
    except ValueError:
        return False
    readiness_evaluation_time = datetime(
        2026,
        9,
        17,
        4,
        43,
        12,
        tzinfo=UTC,
    )
    if not (
        effective_verified_at <= pull_verified_at
        and (pull_verified_at - effective_verified_at).total_seconds() <= 120
        and pull_verified_at <= readiness_evaluation_time
        and (readiness_evaluation_time - pull_verified_at).total_seconds()
        <= 300
    ):
        return False
    return (
        evidence.get("schemaVersion")
        == "athena.wc027AcrDigestPullReadiness.v1"
        and evidence.get("success") is True
        and evidence.get("registryResourceId") == binding["registryResourceId"]
        and evidence.get("registryServer") == binding["registryServer"]
        and evidence.get("image") == binding["image"]
        and evidence.get("repositoryName") == binding["repositoryName"]
        and str(evidence.get("managedIdentityResourceId", "")).casefold()
        == str(binding["identityResourceId"]).casefold()
        and str(evidence.get("managedIdentityClientId", "")).casefold()
        == str(binding["identityClientId"]).casefold()
        and str(evidence.get("managedIdentityPrincipalId", "")).casefold()
        == str(binding["identityPrincipalId"]).casefold()
        and evidence.get("roleAssignmentMode") == binding["roleAssignmentMode"]
        and evidence.get("anonymousPullEnabled") is False
        and evidence.get("anonymousPullEnabled") == binding["anonymousPullEnabled"]
        and evidence.get("roleDefinitionId") == binding["roleDefinitionId"]
        and str(evidence.get("roleAssignmentResourceId", "")).casefold()
        == str(binding["roleAssignmentResourceId"]).casefold()
        and evidence.get("conditionVersion") == binding["conditionVersion"]
        and evidence.get("condition") == binding["condition"]
        and effective_access.get("schemaVersion")
        == "athena.wc027AcrEffectiveAccessEvidence.v1"
        and effective_access.get("verified") is True
        and effective_access.get("tenantId")
        == "10101010-1010-4010-8010-101010101010"
        and effective_access.get("tenantSubscriptionHierarchyComplete") is True
        and effective_access.get("governedSubscriptionIds")
        == ["11111111-1111-1111-1111-111111111111"]
        and effective_access.get("anonymousPullEnabled") is False
        and effective_access.get("expectedAssignmentCount") == 3
        and effective_access.get("pullCapableAssignmentCount") == 3
        and effective_access.get("roleDefinitionsResolved") is True
        and effective_access.get("exactAssignmentReadbacksComplete") is True
        and effective_access.get("directAssignmentsComplete") is True
        and effective_access.get("inheritedAssignmentsComplete") is True
        and effective_access.get("transitiveGroupsComplete") is True
        and effective_access.get("directMembershipTraversalComplete") is True
        and effective_access.get("convergedMembershipReadbacks") is True
        and effective_access.get("roleAssignmentScheduleInstancesComplete") is True
        and effective_access.get("roleAssignmentSchedulesComplete") is True
        and effective_access.get("roleEligibilityScheduleInstancesComplete") is True
        and effective_access.get("roleEligibilitySchedulesComplete") is True
        and effective_access.get("roleManagementPendingRequestsComplete") is True
        and effective_access.get("convergedPimReadbacks") is True
        and effective_access.get("convergedRoleDefinitionReadbacks") is True
        and effective_access.get("siblingRegistriesChecked") is True
        and effective_access.get("acrEscalationPathsChecked") is True
        and completeness
        == {
            "classicRoleAssignments": True,
            "pimRoleAssignmentScheduleInstances": True,
            "pimRoleAssignmentSchedules": True,
            "pimRoleEligibilityScheduleInstances": True,
            "pimRoleEligibilitySchedules": True,
            "pimPendingGrantRequests": True,
            "pimConvergedReadbacks": True,
            "roleDefinitionReadbacks": True,
            "transitiveGroups": True,
            "siblingRegistries": True,
            "acrEscalationPaths": True,
            "exactAssignmentReadbacks": True,
            "paginationBudgets": True,
        }
        and pagination_budgets
        == {
            "tenantHierarchyMaxPages": 64,
            "governedSubscriptionMaxCount": 4096,
            "graphMembershipMaxPagesPerObject": 16,
            "transitiveGroupMaxCountPerPrincipal": 4096,
            "classicRoleAssignmentMaxPagesPerQuery": 64,
            "classicRoleAssignmentMaxApiCalls": 16_384,
            "classicRoleAssignmentMaxItems": 65_536,
            "pimRoleManagementMaxPagesPerQuery": 64,
            "pimRoleManagementMaxApiCalls": 98_304,
            "pimRoleManagementMaxItems": 262_144,
        }
        and str(effective_access.get("evidenceDigest", "")).startswith(
            "sha256:"
        )
        and len(effective_access.get("expectedAssignmentIds", [])) == 3
        and len(effective_access.get("principalIds", [])) == 3
        and len(effective_access.get("registryResourceIds", [])) >= 1
        and len(reviewed_assignments) == 3
        and str(publisher_assignment.get("principalId", "")).casefold()
        == str(binding["identityPrincipalId"]).casefold()
        and str(publisher_assignment.get("assignmentResourceId", "")).casefold()
        == str(binding["roleAssignmentResourceId"]).casefold()
        and str(publisher_assignment.get("registryResourceId", "")).casefold()
        == str(binding["registryResourceId"]).casefold()
        and publisher_assignment.get("repositoryName") == binding["repositoryName"]
        and publisher_assignment.get("roleAssignmentMode")
        == binding["roleAssignmentMode"]
        and publisher_assignment.get("roleDefinitionId") == binding["roleDefinitionId"]
        and publisher_assignment.get("conditionVersion") == binding["conditionVersion"]
        and publisher_assignment.get("condition") == binding["condition"]
        and effective_access.get("extraPullCapableAssignmentIds") == []
        and bool(effective_access.get("verifiedAt"))
        and isinstance(evidence.get("attempts"), int)
        and isinstance(evidence.get("maxAttempts"), int)
        and 1
        <= int(evidence["attempts"])
        <= int(evidence["maxAttempts"])
        <= 20
        and bool(evidence.get("verifiedAt"))
    )


def test_publisher_is_private_idempotent_and_uses_separated_authorities() -> None:
    source = PUBLISHER.read_text(encoding="utf-8")

    for expected in (
        "requiresSession: true",
        "requiresDuplicateDetection: true",
        "defaultMessageTimeToLive: 'PT10M'",
        "maxDeliveryCount: 10",
        "maxMessageSizeInKilobytes: 12288",
        "maxExecutions: 1",
        "wc027-guidance-authority-requests",
        "wc027-enrichment-feed-requests",
        "wc027-guidance-authority",
        "authorityReaderIdentityResourceId",
        "authorityWriterIdentityResourceId",
        "activationWriterIdentityResourceId",
        "bindingSignerIdentityResourceId",
        "requestTrustReaderIdentityResourceId",
        "bindingTrustReaderIdentityResourceId",
        "requestOutboxReaderIdentityResourceId",
        "requestOutboxStorageAccountResourceId",
        "@maxLength(1)\nparam requestSubmitterIdentityResourceIds array",
        "@minLength(5)\n@maxLength(5)\nparam sourceIdentityResourceIds array",
        "requires one dedicated request submitter identity",
        "requestSubmitterIdentityClientId",
        "requestSubmitterIdentityResourceId",
        "requestOutbox:",
        "wc027-guidance-request-outbox",
        "requestOutboxReaderRbac",
        "requestOutboxBlobService.properties.isVersioningEnabled == true",
        "keyId: requestLogicalKeyId",
        "keyId: bindingLogicalKeyId",
        "keyVaultKeyId: requestKey.properties.keyUriWithVersion",
        "keyVaultKeyId: bindingKey.properties.keyUriWithVersion",
        "validatedRequestKeyFingerprint",
        "validatedBindingKeyFingerprint",
        "runtimeTrustDomainFingerprints",
        "validatedRuntimeIdentityResourceIds",
        "validatedSourceIdentityResourceIds",
        "normalizedPublisherOwnedIdentityResourceIds",
        "normalizedAttachedIdentityResourceIds",
        "publisherRuntimeIdentityOverlap = intersection(",
        "requestSubmitterRuntimeIdentityOverlap = intersection(",
        "requestSubmitterAttachedIdentityOverlap = intersection(",
        "binding trust reader must match the embedded runtime trust identity",
        "separate from publisher and runtime identities",
        "public key fingerprints must be distinct",
        "must match runtime guidance trust",
        "authorityStorageAccountResourceId",
        "activationStorageAccountResourceId",
        "runtimeAuthorityAssets.blobEndpoint",
        "runtimeAuthorityAssets.containerName",
        "runtimeActivation.tableEndpoint",
        "runtimeActivation.tableName",
        "runtimeActivation.partitionKey",
        "modules/blob-create-rbac.bicep",
        "modules/table-cas-rbac.bicep",
        "../wc027-enrichment-feed-runtime/modules/blob-reader-rbac.bicep",
        "ATHENA_WC027_GUIDANCE_AUTHORITY_PUBLISHER_CONFIG_JSON",
        "auth: []",
        "athena-context",
        "wc027-guidance-authority-publisher",
        "output publisherImage string = validatedPublisherImage",
        "param registryRoleAssignmentMode string",
        "param brokerIdentityPrincipalId string",
        "brokerIdentity.properties.principalId == brokerIdentityPrincipalId",
        "imagePull:",
        "repositoryName: publisherImagePull.outputs.repositoryName",
        "conditionVersion: publisherImagePull.outputs.?conditionVersion",
        "condition: publisherImagePull.outputs.?condition",
        "output registryPullPrincipalId string = validatedBrokerIdentityPrincipalId",
        "output registryPullConditionVersion string?",
        "output registryPullCondition string?",
    ):
        assert expected in source

    assert "listKeys(" not in source
    assert "allowSharedKeyAccess: true" not in source
    assert "publicNetworkAccess: 'Enabled'" not in source
    assert "delete/action" not in source
    for drift_prone_parameter in (
        "param replayStorageAccountName",
        "param authorityContainerName",
        "param activationTableName",
        "param activationPartitionKey",
    ):
        assert drift_prone_parameter not in source


@pytest.mark.parametrize(
    ("variant", "expected_valid"),
    (
        ("canonical", True),
        ("cross-subscription", True),
        ("cross-resource-group", True),
        ("missing-leading-slash", False),
        ("provider-case-alias", False),
        ("type-case-alias", False),
        ("empty-name", False),
        ("child-resource", False),
        ("duplicate-separator", False),
        ("query", False),
        ("fragment", False),
        ("encoded-separator", False),
    ),
)
def test_publisher_registry_id_and_image_pull_scope_are_evaluated_canonically(
    variant: str,
    expected_valid: bool,
) -> None:
    source = PUBLISHER.read_text(encoding="utf-8")
    subscription_id = "11111111-1111-1111-1111-111111111111"
    resource_group_name = "rg-shared-acr"
    canonical = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/"
        "providers/Microsoft.ContainerRegistry/registries/athenashared"
    )
    variants = {
        "canonical": canonical,
        "cross-subscription": canonical.replace(
            subscription_id,
            "22222222-2222-2222-2222-222222222222",
        ),
        "cross-resource-group": canonical.replace(
            resource_group_name,
            "rg-central-acr",
        ),
        "missing-leading-slash": canonical.removeprefix("/"),
        "provider-case-alias": canonical.replace(
            "Microsoft.ContainerRegistry",
            "microsoft.containerregistry",
        ),
        "type-case-alias": canonical.replace("/registries/", "/Registries/"),
        "empty-name": canonical.removesuffix("athenashared"),
        "child-resource": canonical + "/replications/eastus",
        "duplicate-separator": canonical.replace("/providers/", "//providers/"),
        "query": canonical + "?api-version=2025-04-01",
        "fragment": canonical + "#registry",
        "encoded-separator": canonical.replace("/registries/", "/registries%2F"),
    }

    segments, valid = _evaluate_registry_resource_id(variants[variant])

    assert valid is expected_valid
    if expected_valid:
        assert segments[2] in {
            subscription_id,
            "22222222-2222-2222-2222-222222222222",
        }
        assert segments[4] in {resource_group_name, "rg-central-acr"}
        assert segments[8] == "athenashared"

    for expected in (
        "registryResourceIdRawSegments = split(registryResourceId, '/')",
        "length(registryResourceIdRawSegments) == 9",
        "empty(registryResourceIdSegments[0])",
        "registryResourceIdSegments[1] == 'subscriptions'",
        "registryResourceIdSegments[3] == 'resourceGroups'",
        "registryResourceIdSegments[5] == 'providers'",
        "registryResourceIdSegments[6] == 'Microsoft.ContainerRegistry'",
        "registryResourceIdSegments[7] == 'registries'",
        "!contains(registryResourceId, '//')",
        "!contains(registryResourceId, '?')",
        "!contains(registryResourceId, '#')",
        "!contains(registryResourceId, '%')",
        "registryResourceId must identify one canonical "
        "Microsoft.ContainerRegistry/registries resource",
    ):
        assert expected in source

    registry_block = source.split(
        "resource registry 'Microsoft.ContainerRegistry/registries@2025-11-01' existing =",
        maxsplit=1,
    )[1].split("var expectedRegistryServer", maxsplit=1)[0]
    image_pull_block = source.split(
        "module publisherImagePull "
        "'../wc027-enrichment-feed-runtime/modules/acr-pull-rbac.bicep' =",
        maxsplit=1,
    )[1].split("var requestKeyVerifierRoleId", maxsplit=1)[0]
    assert "scope: resourceGroup(" in registry_block
    assert "validatedRegistryScope.subscriptionId" in registry_block
    assert "validatedRegistryScope.resourceGroupName" in registry_block
    assert "scope: resourceGroup(" in image_pull_block
    assert "registrySubscriptionId" in image_pull_block
    assert "registryResourceGroupName" in image_pull_block
    assert "resourceGroup().name" not in registry_block
    assert "resourceGroup().name" not in image_pull_block


def test_acr_pull_module_matches_pr102_canonical_contract() -> None:
    module = ACR_PULL.read_text(encoding="utf-8")
    repository_condition = (
        "((!(ActionMatches{\\'Microsoft.ContainerRegistry/registries/repositories/"
        "content/read\\'}) AND !(ActionMatches{\\'Microsoft.ContainerRegistry/"
        "registries/repositories/metadata/read\\'})) OR (@Request[Microsoft."
        "ContainerRegistry/registries/repositories:name] StringEqualsIgnoreCase "
        "\\'${validatedRepositoryName}\\'))"
    )

    for expected in (
        "param registryResourceId string",
        "param identityPrincipalId string",
        "param image string",
        "param registryRoleAssignmentMode string",
        "reference(registry.id, '2025-04-01', 'Full')",
        "registryRuntime.properties.roleAssignmentMode == registryRoleAssignmentMode",
        "registryRuntime.properties.?anonymousPullEnabled == false",
        "ACR anonymousPullEnabled must be explicitly false",
        "guardedPullRoleDefinitionResourceId",
        "roleDefinitionId: guardedPullRoleDefinitionResourceId",
        "b93aa761-3e63-49ed-ac28-beffa264f7ac",
        "7f951dda-4ed3-4680-a7ca-43fe172d538d",
        "guid(registry.id, identityPrincipalId, pullRoleDefinitionResourceId)",
        "guid(registry.id, identityPrincipalId, pullRoleDefinitionResourceId, "
        "validatedRepositoryName)",
        "principalType: 'ServicePrincipal'",
        "conditionVersion: pullConditionVersion",
        "condition: pullCondition",
        f"var repositoryCondition = '{repository_condition}'",
        "var pullConditionVersion = validatedRoleAssignmentMode == "
        "'AbacRepositoryPermissions' ? '2.0' : null",
        "var pullCondition = validatedRoleAssignmentMode == "
        "'AbacRepositoryPermissions'",
        "output registryResourceId string = runtimeRegistryResourceId",
        "output roleAssignmentMode string = validatedRoleAssignmentMode",
        "output anonymousPullEnabled bool = validatedAnonymousPullEnabled",
        "output repositoryName string = validatedRepositoryName",
        "output conditionVersion string? = pullConditionVersion",
        "output condition string? = pullCondition",
    ):
        assert expected in module
    assert "param identityResourceId string" not in module
    assert "StringStartsWithIgnoreCase" not in module
    assert not (
        ACR_PULL.parent / "acr-pull-role-assignment.bicep"
    ).exists()


@pytest.mark.parametrize(
    ("requested_repository", "allowed"),
    (
        ("athena/wc027-guidance-authority-publisher", True),
        ("ATHENA/WC027-GUIDANCE-AUTHORITY-PUBLISHER", True),
        ("athena/wc027-guidance-authority-publisher-copy", False),
        ("athena/wc027-guidance-publication-request-producer", False),
        ("other/wc027-guidance-authority-publisher", False),
    ),
)
def test_canonical_abac_condition_denies_cross_repository_access(
    requested_repository: str,
    allowed: bool,
) -> None:
    expected_repository = "athena/wc027-guidance-authority-publisher"

    assert (
        requested_repository.casefold() == expected_repository.casefold()
    ) is allowed
    assert _repository_condition(expected_repository).endswith(
        "StringEqualsIgnoreCase "
        f"'{expected_repository}'))"
    )


def test_each_wc027_job_derives_and_exports_exact_acr_repository_evidence() -> None:
    sources = (
        (
            RUNTIME.read_text(encoding="utf-8"),
            "validatedProducerImage",
            "producerImageRepositoryName",
        ),
        (
            PUBLISHER.read_text(encoding="utf-8"),
            "validatedPublisherImage",
            "publisherImageRepositoryName",
        ),
        (
            REQUEST_PRODUCER.read_text(encoding="utf-8"),
            "validatedProducerImage",
            "producerImageRepositoryName",
        ),
    )

    for source, image_name, repository_name in sources:
        assert f"image: {image_name}" in source
        assert f"var {repository_name} = replace(" in source
        assert "registryRoleAssignmentMode == 'AbacRepositoryPermissions'" in source
        assert "registryPullRoleDefinitionId," in source
        assert f"{repository_name}" in source
        assert ".properties.principalId ==" in source
        for expected in (
            "outputs.registryResourceId",
            "outputs.roleAssignmentMode",
            "outputs.anonymousPullEnabled",
            "outputs.repositoryName",
            "outputs.roleDefinitionResourceId",
            "outputs.roleAssignmentResourceId",
            "outputs.?conditionVersion",
            "outputs.?condition",
        ):
            assert expected in source


def test_module_configuration_and_evidence_share_one_canonical_condition() -> None:
    module = ACR_PULL.read_text(encoding="utf-8")
    publisher = PUBLISHER.read_text(encoding="utf-8")
    root = ROOT_DEPLOYMENT.read_text(encoding="utf-8")
    script = DIGEST_PULL_READINESS.read_text(encoding="utf-8")

    assert (
        "StringEqualsIgnoreCase \\'${validatedRepositoryName}\\'))'"
        in module
    )
    assert "repositoryName: publisherImagePull.outputs.repositoryName" in publisher
    assert "conditionVersion: publisherImagePull.outputs.?conditionVersion" in publisher
    assert "condition: publisherImagePull.outputs.?condition" in publisher
    assert (
        "StringEqualsIgnoreCase "
        "\\'${wc027PublisherImageRepositoryName}\\'))'"
        in root
    )
    assert (
        "StringEqualsIgnoreCase '$repositoryName'))\""
        in script
    )
    assert "conditionVersion = $conditionVersion" in script
    assert "condition = $condition" in script


def test_pr103_readiness_requires_pr102_effective_acr_assignment_scan() -> None:
    root = ROOT_DEPLOYMENT.read_text(encoding="utf-8")

    for expected in (
        "wc027ParsedPublisherImagePullEvidence.effectiveAccess",
        "athena.wc027AcrEffectiveAccessEvidence.v1",
        "length(items(wc027ParsedEffectiveAcrAccess)) == 33",
        "wc027ParsedEffectiveAcrAccess.anonymousPullEnabled == false",
        "wc027ParsedEffectiveAcrAccess.roleDefinitionsResolved == true",
        "wc027ParsedEffectiveAcrAccess.exactAssignmentReadbacksComplete == true",
        "wc027ParsedEffectiveAcrAccess.inheritedAssignmentsComplete == true",
        "wc027ParsedEffectiveAcrAccess.transitiveGroupsComplete == true",
        "wc027ParsedEffectiveAcrAccess.siblingRegistriesChecked == true",
        "wc027ParsedEffectiveAcrAccess.tenantSubscriptionHierarchyComplete == true",
        "wc027ParsedEffectiveAcrAccess.directMembershipTraversalComplete == true",
        "wc027ParsedEffectiveAcrAccess.convergedMembershipReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.roleAssignmentScheduleInstancesComplete == true",
        "wc027ParsedEffectiveAcrAccess.roleAssignmentSchedulesComplete == true",
        "wc027ParsedEffectiveAcrAccess.roleEligibilityScheduleInstancesComplete == true",
        "wc027ParsedEffectiveAcrAccess.roleEligibilitySchedulesComplete == true",
        "wc027ParsedEffectiveAcrAccess.roleManagementPendingRequestsComplete == true",
        "wc027ParsedEffectiveAcrAccess.convergedPimReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.convergedRoleDefinitionReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.acrEscalationPathsChecked == true",
        "length(items(wc027ParsedEffectiveAcrAccess.completeness)) == 13",
        "wc027ParsedEffectiveAcrAccess.completeness.classicRoleAssignments == true",
        "wc027ParsedEffectiveAcrAccess.completeness.pimRoleAssignmentScheduleInstances == true",
        "wc027ParsedEffectiveAcrAccess.completeness.pimRoleAssignmentSchedules == true",
        (
            "wc027ParsedEffectiveAcrAccess.completeness."
            "pimRoleEligibilityScheduleInstances == true"
        ),
        "wc027ParsedEffectiveAcrAccess.completeness.pimRoleEligibilitySchedules == true",
        "wc027ParsedEffectiveAcrAccess.completeness.pimPendingGrantRequests == true",
        "wc027ParsedEffectiveAcrAccess.completeness.pimConvergedReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.completeness.roleDefinitionReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.completeness.transitiveGroups == true",
        "wc027ParsedEffectiveAcrAccess.completeness.siblingRegistries == true",
        "wc027ParsedEffectiveAcrAccess.completeness.acrEscalationPaths == true",
        "wc027ParsedEffectiveAcrAccess.completeness.exactAssignmentReadbacks == true",
        "wc027ParsedEffectiveAcrAccess.completeness.paginationBudgets == true",
        "length(items(wc027ParsedEffectiveAcrAccess.paginationBudgets)) == 10",
        "wc027ParsedEffectiveAcrAccess.paginationBudgets.tenantHierarchyMaxPages == 64",
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "governedSubscriptionMaxCount == 4096"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "graphMembershipMaxPagesPerObject == 16"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "transitiveGroupMaxCountPerPrincipal == 4096"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "classicRoleAssignmentMaxPagesPerQuery == 64"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "classicRoleAssignmentMaxApiCalls == 16384"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "classicRoleAssignmentMaxItems == 65536"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "pimRoleManagementMaxPagesPerQuery == 64"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "pimRoleManagementMaxApiCalls == 98304"
        ),
        (
            "wc027ParsedEffectiveAcrAccess.paginationBudgets."
            "pimRoleManagementMaxItems == 262144"
        ),
        "param wc027ReadinessEvaluationTimeUtc string = utcNow(",
        "dateTimeToEpoch(wc027ReadinessEvaluationTimeUtc)",
        "wc027EffectiveAcrEvidenceFresh",
        "wc027EffectiveAcrEvidenceDigestValid",
        "wc027ReviewedRequestProducerAcrAssignmentValid",
        "wc027ReviewedFeedProducerAcrAssignmentValid",
        "length(items(wc027ReviewedRequestProducerAcrAssignment)) == 9",
        "length(items(wc027ReviewedFeedProducerAcrAssignment)) == 9",
        "length(items(wc027ReviewedPublisherAcrAssignment)) == 9",
        "wc027EffectiveAcrSummarySetsValid",
        "empty(wc027ParsedEffectiveAcrAccess.extraPullCapableAssignmentIds)",
        "param wc027RequestProducerImagePullBindingJson string = ''",
        "param wc027EnrichmentFeedProducerImagePullBindingJson string = ''",
        "athena.wc027AcrPullBinding.v1",
        "resource wc027RequestProducerImagePullIdentity "
        "'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing",
        "wc027RequestProducerImagePullIdentity!.properties.principalId",
        "wc027RequestProducerImagePullAssignmentInDeploymentBinding",
        "wc027RequestProducerImagePullAssignmentScopedToRegistry",
        "wc027RequestProducerImagePullRegistryMatchesImage",
        "resource wc027FeedProducerImagePullIdentity "
        "'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' existing",
        "wc027FeedProducerImagePullIdentity!.properties.principalId",
        "wc027FeedProducerImagePullAssignmentInDeploymentBinding",
        "wc027FeedProducerImagePullAssignmentScopedToRegistry",
        "wc027FeedProducerImagePullRegistryMatchesImage",
        "PR #102-equivalent full role-definition resolution",
        "direct, inherited, group-derived, or sibling-registry pull-capable assignment",
        "wc027RequestProducerReady && !wc027EffectiveAcrAssignmentsVerified",
        "wc027PublisherReady && !wc027EffectiveAcrAssignmentsVerified",
        "wc027FeedV2ProducerReady && !wc027EffectiveAcrAssignmentsVerified",
    ):
        assert expected in root
    assert "param wc027EffectiveAcrAssignmentsVerified" not in root
    assert "RegistryAnonymousPullEnabled bool" not in root


def test_publisher_digest_pull_readiness_is_bounded_and_activation_gated() -> None:
    script = DIGEST_PULL_READINESS.read_text(encoding="utf-8")
    root = ROOT_DEPLOYMENT.read_text(encoding="utf-8")

    for expected in (
        "[ValidateRange(1, 20)]",
        "[int] $MaxAttempts = 10",
        "[ValidateRange(1, 60)]",
        "[int] $DelaySeconds = 30",
        "function Get-RegistryReadback",
        "function Get-ManagedIdentityReadback",
        "function Assert-ExactJsonObjectProperties",
        "function Assert-ExactStringSet",
        "function Test-JsonBoolean",
        "function Test-JsonInteger",
        "az resource show",
        "--subscription $SubscriptionId",
        "--api-version '2025-04-01'",
        "$prePullRegistry = Get-RegistryReadback",
        "$postPullRegistry = Get-RegistryReadback",
        "$prePullIdentity = Get-ManagedIdentityReadback",
        "$postPullIdentity = Get-ManagedIdentityReadback",
        "function Get-EffectiveAccessEvidence",
        "$prePullEffectiveAccessEvidence = Get-EffectiveAccessEvidence",
        "$postPullEffectiveAccessEvidence = Get-EffectiveAccessEvidence",
        "tenantSubscriptionHierarchyComplete",
        "directMembershipTraversalComplete",
        "convergedMembershipReadbacks",
        "roleAssignmentScheduleInstancesComplete",
        "roleAssignmentSchedulesComplete",
        "roleEligibilityScheduleInstancesComplete",
        "roleEligibilitySchedulesComplete",
        "roleManagementPendingRequestsComplete",
        "acrEscalationPathsChecked",
        "classicRoleAssignments",
        "pimRoleAssignmentScheduleInstances",
        "pimRoleAssignmentSchedules",
        "pimRoleEligibilityScheduleInstances",
        "pimRoleEligibilitySchedules",
        "pimPendingGrantRequests",
        "pimConvergedReadbacks",
        "roleDefinitionReadbacks",
        "paginationBudgets",
        "classicRoleAssignmentMaxPagesPerQuery",
        "classicRoleAssignmentMaxApiCalls",
        "classicRoleAssignmentMaxItems",
        "pimRoleManagementMaxPagesPerQuery",
        "pimRoleManagementMaxApiCalls",
        "pimRoleManagementMaxItems",
        "evidenceDigest",
        "verify_wc027_acr_effective_access.py",
        "--expected-assignments-json $ExpectedPullAssignmentsJson",
        "athena.wc027AcrEffectiveAccessEvidence.v1",
        "reviewedAssignments",
        "$ManagedIdentityPrincipalId",
        "$RegistryPullRoleAssignmentResourceId",
        "$isolatedAzureConfigDir",
        "$env:AZURE_CONFIG_DIR = $isolatedAzureConfigDir",
        "Live ACR anonymousPullEnabled must be explicitly false",
        "& az login `",
        "--identity `",
        "--client-id $ManagedIdentityClientId `",
        "& az acr login `",
        "--name $registryName `",
        "--expose-token `",
        "& docker login `",
        "& docker pull $Image",
        "& docker image inspect `",
        "--format '{{json .RepoDigests}}'",
        "if ($Image -notin $repoDigests)",
        "Start-Sleep -Seconds $DelaySeconds",
        "athena.wc027AcrDigestPullReadiness.v1",
        "repositoryName = $repositoryName",
        "managedIdentityResourceId = $ManagedIdentityResourceId",
        "roleAssignmentMode = $RegistryRoleAssignmentMode",
        "anonymousPullEnabled = $false",
        "roleDefinitionId = $roleDefinitionId",
        "conditionVersion = $conditionVersion",
        "condition = $condition",
        "effectiveAccess = $postPullEffectiveAccessEvidence",
        "success = $true",
        "ConvertTo-Json -Depth 8 -Compress",
        "docker logout $registryServer",
    ):
        assert expected in script
    assert "param RegistryAnonymousPullEnabled" not in script
    assert script.index("$prePullRegistry = Get-RegistryReadback") < script.index(
        "& az login"
    )
    assert script.index("$env:AZURE_CONFIG_DIR = $isolatedAzureConfigDir") < script.index(
        "& az account set"
    )
    assert script.index("& docker pull") < script.index(
        "$postPullRegistry = Get-RegistryReadback"
    )
    assert "Write-Output $token" not in script
    assert "Write-Host $token" not in script

    for expected in (
        "param wc027PublisherImagePullEvidenceJson string = ''",
        "wc027PublisherImagePullEvidenceValid",
        "athena.wc027AcrDigestPullReadiness.v1",
        "managedIdentityClientId",
        "managedIdentityResourceId",
        "repositoryName",
        "roleAssignmentMode",
        "anonymousPullEnabled",
        "roleDefinitionId",
        "conditionVersion",
        "condition",
        "wc027PublisherExpectedRepositoryCondition",
        "wc027PublisherImagePullConditionValid",
        "wc027ParsedPublisherImagePullEvidence.anonymousPullEnabled == false",
        "successful bounded managed-identity digest-pull evidence",
    ):
        assert expected in root


@pytest.mark.parametrize(
    (
        "anonymous_pull_enabled",
        "classic_flag_name",
        "classic_assignments_complete",
        "classic_assignment_max_calls_literal",
        "request_summary_assignment_id",
        "should_succeed",
        "expected_error",
    ),
    (
        (
            False,
            "classicRoleAssignments",
            True,
            "16384",
            "request-assignment",
            True,
            None,
        ),
        (
            True,
            "classicRoleAssignments",
            True,
            "16384",
            "request-assignment",
            False,
            "anonymousPullEnabled must be explicitly false",
        ),
        (
            False,
            "classicRoleAssignments",
            False,
            "16384",
            "request-assignment",
            False,
            "Effective ACR assignment evidence is invalid or incomplete",
        ),
        (
            False,
            "classicRoleAssignments",
            True,
            "0",
            "request-assignment",
            False,
            "Effective ACR assignment evidence is invalid or incomplete",
        ),
        (
            False,
            "ClassicRoleAssignments",
            True,
            "16384",
            "request-assignment",
            False,
            "property names.",
        ),
        (
            False,
            "classicRoleAssignments",
            True,
            "'16384'",
            "request-assignment",
            False,
            "Effective ACR assignment evidence is invalid or incomplete",
        ),
        (
            False,
            "classicRoleAssignments",
            True,
            "16384",
            "unrelated-assignment",
            False,
            "does not match its reviewed assignment values",
        ),
    ),
)
def test_digest_pull_probe_validates_live_and_effective_access_contract(
    anonymous_pull_enabled: bool,
    classic_flag_name: str,
    classic_assignments_complete: bool,
    classic_assignment_max_calls_literal: str,
    request_summary_assignment_id: str,
    should_succeed: bool,
    expected_error: str | None,
) -> None:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell is unavailable")
    registry_id = (
        "/subscriptions/11111111-1111-1111-1111-111111111111/"
        "resourceGroups/rg-shared-acr/providers/"
        "Microsoft.ContainerRegistry/registries/athenashared"
    )
    image = (
        "athenashared.azurecr.io/athena/"
        "wc027-guidance-authority-publisher@sha256:" + "a" * 64
    )
    assignment_id = (
        f"{registry_id}/providers/Microsoft.Authorization/"
        "roleAssignments/55555555-5555-4555-8555-555555555555"
    )
    identity_resource_id = (
        "/subscriptions/11111111-1111-1111-1111-111111111111/"
        "resourceGroups/rg-wc027/providers/Microsoft.ManagedIdentity/"
        "userAssignedIdentities/wc027-publisher-broker"
    )
    command = r"""
function global:az {
    $arguments = @($args)
    $global:LASTEXITCODE = 0
    if ($arguments[0] -eq 'resource' -and $arguments[1] -eq 'show') {
        $resourceId = $arguments[$arguments.IndexOf('--ids') + 1]
        if ($resourceId -eq '__IDENTITY_ID__') {
            [ordered]@{
                id = '__IDENTITY_ID__'
                properties = [ordered]@{
                    clientId = '22222222-2222-2222-2222-222222222222'
                    principalId = '22222222-2222-4222-8222-222222222222'
                }
            } | ConvertTo-Json -Compress
            return
        }
        [ordered]@{
            id = '__REGISTRY_ID__'
            properties = [ordered]@{
                roleAssignmentMode = 'AbacRepositoryPermissions'
                anonymousPullEnabled = __ANONYMOUS__
            }
        } | ConvertTo-Json -Compress
        return
    }
    if ($arguments[0] -eq 'acr' -and $arguments[1] -eq 'login') {
        'synthetic-token'
        return
    }
}
function global:docker {
    $arguments = @($args)
    $global:LASTEXITCODE = 0
    if ($arguments[0] -eq 'image' -and $arguments[1] -eq 'inspect') {
        '["__IMAGE__"]'
    }
}
function global:python {
    $global:LASTEXITCODE = 0
    [ordered]@{
        schemaVersion = 'athena.wc027AcrEffectiveAccessEvidence.v1'
        verified = $true
        tenantId = '10101010-1010-4010-8010-101010101010'
        tenantSubscriptionHierarchyComplete = $true
        governedSubscriptionIds = @('11111111-1111-1111-1111-111111111111')
        anonymousPullEnabled = $false
        expectedAssignmentCount = 3
        pullCapableAssignmentCount = 3
        roleDefinitionsResolved = $true
        exactAssignmentReadbacksComplete = $true
        directAssignmentsComplete = $true
        inheritedAssignmentsComplete = $true
        transitiveGroupsComplete = $true
        directMembershipTraversalComplete = $true
        convergedMembershipReadbacks = $true
        roleAssignmentScheduleInstancesComplete = $true
        roleAssignmentSchedulesComplete = $true
        roleEligibilityScheduleInstancesComplete = $true
        roleEligibilitySchedulesComplete = $true
        roleManagementPendingRequestsComplete = $true
        convergedPimReadbacks = $true
        convergedRoleDefinitionReadbacks = $true
        siblingRegistriesChecked = $true
        acrEscalationPathsChecked = $true
        completeness = [ordered]@{
            __CLASSIC_FLAG_NAME__ = __CLASSIC_COMPLETE__
            pimRoleAssignmentScheduleInstances = $true
            pimRoleAssignmentSchedules = $true
            pimRoleEligibilityScheduleInstances = $true
            pimRoleEligibilitySchedules = $true
            pimPendingGrantRequests = $true
            pimConvergedReadbacks = $true
            roleDefinitionReadbacks = $true
            transitiveGroups = $true
            siblingRegistries = $true
            acrEscalationPaths = $true
            exactAssignmentReadbacks = $true
            paginationBudgets = $true
        }
        paginationBudgets = [ordered]@{
            tenantHierarchyMaxPages = 64
            governedSubscriptionMaxCount = 4096
            graphMembershipMaxPagesPerObject = 16
            transitiveGroupMaxCountPerPrincipal = 4096
            classicRoleAssignmentMaxPagesPerQuery = 64
            classicRoleAssignmentMaxApiCalls = __CLASSIC_MAX_CALLS__
            classicRoleAssignmentMaxItems = 65536
            pimRoleManagementMaxPagesPerQuery = 64
            pimRoleManagementMaxApiCalls = 98304
            pimRoleManagementMaxItems = 262144
        }
        evidenceDigest = 'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
        expectedAssignmentIds = @(
            '__REQUEST_SUMMARY_ASSIGNMENT_ID__'
            'feed-assignment'
            '__ASSIGNMENT_ID__'
        )
        principalIds = @(
            '22222222-2222-4222-8222-222222222222'
            '33333333-3333-4333-8333-333333333333'
            '44444444-4444-4444-8444-444444444444'
        )
        registryResourceIds = @('__REGISTRY_ID__')
        reviewedAssignments = @(
            [ordered]@{
                label = 'request-producer'
                principalId = '33333333-3333-4333-8333-333333333333'
                assignmentResourceId = 'request-assignment'
                registryResourceId = '__REGISTRY_ID__'
                repositoryName = 'athena/wc027-guidance-publication-request-producer'
                roleAssignmentMode = 'AbacRepositoryPermissions'
                roleDefinitionId = 'b93aa761-3e63-49ed-ac28-beffa264f7ac'
                conditionVersion = '2.0'
                condition = 'request-condition'
            }
            [ordered]@{
                label = 'feed-producer'
                principalId = '44444444-4444-4444-8444-444444444444'
                assignmentResourceId = 'feed-assignment'
                registryResourceId = '__REGISTRY_ID__'
                repositoryName = 'athena/wc027-enrichment-feed-producer'
                roleAssignmentMode = 'AbacRepositoryPermissions'
                roleDefinitionId = 'b93aa761-3e63-49ed-ac28-beffa264f7ac'
                conditionVersion = '2.0'
                condition = 'feed-condition'
            }
            [ordered]@{
                label = 'publisher'
                principalId = '22222222-2222-4222-8222-222222222222'
                assignmentResourceId = '__ASSIGNMENT_ID__'
                registryResourceId = '__REGISTRY_ID__'
                repositoryName = 'athena/wc027-guidance-authority-publisher'
                roleAssignmentMode = 'AbacRepositoryPermissions'
                roleDefinitionId = 'b93aa761-3e63-49ed-ac28-beffa264f7ac'
                conditionVersion = '2.0'
                condition = (
                    "((!(ActionMatches{'Microsoft.ContainerRegistry/registries/" +
                    "repositories/content/read'}) AND !(ActionMatches{" +
                    "'Microsoft.ContainerRegistry/registries/repositories/metadata/read'})) " +
                    "OR (@Request[Microsoft.ContainerRegistry/registries/repositories:name] " +
                    "StringEqualsIgnoreCase 'athena/wc027-guidance-authority-publisher'))"
                )
            }
        )
        extraPullCapableAssignmentIds = @()
        verifiedAt = '2026-09-17T04:40:00.000Z'
    } | ConvertTo-Json -Depth 6 -Compress
}
& '__SCRIPT__' `
    -RegistryResourceId '__REGISTRY_ID__' `
    -Image '__IMAGE__' `
    -ManagedIdentityResourceId '__IDENTITY_ID__' `
    -ManagedIdentityClientId '22222222-2222-2222-2222-222222222222' `
    -ManagedIdentityPrincipalId '22222222-2222-4222-8222-222222222222' `
    -RegistryRoleAssignmentMode 'AbacRepositoryPermissions' `
    -RegistryPullRoleAssignmentResourceId '__ASSIGNMENT_ID__' `
    -ExpectedPullAssignmentsJson '[]' `
    -MaxAttempts 1 `
    -DelaySeconds 1
""".replace("__REGISTRY_ID__", registry_id).replace(
        "__IMAGE__", image
    ).replace(
        "__IDENTITY_ID__", identity_resource_id
    ).replace(
        "__ANONYMOUS__", "$true" if anonymous_pull_enabled else "$false"
    ).replace(
        "__CLASSIC_COMPLETE__",
        "$true" if classic_assignments_complete else "$false",
    ).replace(
        "__CLASSIC_FLAG_NAME__",
        classic_flag_name,
    ).replace(
        "__CLASSIC_MAX_CALLS__",
        classic_assignment_max_calls_literal,
    ).replace(
        "__REQUEST_SUMMARY_ASSIGNMENT_ID__",
        request_summary_assignment_id,
    ).replace(
        "__ASSIGNMENT_ID__", assignment_id
    ).replace(
        "__SCRIPT__", str(DIGEST_PULL_READINESS).replace("'", "''")
    )

    completed = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert (completed.returncode == 0) is should_succeed
    combined = completed.stdout + completed.stderr
    if should_succeed:
        evidence = json.loads(
            next(
                line
                for line in reversed(completed.stdout.splitlines())
                if line.startswith("{")
            )
        )
        assert evidence["anonymousPullEnabled"] is False
        assert evidence["managedIdentityResourceId"] == identity_resource_id
        assert (
            evidence["managedIdentityPrincipalId"]
            == "22222222-2222-4222-8222-222222222222"
        )
        assert evidence["roleAssignmentResourceId"] == assignment_id
        assert evidence["effectiveAccess"]["verified"] is True
        assert evidence["success"] is True
    else:
        assert expected_error is not None
        assert expected_error in combined


def test_publisher_digest_pull_evidence_evaluates_ready() -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")
    bindings, evidence, live_bindings = _publisher_image_pull_evidence()

    assert _evaluate_publisher_image_pull_evidence(
        source,
        bindings=bindings,
        evidence=evidence,
        live_bindings=live_bindings,
    )


def test_legacy_digest_pull_evidence_uses_null_repository_conditions() -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")
    bindings, evidence, live_bindings = _publisher_image_pull_evidence()
    binding = bindings["publisher"]
    binding["roleAssignmentMode"] = "LegacyRegistryPermissions"
    binding["roleDefinitionId"] = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
    binding["conditionVersion"] = None
    binding["condition"] = None
    evidence["roleAssignmentMode"] = binding["roleAssignmentMode"]
    evidence["roleDefinitionId"] = binding["roleDefinitionId"]
    evidence["conditionVersion"] = None
    evidence["condition"] = None
    effective_access = evidence["effectiveAccess"]
    assert isinstance(effective_access, dict)
    reviewed_assignments = effective_access["reviewedAssignments"]
    assert isinstance(reviewed_assignments, list)
    for label, expected_binding in bindings.items():
        expected_binding["roleAssignmentMode"] = "LegacyRegistryPermissions"
        expected_binding["roleDefinitionId"] = (
            "7f951dda-4ed3-4680-a7ca-43fe172d538d"
        )
        expected_binding["conditionVersion"] = None
        expected_binding["condition"] = None
        live_binding = live_bindings[label]
        live_binding["roleAssignmentMode"] = "LegacyRegistryPermissions"
        live_binding["roleDefinitionId"] = (
            "7f951dda-4ed3-4680-a7ca-43fe172d538d"
        )
        live_binding["conditionVersion"] = None
        live_binding["condition"] = None
        reviewed_assignment = next(
            item
            for item in reviewed_assignments
            if isinstance(item, dict) and item.get("label") == label
        )
        reviewed_assignment["roleAssignmentMode"] = "LegacyRegistryPermissions"
        reviewed_assignment["roleDefinitionId"] = (
            "7f951dda-4ed3-4680-a7ca-43fe172d538d"
        )
        reviewed_assignment["conditionVersion"] = None
        reviewed_assignment["condition"] = None

    assert _evaluate_publisher_image_pull_evidence(
        source,
        bindings=bindings,
        evidence=evidence,
        live_bindings=live_bindings,
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "schema",
        "success",
        "registry",
        "server",
        "image",
        "identity-resource",
        "identity",
        "identity-principal",
        "anonymous",
        "repository",
        "mode",
        "role",
        "assignment-resource",
        "condition-version",
        "condition",
        "effective-anonymous",
        "effective-role-definitions",
        "effective-exact-readbacks",
        "effective-inherited",
        "effective-groups",
        "effective-direct-membership",
        "effective-convergence",
        "effective-schedules",
        "effective-assignment-schedules",
        "effective-eligibility-instances",
        "effective-eligibility-schedules",
        "effective-pending-requests",
        "effective-pim-convergence",
        "effective-role-definition-convergence",
        "effective-escalation",
        "effective-completeness-classic",
        "effective-completeness-pim",
        "effective-completeness-assignment-schedules",
        "effective-completeness-eligibility-instances",
        "effective-completeness-eligibility-schedules",
        "effective-completeness-pending-requests",
        "effective-completeness-pim-convergence",
        "effective-completeness-role-definitions",
        "effective-completeness-groups",
        "effective-completeness-siblings",
        "effective-completeness-escalation",
        "effective-completeness-readbacks",
        "effective-completeness-budgets",
        "effective-budget-tenant-pages",
        "effective-budget-subscriptions",
        "effective-budget-graph-pages",
        "effective-budget-groups",
        "effective-budget-classic-pages",
        "effective-budget-classic-calls",
        "effective-budget-classic-items",
        "effective-budget-pim-pages",
        "effective-budget-pim-calls",
        "effective-budget-pim-items",
        "effective-extra-field",
        "effective-reviewed-extra-field",
        "effective-summary-assignments",
        "effective-summary-principals",
        "effective-summary-registries",
        "effective-completeness-case",
        "effective-budget-string",
        "effective-budget-extra-field",
        "effective-hierarchy",
        "effective-stale",
        "effective-count",
        "effective-extra",
        "effective-reviewed-condition",
        "effective-reviewed-label",
        "attempts-zero",
        "attempts-over-max",
        "max-over-bound",
        "verified-at",
        "pull-stale",
    ),
)
def test_publisher_digest_pull_evidence_rejects_drift(mutation: str) -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")
    bindings, evidence, live_bindings = _publisher_image_pull_evidence()
    binding = bindings["publisher"]
    selected = deepcopy(evidence)
    mutations = {
        "schema": ("schemaVersion", "synthetic.invalid"),
        "success": ("success", False),
        "registry": ("registryResourceId", "/synthetic/registry"),
        "server": ("registryServer", "different.azurecr.io"),
        "image": ("image", str(binding["image"]).replace("a" * 64, "b" * 64)),
        "identity-resource": (
            "managedIdentityResourceId",
            "/subscriptions/11111111-1111-1111-1111-111111111111/"
            "resourceGroups/rg-wc027/providers/Microsoft.ManagedIdentity/"
            "userAssignedIdentities/other-publisher",
        ),
        "identity": (
            "managedIdentityClientId",
            "33333333-3333-3333-3333-333333333333",
        ),
        "identity-principal": (
            "managedIdentityPrincipalId",
            "33333333-3333-4333-8333-333333333333",
        ),
        "anonymous": ("anonymousPullEnabled", True),
        "repository": ("repositoryName", "athena/other-repository"),
        "mode": ("roleAssignmentMode", "LegacyRegistryPermissions"),
        "role": (
            "roleDefinitionId",
            "7f951dda-4ed3-4680-a7ca-43fe172d538d",
        ),
        "assignment-resource": (
            "roleAssignmentResourceId",
            "/synthetic/assignment",
        ),
        "condition-version": ("conditionVersion", None),
        "condition": (
            "condition",
            _repository_condition("athena/other-repository"),
        ),
        "attempts-zero": ("attempts", 0),
        "attempts-over-max": ("attempts", 11),
        "max-over-bound": ("maxAttempts", 21),
        "verified-at": ("verifiedAt", ""),
        "pull-stale": ("verifiedAt", "2020-01-01T00:00:00.000Z"),
    }
    effective_mutations = {
        "effective-anonymous": ("anonymousPullEnabled", True),
        "effective-role-definitions": ("roleDefinitionsResolved", False),
        "effective-exact-readbacks": ("exactAssignmentReadbacksComplete", False),
        "effective-inherited": ("inheritedAssignmentsComplete", False),
        "effective-groups": ("transitiveGroupsComplete", False),
        "effective-direct-membership": (
            "directMembershipTraversalComplete",
            False,
        ),
        "effective-convergence": ("convergedMembershipReadbacks", False),
        "effective-schedules": (
            "roleAssignmentScheduleInstancesComplete",
            False,
        ),
        "effective-assignment-schedules": (
            "roleAssignmentSchedulesComplete",
            False,
        ),
        "effective-eligibility-instances": (
            "roleEligibilityScheduleInstancesComplete",
            False,
        ),
        "effective-eligibility-schedules": (
            "roleEligibilitySchedulesComplete",
            False,
        ),
        "effective-pending-requests": (
            "roleManagementPendingRequestsComplete",
            False,
        ),
        "effective-pim-convergence": ("convergedPimReadbacks", False),
        "effective-role-definition-convergence": (
            "convergedRoleDefinitionReadbacks",
            False,
        ),
        "effective-escalation": ("acrEscalationPathsChecked", False),
        "effective-hierarchy": ("tenantSubscriptionHierarchyComplete", False),
        "effective-stale": ("verifiedAt", "2020-01-01T00:00:00.000Z"),
        "effective-count": ("expectedAssignmentCount", 2),
        "effective-extra": (
            "extraPullCapableAssignmentIds",
            ["unexpected-assignment"],
        ),
    }
    effective_completeness_mutations = {
        "effective-completeness-classic": "classicRoleAssignments",
        "effective-completeness-pim": "pimRoleAssignmentScheduleInstances",
        "effective-completeness-assignment-schedules": "pimRoleAssignmentSchedules",
        "effective-completeness-eligibility-instances": (
            "pimRoleEligibilityScheduleInstances"
        ),
        "effective-completeness-eligibility-schedules": "pimRoleEligibilitySchedules",
        "effective-completeness-pending-requests": "pimPendingGrantRequests",
        "effective-completeness-pim-convergence": "pimConvergedReadbacks",
        "effective-completeness-role-definitions": "roleDefinitionReadbacks",
        "effective-completeness-groups": "transitiveGroups",
        "effective-completeness-siblings": "siblingRegistries",
        "effective-completeness-escalation": "acrEscalationPaths",
        "effective-completeness-readbacks": "exactAssignmentReadbacks",
        "effective-completeness-budgets": "paginationBudgets",
    }
    effective_budget_mutations = {
        "effective-budget-tenant-pages": "tenantHierarchyMaxPages",
        "effective-budget-subscriptions": "governedSubscriptionMaxCount",
        "effective-budget-graph-pages": "graphMembershipMaxPagesPerObject",
        "effective-budget-groups": "transitiveGroupMaxCountPerPrincipal",
        "effective-budget-classic-pages": "classicRoleAssignmentMaxPagesPerQuery",
        "effective-budget-classic-calls": "classicRoleAssignmentMaxApiCalls",
        "effective-budget-classic-items": "classicRoleAssignmentMaxItems",
        "effective-budget-pim-pages": "pimRoleManagementMaxPagesPerQuery",
        "effective-budget-pim-calls": "pimRoleManagementMaxApiCalls",
        "effective-budget-pim-items": "pimRoleManagementMaxItems",
    }
    effective_access = selected["effectiveAccess"]
    assert isinstance(effective_access, dict)
    if mutation == "effective-extra-field":
        effective_access["unexpected"] = True
    elif mutation == "effective-reviewed-extra-field":
        reviewed_assignments = effective_access["reviewedAssignments"]
        assert isinstance(reviewed_assignments, list)
        reviewed_assignment = reviewed_assignments[0]
        assert isinstance(reviewed_assignment, dict)
        reviewed_assignment["unexpected"] = True
    elif mutation == "effective-summary-assignments":
        effective_access["expectedAssignmentIds"] = [
            "synthetic-unrelated-assignment-1",
            "synthetic-unrelated-assignment-2",
            "synthetic-unrelated-assignment-3",
        ]
    elif mutation == "effective-summary-principals":
        effective_access["principalIds"] = [
            "55555555-5555-4555-8555-555555555555",
            "66666666-6666-4666-8666-666666666666",
            "77777777-7777-4777-8777-777777777777",
        ]
    elif mutation == "effective-summary-registries":
        effective_access["registryResourceIds"] = ["/synthetic/registry"]
    elif mutation == "effective-completeness-case":
        completeness = effective_access["completeness"]
        assert isinstance(completeness, dict)
        completeness["ClassicRoleAssignments"] = completeness.pop(
            "classicRoleAssignments"
        )
    elif mutation == "effective-budget-string":
        pagination_budgets = effective_access["paginationBudgets"]
        assert isinstance(pagination_budgets, dict)
        pagination_budgets["classicRoleAssignmentMaxApiCalls"] = "16384"
    elif mutation == "effective-budget-extra-field":
        pagination_budgets = effective_access["paginationBudgets"]
        assert isinstance(pagination_budgets, dict)
        pagination_budgets["unexpected"] = 1
    elif mutation in effective_mutations:
        key, value = effective_mutations[mutation]
        effective_access[key] = value
    elif mutation in effective_completeness_mutations:
        completeness = effective_access["completeness"]
        assert isinstance(completeness, dict)
        completeness[effective_completeness_mutations[mutation]] = False
    elif mutation in effective_budget_mutations:
        pagination_budgets = effective_access["paginationBudgets"]
        assert isinstance(pagination_budgets, dict)
        pagination_budgets[effective_budget_mutations[mutation]] = 0
    elif mutation.startswith("effective-reviewed-"):
        reviewed_assignments = effective_access["reviewedAssignments"]
        assert isinstance(reviewed_assignments, list)
        publisher_assignment = next(
            item
            for item in reviewed_assignments
            if isinstance(item, dict) and item.get("label") == "publisher"
        )
        if mutation == "effective-reviewed-condition":
            publisher_assignment["condition"] = _repository_condition(
                "athena/other-repository"
            )
        else:
            publisher_assignment["label"] = "other"
    else:
        key, value = mutations[mutation]
        selected[key] = value

    assert not _evaluate_publisher_image_pull_evidence(
        source,
        bindings=bindings,
        evidence=selected,
        live_bindings=live_bindings,
    )


def test_publisher_client_and_scanned_principal_must_be_one_live_identity() -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")
    bindings, evidence, live_bindings = _publisher_image_pull_evidence()
    stale_client_id = "99999999-9999-4999-8999-999999999999"
    bindings["publisher"]["identityClientId"] = stale_client_id
    evidence["managedIdentityClientId"] = stale_client_id

    assert not _evaluate_publisher_image_pull_evidence(
        source,
        bindings=bindings,
        evidence=evidence,
        live_bindings=live_bindings,
    )


@pytest.mark.parametrize("label", ("request-producer", "feed-producer"))
def test_effective_access_evidence_binds_each_deployed_producer(
    label: str,
) -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")
    bindings, evidence, live_bindings = _publisher_image_pull_evidence()
    selected = deepcopy(evidence)
    effective_access = selected["effectiveAccess"]
    assert isinstance(effective_access, dict)
    reviewed_assignments = effective_access["reviewedAssignments"]
    assert isinstance(reviewed_assignments, list)
    reviewed_assignment = next(
        item
        for item in reviewed_assignments
        if isinstance(item, dict) and item.get("label") == label
    )
    stale_principal_id = "99999999-9999-4999-8999-999999999999"
    bindings[label]["principalId"] = stale_principal_id
    reviewed_assignment["principalId"] = stale_principal_id

    assert not _evaluate_publisher_image_pull_evidence(
        source,
        bindings=bindings,
        evidence=selected,
        live_bindings=live_bindings,
    )


def test_publisher_data_plane_roles_are_exact_and_non_destructive() -> None:
    blob = BLOB_CREATOR.read_text(encoding="utf-8")
    table = TABLE_CAS.read_text(encoding="utf-8")
    signer = KEY_SIGNER.read_text(encoding="utf-8")

    assert (
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"
        in blob
    )
    for forbidden in (
        "blobs/read",
        "blobs/write",
        "blobs/delete",
        "blobs/move",
        "blobs/tags/write",
        "immutableStorage/runAsSuperUser",
    ):
        assert forbidden not in blob
    assert "scope: container" in blob

    for allowed in (
        "tables/entities/read",
        "tables/entities/add/action",
        "tables/entities/update/action",
    ):
        assert allowed in table
    for forbidden in (
        "tables/entities/delete",
        "tableServices/tables/delete",
        "tableServices/tables/write",
    ):
        assert forbidden not in table
    assert "scope: table" in table

    assert "Microsoft.KeyVault/vaults/keys/sign/action" in signer
    for forbidden in (
        "keys/read",
        "keys/verify/action",
        "keys/encrypt/action",
        "keys/decrypt/action",
        "keys/wrap/action",
        "keys/unwrap/action",
        "keys/update",
        "keys/backup/action",
    ):
        assert forbidden not in signer
    assert "scope: key" in signer
    assert "12338af0-0e69-4776-bea7-57ae8d297424" not in signer


def test_runtime_requires_current_activation_and_logical_binding_key() -> None:
    source = RUNTIME.read_text(encoding="utf-8")

    assert "param guidanceActivationReaderIdentityResourceId string" in source
    assert "param guidanceBindingLogicalKeyId string" in source
    assert "tableName: guidanceActivation.name" in source
    assert "keyId: guidanceBindingLogicalKeyId" in source
    assert "guidanceActivationMaterializerRbac" in source
    assert "guidanceActivationMaterializerRoleId" in source
    assert "guidanceActivationMaterializerAssignmentId" in source
    assert "runtimeTrustDomainFingerprints" in source
    assert "validatedTrustDomainMetadata" in source
    assert "trust-domain public key fingerprints must be distinct" in source


def test_readiness_remains_false_until_deployment_is_proven() -> None:
    source = ROOT_DEPLOYMENT.read_text(encoding="utf-8")

    assert "param wc027FeedV2ProducerReady bool = false" in source
    assert "param wc027PublisherReady bool = false" in source
    assert (
        "WC-027 Notification v2 requires an explicitly ready "
        "PublishedGuidanceAuthorityBinding.v2 publisher"
    ) in source
    assert "wc027ParsedConfiguration.guidanceActivation.identityResourceId" in source
