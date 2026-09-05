import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
RUNTIME_BICEP = ROOT / "infra" / "wc016-event-reassessment" / "main.bicep"
ROOT_BICEP = ROOT / "infra" / "wc013-live-acceptance" / "main.bicep"
PARAMETERS = ROOT / ".azure" / "wc013.parameters.json"
CLEANUP_SCRIPT = ROOT / "scripts" / "audit-remove-wc016-legacy-runtime.ps1"
WC016_LOCK = ROOT / "requirements-wc016.lock"
WC016_DOCKERFILES = (
    ROOT / "apps" / "signal-detector" / "Dockerfile",
    ROOT / "apps" / "incident-orchestrator" / "Dockerfile",
)
SIGNAL_RBAC = (
    ROOT
    / "infra"
    / "wc013-live-acceptance"
    / "modules"
    / "wc016-signal-reader-rbac.bicep"
)
SIGNAL_ROLE = (
    ROOT
    / "infra"
    / "wc013-live-acceptance"
    / "modules"
    / "wc016-signal-reader-role.bicep"
)


def test_wc016_images_install_only_hash_locked_dependencies_from_reviewed_index() -> None:
    lock = WC016_LOCK.read_text(encoding="utf-8")
    requirement_blocks = [
        block
        for block in re.split(r"(?m)(?=^[a-z0-9][a-z0-9._-]+==)", lock)
        if re.match(r"^[a-z0-9][a-z0-9._-]+==", block)
    ]

    assert requirement_blocks
    assert not any(
        line.startswith(("--index-url", "--extra-index-url", "--trusted-host"))
        for line in lock.splitlines()
    )
    assert all("--hash=sha256:" in block for block in requirement_blocks)
    assert all(
        re.match(r"^[a-z0-9][a-z0-9._-]+==[^\s\\]+", block)
        for block in requirement_blocks
    )
    assert not {
        "httpx",
        "jsonschema",
        "mypy",
        "pytest",
        "pytest-cov",
        "ruff",
        "types-jsonschema",
    }.intersection(block.partition("==")[0] for block in requirement_blocks)

    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "!requirements-wc016.lock" in dockerignore

    for dockerfile_path in WC016_DOCKERFILES:
        dockerfile = dockerfile_path.read_text(encoding="utf-8")
        assert "ARG PIP_INDEX_URL" not in dockerfile
        assert "COPY requirements-wc016.lock ./" in dockerfile
        assert (
            "--index-url https://packagefeedproxy.microsoft.io/pypi/simple/"
            in dockerfile
        )
        assert "--require-hashes" in dockerfile
        assert "--only-binary=:all:" in dockerfile
        assert "--requirement requirements-wc016.lock" in dockerfile
        assert "--no-deps" in dockerfile
        assert "--no-build-isolation" in dockerfile
        assert dockerfile.index("COPY requirements-wc016.lock ./") < dockerfile.index(
            "COPY src ./src"
        )


def _resource_block(source: str, resource_name: str) -> str:
    start = source.index(f"resource {resource_name} ")
    end = source.index("\n}\n", start) + 2
    return source[start:end]


def test_wc016_service_bus_is_private_keyless_and_duplicate_safe() -> None:
    source = RUNTIME_BICEP.read_text(encoding="utf-8")

    assert "name: 'Premium'" in source
    assert "publicNetworkAccess: 'Disabled'" in source
    assert "disableLocalAuth: true" in source
    assert "privateEndpoints@2024-10-01" in source
    assert "privatelink.servicebus.windows.net" in source
    assert "requiresDuplicateDetection: true" in source
    assert "deadLetteringOnMessageExpiration: true" in source
    assert "requiresSession: true" in source
    assert "listKeys(" not in source
    assert "connectionString" not in source


def test_wc016_runtime_has_four_managed_identity_jobs_without_raw_normalizer() -> None:
    source = RUNTIME_BICEP.read_text(encoding="utf-8")

    assert "cronExpression: '* * * * *'" in source
    assert "cronExpression: '*/5 * * * *'" in source
    assert source.count("Microsoft.App/jobs@2025-01-01") == 4
    assert "jobNamePrefix = take(namePrefix, 18)" in source
    assert source.count("type: 'azure-servicebus'") == 2
    assert "name: '${jobNamePrefix}-w16-det-v2'" in source
    assert "name: '${jobNamePrefix}-w16-orch-v2'" in source
    assert "name: '${jobNamePrefix}-w16-feed-v2'" in source
    assert "name: '${jobNamePrefix}-w16-notify-v2'" in source
    assert "name: '${jobNamePrefix}-w16-det'" not in source
    assert "name: '${jobNamePrefix}-w16-orch'" not in source
    assert "name: '${jobNamePrefix}-w16-notify'" not in source
    assert "'wc016-signal-detector'" in source
    assert "'wc016-incident-orchestrator'" in source
    assert "'wc016-incident-feed-heartbeat'" in source
    assert "'wc016-notification-dispatcher'" in source
    assert "Post_a_message_to_myself" in source
    assert "listCallbackURL(" in source
    assert "teamsCallback.basePath" in source
    assert "teamsCallback.value" not in source
    assert "sasAuthenticationPolicy" in source
    assert "state: 'Disabled'" in source
    assert "openAuthenticationPolicies" in source
    assert "notificationIdentityPrincipalId" in source
    assert "'notificationId'" in source
    assert "'^notify-[a-f0-9]{64}$'" in source
    assert "param notificationStateTableEndpoint string" in source
    assert "param notificationStateTableName string" in source
    assert "param notificationStatePartitionKey string" in source
    notification_job = _resource_block(source, "notificationJob")
    heartbeat_job = _resource_block(source, "heartbeatJob")
    assert "orchestratorIdentityResourceId" in heartbeat_job
    assert "detectorIdentityResourceId" not in heartbeat_job
    assert "notificationIdentityResourceId" not in heartbeat_job
    assert "'ATHENA_WC016_APPROVED_RESOURCE_ROLES_JSON'" in heartbeat_job
    assert "'ATHENA_WC016_APPROVED_ALERT_RULES_JSON'" in heartbeat_job
    assert "'--service-bus-namespace'" not in heartbeat_job
    assert "'--notification-state-table-endpoint'" in notification_job
    assert "notificationStateTableEndpoint" in notification_job
    assert "'--notification-state-table-name'" in notification_job
    assert "notificationStateTableName" in notification_job
    assert "'--notification-state-partition-key'" in notification_job
    assert "notificationStatePartitionKey" in notification_job
    assert "detectorStateTableName" not in notification_job
    assert "detectorStatePartitionKey" not in notification_job
    assert "'https://management.azure.com/'" in source
    assert "'synthetic-key://athena-argus-demo/wc016-incidents-rs256-v1'" in source
    assert "raw-monitor-events" not in source
    assert "normalizer" not in source.casefold()
    assert "monitorActionGroupResourceId" not in source
    assert "Microsoft.Insights/metricAlerts" not in source


def test_wc016_is_composed_into_wc013_with_exact_outputs_and_narrow_access() -> None:
    source = ROOT_BICEP.read_text(encoding="utf-8")
    signal_rbac = SIGNAL_RBAC.read_text(encoding="utf-8")
    signal_role = SIGNAL_ROLE.read_text(encoding="utf-8")

    assert "module wc016Runtime '../wc016-event-reassessment/main.bicep'" in source
    assert "param wc016RuntimeEnabled bool = false" in source
    assert "param wc016LegacyCleanupConfirmed bool = false" in source
    assert "= if (validatedWc016RuntimeEnabled)" in source
    assert "wc016RuntimeEnabled && !wc016LegacyCleanupConfirmed" in source
    assert (
        "WC-016 cannot be activated until the exact legacy cleanup report confirms zero residuals"
        in source
    )
    assert "WC-016 cannot be activated with the checked-in incident trust fixture" in source
    assert "wc016DetectorIdentity" in source
    assert "wc016OrchestratorIdentity" in source
    assert "wc016NotificationIdentity" in source
    assert "${namePrefix}-wc016-detector-v2-id" in source
    assert "${namePrefix}-wc016-orchestrator-v2-id" in source
    assert "${namePrefix}-wc016-notification-v2-id" in source
    assert "${namePrefix}-wc016-detector-id'" not in source
    assert "${namePrefix}-wc016-orchestrator-id'" not in source
    assert "${namePrefix}-wc016-notification-id'" not in source
    assert "incidentOrchestratorPrincipalId" in source
    assert "param wc016NotificationStateTableName string = 'Wc016NotificationState'" in source
    assert (
        "param wc016NotificationStatePartitionKey string = "
        "'wc016-notification-delivery'"
        in source
    )
    assert (
        "notificationStateTableName: wc016NotificationStateTableName"
        in source
    )
    assert (
        "notificationStateTableName: acceptanceResources.outputs.notificationStateTableName"
        in source
    )
    assert "wc016ApprovedResourceRolesJson" in source
    assert "wc016ApprovedAlertRulesJson" in source
    assert "wc016DetectorJobResourceId" in source
    assert "wc016OrchestratorJobResourceId" in source
    assert "wc016DatabaseVmResourceId" in source
    assert "wc016WebVmResourceIds" in source
    assert "wc016LoadBalancerResourceId" in source
    assert "scope: subscription(targetDemoWorkloadSubscriptionId)" in source
    assert "Athena WC016 Approved Signal Reader" in signal_role
    assert "Microsoft.Compute/virtualMachines/instanceView/read" in signal_role
    assert "Microsoft.Insights/metrics/read" in signal_role
    assert "roleDefinitionId: wc016SignalReaderRole!.outputs.roleDefinitionId" in source
    assert (
        "module wc016SignalReaderRole 'modules/wc016-signal-reader-role.bicep' = "
        "if (validatedWc016RuntimeEnabled)"
        in source
    )
    assert (
        "module wc016SignalReaderRbac 'modules/wc016-signal-reader-rbac.bicep' = "
        "if (validatedWc016RuntimeEnabled)"
        in source
    )
    assert source.count(
        "module wc016DetectorImagePull 'modules/acr-pull-rbac.bicep' = "
        "if (validatedWc016RuntimeEnabled)"
    ) == 1
    assert "principalId: detectorPrincipalId" in signal_rbac
    assert "principalId: orchestratorPrincipalId" in signal_rbac
    assert "Microsoft.Resources/subscriptions/resourceGroups/read" not in source

    resources = (
        ROOT
        / "infra"
        / "wc013-live-acceptance"
        / "modules"
        / "acceptance-resources.bicep"
    ).read_text(encoding="utf-8")
    assert "param wc016RuntimeEnabled bool = false" in resources
    assert "roleAssignments: wc016RuntimeEnabled" in resources
    assert (
        "resource detectorStateTableDataContributor "
        "'Microsoft.Authorization/roleAssignments@2022-04-01' = "
        "if (wc016RuntimeEnabled)"
        in resources
    )
    assert (
        "resource notificationStateTableDataContributor "
        "'Microsoft.Authorization/roleAssignments@2022-04-01' = "
        "if (wc016RuntimeEnabled)"
        in resources
    )
    assert "principalId: notificationDispatcherPrincipalId" in resources
    assert (
        "resource notificationStateTable "
        "'Microsoft.Storage/storageAccounts/tableServices/tables@2025-06-01'"
        in resources
    )
    detector_role = _resource_block(resources, "detectorStateTableDataContributor")
    notification_role = _resource_block(
        resources,
        "notificationStateTableDataContributor",
    )
    assert "scope: detectorStateTable" in detector_role
    assert "notificationDispatcherPrincipalId" not in detector_role
    assert "scope: notificationStateTable" in notification_role
    assert "notificationDispatcherPrincipalId" in notification_role
    assert "detectorStateTable" not in notification_role
    assert (
        "resource incidentPresentationAssetBlobDataContributor "
        "'Microsoft.Authorization/roleAssignments@2022-04-01' = "
        "if (wc016RuntimeEnabled)"
        in resources
    )
    assert (
        "resource incidentAssetBlobDataReader "
        "'Microsoft.Authorization/roleAssignments@2022-04-01' = "
        "if (wc016RuntimeEnabled)"
        in resources
    )


def test_wc016_deployment_parameters_use_published_image_digests() -> None:
    source = PARAMETERS.read_text(encoding="utf-8")
    rejected = "@sha256:" + "0" * 64

    assert rejected not in source
    assert (
        "athena/wc016-detector@sha256:"
        "a934a034b900f5f36a1485e4772bb80f71db608be91c55042577a3904b0964bb"
    ) in source
    assert "wc016-normalizer" not in source
    assert (
        "athena/wc016-orchestrator@sha256:"
        "6a6038a103bd92132e7c2baf5f9a0ff77a4b520ba0a9a847b1c53e494b301818"
    ) in source
    assert "athena-hackathon-sqlvm-01" in source
    assert "athena-hackathon-web-03" in source
    assert "athena-hackathon-ilb-middle" in source
    assert "Wc016DetectorState" in source
    assert "Wc016NotificationState" in source
    assert "wc016-notification-delivery" in source
    assert '"wc016RuntimeEnabled"' in source
    assert '"wc016LegacyCleanupConfirmed"' in source
    assert source.count('"value": false') >= 2
    assert '"value": false' in source
    assert (
        "sha256:22be507b9bc31492e1dec2c0f8e9db1c75ca999c13dfb6670e2cce2320ee1a2e"
        in source
    )


def test_wc016_cleanup_script_is_exact_auditable_and_read_only_by_default() -> None:
    source = CLEANUP_SCRIPT.read_text(encoding="utf-8")

    for job_name in (
        "athena-wc013-live-w16-det",
        "athena-wc013-live-w16-orch",
        "athena-wc013-live-w16-norm",
        "athena-wc013-live-w16-notify",
    ):
        assert job_name in source
    for queue_name in (
        "raw-monitor-events",
        "incident-reassessment-requests",
        "incident-notification-outbox",
    ):
        assert queue_name in source
    for identity_name in (
        "athena-wc013-live-wc016-normalizer-id",
        "athena-wc013-live-wc016-orchestrator-id",
        "athena-wc013-live-wc016-notification-id",
    ):
        assert identity_name in source
    for alert_name in (
        "athena-wc013-live-database-availability",
        "athena-wc013-live-web-0-availability",
        "athena-wc013-live-web-1-availability",
        "athena-wc013-live-web-2-availability",
        "athena-wc013-live-load-balancer-vip-availability",
        "athena-wc013-live-load-balancer-dip-availability",
    ):
        assert (
            "$resourceGroupId/providers/Microsoft.Insights/metricAlerts/"
            f"{alert_name}\""
        ) in source

    assert "[switch]$Apply" in source
    assert "if ($Apply)" in source
    assert "wouldDelete" in source
    assert "zeroResidualReadback" in source
    assert "payloadDigestSha256" in source
    assert "[pscustomobject][ordered]@{" in source
    assert "Sort-Object -Property assignmentId -Unique" not in source
    assert "$expectedRoleAssignmentAllowlist" in source
    assert "$beforeUnexpectedLegacyRoleAssignments" in source
    assert "mutationBlockedByUnexpectedAssignment" in source
    assert "residualExpectedLegacyRoleAssignments" in source
    assert "residualUnexpectedLegacyRoleAssignments" in source
    assert "legacyMetricAlerts = @($beforeLegacyMetricAlerts)" in source
    assert "legacyMetricAlerts = @($afterLegacyMetricAlerts)" in source
    assert "expectedLegacyMetricAlertCount = $beforeLegacyMetricAlerts.Count" in source
    assert "presentLegacyMetricAlertCountBefore" in source
    assert "residualLegacyMetricAlertCount" in source
    assert "allLegacyMetricAlertsAbsentBefore" in source
    assert "allLegacyMetricAlertsAbsentAfter" in source
    assert (
        "expectedLegacyRoleAssignmentCountBefore = "
        "$beforeExpectedLegacyRoleAssignments.Count"
    ) in source
    assert (
        "unexpectedLegacyRoleAssignmentCountBefore = "
        "$beforeUnexpectedLegacyRoleAssignments.Count"
    ) in source
    assert (
        "evidenceSenderAssignmentCountBefore = $beforeEvidenceSenderAssignments.Count"
    ) in source
    assert source.count("apiVersion = '2018-03-01'") == 6
    assert "@('metricAlert', 'job', 'queue', 'identity')" in source
    assert "12338af0-0e69-4776-bea7-57ae8d297424" in source
    assert "ba92f5b4-2d11-453d-a403-e96b0029c9fe" in source
    assert "7f951dda-4ed3-4680-a7ca-43fe172d538d" in source
    assert "/keys/wc013-signing" in source
    assert "/containers/presentation-assets" in source
    assert "/keys/wc016-incident-signing" not in source
    assert "/containers/incident-assets" not in source
    assert "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39" in source
    assert "Test-SameResourceId -Left $_.scope" in source
    assert "athena-wc013-live-mcp-evidence-id" in source
    assert "athena-wc013-live-wc016-events" in source
    assert "athena-wc016-teams-notifier" in source
    assert "wc016-detector-v2-id" not in source
    assert "wc016-orchestrator-v2-id" not in source
    assert "wc016-notification-v2-id" not in source
    assert "Remove-AzRoleAssignment" not in source
    assert "--name '*'" not in source
    assert re.search(r"(?<!\[pscustomobject\])\[ordered\]@\{", source) is None

    allowlist = source.split(
        "$expectedRoleAssignmentAllowlist = @(",
        maxsplit=1,
    )[1].split(
        "$beforeExpectedLegacyRoleAssignments",
        maxsplit=1,
    )[0]
    assert allowlist.count("[pscustomobject][ordered]@{") == 11
    assert (
        allowlist.count(
            "principalName = 'athena-wc013-live-wc016-normalizer-id'"
        )
        == 3
    )
    assert (
        allowlist.count(
            "principalName = 'athena-wc013-live-wc016-orchestrator-id'"
        )
        == 5
    )
    assert (
        allowlist.count(
            "principalName = 'athena-wc013-live-wc016-notification-id'"
        )
        == 2
    )
    assert "principalName = $evidenceIdentityName" in allowlist
    assert "scope = $legacySigningKeyId.ToLowerInvariant()" in allowlist
    assert "scope = $legacyPresentationContainerId.ToLowerInvariant()" in allowlist
    assert source.count("$Apply -and -not $mutationBlocked") == 2
    assert (
        "throw 'WC-016 cleanup blocked before mutation because a legacy principal "
        "has an unexpected role assignment.'"
        in source
    )
