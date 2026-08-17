import type { AuthState, CatalogItem, ComparisonRow, ControlRecord, EvidenceItem, ManifestDraft, RiskAcceptance, TopologyRelationship, WorkloadContext } from '../types'

export const authFixture: AuthState = {
  actorId: 'human-publisher',
  kind: 'human',
  role: 'publisher',
  userLabel: 'Human publisher',
  port: 'context-api://wc-007',
  bearerToken: 'synthetic-context-bearer-token',
}

export const workloadCatalogueFixture: CatalogItem[] = [
  {
    id: 'atlas-api',
    name: 'Atlas API',
    owner: 'Platform Reliability',
    criticality: 'Tier-1',
    zoneCount: 2,
    status: 'Healthy',
  },
  {
    id: 'trade-batch',
    name: 'Trade Batch',
    owner: 'Data Ops',
    criticality: 'Tier-2',
    zoneCount: 2,
    status: 'Review',
  },
  {
    id: 'training-sim',
    name: 'Training Sim',
    owner: 'Learning Services',
    criticality: 'Tier-3',
    zoneCount: 1,
    status: 'Approved',
  },
]

const commonControls: ControlRecord[] = [
  {
    id: 'ctl-net-01',
    name: 'Private ingress',
    owner: 'Platform Security',
    description: 'Management endpoints remain private and only accessible through approved services.',
    status: 'active',
  },
  {
    id: 'ctl-backup-01',
    name: 'Restore rehearsal',
    owner: 'Database Ops',
    description: 'Quarterly restore rehearsal validates dependent application recovery.',
    status: 'review',
  },
  {
    id: 'ctl-risk-01',
    name: 'Residual risk sign-off',
    owner: 'Service Owner',
    description: 'Risk acceptance remains visible and tied to an explicit clause.',
    status: 'accepted',
  },
]

const baseRiskAcceptances: RiskAcceptance[] = [
  {
    id: 'accept-01',
    description: 'Single-zone database loss is accepted for the Production profile with restore and RTO alignment.',
    owner: 'Platform Reliability',
    accepted: true,
  },
  {
    id: 'accept-02',
    description: 'No generic cross-zone high availability recommendation is accepted by policy for this workload.',
    owner: 'Architecture',
    accepted: true,
  },
]

const atlasManifest: ManifestDraft = {
  manifestId: 'atlas-api',
  manifestVersion: '1.0.0',
  workloadName: 'Atlas API',
  environment: 'Production',
  businessOwner: 'Platform Reliability',
  runbook: 'runbooks/platform/atlas-api-recovery.md',
  requiredRelationships: [
    'Web services span at least two zones',
    'Worker VMs share the database availability zone',
    'Database backup retention is aligned to restore SLA',
  ],
  optionalRelationships: ['Warm standby policies are reviewed quarterly'],
  controls: [
    {
      id: 'ctl-network',
      name: 'Network segmentation',
      owner: 'Networking',
      description: 'Layered subnets and private connectivity restrict management access.',
      status: 'active',
    },
    {
      id: 'ctl-backup',
      name: 'Database backup verification',
      owner: 'Database Ops',
      description: 'Daily restore checks confirm point-in-time RPO can be met.',
      status: 'review',
    },
  ],
  riskAcceptances: [
    {
      id: 'ra-db-zone',
      description: 'Single-zone database loss is accepted with restore-driven recovery.',
      owner: 'Service Owner',
      accepted: true,
    },
  ],
  manifestDigest: 'sha256:7b080b2f1c19ef0f2a12a4dc7fba4fba5d1584d7c1d38f76fa71e9af66b5f7a4',
  compatibility: {
    artifactKind: 'workloadManifest',
    artifactDigest: 'sha256:7b080b2f1c19ef0f2a12a4dc7fba4fba5d1584d7c1d38f76fa71e9af66b5f7a4',
    semanticDigest: 'sha256:81d0e1b8a1d7d00cf7b1144d0f7eeab8ec7b4b89d7c1c4f59b2dcac7cfbf045',
    schemaVersion: '1.0.0',
    semanticContractVersion: '1.0.0',
    policyContractVersion: '1.0.0',
    minimumReaderVersion: '1.0.0',
    requiresCapabilities: [],
  },
}

const atlasComparison: ComparisonRow[] = [
  {
    environment: 'Production',
    topology: 'Web tier spans two zones; database VM remains singleton in one zone.',
    policy: 'Protect recovery posture; no unsupported HA recommendation.',
    residualRisk: 'Single-zone database loss accepted with backup restore and failover plan.',
    confidence: 0.93,
  },
  {
    environment: 'Development',
    topology: 'One zone web and singleton database are acceptable for non-prod.',
    policy: 'Developer tasking stays inside the local sandbox profile.',
    residualRisk: 'Lower blast radius; recovery windows remain limited to business hours.',
    confidence: 0.89,
  },
  {
    environment: 'Training',
    topology: 'Training tenant uses one-zone topology with isolated data snapshots.',
    policy: 'No production continuity expectation; synthetic data and scheduled resets.',
    residualRisk: 'Training data is intentionally disposable and not production-relevant.',
    confidence: 0.94,
  },
]

const atlasRelationships: TopologyRelationship[] = [
  {
    kind: 'declared',
    title: 'Web services span at least two zones',
    detail: 'Intent states the web tier must meet a two-zone deployment in Production.',
    clause: 'environment.profile.production.web.zones',
  },
  {
    kind: 'observed',
    title: 'Database VM is singleton in a single zone',
    detail: 'Observed topology confirms a single database VM in one availability zone.',
    clause: 'observed.topology.database.singleton',
  },
  {
    kind: 'inferred',
    title: 'Residual risk remains single-zone database loss',
    detail: 'Athena infers the database risk remains because recovery is bounded by restore and failover posture.',
    clause: 'risk.residual.database.single_zone_loss',
  },
  {
    kind: 'exception',
    title: 'No unsupported high availability advice is generated',
    detail: 'Context policy intentionally suppresses generic cross-zone database HA suggestions.',
    clause: 'context.policy.no_generic_ha_recommendation',
  },
]

const atlasProvenance: EvidenceItem[] = [
  {
    id: 'prov-01',
    source: 'Azure MCP',
    summary: 'Observed singleton database and web tier distribution were captured from synthetic topology fixtures.',
    clause: 'observed.topology.vm_database_stage',
    manifestVersion: '1.0.0',
    confidence: 0.93,
  },
  {
    id: 'prov-02',
    source: 'Athena policy',
    summary: 'Manifest constraints suppress unsupported high availability guidance while preserving true residual risk.',
    clause: 'context.policy.production_constraints',
    manifestVersion: '1.0.0',
    confidence: 0.91,
  },
]

const tradeManifest: ManifestDraft = {
  manifestId: 'trade-batch',
  manifestVersion: '1.0.0',
  workloadName: 'Trade Batch',
  environment: 'Development',
  businessOwner: 'Data Ops',
  runbook: 'runbooks/data/trade-batch-recovery.md',
  requiredRelationships: ['Batch jobs run with isolated tenant boundaries'],
  optionalRelationships: ['Development snapshots are retained for 7 days'],
  controls: [
    {
      id: 'ctl-batch',
      name: 'Batch isolation',
      owner: 'Platform Ops',
      description: 'Batch workers are restricted to the isolated staging network.',
      status: 'active',
    },
  ],
  riskAcceptances: [
    {
      id: 'ra-dev-window',
      description: 'Recovery window remains bounded to business hours for the development profile.',
      owner: 'Data Ops',
      accepted: true,
    },
  ],
  manifestDigest: 'sha256:2d8b7c5d09c60f80ace77f4dfe27969ba798074efb9d8d31ab9c327fee54bc5d',
  compatibility: {
    artifactKind: 'workloadManifest',
    artifactDigest: 'sha256:2d8b7c5d09c60f80ace77f4dfe27969ba798074efb9d8d31ab9c327fee54bc5d',
    semanticDigest: 'sha256:4d87d71d7a1d32e4ca619a8d3f86b312f6d53cbeb4d0b27d3d951f7af813f3fa',
    schemaVersion: '1.0.0',
    semanticContractVersion: '1.0.0',
    policyContractVersion: '1.0.0',
    minimumReaderVersion: '1.0.0',
    requiresCapabilities: [],
  },
}

const trainingManifest: ManifestDraft = {
  manifestId: 'training-sim',
  manifestVersion: '1.0.0',
  workloadName: 'Training Sim',
  environment: 'Training',
  businessOwner: 'Learning Services',
  runbook: 'runbooks/learning/training-sim-reset.md',
  requiredRelationships: ['Synthetic data stays isolated from production workloads'],
  optionalRelationships: ['Scheduled reset events recreate the training dataset'],
  controls: [
    {
      id: 'ctl-sim',
      name: 'Synthetic reset',
      owner: 'Learning Services',
      description: 'Daily reset pipeline removes sensitive and production-matched data.',
      status: 'active',
    },
  ],
  riskAcceptances: [
    {
      id: 'ra-training',
      description: 'Training data is intentionally disposable and not production-relevant.',
      owner: 'Learning Services',
      accepted: true,
    },
  ],
  manifestDigest: 'sha256:73d7fcb90574465d4f91d16bb2a6a3c5ef1f2e8e4e1a63a4a93926f0dbb7b36d',
  compatibility: {
    artifactKind: 'workloadManifest',
    artifactDigest: 'sha256:73d7fcb90574465d4f91d16bb2a6a3c5ef1f2e8e4e1a63a4a93926f0dbb7b36d',
    semanticDigest: 'sha256:5b93cfe1959edeaac5c5bf8458f5150333d7b8124f4a28a01f6afc2ecede42a6',
    schemaVersion: '1.0.0',
    semanticContractVersion: '1.0.0',
    policyContractVersion: '1.0.0',
    minimumReaderVersion: '1.0.0',
    requiresCapabilities: [],
  },
}

export const workloadFixtureMap: Record<string, WorkloadContext> = {
  'atlas-api': {
    workloadId: 'atlas-api',
    auth: authFixture,
    environment: 'Production',
    evidenceSource: 'Azure MCP synthetic fixture',
    confidence: 0.91,
    manifestVersion: atlasManifest.manifestVersion,
    approvalState: 'draft',
    workloadCatalogue: workloadCatalogueFixture,
    comparison: atlasComparison,
    relationships: atlasRelationships,
    manifest: atlasManifest,
    controls: commonControls,
    riskAcceptances: baseRiskAcceptances,
    provenance: atlasProvenance,
    validationMessages: [
      'Draft is ready for human validation.',
      'Residual risk is explicit and linked to accepted controls.',
    ],
    draft: null,
    published: null,
  },
  'trade-batch': {
    workloadId: 'trade-batch',
    auth: authFixture,
    environment: 'Development',
    evidenceSource: 'Azure MCP synthetic fixture',
    confidence: 0.84,
    manifestVersion: tradeManifest.manifestVersion,
    approvalState: 'draft',
    workloadCatalogue: workloadCatalogueFixture,
    comparison: atlasComparison,
    relationships: [
      {
        kind: 'declared',
        title: 'Development worker policies remain isolated',
        detail: 'Local development workloads remain in the bounded non-production profile.',
        clause: 'environment.profile.development.worker.isolation',
      },
    ],
    manifest: tradeManifest,
    controls: commonControls,
    riskAcceptances: baseRiskAcceptances,
    provenance: [
      {
        id: 'prov-03',
        source: 'Synthetic Azure evidence',
        summary: 'Workers remain isolated to the developer sandbox and use synthetic data.',
        clause: 'observed.topology.development_worker_zone',
        manifestVersion: '1.0.0',
        confidence: 0.82,
      },
    ],
    validationMessages: ['Development policy remains valid for the non-production profile.'],
    draft: null,
    published: null,
  },
  'training-sim': {
    workloadId: 'training-sim',
    auth: authFixture,
    environment: 'Training',
    evidenceSource: 'Azure MCP synthetic fixture',
    confidence: 0.9,
    manifestVersion: trainingManifest.manifestVersion,
    approvalState: 'draft',
    workloadCatalogue: workloadCatalogueFixture,
    comparison: atlasComparison,
    relationships: [
      {
        kind: 'declared',
        title: 'Training workloads use synthetic reset workflows',
        detail: 'Training data is intentionally synthetic and scheduled for resets.',
        clause: 'environment.profile.training.synthetic_reset',
      },
    ],
    manifest: trainingManifest,
    controls: commonControls,
    riskAcceptances: baseRiskAcceptances,
    provenance: [
      {
        id: 'prov-04',
        source: 'Synthetic Azure evidence',
        summary: 'Training environment uses isolated snapshots with scheduled resets.',
        clause: 'observed.topology.training_snapshot',
        manifestVersion: '1.0.0',
        confidence: 0.9,
      },
    ],
    validationMessages: ['Training profile accepts synthetic-only data and scheduled resets.'],
    draft: null,
    published: null,
  },
}

export const wc007CanonicalManifestFixture = {
  manifestId: atlasManifest.manifestId,
  manifestVersion: atlasManifest.manifestVersion,
  workloadName: atlasManifest.workloadName,
  environment: atlasManifest.environment,
  businessOwner: atlasManifest.businessOwner,
  runbook: atlasManifest.runbook,
  requiredRelationships: atlasManifest.requiredRelationships,
  optionalRelationships: atlasManifest.optionalRelationships,
  controls: atlasManifest.controls,
  riskAcceptances: atlasManifest.riskAcceptances,
  compatibility: atlasManifest.compatibility,
}

export const wc007DraftApiFixture = {
  draft_id: 'draft-atlas-api',
  manifest_id: atlasManifest.manifestId,
  state: 'approved',
  revision: 5,
  manifest: wc007CanonicalManifestFixture,
  manifest_digest: atlasManifest.manifestDigest,
  previous_version: null,
  created_by: { actor_id: authFixture.actorId, kind: authFixture.kind },
  created_at: '2026-08-17T00:00:00.000Z',
  updated_by: { actor_id: authFixture.actorId, kind: authFixture.kind },
  updated_at: '2026-08-17T00:00:00.000Z',
  reason: 'Approved by the authoritative Context API.',
  validation: null,
  review: null,
  publication_candidate: {
    finalized_by: { actor_id: 'human-approver', kind: 'human' },
    finalized_at: '2026-08-17T00:00:00.000Z',
    manifest_version: atlasManifest.manifestVersion,
    manifest_digest: atlasManifest.manifestDigest,
    semantic_digest: atlasManifest.compatibility?.semanticDigest ?? atlasManifest.manifestDigest,
    approval_status: 'approved',
  },
  approval: {
    decision_id: 'approval-draft-atlas-api',
    approved_by: { actor_id: 'human-approver', kind: 'human' },
    approved_at: '2026-08-17T00:00:00.000Z',
    approved_revision: 5,
    manifest_version: atlasManifest.manifestVersion,
    manifest_digest: atlasManifest.manifestDigest,
    reason: 'Server-authorized approval decision.',
  },
}

export const wc007PublishedApiFixture = {
  manifest_id: atlasManifest.manifestId,
  manifest_version: atlasManifest.manifestVersion,
  manifest_digest: atlasManifest.manifestDigest,
  manifest: wc007CanonicalManifestFixture,
  source_draft_id: 'draft-atlas-api',
  source_draft_revision: 5,
  previous_version: null,
  approval: wc007DraftApiFixture.approval,
  published_by: { actor_id: 'human-publisher', kind: 'human' },
  published_at: '2026-08-17T00:00:00.000Z',
  publication_authorized_by: { actor_id: 'athena-context-api', kind: 'service' },
  publication_authorized_at: '2026-08-17T00:00:00.000Z',
  reason: 'Published by the authoritative Context API.',
}
