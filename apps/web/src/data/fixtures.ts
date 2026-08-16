import type { ContextStudioSnapshot } from '../types'

export const contextStudioFixture: ContextStudioSnapshot = {
  environment: 'Production',
  auth: {
    status: 'authenticated',
    user: 'ops-admin-demo',
    port: 'context-api://stub',
  },
  evidenceSource: 'Azure MCP synthetic fixture',
  confidence: 0.91,
  manifestVersion: 'v4.2.1',
  approvalState: 'draft',
  workloadCatalogue: [
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
  ],
  comparison: [
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
  ],
  relationships: [
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
  ],
  manifest: {
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
        id: 'ctl-rdp',
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
  },
  controls: [
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
  ],
  riskAcceptances: [
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
  ],
  provenance: [
    {
      id: 'prov-01',
      source: 'Azure MCP',
      summary: 'Observed singleton database and web tier distribution were captured from synthetic topology fixtures.',
      clause: 'observed.topology.vm_database_stage',
      manifestVersion: 'v4.2.1',
      confidence: 0.93,
    },
    {
      id: 'prov-02',
      source: 'Athena policy',
      summary: 'Manifest constraints suppress unsupported high availability guidance while preserving true residual risk.',
      clause: 'context.policy.production_constraints',
      manifestVersion: 'v4.2.1',
      confidence: 0.91,
    },
  ],
  validationMessages: [
    'Draft is ready for human validation.',
    'Residual risk is explicit and linked to accepted controls.',
  ],
}
