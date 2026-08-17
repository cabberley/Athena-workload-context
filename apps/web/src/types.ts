export type EnvironmentName = 'Production' | 'Development' | 'Training'
export type RelationshipKind = 'declared' | 'observed' | 'inferred' | 'exception'
export type DraftState = 'draft' | 'validated' | 'in_review' | 'approved' | 'published' | 'superseded'
export type AppRoute = 'overview' | 'catalogue' | 'manifest' | 'controls'
export type ActorKind = 'human' | 'agent' | 'service'
export type RoleName = 'proposer' | 'reviewer' | 'approver' | 'publisher' | 'reader' | 'auditor'

export interface Actor {
  actorId: string
  kind: ActorKind
}

export interface AuthState {
  actorId: string
  kind: ActorKind
  role: RoleName
  userLabel: string
  port: string
  bearerToken: string
}

export interface CatalogItem {
  id: string
  name: string
  owner: string
  criticality: string
  zoneCount: number
  status: string
}

export interface ComparisonRow {
  environment: EnvironmentName
  topology: string
  policy: string
  residualRisk: string
  confidence: number
}

export interface TopologyRelationship {
  kind: RelationshipKind
  title: string
  detail: string
  clause: string
}

export interface ControlRecord {
  id: string
  name: string
  owner: string
  description: string
  status: 'active' | 'review' | 'accepted'
}

export interface RiskAcceptance {
  id: string
  description: string
  owner: string
  accepted: boolean
}

export interface EvidenceItem {
  id: string
  source: string
  summary: string
  clause: string
  manifestVersion: string
  confidence: number
}

export interface CompatibilityMetadata {
  artifactKind: 'workloadManifest'
  artifactDigest: string
  semanticDigest: string
  schemaVersion: string
  semanticContractVersion: string
  policyContractVersion: string
  minimumReaderVersion: string
  requiresCapabilities: string[]
}

export interface ManifestDraft {
  manifestId: string
  manifestVersion: string
  workloadName: string
  environment: EnvironmentName
  businessOwner: string
  runbook: string
  requiredRelationships: string[]
  optionalRelationships: string[]
  controls: ControlRecord[]
  riskAcceptances: RiskAcceptance[]
  manifestDigest?: string
  compatibility?: CompatibilityMetadata
}

export interface ValidationRecord {
  validatedBy: Actor
  validatedAt: string
  validatedRevision: number
  manifestDigest: string
}

export interface ReviewSubmission {
  submittedBy: Actor
  submittedAt: string
  submittedRevision: number
  publicationCandidateDigest: string
  reason: string
}

export interface PublicationCandidate {
  finalizedBy: Actor
  finalizedAt: string
  manifestVersion: string
  manifestDigest: string
  semanticDigest: string
  approvalStatus: 'approved'
}

export interface ApprovalDecision {
  decisionId: string
  approvedBy: Actor
  approvedAt: string
  approvedRevision: number
  manifestVersion: string
  manifestDigest: string
  reason: string
}

export interface DraftRecord {
  draftId: string
  manifestId: string
  state: DraftState
  revision: number
  manifest: ManifestDraft
  manifestDigest: string
  previousVersion: string | null
  createdBy: Actor
  createdAt: string
  updatedBy: Actor
  updatedAt: string
  reason: string
  validation: ValidationRecord | null
  review: ReviewSubmission | null
  publicationCandidate: PublicationCandidate | null
  approval: ApprovalDecision | null
}

export interface PublishedManifest {
  manifestId: string
  manifestVersion: string
  manifestDigest: string
  manifest: ManifestDraft
  sourceDraftId: string
  sourceDraftRevision: number
  previousVersion: string | null
  approval: ApprovalDecision
  publishedBy: Actor
  publishedAt: string
  publicationAuthorizedBy: Actor
  publicationAuthorizedAt: string
  reason: string
}

export interface WorkloadContext {
  workloadId: string
  auth: AuthState
  environment: EnvironmentName
  evidenceSource: string
  confidence: number
  manifestVersion: string
  approvalState: DraftState
  workloadCatalogue: CatalogItem[]
  comparison: ComparisonRow[]
  relationships: TopologyRelationship[]
  manifest: ManifestDraft
  controls: ControlRecord[]
  riskAcceptances: RiskAcceptance[]
  provenance: EvidenceItem[]
  validationMessages: string[]
  draft: DraftRecord | null
  published: PublishedManifest | null
}

export interface PublishRequest {
  draftId: string
  expectedRevision: number
  expectedManifestVersion: string
  expectedDigest: string
  approvalId: string
  reason: string
  workloadId?: string
  manifestId?: string
}

export interface ContextApiClientOptions {
  baseUrl: string
  auth: AuthState
  fetchImpl?: typeof fetch
}

export interface WireActor {
  actor_id: string
  kind: 'human' | 'agent' | 'service'
}

export interface WireCompatibility {
  artifact_kind: 'workloadManifest'
  artifact_digest: string
  semantic_digest: string
  schema_version: string
  semantic_contract_version: string
  policy_contract_version: string
  minimum_reader_version: string
  requires_capabilities: string[]
}

export interface WireManifest {
  manifestId: string
  manifestVersion: string
  workloadName: string
  environment: EnvironmentName
  businessOwner: string
  runbook: string
  requiredRelationships: string[]
  optionalRelationships: string[]
  controls: ControlRecord[]
  riskAcceptances: RiskAcceptance[]
  manifestDigest?: string
  compatibility?: CompatibilityMetadata
}

export interface WireDraftRecord {
  draft_id: string
  manifest_id: string
  state: DraftState
  revision: number
  manifest: WireManifest
  manifest_digest: string
  previous_version: string | null
  created_by: WireActor
  created_at: string
  updated_by: WireActor
  updated_at: string
  reason: string
  validation: {
    validated_by: WireActor
    validated_at: string
    validated_revision: number
    manifest_digest: string
  } | null
  review: {
    submitted_by: WireActor
    submitted_at: string
    submitted_revision: number
    publication_candidate_digest: string
    reason: string
  } | null
  publication_candidate: {
    finalized_by: WireActor
    finalized_at: string
    manifest_version: string
    manifest_digest: string
    semantic_digest: string
    approval_status: 'approved'
  } | null
  approval: {
    decision_id: string
    approved_by: WireActor
    approved_at: string
    approved_revision: number
    manifest_version: string
    manifest_digest: string
    reason: string
  } | null
}

export interface WirePublishedManifest {
  manifest_id: string
  manifest_version: string
  manifest_digest: string
  manifest: WireManifest
  source_draft_id: string
  source_draft_revision: number
  previous_version: string | null
  approval: {
    decision_id: string
    approved_by: WireActor
    approved_at: string
    approved_revision: number
    manifest_version: string
    manifest_digest: string
    reason: string
  }
  published_by: WireActor
  published_at: string
  publication_authorized_by: WireActor
  publication_authorized_at: string
  reason: string
}

export interface ContextApiClientPort {
  auth: AuthState
  loadWorkloads: () => Promise<CatalogItem[]>
  loadWorkloadContext: (workloadId: string) => Promise<WorkloadContext>
  loadWorkloadSync: (workloadId: string) => WorkloadContext
  reloadWorkload: (workloadId: string) => Promise<WorkloadContext>
  createDraft: (
    workloadId: string,
    manifest: ManifestDraft,
    reason: string,
  ) => Promise<DraftRecord>
  updateDraft: (request: {
    draftId: string
    expectedRevision: number
    expectedManifestVersion: string
    expectedDigest: string
    replacementManifest: ManifestDraft
    reason: string
  }) => Promise<DraftRecord>
  validateDraft: (request: {
    draftId: string
    expectedRevision: number
    expectedManifestVersion: string
    expectedDigest: string
    reason: string
  }) => Promise<DraftRecord>
  submitForReview: (request: {
    draftId: string
    expectedRevision: number
    expectedManifestVersion: string
    expectedDigest: string
    reason: string
  }) => Promise<DraftRecord>
  approveDraft: (request: {
    draftId: string
    expectedRevision: number
    expectedManifestVersion: string
    expectedDigest: string
    reason: string
  }) => Promise<DraftRecord>
  publishDraft: (request: PublishRequest) => Promise<PublishedManifest>
}

export type ContextStudioSnapshot = WorkloadContext
