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
  baseUrl?: string
  auth?: AuthState
  fetchImpl?: typeof fetch
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
