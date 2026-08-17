export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | JsonObject | JsonValue[]
export interface JsonObject {
  [key: string]: JsonValue
}

export type EnvironmentName =
  | 'production'
  | 'development'
  | 'training'
  | 'test'
  | 'disasterRecovery'
  | 'sandbox'
export type RelationshipKind = 'declared' | 'observed' | 'inferred' | 'exception'
export type DeclaredRelationshipType =
  | 'requires'
  | 'dependsOn'
  | 'calls'
  | 'storesDataIn'
  | 'replicatesTo'
  | 'failsOverTo'
  | 'sharesZoneWith'
  | 'isolatedFrom'
  | 'monitors'
  | 'protectedBy'
  | 'prohibited'
export type DraftState = 'draft' | 'validated' | 'in_review' | 'approved' | 'published' | 'superseded'
export type AppRoute = 'overview' | 'catalogue' | 'manifest' | 'controls'
export type ActorKind = 'human' | 'agent' | 'service'
export type RoleName = 'proposer' | 'reviewer' | 'approver' | 'publisher' | 'reader' | 'auditor'

export interface Actor {
  actorId: string
  kind: ActorKind
}

/**
 * Verified identity metadata returned by the host authentication integration.
 * Access tokens are deliberately absent and are acquired just-in-time through AuthPort.
 */
export interface AuthSession {
  actorId: string
  kind: ActorKind
  role: RoleName
  userLabel: string
  port: string
  authorizedWorkloadIds: string[]
}

export interface AuthPort {
  acquireSession: () => Promise<AuthSession | null>
  acquireAccessToken: (session: AuthSession) => Promise<string | null>
}

export interface ContextStudioRuntime {
  apiBaseUrl: string
  authPort: AuthPort
  fetchImpl?: typeof fetch
  createId?: () => string
}

export interface CatalogItem {
  id: string
  name: string
  owner: string | null
  criticality: string | null
  zoneCount: number | null
  status: DraftState
}

export interface ComparisonRow {
  environment: EnvironmentName
  topology: string
  policy: string
  residualRisk: string
  confidence: number | null
  relationshipKind: 'declared'
}

export interface DeclaredTopologyRelationship {
  id: string
  kind: 'declared'
  relationshipType: string
  source: string
  target: string
  ownerRef: string
  clause: string
  profileId: string | null
}

export interface ExceptionTopologyRelationship {
  id: string
  kind: 'exception'
  targetType: 'relationship' | 'clause'
  targetRef: string
  riskAcceptanceRef: string
  governanceScope: CanonicalClauseScope
  ownerRef: string
  rationale: string
  expiresAt: string
  profileId: string | null
}

export type TopologyRelationship =
  | DeclaredTopologyRelationship
  | ExceptionTopologyRelationship

export interface ControlRecord {
  id: string
  ownerRef: string
  health: string
  runbookRef: string | null
  profiles: string[]
}

export interface RiskAcceptance {
  id: string
  residualRiskStatement: string
  ownedBy: string
  status: string
  profiles: string[]
}

export interface EvidenceItem {
  id: string
  source: string
  summary: string
  clause: string
  manifestVersion: string
  confidence: number | null
}

export interface CapabilityRequirement {
  capabilityId: string
  minimumVersion: string
  requiredFor: 'read' | 'publish' | 'evaluate' | 'render'
}

export interface CompatibilityMetadata {
  artifactKind: 'workloadManifest'
  schemaVersion: string
  semanticContractVersion: string
  policyContractVersion: string
  minimumReaderVersion: string
  requiresCapabilities: CapabilityRequirement[]
  producedBy: {
    producerId: string
    version: string
  }
  extensionPolicy: 'rejectUnknownDecisionFields'
  artifactDigest: string
  semanticDigest: string
}

export interface CanonicalWorkloadIdentity {
  displayName: string
  environments: EnvironmentName[]
  allowedEvidenceScopes: JsonObject[]
}

export interface CanonicalManifestAudit {
  publishedBy: string
  publishedAt: string
  approvalStatus: 'approved'
}

export interface CanonicalRoleEndpoint {
  endpointType: 'role'
  roleRef: string
}

export interface CanonicalExternalEndpoint {
  endpointType: 'external'
  externalRef: string
}

export type CanonicalManifestEndpoint =
  | CanonicalRoleEndpoint
  | CanonicalExternalEndpoint

export interface CanonicalClauseScope {
  governanceScopeType: 'clause'
  manifestId: string
  profileId: string
  clausePath: string
  ownerRef: string
}

export interface CanonicalDeclaredRelationship {
  relationshipClass: 'declared'
  relationshipId: string
  kind: DeclaredRelationshipType
  source: CanonicalManifestEndpoint
  target: CanonicalManifestEndpoint
  ownerRef: string
  profiles: EnvironmentName[]
  sourceClause: string
}

interface CanonicalExceptionRelationshipBase {
  relationshipClass: 'exception'
  exceptionId: string
  riskAcceptanceRef: string
  governanceScope: CanonicalClauseScope
  ownerRef: string
  rationale: string
  expiresAt: string
}

export type CanonicalExceptionRelationship =
  CanonicalExceptionRelationshipBase &
  (
    | {
        appliesToRelationshipRef: string
        appliesToClauseRef?: never
      }
    | {
        appliesToRelationshipRef?: never
        appliesToClauseRef: string
      }
  )

export type CanonicalRelationship =
  | CanonicalDeclaredRelationship
  | CanonicalExceptionRelationship

export interface CanonicalControl {
  controlId: string
  ownerRef: string
  health: string
  runbookRef?: string
  profiles: string[]
}

export interface CanonicalRiskAcceptance {
  riskAcceptanceId: string
  residualRiskStatement: string
  ownedBy: string
  status: string
  profiles: string[]
}

export interface CanonicalManifestOwner {
  ownerRef: string
  ownerRole: string
  authorityRef: string
}

export interface CanonicalManifestProfile {
  profileId: string
  profileType: EnvironmentName
  settings: JsonObject
  roles: JsonObject[]
  relationships: CanonicalRelationship[]
  constraints: JsonObject[]
  controls: CanonicalControl[]
  riskAcceptances: CanonicalRiskAcceptance[]
  objectives: JsonObject[]
  ownership: CanonicalManifestOwner[]
  weakeningOverrides: JsonObject[]
  disabledRefs: JsonObject[]
}

/**
 * Exact camelCase WC-001 canonical manifest nested inside the snake_case WC-007 API records.
 * Every section is retained when an editable field changes.
 */
export interface CanonicalWorkloadManifest {
  manifestId: string
  manifestVersion: string
  cloud: string
  workload: CanonicalWorkloadIdentity
  profiles: Record<string, CanonicalManifestProfile>
  roles: JsonObject[]
  relationships: CanonicalRelationship[]
  constraints: JsonObject[]
  controls: CanonicalControl[]
  riskAcceptances: CanonicalRiskAcceptance[]
  objectives: JsonObject[]
  ownership: CanonicalManifestOwner[]
  compatibility: CompatibilityMetadata
  audit: CanonicalManifestAudit
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
  manifest: CanonicalWorkloadManifest
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
  manifest: CanonicalWorkloadManifest
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

export interface Supersession {
  manifestId: string
  supersededVersion: string
  replacementVersion: string
  supersededBy: Actor
  supersededAt: string
  reason: string
}

export interface WorkloadContext {
  workloadId: string
  auth: AuthSession
  environment: EnvironmentName
  evidenceSource: string
  confidence: number | null
  manifestVersion: string
  approvalState: DraftState
  catalogueItem: CatalogItem
  comparison: ComparisonRow[]
  relationships: TopologyRelationship[]
  manifest: CanonicalWorkloadManifest
  controls: ControlRecord[]
  riskAcceptances: RiskAcceptance[]
  provenance: EvidenceItem[]
  validationMessages: string[]
  draft: DraftRecord | null
  published: PublishedManifest | null
}

export interface ConcurrencyRequest {
  workloadId: string
  draftId: string
  expectedRevision: number
  expectedManifestVersion: string
  expectedDigest: string
  reason: string
}

export interface PublishRequest extends ConcurrencyRequest {
  approvalId: string
}

export interface SupersessionRecovery {
  workloadId: string
  predecessorVersion: string
  predecessorRevision: number
  predecessorDigest: string
  successorVersion: string
  successorDigest: string
  reason: string
  idempotencyKey: string
}

export interface ContextApiClientOptions {
  baseUrl: string
  authPort: AuthPort
  session: AuthSession
  fetchImpl?: typeof fetch
  createId?: () => string
}

export interface WireActor {
  actor_id: string
  kind: ActorKind
}

export interface WireApprovalDecision {
  decision_id: string
  approved_by: WireActor
  approved_at: string
  approved_revision: number
  manifest_version: string
  manifest_digest: string
  reason: string
}

export interface WireDraftRecord {
  draft_id: string
  manifest_id: string
  state: DraftState
  revision: number
  manifest: CanonicalWorkloadManifest
  manifest_digest: string
  previous_version?: string | null
  created_by: WireActor
  created_at: string
  updated_by: WireActor
  updated_at: string
  reason: string
  validation?: {
    validated_by: WireActor
    validated_at: string
    validated_revision: number
    manifest_digest: string
  }
  review?: {
    submitted_by: WireActor
    submitted_at: string
    submitted_revision: number
    publication_candidate_digest: string
    reason: string
  }
  publication_candidate?: {
    finalized_by: WireActor
    finalized_at: string
    manifest_version: string
    manifest_digest: string
    semantic_digest: string
    approval_status: 'approved'
  }
  approval?: WireApprovalDecision
}

export interface WirePublishedManifest {
  manifest_id: string
  manifest_version: string
  manifest_digest: string
  manifest: CanonicalWorkloadManifest
  source_draft_id: string
  source_draft_revision: number
  previous_version?: string | null
  approval: WireApprovalDecision
  published_by: WireActor
  published_at: string
  publication_authorized_by: WireActor
  publication_authorized_at: string
  reason: string
}

export interface WireSupersession {
  manifest_id: string
  superseded_version: string
  replacement_version: string
  superseded_by: WireActor
  superseded_at: string
  reason: string
}

export interface WirePublishedManifestView {
  published: WirePublishedManifest
  supersession?: WireSupersession
}

export interface ContextApiClientPort {
  auth: AuthSession
  loadAuthorizedWorkloads: () => Promise<WorkloadContext[]>
  loadWorkloadContext: (workloadId: string) => Promise<WorkloadContext>
  createSuccessorDraft: (workloadId: string, reason: string) => Promise<DraftRecord>
  updateDraft: (
    request: ConcurrencyRequest & { replacementManifest: CanonicalWorkloadManifest },
  ) => Promise<DraftRecord>
  validateDraft: (request: ConcurrencyRequest) => Promise<DraftRecord>
  submitForReview: (request: ConcurrencyRequest) => Promise<DraftRecord>
  approveDraft: (request: ConcurrencyRequest) => Promise<DraftRecord>
  publishDraft: (request: PublishRequest) => Promise<PublishedManifest>
  completeSupersession: (recovery: SupersessionRecovery) => Promise<Supersession>
}

declare global {
  interface Window {
    athenaContextStudioRuntime?: ContextStudioRuntime
  }
}
