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
export type AppRoute = 'overview' | 'cohorts' | 'catalogue' | 'manifest' | 'versions' | 'controls'
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
  cohortApiBaseUrl: string
  authPort: AuthPort
  operationalContextPort?: OperationalContextPort
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

export interface ObservedTopologyRelationship {
  id: string
  kind: 'observed'
  source: string
  target: string
  evidenceRefs: string[]
  observedAt: string
  confidence: number
  profileId: string | null
}

export interface InferredTopologyRelationship {
  id: string
  kind: 'inferred'
  source: string
  target: string
  hypothesis: string
  evidenceRefs: string[]
  confidence: number
  profileId: string | null
}

export type TopologyRelationship =
  | DeclaredTopologyRelationship
  | ObservedTopologyRelationship
  | InferredTopologyRelationship
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

export interface ContextFinding {
  id: string
  verdict: string
  summary: string
  manifestVersion: string
  profileId: string
  clause: string
  evidenceRefs: string[]
  residualRisk: string | null
  controlState: string | null
  confidence: number | null
}

export interface PublishedVersionSummary {
  manifestVersion: string
  manifestDigest: string
  publishedAt: string
  publishedBy: string
  supersededBy: string | null
  active: boolean
}

export interface ExactVersionComparison {
  manifestId: string
  fromVersion: string
  toVersion: string
  fromDigest: string
  toDigest: string
  equivalent: boolean
  changedPaths: string[]
}

export interface OperationalContextRequest {
  workloadId: string
  manifestVersion: string
  profileId: string
  draftId: string
  draftRevision: number
  manifestDigest: string
  profileDigest: string
  asOf: string
}

export interface OperationalContextReceipt {
  schemaVersion: 'athena.context-api.operational-context-receipt.v1'
  receiptId: string
  issuedBy: Actor
  issuedAt: string
  manifestId: string
  manifestVersion: string
  profileId: string
  draftId: string
  draftRevision: number
  manifestDigest: string
  profileDigest: string
  snapshotId: string
  collectedAt: string
  expiresAt: string
  evidenceCount: number
  evidenceInventoryDigest: string
  contentDigest: string
  bindingDigest: string
  receiptDigest: string
}

export interface OperationalContextSnapshot {
  schemaVersion: 'athena.contextStudio.operationalContext.v1'
  workloadId: string
  manifestVersion: string
  profileId: string
  draftId: string
  draftRevision: number
  manifestDigest: string
  profileDigest: string
  receiptId: string
  receipt: OperationalContextReceipt
  snapshotId: string
  collectedAt: string
  expiresAt: string
  evidenceSource: string
  confidence: number | null
  evidenceInventory: Array<{
    evidenceRef: string
    evidenceDigest: string
  }>
  evidenceInventoryDigest: string
  contentDigest: string
  bindingDigest: string
  relationships: Array<ObservedTopologyRelationship | InferredTopologyRelationship>
  findings: ContextFinding[]
}

export interface OperationalContextPort {
  loadOperationalContext: (
    request: OperationalContextRequest,
  ) => Promise<unknown>
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

interface CanonicalSelectorBase {
  selectorId: string
  maxMatches: number
}

export interface CanonicalResourceIdListSelector extends CanonicalSelectorBase {
  selectorType: 'resourceIdList'
  resourceIds: string[]
}

export interface CanonicalTagPredicateSelector extends CanonicalSelectorBase {
  selectorType: 'tagPredicate'
  predicates: Array<{ key: string; value: string }>
}

export interface CanonicalNamePredicateSelector extends CanonicalSelectorBase {
  selectorType: 'namePredicate'
  prefix?: string
  suffix?: string
}

export interface CanonicalResourceTypeSelector extends CanonicalSelectorBase {
  selectorType: 'resourceType'
  resourceType: string
  locations: string[]
  resourceGroups: string[]
}

export interface CanonicalVmssSelector extends CanonicalSelectorBase {
  selectorType: 'vmScaleSet'
  scaleSetResourceId: string
  instanceIds: string[]
}

export interface CanonicalLoadBalancerBackendSelector extends CanonicalSelectorBase {
  selectorType: 'loadBalancerBackend'
  loadBalancerResourceId: string
  backendPoolName: string
}

export interface CanonicalSubnetSelector extends CanonicalSelectorBase {
  selectorType: 'subnet'
  subnetResourceId: string
}

export interface CanonicalImageSelector extends CanonicalSelectorBase {
  selectorType: 'image'
  publisher: string
  offer: string
  sku: string
  version?: string
}

export interface CanonicalProvenanceSelector extends CanonicalSelectorBase {
  selectorType: 'provenance'
  collectorToolName: string
  collectorToolVersion: string
  identityEvidenceRef: string
}

export type CanonicalAtomicSelector =
  | CanonicalResourceIdListSelector
  | CanonicalTagPredicateSelector
  | CanonicalNamePredicateSelector
  | CanonicalResourceTypeSelector
  | CanonicalVmssSelector
  | CanonicalLoadBalancerBackendSelector
  | CanonicalSubnetSelector
  | CanonicalImageSelector
  | CanonicalProvenanceSelector

export interface CanonicalCompositeAllSelector extends CanonicalSelectorBase {
  selectorType: 'compositeAll'
  children: CanonicalAtomicSelector[]
}

export interface CanonicalCompositeAnySelector extends CanonicalSelectorBase {
  selectorType: 'compositeAny'
  children: CanonicalAtomicSelector[]
}

export type CanonicalManifestSelector =
  | CanonicalAtomicSelector
  | CanonicalCompositeAllSelector
  | CanonicalCompositeAnySelector

export type CanonicalManifestCardinality =
  | { cardinalityKind: 'exactlyOne' }
  | { cardinalityKind: 'oneOrMore' }
  | { cardinalityKind: 'zeroOrMore' }
  | { cardinalityKind: 'boundedRange'; minimum: number; maximum: number }

export interface CanonicalManifestRole {
  roleId: string
  kind:
    | 'singletonDatabase'
    | 'databaseReplica'
    | 'worker'
    | 'webService'
    | 'loadBalancer'
    | 'integrationEndpoint'
    | 'storage'
    | 'network'
    | 'identity'
    | 'observability'
    | 'externalDependency'
  cardinality: CanonicalManifestCardinality
  selectors: CanonicalManifestSelector[]
  ownerRef: string
  status: 'approved' | 'deprecated'
}

export interface CanonicalManifestProfile {
  profileId: string
  profileType: EnvironmentName
  settings: JsonObject
  roles: CanonicalManifestRole[]
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
  roles: CanonicalManifestRole[]
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

export type ReviewDecisionKind = 'approved' | 'changes_requested'

export interface ReviewDecision {
  decisionId: string
  decision: ReviewDecisionKind
  reviewedBy: Actor
  reviewedAt: string
  reviewedRevision: number
  manifestVersion: string
  manifestDigest: string
  comments: string
  rejectedFields: string[]
  requiredCorrections: string[]
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
  reviewDecisionId: string | null
  operationalContextReceiptId: string | null
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
  rollbackSourceVersion?: string | null
  createdBy: Actor
  createdAt: string
  updatedBy: Actor
  updatedAt: string
  reason: string
  validation: ValidationRecord | null
  review: ReviewSubmission | null
  publicationCandidate: PublicationCandidate | null
  reviewDecisions: ReviewDecision[]
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
  operationalContextReceiptId: string | null
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
  profileId: string
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
  findings: ContextFinding[]
  publishedVersions: PublishedVersionSummary[]
  validationMessages: string[]
  draft: DraftRecord | null
  published: PublishedManifest | null
  pendingSupersessionRecovery: SupersessionRecovery | null
  operationalContext: OperationalContextSnapshot | null
  operationalContextRequired: boolean
}

export interface ConcurrencyRequest {
  workloadId: string
  draftId: string
  expectedRevision: number
  expectedManifestVersion: string
  expectedDigest: string
  reason: string
  idempotencyKey?: string
}

export interface PublishRequest extends ConcurrencyRequest {
  approvalId: string
  operationalContextReceiptId: string
}

export interface ApproveRequest extends ConcurrencyRequest {
  operationalContextReceiptId: string
}

export interface ReviewRequest extends ConcurrencyRequest {
  decision: ReviewDecisionKind
  comments: string
  rejectedFields: string[]
  requiredCorrections: string[]
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
  review_decision_id?: string | null
  operational_context_receipt_id?: string | null
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
  rollback_source_version?: string | null
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
  review_decisions?: Array<{
    decision_id: string
    decision: ReviewDecisionKind
    reviewed_by: WireActor
    reviewed_at: string
    reviewed_revision: number
    manifest_version: string
    manifest_digest: string
    comments: string
    rejected_fields: string[]
    required_corrections: string[]
  }>
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
  operational_context_receipt_id?: string | null
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
  loadResolvedProfileDigest: (context: WorkloadContext) => Promise<string>
  createSuccessorDraft: (workloadId: string, reason: string) => Promise<DraftRecord>
  createRollbackDraft: (
    workloadId: string,
    sourceVersion: string,
    reason: string,
  ) => Promise<DraftRecord>
  comparePublishedVersions: (
    workloadId: string,
    fromVersion: string,
    toVersion: string,
  ) => Promise<ExactVersionComparison>
  updateDraft: (
    request: ConcurrencyRequest & { replacementManifest: CanonicalWorkloadManifest },
  ) => Promise<DraftRecord>
  validateDraft: (request: ConcurrencyRequest) => Promise<DraftRecord>
  submitForReview: (request: ConcurrencyRequest) => Promise<DraftRecord>
  reviewDraft: (request: ReviewRequest) => Promise<DraftRecord>
  approveDraft: (request: ApproveRequest) => Promise<DraftRecord>
  publishDraft: (request: PublishRequest) => Promise<PublishedManifest>
  completeSupersession: (recovery: SupersessionRecovery) => Promise<Supersession>
}

declare global {
  interface Window {
    athenaContextStudioRuntime?: ContextStudioRuntime
  }
}
