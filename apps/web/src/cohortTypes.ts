import type {
  AuthPort,
  AuthSession,
  CanonicalManifestRole,
  CanonicalManifestSelector,
  EnvironmentName,
} from './types'

export type ConfidenceBand = 'high' | 'medium' | 'low' | 'conflicting'
export type CohortReviewAction = 'approve' | 'split' | 'merge'
export type CohortDecisionAction = CohortReviewAction | 'reject'
export type CohortDecisionState = 'pending' | 'applied' | 'rejected'
export type CohortSignalType =
  | 'approvedTags'
  | 'namePredicate'
  | 'resourceType'
  | 'vmScaleSet'
  | 'loadBalancerBackend'
  | 'subnet'
  | 'image'
  | 'deploymentProvenance'
  | 'provenance'
  | 'observedCommunication'

export type CohortConflictCode =
  | 'ambiguousRole'
  | 'conflictingSignal'
  | 'crossEnvironment'
  | 'duplicateResourceId'
  | 'evidenceGap'
  | 'invalidEvidenceReference'
  | 'missingEvidence'
  | 'noEligibleMembers'
  | 'outOfScope'
  | 'overMaxMatches'
  | 'selectorPreviewMismatch'
  | 'snapshotDigestMismatch'
  | 'staleEvidence'

export type CohortRejectionReason =
  | 'ambiguousRole'
  | 'conflictingRoleEvidence'
  | 'crossEnvironment'
  | 'differentCohortSignal'
  | 'duplicateResourceId'
  | 'invalidEvidenceReference'
  | 'missingEnvironment'
  | 'missingRoleEvidence'
  | 'outOfProfileScope'
  | 'outOfSnapshotScope'
  | 'overMaxMatches'
  | 'staleEvidence'

export interface CohortProposalScope {
  manifestId: string
  manifestVersion: string
  profileId: string
  profileType: EnvironmentName
  resolvedProfileDigest: string
}

export interface CohortProposalSnapshot {
  snapshotId: string
  artifactDigest: string
  semanticDigest: string
  collectedAt: string
  expiresAt: string
}

/**
 * Evidence references are reduced to bounded counts at the browser boundary.
 * Context Studio never retains or renders unrestricted evidence or log bodies.
 */
export interface CohortSupportingEvidence {
  signalType: CohortSignalType
  signalValue: string
  memberCount: number
  evidenceRefCount: number
}

export interface CohortDissent {
  resourceId: string
  signalType: CohortSignalType
  expectedValue: string
  observedValue: string | null
  reason: string
  evidenceRefCount: number
}

export interface CohortRejectedCandidate {
  resourceId: string
  reasons: CohortRejectionReason[]
  evidenceRefCount: number
}

export interface CohortConflict {
  code: CohortConflictCode
  detail: string
  resourceIds: string[]
  roleRefs: string[]
}

export interface CohortSelectorPreview {
  selector: CanonicalManifestSelector
  matchedResourceIds: string[]
  selectorResultDigest: string
  maxMatches: number
}

export interface CohortProposal {
  proposalId: string
  scope: CohortProposalScope
  role: CanonicalManifestRole
  members: string[]
  confidence: number
  confidenceBand: ConfidenceBand
  supportingEvidence: CohortSupportingEvidence[]
  dissent: CohortDissent[]
  rejectedCandidates: CohortRejectedCandidate[]
  conflicts: CohortConflict[]
  selectorPreview: CohortSelectorPreview | null
  snapshot: CohortProposalSnapshot
  disposition: 'bulkHumanReview' | 'humanResolution'
  requiresHumanReview: true
  bulkReviewEligible: boolean
  publicationAllowed: false
  manifestMutated: false
}

export interface CohortProposalBatch {
  sourceDraft: CohortDraftBinding
  scope: CohortProposalScope
  snapshot: CohortProposalSnapshot
  evaluatedAt: string
  inputDigest: string
  proposalSetDigest: string
  proposals: CohortProposal[]
  conflicts: CohortConflict[]
  requiresHumanReview: true
  publicationAllowed: false
  manifestMutated: false
}

export interface CohortDraftBinding {
  draftId: string
  revision: number
  manifestDigest: string
}

export interface CohortProposalLoadRequest {
  workloadId: string
  manifestVersion: string
  profileId: string
  sourceDraft: CohortDraftBinding
}

export interface CohortReviewPreviewRequest extends CohortProposalLoadRequest {
  action: 'split' | 'merge'
  proposalIds: string[]
  sourceRoles: CanonicalManifestRole[]
  sourceMembers: string[]
  proposalSetDigest: string
  snapshotArtifactDigest: string
  resolution: string
}

export interface CohortRoleUpdate {
  role: CanonicalManifestRole
  selectorPreviews: CohortSelectorPreview[]
  memberCount: number
}

export interface CohortReviewCandidate {
  candidateId: string
  action: CohortReviewAction
  sourceDraft: CohortDraftBinding
  scope: CohortProposalScope
  sourceProposalIds: string[]
  proposalSetDigest: string
  snapshot: CohortProposalSnapshot
  roleUpdates: CohortRoleUpdate[]
  replaceRoleRefs: string[]
  resolution: string
  generatedAt: string
  expiresAt: string
  requiresHumanReview: true
  publicationAllowed: false
  manifestMutated: false
}

export interface CohortDecisionLoadRequest extends CohortProposalLoadRequest {
  scope: CohortProposalScope
  proposalIds: string[]
  proposalSetDigest: string
  snapshotArtifactDigest: string
}

export interface CohortDecisionSubmitRequest extends CohortDecisionLoadRequest {
  action: CohortDecisionAction
  candidate: CohortReviewCandidate | null
  rationale: string
}

export interface CohortDecisionDraftResult {
  draftId: string
  revision: number
  manifestDigest: string
}

/**
 * Durable decision state returned by the decision service. No production HTTP
 * mapping is defined until issue #34 establishes and merges the wire contract.
 */
export interface CohortDecisionRecord {
  decisionId: string
  action: CohortDecisionAction
  sourceDraft: CohortDraftBinding
  scope: CohortProposalScope
  proposalIds: string[]
  proposalSetDigest: string
  snapshotArtifactDigest: string
  candidateId: string | null
  rationale: string
  state: Exclude<CohortDecisionState, 'pending'>
  decidedBy: string
  decidedAt: string
  draftResult: CohortDecisionDraftResult | null
  publicationAllowed: false
}

export interface CohortProposalApiPort {
  auth: AuthSession
  loadProposalBatch: (request: CohortProposalLoadRequest) => Promise<CohortProposalBatch>
  previewReview: (request: CohortReviewPreviewRequest) => Promise<CohortReviewCandidate>
}

export interface CohortDecisionApiPort {
  auth: AuthSession
  loadDecisions: (request: CohortDecisionLoadRequest) => Promise<CohortDecisionRecord[]>
  submitDecision: (request: CohortDecisionSubmitRequest) => Promise<CohortDecisionRecord>
}

export interface CohortProposalApiOptions {
  baseUrl: string
  authPort: AuthPort
  session: AuthSession
  fetchImpl?: typeof fetch
  createId?: () => string
}
