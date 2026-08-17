import { refreshCanonicalManifestDigests } from './canonical'
import type {
  ApprovalDecision,
  AuthSession,
  CanonicalControl,
  CanonicalDeclaredRelationship,
  CanonicalManifestEndpoint,
  CanonicalManifestProfile,
  CanonicalRelationship,
  CanonicalRiskAcceptance,
  CanonicalWorkloadManifest,
  CatalogItem,
  ComparisonRow,
  ConcurrencyRequest,
  ContextApiClientOptions,
  ContextApiClientPort,
  ControlRecord,
  DraftRecord,
  DraftState,
  EvidenceItem,
  PublishRequest,
  PublishedManifest,
  RiskAcceptance,
  Supersession,
  SupersessionRecovery,
  TopologyRelationship,
  WireActor,
  WireApprovalDecision,
  WireDraftRecord,
  WirePublishedManifest,
  WirePublishedManifestView,
  WireSupersession,
  WorkloadContext,
} from './types'

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/
const DIGEST = /^sha256:[a-f0-9]{64}$/
const DECLARED_RELATIONSHIP_TYPES = new Set<CanonicalDeclaredRelationship['kind']>([
  'requires',
  'dependsOn',
  'calls',
  'storesDataIn',
  'replicatesTo',
  'failsOverTo',
  'sharesZoneWith',
  'isolatedFrom',
  'monitors',
  'protectedBy',
  'prohibited',
])
const EDITABLE_STATES = new Set<DraftState>(['draft', 'validated', 'in_review', 'approved'])
const MAX_ERROR_BODY = 16_384
const MAX_ERROR_MESSAGE = 300

export class ContextApiRequestError extends Error {
  readonly status: number
  readonly code: string

  constructor(message: string, status: number, code: string) {
    super(message)
    this.name = 'ContextApiRequestError'
    this.status = status
    this.code = code
  }
}

export class SupersessionRecoveryRequiredError extends Error {
  readonly recovery: SupersessionRecovery
  readonly published: PublishedManifest
  readonly cause: unknown

  constructor(recovery: SupersessionRecovery, published: PublishedManifest, cause: unknown) {
    super(
      `Successor ${recovery.successorVersion} is published, but predecessor ${recovery.predecessorVersion} ` +
      'is still active or supersession could not be verified. Publication is blocked pending supersession recovery.',
    )
    this.name = 'SupersessionRecoveryRequiredError'
    this.recovery = recovery
    this.published = published
    this.cause = cause
  }
}

const asRecord = (value: unknown, label: string): Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`Context API returned an invalid ${label}.`)
  }
  return value as Record<string, unknown>
}

const asArray = (value: unknown, label: string): unknown[] => {
  if (!Array.isArray(value)) {
    throw new Error(`Context API returned an invalid ${label}.`)
  }
  return value
}

const requiredString = (record: Record<string, unknown>, key: string, label: string): string => {
  const value = record[key]
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Context API returned an invalid ${label}.${key}.`)
  }
  return value
}

const requiredNumber = (record: Record<string, unknown>, key: string, label: string): number => {
  const value = record[key]
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new Error(`Context API returned an invalid ${label}.${key}.`)
  }
  return value
}

const parseActor = (value: unknown, label: string): WireActor => {
  const record = asRecord(value, label)
  const actorId = requiredString(record, 'actor_id', label)
  const kind = requiredString(record, 'kind', label)
  if (!IDENTIFIER.test(actorId) || !['human', 'agent', 'service'].includes(kind)) {
    throw new Error(`Context API returned an invalid ${label}.`)
  }
  return { actor_id: actorId, kind: kind as WireActor['kind'] }
}

const parseManifestEndpoint = (value: unknown, label: string): CanonicalManifestEndpoint => {
  const endpoint = asRecord(value, label)
  const endpointType = requiredString(endpoint, 'endpointType', label)
  if (endpointType === 'role') {
    return {
      endpointType,
      roleRef: requiredString(endpoint, 'roleRef', label),
    }
  }
  if (endpointType === 'external') {
    return {
      endpointType,
      externalRef: requiredString(endpoint, 'externalRef', label),
    }
  }
  throw new Error(`Context API returned an invalid ${label}.endpointType.`)
}

const parseCanonicalRelationship = (value: unknown, label: string): CanonicalRelationship => {
  const relationship = asRecord(value, label)
  const relationshipClass = requiredString(relationship, 'relationshipClass', label)
  if (relationshipClass === 'declared') {
    const exceptionOnlyFields = [
      'exceptionId',
      'appliesToRelationshipRef',
      'appliesToClauseRef',
      'riskAcceptanceRef',
      'governanceScope',
      'rationale',
      'expiresAt',
    ]
    if (exceptionOnlyFields.some((field) => field in relationship) || !Array.isArray(relationship.profiles)) {
      throw new Error(`Context API returned an invalid declared ${label}.`)
    }
    const kind = requiredString(relationship, 'kind', label)
    if (!DECLARED_RELATIONSHIP_TYPES.has(kind as CanonicalDeclaredRelationship['kind'])) {
      throw new Error(`Context API returned an invalid ${label}.kind.`)
    }
    const parsed: CanonicalDeclaredRelationship = {
      relationshipClass,
      relationshipId: requiredString(relationship, 'relationshipId', label),
      kind: kind as CanonicalDeclaredRelationship['kind'],
      source: parseManifestEndpoint(relationship.source, `${label}.source`),
      target: parseManifestEndpoint(relationship.target, `${label}.target`),
      ownerRef: requiredString(relationship, 'ownerRef', label),
      profiles: relationship.profiles.map((profile) => {
        if (typeof profile !== 'string') throw new Error(`Context API returned invalid ${label}.profiles.`)
        return profile as CanonicalDeclaredRelationship['profiles'][number]
      }),
      sourceClause: requiredString(relationship, 'sourceClause', label),
    }
    return parsed
  }
  if (relationshipClass === 'exception') {
    const declaredOnlyFields = [
      'relationshipId',
      'kind',
      'source',
      'target',
      'profiles',
      'sourceClause',
    ]
    if (declaredOnlyFields.some((field) => field in relationship)) {
      throw new Error(`Context API returned declared-only fields on exception ${label}.`)
    }
    const scope = asRecord(relationship.governanceScope, `${label}.governanceScope`)
    if (scope.governanceScopeType !== 'clause') {
      throw new Error(`Context API returned an invalid ${label}.governanceScopeType.`)
    }
    const appliesToRelationshipRef = optionalNullableString(relationship, 'appliesToRelationshipRef')
    const appliesToClauseRef = optionalNullableString(relationship, 'appliesToClauseRef')
    if ((appliesToRelationshipRef == null) === (appliesToClauseRef == null)) {
      throw new Error(`Context API returned an exception ${label} without exactly one target.`)
    }
    const common = {
      relationshipClass: 'exception' as const,
      exceptionId: requiredString(relationship, 'exceptionId', label),
      riskAcceptanceRef: requiredString(relationship, 'riskAcceptanceRef', label),
      governanceScope: {
        governanceScopeType: 'clause' as const,
        manifestId: requiredString(scope, 'manifestId', `${label}.governanceScope`),
        profileId: requiredString(scope, 'profileId', `${label}.governanceScope`),
        clausePath: requiredString(scope, 'clausePath', `${label}.governanceScope`),
        ownerRef: requiredString(scope, 'ownerRef', `${label}.governanceScope`),
      },
      ownerRef: requiredString(relationship, 'ownerRef', label),
      rationale: requiredString(relationship, 'rationale', label),
      expiresAt: requiredString(relationship, 'expiresAt', label),
    }
    return appliesToRelationshipRef == null
      ? { ...common, appliesToClauseRef: appliesToClauseRef! }
      : { ...common, appliesToRelationshipRef }
  }
  throw new Error(`Context API returned unsupported ${label}.relationshipClass.`)
}

const parseCanonicalManifest = (value: unknown): CanonicalWorkloadManifest => {
  const record = asRecord(value, 'canonical manifest')
  if ('manifestDigest' in record) {
    throw new Error('Context API returned a forbidden manifestDigest member inside the canonical manifest.')
  }
  const manifestId = requiredString(record, 'manifestId', 'canonical manifest')
  const manifestVersion = requiredString(record, 'manifestVersion', 'canonical manifest')
  const workload = asRecord(record.workload, 'canonical manifest workload')
  const compatibility = asRecord(record.compatibility, 'canonical manifest compatibility')
  if (
    manifestId.length > 128 ||
    !VERSION.test(manifestVersion) ||
    typeof workload.displayName !== 'string' ||
    !Array.isArray(workload.environments) ||
    !Array.isArray(workload.allowedEvidenceScopes) ||
    typeof record.profiles !== 'object' ||
    record.profiles === null ||
    Array.isArray(record.profiles) ||
    !Array.isArray(record.roles) ||
    !Array.isArray(record.relationships) ||
    !Array.isArray(record.constraints) ||
    !Array.isArray(record.controls) ||
    !Array.isArray(record.riskAcceptances) ||
    !Array.isArray(record.objectives) ||
    !Array.isArray(record.ownership) ||
    compatibility.artifactKind !== 'workloadManifest' ||
    typeof compatibility.artifactDigest !== 'string' ||
    !DIGEST.test(compatibility.artifactDigest) ||
    typeof compatibility.semanticDigest !== 'string' ||
    !DIGEST.test(compatibility.semanticDigest) ||
    typeof record.audit !== 'object' ||
    record.audit === null ||
    Array.isArray(record.audit)
  ) {
    throw new Error('Context API returned a malformed canonical workload manifest.')
  }
  record.relationships.map((relationship, index) =>
    parseCanonicalRelationship(relationship, `canonical manifest.relationships[${index}]`),
  )
  for (const [profileId, profileValue] of Object.entries(record.profiles as Record<string, unknown>)) {
    const profile = asRecord(profileValue, `canonical manifest.profiles.${profileId}`)
    asArray(profile.relationships, `canonical manifest.profiles.${profileId}.relationships`).map(
      (relationship, index) =>
        parseCanonicalRelationship(
          relationship,
          `canonical manifest.profiles.${profileId}.relationships[${index}]`,
        ),
    )
  }
  return structuredClone(record) as unknown as CanonicalWorkloadManifest
}

const parseApproval = (value: unknown, label: string): WireApprovalDecision => {
  const record = asRecord(value, label)
  return {
    decision_id: requiredString(record, 'decision_id', label),
    approved_by: parseActor(record.approved_by, `${label}.approved_by`),
    approved_at: requiredString(record, 'approved_at', label),
    approved_revision: requiredNumber(record, 'approved_revision', label),
    manifest_version: requiredString(record, 'manifest_version', label),
    manifest_digest: requiredString(record, 'manifest_digest', label),
    reason: requiredString(record, 'reason', label),
  }
}

const optionalNullableString = (record: Record<string, unknown>, key: string): string | null | undefined => {
  const value = record[key]
  if (value === undefined || value === null || typeof value === 'string') {
    return value
  }
  throw new Error(`Context API returned an invalid ${key}.`)
}

const parseDraft = (value: unknown): WireDraftRecord => {
  const record = asRecord(value, 'draft record')
  const state = requiredString(record, 'state', 'draft record')
  if (!['draft', 'validated', 'in_review', 'approved', 'published', 'superseded'].includes(state)) {
    throw new Error('Context API returned an invalid draft state.')
  }
  const wire: WireDraftRecord = {
    draft_id: requiredString(record, 'draft_id', 'draft record'),
    manifest_id: requiredString(record, 'manifest_id', 'draft record'),
    state: state as DraftState,
    revision: requiredNumber(record, 'revision', 'draft record'),
    manifest: parseCanonicalManifest(record.manifest),
    manifest_digest: requiredString(record, 'manifest_digest', 'draft record'),
    previous_version: optionalNullableString(record, 'previous_version'),
    created_by: parseActor(record.created_by, 'draft record.created_by'),
    created_at: requiredString(record, 'created_at', 'draft record'),
    updated_by: parseActor(record.updated_by, 'draft record.updated_by'),
    updated_at: requiredString(record, 'updated_at', 'draft record'),
    reason: requiredString(record, 'reason', 'draft record'),
  }
  if (record.validation !== undefined && record.validation !== null) {
    const validation = asRecord(record.validation, 'draft validation')
    wire.validation = {
      validated_by: parseActor(validation.validated_by, 'draft validation.validated_by'),
      validated_at: requiredString(validation, 'validated_at', 'draft validation'),
      validated_revision: requiredNumber(validation, 'validated_revision', 'draft validation'),
      manifest_digest: requiredString(validation, 'manifest_digest', 'draft validation'),
    }
  }
  if (record.review !== undefined && record.review !== null) {
    const review = asRecord(record.review, 'draft review')
    wire.review = {
      submitted_by: parseActor(review.submitted_by, 'draft review.submitted_by'),
      submitted_at: requiredString(review, 'submitted_at', 'draft review'),
      submitted_revision: requiredNumber(review, 'submitted_revision', 'draft review'),
      publication_candidate_digest: requiredString(review, 'publication_candidate_digest', 'draft review'),
      reason: requiredString(review, 'reason', 'draft review'),
    }
  }
  if (record.publication_candidate !== undefined && record.publication_candidate !== null) {
    const candidate = asRecord(record.publication_candidate, 'publication candidate')
    if (candidate.approval_status !== 'approved') {
      throw new Error('Context API returned an invalid publication candidate approval status.')
    }
    wire.publication_candidate = {
      finalized_by: parseActor(candidate.finalized_by, 'publication candidate.finalized_by'),
      finalized_at: requiredString(candidate, 'finalized_at', 'publication candidate'),
      manifest_version: requiredString(candidate, 'manifest_version', 'publication candidate'),
      manifest_digest: requiredString(candidate, 'manifest_digest', 'publication candidate'),
      semantic_digest: requiredString(candidate, 'semantic_digest', 'publication candidate'),
      approval_status: 'approved',
    }
  }
  if (record.approval !== undefined && record.approval !== null) {
    wire.approval = parseApproval(record.approval, 'draft approval')
  }
  return wire
}

const parsePublished = (value: unknown): WirePublishedManifest => {
  const record = asRecord(value, 'published manifest')
  return {
    manifest_id: requiredString(record, 'manifest_id', 'published manifest'),
    manifest_version: requiredString(record, 'manifest_version', 'published manifest'),
    manifest_digest: requiredString(record, 'manifest_digest', 'published manifest'),
    manifest: parseCanonicalManifest(record.manifest),
    source_draft_id: requiredString(record, 'source_draft_id', 'published manifest'),
    source_draft_revision: requiredNumber(record, 'source_draft_revision', 'published manifest'),
    previous_version: optionalNullableString(record, 'previous_version'),
    approval: parseApproval(record.approval, 'published manifest.approval'),
    published_by: parseActor(record.published_by, 'published manifest.published_by'),
    published_at: requiredString(record, 'published_at', 'published manifest'),
    publication_authorized_by: parseActor(
      record.publication_authorized_by,
      'published manifest.publication_authorized_by',
    ),
    publication_authorized_at: requiredString(record, 'publication_authorized_at', 'published manifest'),
    reason: requiredString(record, 'reason', 'published manifest'),
  }
}

const parseSupersession = (value: unknown): WireSupersession => {
  const record = asRecord(value, 'supersession')
  return {
    manifest_id: requiredString(record, 'manifest_id', 'supersession'),
    superseded_version: requiredString(record, 'superseded_version', 'supersession'),
    replacement_version: requiredString(record, 'replacement_version', 'supersession'),
    superseded_by: parseActor(record.superseded_by, 'supersession.superseded_by'),
    superseded_at: requiredString(record, 'superseded_at', 'supersession'),
    reason: requiredString(record, 'reason', 'supersession'),
  }
}

const parsePublishedView = (value: unknown): WirePublishedManifestView => {
  const record = asRecord(value, 'published manifest view')
  return {
    published: parsePublished(record.published),
    supersession:
      record.supersession === undefined || record.supersession === null
        ? undefined
        : parseSupersession(record.supersession),
  }
}

const toViewActor = (actor: WireActor): { actorId: string; kind: WireActor['kind'] } => ({
  actorId: actor.actor_id,
  kind: actor.kind,
})

const toViewApproval = (approval: WireApprovalDecision): ApprovalDecision => ({
  decisionId: approval.decision_id,
  approvedBy: toViewActor(approval.approved_by),
  approvedAt: approval.approved_at,
  approvedRevision: approval.approved_revision,
  manifestVersion: approval.manifest_version,
  manifestDigest: approval.manifest_digest,
  reason: approval.reason,
})

const toViewDraft = (wire: WireDraftRecord): DraftRecord => ({
  draftId: wire.draft_id,
  manifestId: wire.manifest_id,
  state: wire.state,
  revision: wire.revision,
  manifest: structuredClone(wire.manifest),
  manifestDigest: wire.manifest_digest,
  previousVersion: wire.previous_version ?? null,
  createdBy: toViewActor(wire.created_by),
  createdAt: wire.created_at,
  updatedBy: toViewActor(wire.updated_by),
  updatedAt: wire.updated_at,
  reason: wire.reason,
  validation: wire.validation
    ? {
        validatedBy: toViewActor(wire.validation.validated_by),
        validatedAt: wire.validation.validated_at,
        validatedRevision: wire.validation.validated_revision,
        manifestDigest: wire.validation.manifest_digest,
      }
    : null,
  review: wire.review
    ? {
        submittedBy: toViewActor(wire.review.submitted_by),
        submittedAt: wire.review.submitted_at,
        submittedRevision: wire.review.submitted_revision,
        publicationCandidateDigest: wire.review.publication_candidate_digest,
        reason: wire.review.reason,
      }
    : null,
  publicationCandidate: wire.publication_candidate
    ? {
        finalizedBy: toViewActor(wire.publication_candidate.finalized_by),
        finalizedAt: wire.publication_candidate.finalized_at,
        manifestVersion: wire.publication_candidate.manifest_version,
        manifestDigest: wire.publication_candidate.manifest_digest,
        semanticDigest: wire.publication_candidate.semantic_digest,
        approvalStatus: wire.publication_candidate.approval_status,
      }
    : null,
  approval: wire.approval ? toViewApproval(wire.approval) : null,
})

const toViewPublished = (wire: WirePublishedManifest): PublishedManifest => ({
  manifestId: wire.manifest_id,
  manifestVersion: wire.manifest_version,
  manifestDigest: wire.manifest_digest,
  manifest: structuredClone(wire.manifest),
  sourceDraftId: wire.source_draft_id,
  sourceDraftRevision: wire.source_draft_revision,
  previousVersion: wire.previous_version ?? null,
  approval: toViewApproval(wire.approval),
  publishedBy: toViewActor(wire.published_by),
  publishedAt: wire.published_at,
  publicationAuthorizedBy: toViewActor(wire.publication_authorized_by),
  publicationAuthorizedAt: wire.publication_authorized_at,
  reason: wire.reason,
})

const toViewSupersession = (wire: WireSupersession): Supersession => ({
  manifestId: wire.manifest_id,
  supersededVersion: wire.superseded_version,
  replacementVersion: wire.replacement_version,
  supersededBy: toViewActor(wire.superseded_by),
  supersededAt: wire.superseded_at,
  reason: wire.reason,
})

const endpointLabel = (endpoint: CanonicalManifestEndpoint): string =>
  endpoint.endpointType === 'role' ? endpoint.roleRef : endpoint.externalRef

const toRelationship = (
  relationship: CanonicalRelationship,
  profileId: string | null,
): TopologyRelationship => {
  if (relationship.relationshipClass === 'declared') {
    return {
      id: relationship.relationshipId,
      kind: 'declared',
      relationshipType: relationship.kind,
      source: endpointLabel(relationship.source),
      target: endpointLabel(relationship.target),
      ownerRef: relationship.ownerRef,
      clause: relationship.sourceClause,
      profileId,
    }
  }
  const relationshipTarget = relationship.appliesToRelationshipRef
  return {
    id: relationship.exceptionId,
    kind: 'exception',
    targetType: relationshipTarget ? 'relationship' : 'clause',
    targetRef: relationshipTarget ?? relationship.appliesToClauseRef!,
    riskAcceptanceRef: relationship.riskAcceptanceRef,
    governanceScope: structuredClone(relationship.governanceScope),
    ownerRef: relationship.ownerRef,
    rationale: relationship.rationale,
    expiresAt: relationship.expiresAt,
    profileId,
  }
}

const toControl = (control: CanonicalControl): ControlRecord => ({
  id: control.controlId,
  ownerRef: control.ownerRef,
  health: control.health,
  runbookRef: control.runbookRef ?? null,
  profiles: [...control.profiles],
})

const toRisk = (risk: CanonicalRiskAcceptance): RiskAcceptance => ({
  id: risk.riskAcceptanceId,
  residualRiskStatement: risk.residualRiskStatement,
  ownedBy: risk.ownedBy,
  status: risk.status,
  profiles: [...risk.profiles],
})

const profileControls = (manifest: CanonicalWorkloadManifest): CanonicalControl[] => [
  ...manifest.controls,
  ...Object.values(manifest.profiles).flatMap((profile) => profile.controls),
]

const profileRisks = (manifest: CanonicalWorkloadManifest): CanonicalRiskAcceptance[] => [
  ...manifest.riskAcceptances,
  ...Object.values(manifest.profiles).flatMap((profile) => profile.riskAcceptances),
]

const compareProfile = (profile: CanonicalManifestProfile): ComparisonRow => ({
  environment: profile.profileType,
  topology: `${profile.roles.length} profile roles and ${profile.relationships.length} profile relationships declared.`,
  policy: `${profile.constraints.length} constraints and ${profile.controls.length} controls declared.`,
  residualRisk:
    profile.riskAcceptances.map((risk) => risk.residualRiskStatement).join(' ') ||
    'No residual-risk statement is declared for this profile.',
  confidence: null,
  relationshipKind: 'declared',
})

const provenanceFrom = (
  manifest: CanonicalWorkloadManifest,
  published: PublishedManifest | null,
): EvidenceItem[] => {
  const items: EvidenceItem[] = [
    {
      id: `manifest-audit-${manifest.manifestVersion}`,
      source: 'Canonical manifest audit',
      summary: `Published by ${manifest.audit.publishedBy} at ${manifest.audit.publishedAt}; approval status ${manifest.audit.approvalStatus}.`,
      clause: '/audit',
      manifestVersion: manifest.manifestVersion,
      confidence: null,
    },
  ]
  if (published) {
    items.push({
      id: `wc007-publication-${published.sourceDraftId}`,
      source: 'WC-007 publication record',
      summary: `Published by ${published.publishedBy.actorId} at ${published.publishedAt}; authorization recorded by ${published.publicationAuthorizedBy.actorId}.`,
      clause: '/v1/manifests/{manifest_id}/versions',
      manifestVersion: published.manifestVersion,
      confidence: null,
    })
  }
  return items
}

const selectUnique = <T>(items: T[], label: string): T | null => {
  if (items.length > 1) {
    throw new Error(`Context API returned ambiguous ${label}; human review is required.`)
  }
  return items[0] ?? null
}

interface LifecycleState {
  drafts: WireDraftRecord[]
  publishedViews: WirePublishedManifestView[]
}

const buildContext = (
  session: AuthSession,
  workloadId: string,
  lifecycle: LifecycleState,
): WorkloadContext => {
  const activeDraftWire = selectUnique(
    lifecycle.drafts.filter((draft) => EDITABLE_STATES.has(draft.state)),
    `active drafts for ${workloadId}`,
  )
  const activePublishedWire = selectUnique(
    lifecycle.publishedViews.filter((view) => !view.supersession).map((view) => view.published),
    `unsuperseded published versions for ${workloadId}`,
  )
  const draft = activeDraftWire ? toViewDraft(activeDraftWire) : null
  const published = activePublishedWire ? toViewPublished(activePublishedWire) : null
  if (draft && published) {
    if (
      draft.previousVersion !== published.manifestVersion ||
      compareVersions(draft.manifest.manifestVersion, published.manifestVersion) <= 0
    ) {
      throw new Error(`Active draft lineage for ${workloadId} does not match the unique unsuperseded predecessor.`)
    }
  } else if (draft?.previousVersion) {
    throw new Error(`Active draft lineage for ${workloadId} has no unsuperseded published predecessor.`)
  }
  const manifest = draft?.manifest ?? published?.manifest
  if (!manifest) {
    throw new Error(`Unknown workload or no active lifecycle state for ${workloadId}.`)
  }
  if (manifest.manifestId !== workloadId) {
    throw new Error(`Context API returned a manifest identity mismatch for ${workloadId}.`)
  }

  const environment = manifest.workload.environments[0]
  if (!environment) {
    throw new Error(`Context API returned no declared environment for ${workloadId}.`)
  }
  const relationships = [
    ...manifest.relationships.map((relationship) => toRelationship(relationship, null)),
    ...Object.values(manifest.profiles).flatMap((profile) =>
      profile.relationships.map((relationship) => toRelationship(relationship, profile.profileId)),
    ),
  ]
  const owner = manifest.ownership[0]?.ownerRef ?? null
  const approvalState = draft?.state ?? 'published'
  const catalogueItem: CatalogItem = {
    id: workloadId,
    name: manifest.workload.displayName,
    owner,
    criticality: null,
    zoneCount: null,
    status: approvalState,
  }

  return {
    workloadId,
    auth: session,
    environment,
    evidenceSource: 'WC-007 Context API lifecycle response; observed Azure evidence is not provided by this route.',
    confidence: null,
    manifestVersion: manifest.manifestVersion,
    approvalState,
    catalogueItem,
    comparison: ['production', 'development', 'training']
      .map((profileId) => manifest.profiles[profileId])
      .filter((profile): profile is CanonicalManifestProfile => profile !== undefined)
      .map(compareProfile),
    relationships,
    manifest,
    controls: profileControls(manifest).map(toControl),
    riskAcceptances: profileRisks(manifest).map(toRisk),
    provenance: provenanceFrom(manifest, published),
    validationMessages: draft?.validation ? [] : ['No WC-007 validation record exists for the active draft.'],
    draft,
    published,
  }
}

const safeError = async (response: Response): Promise<ContextApiRequestError> => {
  let message = `Context API request failed with status ${response.status}.`
  let code = response.status === 403 ? 'authorization_denied' : 'request_failed'
  const contentType = response.headers.get('Content-Type')?.toLowerCase() ?? ''
  const declaredLength = Number(response.headers.get('Content-Length') ?? '0')
  if (contentType.includes('application/json') && (!declaredLength || declaredLength <= MAX_ERROR_BODY)) {
    const body = await response.text()
    if (body.length <= MAX_ERROR_BODY) {
      try {
        const parsed = asRecord(JSON.parse(body), 'error response')
        const detail = asRecord(parsed.error, 'error detail')
        if (typeof detail.code === 'string') code = detail.code.slice(0, 128)
        if (typeof detail.message === 'string') message = detail.message.slice(0, MAX_ERROR_MESSAGE)
      } catch {
        // Keep the bounded generic message. Raw response bodies are never rendered.
      }
    }
  }
  return new ContextApiRequestError(message, response.status, code)
}

const ensureOptions = (options: ContextApiClientOptions): ContextApiClientOptions => {
  if (!options.baseUrl?.trim() || !options.authPort || !options.session) {
    throw new Error('Context API client requires an injected base URL, AuthPort, and authenticated session.')
  }
  if (
    !IDENTIFIER.test(options.session.actorId) ||
    options.session.authorizedWorkloadIds.length === 0 ||
    new Set(options.session.authorizedWorkloadIds).size !== options.session.authorizedWorkloadIds.length ||
    options.session.authorizedWorkloadIds.some((id) => id === '*' || id.length > 128 || id.trim() !== id)
  ) {
    throw new Error('Authenticated session has invalid or ambiguous authorized workload IDs.')
  }
  return options
}

const versionTuple = (version: string): [number, number, number] => {
  const match = VERSION.exec(version)
  if (!match) throw new Error(`Context API returned invalid manifest version ${version}.`)
  const result: [number, number, number] = [Number(match[1]), Number(match[2]), Number(match[3])]
  if (result.some((part) => !Number.isSafeInteger(part))) {
    throw new Error(`Manifest version ${version} exceeds browser-safe integer bounds.`)
  }
  return result
}

const compareVersions = (left: string, right: string): number => {
  const leftTuple = versionTuple(left)
  const rightTuple = versionTuple(right)
  for (let index = 0; index < 3; index += 1) {
    const difference = leftTuple[index]! - rightTuple[index]!
    if (difference !== 0) return difference
  }
  return 0
}

const nextUniqueVersion = (predecessor: string, existing: Set<string>): string => {
  const highest = [...existing, predecessor].sort(compareVersions).at(-1)!
  const [major, minor, patch] = versionTuple(highest)
  let candidate = `${major}.${minor}.${patch + 1}`
  while (existing.has(candidate) || compareVersions(candidate, predecessor) <= 0) {
    const [, , candidatePatch] = versionTuple(candidate)
    candidate = `${major}.${minor}.${candidatePatch + 1}`
  }
  return candidate
}

export const createContextApiClient = (options: ContextApiClientOptions): ContextApiClientPort => {
  const config = ensureOptions(options)
  const baseUrl = config.baseUrl.replace(/\/+$/, '')
  const fetchImpl = config.fetchImpl ?? globalThis.fetch
  const createId = config.createId ?? (() => crypto.randomUUID())
  const authorizedIds = new Set(config.session.authorizedWorkloadIds)

  const assertAuthorized = (workloadId: string): void => {
    if (!authorizedIds.has(workloadId)) {
      throw new ContextApiRequestError(`Workload ${workloadId} is not authorized for this session.`, 403, 'authorization_denied')
    }
  }

  const safeId = (prefix: string): string => {
    const normalizedPrefix = prefix.replace(/[^A-Za-z0-9._-]/g, '-')
    const suffix = createId().replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 80)
    const value = `${normalizedPrefix}-${suffix}`.slice(0, 128)
    if (!IDENTIFIER.test(value)) throw new Error('Injected ID generator returned an invalid identifier.')
    return value
  }

  const requestJson = async (
    path: string,
    requestInit: RequestInit,
    idempotencyKey?: string,
  ): Promise<unknown> => {
    const token = (await config.authPort.acquireAccessToken(config.session))?.trim()
    if (!token) {
      throw new ContextApiRequestError('Authentication is required before Context Studio can access workload state.', 401, 'authentication_required')
    }
    const headers = new Headers(requestInit.headers)
    headers.set('Authorization', `Bearer ${token}`)
    if (requestInit.body !== undefined && requestInit.body !== null) {
      headers.set('Content-Type', 'application/json')
    }
    if (requestInit.method && !['GET', 'HEAD'].includes(requestInit.method.toUpperCase())) {
      headers.set('Idempotency-Key', idempotencyKey ?? safeId('mutation'))
    }
    const response = await fetchImpl(`${baseUrl}${path}`, { ...requestInit, headers })
    if (!response.ok) throw await safeError(response)
    return response.status === 204 ? undefined : response.json()
  }

  const loadLifecycle = async (workloadId: string): Promise<LifecycleState> => {
    assertAuthorized(workloadId)
    const encoded = encodeURIComponent(workloadId)
    const draftPayload = await requestJson(`/v1/drafts?manifest_id=${encoded}`, { method: 'GET' })
    const publishedPayload = await requestJson(`/v1/manifests/${encoded}/versions`, { method: 'GET' })
    return {
      drafts: asArray(draftPayload, 'draft list').map(parseDraft),
      publishedViews: asArray(publishedPayload, 'published manifest view list').map(parsePublishedView),
    }
  }

  const transition = async (
    request: ConcurrencyRequest,
    operation: 'validate' | 'submit' | 'approve',
  ): Promise<DraftRecord> => {
    assertAuthorized(request.workloadId)
    const response = await requestJson(
      `/v1/drafts/${encodeURIComponent(request.draftId)}/${operation}`,
      {
        method: 'POST',
        body: JSON.stringify({
          expected_revision: request.expectedRevision,
          expected_manifest_version: request.expectedManifestVersion,
          expected_digest: request.expectedDigest,
          reason: request.reason,
        }),
      },
    )
    const draft = toViewDraft(parseDraft(response))
    if (draft.manifestId !== request.workloadId) {
      throw new Error('Context API returned a draft outside the authorized workload scope.')
    }
    return draft
  }

  const supersede = async (recovery: SupersessionRecovery): Promise<Supersession> => {
    assertAuthorized(recovery.workloadId)
    if (!IDENTIFIER.test(recovery.idempotencyKey)) {
      throw new Error('Supersession recovery requires its original valid idempotency key.')
    }
    const response = await requestJson(
      `/v1/manifests/${encodeURIComponent(recovery.workloadId)}/versions/` +
        `${encodeURIComponent(recovery.predecessorVersion)}/supersede`,
      {
        method: 'POST',
        body: JSON.stringify({
          expected_revision: recovery.predecessorRevision,
          expected_manifest_version: recovery.predecessorVersion,
          expected_digest: recovery.predecessorDigest,
          replacement_version: recovery.successorVersion,
          replacement_digest: recovery.successorDigest,
          reason: recovery.reason,
        }),
      },
      recovery.idempotencyKey,
    )
    const relation = toViewSupersession(parseSupersession(response))
    if (
      relation.manifestId !== recovery.workloadId ||
      relation.supersededVersion !== recovery.predecessorVersion ||
      relation.replacementVersion !== recovery.successorVersion
    ) {
      throw new Error('Context API returned a supersession outside the exact publication lineage.')
    }
    return relation
  }

  const verifySupersession = async (recovery: SupersessionRecovery): Promise<void> => {
    const lifecycle = await loadLifecycle(recovery.workloadId)
    const active = lifecycle.publishedViews.filter((view) => !view.supersession)
    if (
      active.length !== 1 ||
      active[0]!.published.manifest_version !== recovery.successorVersion ||
      active[0]!.published.manifest_digest !== recovery.successorDigest
    ) {
      throw new Error('Reload did not yield exactly one active unsuperseded successor version.')
    }
    const predecessor = lifecycle.publishedViews.find(
      (view) => view.published.manifest_version === recovery.predecessorVersion,
    )
    if (
      predecessor?.supersession?.replacement_version !== recovery.successorVersion ||
      predecessor.supersession.superseded_version !== recovery.predecessorVersion
    ) {
      throw new Error('Reload did not return the exact predecessor-to-successor supersession.')
    }
  }

  return {
    auth: config.session,
    loadAuthorizedWorkloads: async () =>
      Promise.all(
        config.session.authorizedWorkloadIds.map(async (workloadId) =>
          buildContext(config.session, workloadId, await loadLifecycle(workloadId)),
        ),
      ),
    loadWorkloadContext: async (workloadId) =>
      buildContext(config.session, workloadId, await loadLifecycle(workloadId)),
    createSuccessorDraft: async (workloadId, reason) => {
      const lifecycle = await loadLifecycle(workloadId)
      const activeDrafts = lifecycle.drafts.filter((draft) => EDITABLE_STATES.has(draft.state))
      if (activeDrafts.length > 0) {
        throw new Error('An active draft already exists; reload and update that draft instead.')
      }
      const activePublished = selectUnique(
        lifecycle.publishedViews.filter((view) => !view.supersession),
        `unsuperseded published versions for ${workloadId}`,
      )
      if (!activePublished) {
        throw new Error('A unique unsuperseded published predecessor is required to create a successor draft.')
      }
      const predecessor = activePublished.published
      if (predecessor.manifest_id !== workloadId) {
        throw new Error('Published predecessor identity does not match the authorized workload.')
      }
      const existingVersions = new Set([
        ...lifecycle.drafts.map((draft) => draft.manifest.manifestVersion),
        ...lifecycle.publishedViews.map((view) => view.published.manifest_version),
      ])
      const candidate = structuredClone(predecessor.manifest)
      candidate.manifestVersion = nextUniqueVersion(predecessor.manifest_version, existingVersions)
      const canonicalCandidate = await refreshCanonicalManifestDigests(candidate)

      let draftId = ''
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const candidateId = safeId(`draft-${workloadId.slice(0, 36)}`)
        if (!lifecycle.drafts.some((draft) => draft.draft_id === candidateId)) {
          draftId = candidateId
          break
        }
      }
      if (!draftId) throw new Error('Unable to allocate a unique successor draft identifier.')

      const response = await requestJson('/v1/drafts', {
        method: 'POST',
        body: JSON.stringify({
          draft_id: draftId,
          manifest: canonicalCandidate,
          manifest_digest: canonicalCandidate.compatibility.artifactDigest,
          previous_version: predecessor.manifest_version,
          reason,
        }),
      })
      return toViewDraft(parseDraft(response))
    },
    updateDraft: async (request) => {
      assertAuthorized(request.workloadId)
      if (request.replacementManifest.manifestId !== request.workloadId) {
        throw new Error('A replacement manifest cannot change the authorized workload identity.')
      }
      const canonicalReplacement = await refreshCanonicalManifestDigests(request.replacementManifest)
      const response = await requestJson(`/v1/drafts/${encodeURIComponent(request.draftId)}`, {
        method: 'PUT',
        body: JSON.stringify({
          expected_revision: request.expectedRevision,
          expected_manifest_version: request.expectedManifestVersion,
          expected_digest: request.expectedDigest,
          replacement_manifest: canonicalReplacement,
          replacement_digest: canonicalReplacement.compatibility.artifactDigest,
          reason: request.reason,
        }),
      })
      return toViewDraft(parseDraft(response))
    },
    validateDraft: async (request) => transition(request, 'validate'),
    submitForReview: async (request) => transition(request, 'submit'),
    approveDraft: async (request) => transition(request, 'approve'),
    publishDraft: async (request: PublishRequest) => {
      assertAuthorized(request.workloadId)
      const beforePublication = await loadLifecycle(request.workloadId)
      const sourceDraft = selectUnique(
        beforePublication.drafts.filter((draft) => draft.draft_id === request.draftId),
        `publication source drafts for ${request.workloadId}`,
      )
      if (
        !sourceDraft ||
        sourceDraft.state !== 'approved' ||
        sourceDraft.revision !== request.expectedRevision ||
        sourceDraft.manifest.manifestVersion !== request.expectedManifestVersion ||
        sourceDraft.manifest_digest !== request.expectedDigest
      ) {
        throw new Error('Publication source is not the exact current approved draft.')
      }
      const activeBefore = beforePublication.publishedViews.filter((view) => !view.supersession)
      const predecessor =
        sourceDraft.previous_version == null
          ? null
          : selectUnique(
              activeBefore.filter(
                (view) => view.published.manifest_version === sourceDraft.previous_version,
              ),
              `unsuperseded predecessors for ${request.workloadId}`,
            )
      if (
        (sourceDraft.previous_version == null && activeBefore.length !== 0) ||
        (sourceDraft.previous_version != null &&
          (activeBefore.length !== 1 || predecessor == null))
      ) {
        throw new Error('Publication requires the exact unique unsuperseded predecessor from the draft lineage.')
      }
      const response = await requestJson(`/v1/drafts/${encodeURIComponent(request.draftId)}/publish`, {
        method: 'POST',
        body: JSON.stringify({
          expected_revision: request.expectedRevision,
          expected_manifest_version: request.expectedManifestVersion,
          expected_digest: request.expectedDigest,
          reason: request.reason,
          approval_id: request.approvalId,
        }),
      })
      const published = toViewPublished(parsePublished(response))
      if (published.manifestId !== request.workloadId) {
        throw new Error('Context API returned a publication outside the authorized workload scope.')
      }
      if (published.previousVersion !== (predecessor?.published.manifest_version ?? null)) {
        throw new Error('Published successor did not retain the exact predecessor version.')
      }
      if (predecessor) {
        const recovery: SupersessionRecovery = {
          workloadId: request.workloadId,
          predecessorVersion: predecessor.published.manifest_version,
          predecessorRevision: predecessor.published.source_draft_revision,
          predecessorDigest: predecessor.published.manifest_digest,
          successorVersion: published.manifestVersion,
          successorDigest: published.manifestDigest,
          reason: `Supersede ${predecessor.published.manifest_version} with published successor ${published.manifestVersion}.`,
          idempotencyKey: safeId('supersede'),
        }
        try {
          await supersede(recovery)
          await verifySupersession(recovery)
        } catch (error) {
          throw new SupersessionRecoveryRequiredError(recovery, published, error)
        }
      } else {
        const afterPublication = await loadLifecycle(request.workloadId)
        const activeAfter = afterPublication.publishedViews.filter((view) => !view.supersession)
        if (
          activeAfter.length !== 1 ||
          activeAfter[0]!.published.manifest_version !== published.manifestVersion
        ) {
          throw new Error('Initial publication reload did not yield exactly one active version.')
        }
      }
      return published
    },
    completeSupersession: async (recovery) => {
      const relation = await supersede(recovery)
      await verifySupersession(recovery)
      return relation
    },
  }
}

export const unwrapPublishedManifestView = (
  value: WirePublishedManifestView,
): { published: PublishedManifest; supersession: Supersession | null } => ({
  published: toViewPublished(value.published),
  supersession: value.supersession ? toViewSupersession(value.supersession) : null,
})
