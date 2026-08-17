import { ContextApiRequestError } from './client'
import type {
  CohortConflict,
  CohortConflictCode,
  CohortDissent,
  CohortDraftBinding,
  CohortProposal,
  CohortProposalApiOptions,
  CohortProposalApiPort,
  CohortProposalBatch,
  CohortProposalScope,
  CohortProposalSnapshot,
  CohortRejectedCandidate,
  CohortRejectionReason,
  CohortReviewCandidate,
  CohortReviewPreviewRequest,
  CohortRoleUpdate,
  CohortSelectorPreview,
  CohortSignalType,
  CohortSupportingEvidence,
  ConfidenceBand,
} from './cohortTypes'
import type {
  CanonicalAtomicSelector,
  CanonicalManifestCardinality,
  CanonicalManifestRole,
  CanonicalManifestSelector,
  EnvironmentName,
} from './types'

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/
const DIGEST = /^sha256:[a-f0-9]{64}$/
const PROPOSAL_ID = /^proposal-[a-f0-9]{16}$/
const MAX_RESPONSE_BODY = 8 * 1024 * 1024
const MAX_ERROR_BODY = 16_384
const MAX_ERROR_MESSAGE = 300
const ENVIRONMENTS = new Set<EnvironmentName>([
  'production',
  'development',
  'training',
  'test',
  'disasterRecovery',
  'sandbox',
])
const SIGNAL_TYPES = new Set<CohortSignalType>([
  'approvedTags',
  'namePredicate',
  'resourceType',
  'vmScaleSet',
  'loadBalancerBackend',
  'subnet',
  'image',
  'deploymentProvenance',
  'provenance',
  'observedCommunication',
])
const CONFLICT_CODES = new Set<CohortConflictCode>([
  'ambiguousRole',
  'conflictingSignal',
  'crossEnvironment',
  'duplicateResourceId',
  'evidenceGap',
  'invalidEvidenceReference',
  'missingEvidence',
  'noEligibleMembers',
  'outOfScope',
  'overMaxMatches',
  'selectorPreviewMismatch',
  'snapshotDigestMismatch',
  'staleEvidence',
])
const REJECTION_REASONS = new Set<CohortRejectionReason>([
  'ambiguousRole',
  'conflictingRoleEvidence',
  'crossEnvironment',
  'differentCohortSignal',
  'duplicateResourceId',
  'invalidEvidenceReference',
  'missingEnvironment',
  'missingRoleEvidence',
  'outOfProfileScope',
  'outOfSnapshotScope',
  'overMaxMatches',
  'staleEvidence',
])
const CONFIDENCE_BANDS = new Set<ConfidenceBand>(['high', 'medium', 'low', 'conflicting'])
const ROLE_KINDS = new Set<CanonicalManifestRole['kind']>([
  'singletonDatabase',
  'databaseReplica',
  'worker',
  'webService',
  'loadBalancer',
  'integrationEndpoint',
  'storage',
  'network',
  'identity',
  'observability',
  'externalDependency',
])

const idempotencyDigest = async (value: string): Promise<string> => {
  const bytes = new TextEncoder().encode(value)
  const result = await crypto.subtle.digest('SHA-256', bytes)
  return Array.from(
    new Uint8Array(result),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('')
}

const asRecord = (value: unknown, label: string): Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`Cohort API returned an invalid ${label}.`)
  }
  return value as Record<string, unknown>
}

const asArray = (value: unknown, label: string, maximum: number): unknown[] => {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new Error(`Cohort API returned an invalid or oversized ${label}.`)
  }
  return value
}

const requiredString = (
  record: Record<string, unknown>,
  key: string,
  label: string,
  maximum = 2048,
): string => {
  const value = record[key]
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum) {
    throw new Error(`Cohort API returned an invalid ${label}.${key}.`)
  }
  return value
}

const optionalString = (
  record: Record<string, unknown>,
  key: string,
  label: string,
  maximum = 2048,
): string | undefined => {
  const value = record[key]
  if (value === undefined) return undefined
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum) {
    throw new Error(`Cohort API returned an invalid ${label}.${key}.`)
  }
  return value
}

const requiredInteger = (
  record: Record<string, unknown>,
  key: string,
  label: string,
  minimum: number,
  maximum: number,
): number => {
  const value = record[key]
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`Cohort API returned an invalid ${label}.${key}.`)
  }
  return value as number
}

const requiredBoolean = (record: Record<string, unknown>, key: string, label: string): boolean => {
  const value = record[key]
  if (typeof value !== 'boolean') {
    throw new Error(`Cohort API returned an invalid ${label}.${key}.`)
  }
  return value
}

const stringArray = (
  value: unknown,
  label: string,
  maximum: number,
  itemMaximum = 2048,
): string[] =>
  asArray(value, label, maximum).map((item) => {
    if (typeof item !== 'string' || item.length === 0 || item.length > itemMaximum) {
      throw new Error(`Cohort API returned an invalid ${label} item.`)
    }
    return item
  })

const uniqueNormalized = (values: string[], label: string): void => {
  const normalized = values.map((value) => value.normalize('NFC').toLowerCase())
  if (new Set(normalized).size !== values.length) {
    throw new Error(`Cohort API returned duplicate normalized ${label}.`)
  }
}

const sortedNormalized = (values: string[], label: string): void => {
  const normalized = values.map((value) => value.normalize('NFC').toLowerCase())
  if (JSON.stringify(normalized) !== JSON.stringify([...normalized].sort())) {
    throw new Error(`Cohort API returned unsorted normalized ${label}.`)
  }
}

const timestamp = (record: Record<string, unknown>, key: string, label: string): string => {
  const value = requiredString(record, key, label, 64)
  if (!/(?:Z|[+-]\d{2}:\d{2})$/.test(value) || Number.isNaN(Date.parse(value))) {
    throw new Error(`Cohort API returned an invalid ${label}.${key}.`)
  }
  return value
}

const digest = (record: Record<string, unknown>, key: string, label: string): string => {
  const value = requiredString(record, key, label, 71)
  if (!DIGEST.test(value)) throw new Error(`Cohort API returned an invalid ${label}.${key}.`)
  return value
}

const parseAtomicSelector = (
  record: Record<string, unknown>,
  label: string,
): CanonicalAtomicSelector => {
  const selectorType = requiredString(record, 'selectorType', label, 32)
  const selectorId = requiredString(record, 'selectorId', label, 128)
  const maxMatches = requiredInteger(record, 'maxMatches', label, 1, 1000)
  switch (selectorType) {
    case 'resourceIdList': {
      const resourceIds = stringArray(record.resourceIds, `${label}.resourceIds`, 200)
      if (resourceIds.length === 0) throw new Error(`Cohort API returned an empty ${label}.resourceIds.`)
      uniqueNormalized(resourceIds, `${label}.resourceIds`)
      return { selectorType, selectorId, resourceIds, maxMatches }
    }
    case 'tagPredicate': {
      const predicates = asArray(record.predicates, `${label}.predicates`, 20).map((item, index) => {
        const predicate = asRecord(item, `${label}.predicates[${index}]`)
        return {
          key: requiredString(predicate, 'key', `${label}.predicates[${index}]`, 128),
          value: requiredString(predicate, 'value', `${label}.predicates[${index}]`, 256),
        }
      })
      if (predicates.length === 0) throw new Error(`Cohort API returned empty ${label}.predicates.`)
      uniqueNormalized(predicates.map((item) => item.key), `${label} predicate keys`)
      return { selectorType, selectorId, predicates, maxMatches }
    }
    case 'namePredicate': {
      const prefix = optionalString(record, 'prefix', label, 128)
      const suffix = optionalString(record, 'suffix', label, 128)
      if (
        (!prefix && !suffix) ||
        [prefix, suffix].some((value) =>
          value != null && ['*', '?', '[', ']', '(', ')'].some((token) => value.includes(token)),
        )
      ) {
        throw new Error(`Cohort API returned an unbounded ${label}.`)
      }
      return { selectorType, selectorId, prefix, suffix, maxMatches }
    }
    case 'resourceType':
      return {
        selectorType,
        selectorId,
        resourceType: requiredString(record, 'resourceType', label, 200),
        locations: stringArray(record.locations ?? [], `${label}.locations`, 20, 128),
        resourceGroups: stringArray(record.resourceGroups ?? [], `${label}.resourceGroups`, 20, 128),
        maxMatches,
      }
    case 'vmScaleSet':
      return {
        selectorType,
        selectorId,
        scaleSetResourceId: requiredString(record, 'scaleSetResourceId', label),
        instanceIds: stringArray(record.instanceIds ?? [], `${label}.instanceIds`, 200, 128),
        maxMatches,
      }
    case 'loadBalancerBackend':
      return {
        selectorType,
        selectorId,
        loadBalancerResourceId: requiredString(record, 'loadBalancerResourceId', label),
        backendPoolName: requiredString(record, 'backendPoolName', label, 128),
        maxMatches,
      }
    case 'subnet':
      return {
        selectorType,
        selectorId,
        subnetResourceId: requiredString(record, 'subnetResourceId', label),
        maxMatches,
      }
    case 'image':
      return {
        selectorType,
        selectorId,
        publisher: requiredString(record, 'publisher', label, 128),
        offer: requiredString(record, 'offer', label, 128),
        sku: requiredString(record, 'sku', label, 128),
        version: optionalString(record, 'version', label, 64),
        maxMatches,
      }
    case 'provenance':
      return {
        selectorType,
        selectorId,
        collectorToolName: requiredString(record, 'collectorToolName', label, 128),
        collectorToolVersion: requiredString(record, 'collectorToolVersion', label, 64),
        identityEvidenceRef: requiredString(record, 'identityEvidenceRef', label, 128),
        maxMatches,
      }
    default:
      throw new Error(`Cohort API returned an unsupported ${label}.selectorType.`)
  }
}

const parseSelector = (value: unknown, label: string): CanonicalManifestSelector => {
  const record = asRecord(value, label)
  const selectorType = requiredString(record, 'selectorType', label, 32)
  if (selectorType !== 'compositeAll' && selectorType !== 'compositeAny') {
    return parseAtomicSelector(record, label)
  }
  const selectorId = requiredString(record, 'selectorId', label, 128)
  const maxMatches = requiredInteger(record, 'maxMatches', label, 1, 1000)
  const children = asArray(record.children, `${label}.children`, 10).map((child, index) =>
    parseAtomicSelector(asRecord(child, `${label}.children[${index}]`), `${label}.children[${index}]`),
  )
  if (children.length === 0) throw new Error(`Cohort API returned empty ${label}.children.`)
  uniqueNormalized(children.map((child) => child.selectorId), `${label} child selector IDs`)
  return { selectorType, selectorId, children, maxMatches }
}

const parseCardinality = (value: unknown, label: string): CanonicalManifestCardinality => {
  const record = asRecord(value, label)
  const kind = requiredString(record, 'cardinalityKind', label, 32)
  if (kind === 'exactlyOne' || kind === 'oneOrMore' || kind === 'zeroOrMore') {
    return { cardinalityKind: kind }
  }
  if (kind === 'boundedRange') {
    const minimum = requiredInteger(record, 'minimum', label, 0, 10_000)
    const maximum = requiredInteger(record, 'maximum', label, 0, 10_000)
    if (maximum < minimum) throw new Error(`Cohort API returned an invalid ${label} range.`)
    return { cardinalityKind: kind, minimum, maximum }
  }
  throw new Error(`Cohort API returned an unsupported ${label}.cardinalityKind.`)
}

const parseRole = (value: unknown, label: string): CanonicalManifestRole => {
  const record = asRecord(value, label)
  const kind = requiredString(record, 'kind', label, 32)
  const status = requiredString(record, 'status', label, 16)
  if (!ROLE_KINDS.has(kind as CanonicalManifestRole['kind']) || !['approved', 'deprecated'].includes(status)) {
    throw new Error(`Cohort API returned an invalid ${label}.`)
  }
  const selectors = asArray(record.selectors, `${label}.selectors`, 20).map((selector, index) =>
    parseSelector(selector, `${label}.selectors[${index}]`),
  )
  if (selectors.length === 0) throw new Error(`Cohort API returned no ${label}.selectors.`)
  uniqueNormalized(selectors.map((selector) => selector.selectorId), `${label} selector IDs`)
  return {
    roleId: requiredString(record, 'roleId', label, 128),
    kind: kind as CanonicalManifestRole['kind'],
    cardinality: parseCardinality(record.cardinality, `${label}.cardinality`),
    selectors,
    ownerRef: requiredString(record, 'ownerRef', label, 128),
    status: status as CanonicalManifestRole['status'],
  }
}

const parseScope = (value: unknown, label: string): CohortProposalScope => {
  const record = asRecord(value, label)
  const manifestVersion = requiredString(record, 'manifestVersion', label, 128)
  const profileType = requiredString(record, 'profileType', label, 32)
  if (!VERSION.test(manifestVersion) || !ENVIRONMENTS.has(profileType as EnvironmentName)) {
    throw new Error(`Cohort API returned an invalid ${label}.`)
  }
  return {
    manifestId: requiredString(record, 'manifestId', label, 128),
    manifestVersion,
    profileId: requiredString(record, 'profileId', label, 128),
    profileType: profileType as EnvironmentName,
    resolvedProfileDigest: digest(record, 'resolvedProfileDigest', label),
  }
}

const parseDraftBinding = (value: unknown, label: string): CohortDraftBinding => {
  const record = asRecord(value, label)
  const draftId = requiredString(record, 'draftId', label, 128)
  if (!IDENTIFIER.test(draftId)) throw new Error(`Cohort API returned an invalid ${label}.draftId.`)
  return {
    draftId,
    revision: requiredInteger(record, 'revision', label, 1, Number.MAX_SAFE_INTEGER),
    manifestDigest: digest(record, 'manifestDigest', label),
  }
}

const parseSnapshot = (value: unknown, label: string): CohortProposalSnapshot => {
  const record = asRecord(value, label)
  const result = {
    snapshotId: requiredString(record, 'snapshotId', label, 128),
    artifactDigest: digest(record, 'artifactDigest', label),
    semanticDigest: digest(record, 'semanticDigest', label),
    collectedAt: timestamp(record, 'collectedAt', label),
    expiresAt: timestamp(record, 'expiresAt', label),
  }
  if (Date.parse(result.expiresAt) <= Date.parse(result.collectedAt)) {
    throw new Error(`Cohort API returned an invalid ${label} lifetime.`)
  }
  return result
}

const parseEvidenceRefs = (value: unknown, label: string): number => {
  const references = asArray(value, label, 1000)
  references.forEach((reference, index) => {
    asRecord(reference, `${label}[${index}]`)
  })
  return references.length
}

const parseConflict = (value: unknown, label: string): CohortConflict => {
  const record = asRecord(value, label)
  const code = requiredString(record, 'code', label, 64)
  if (!CONFLICT_CODES.has(code as CohortConflictCode)) {
    throw new Error(`Cohort API returned an invalid ${label}.code.`)
  }
  const resourceIds = stringArray(record.resourceIds ?? [], `${label}.resourceIds`, 1000)
  const roleRefs = stringArray(record.roleRefs ?? [], `${label}.roleRefs`, 200, 128)
  uniqueNormalized(resourceIds, `${label} resource IDs`)
  uniqueNormalized(roleRefs, `${label} role refs`)
  return {
    code: code as CohortConflictCode,
    detail: requiredString(record, 'detail', label, 1000),
    resourceIds,
    roleRefs,
  }
}

const parseSelectorPreview = (value: unknown, label: string): CohortSelectorPreview => {
  const record = asRecord(value, label)
  const selector = parseSelector(record.selector, `${label}.selector`)
  const maxMatches = requiredInteger(record, 'maxMatches', label, 1, 1000)
  if (selector.maxMatches !== maxMatches) {
    throw new Error(`Cohort API returned mismatched ${label}.maxMatches.`)
  }
  const matchedResourceIds = stringArray(record.matchedResourceIds, `${label}.matchedResourceIds`, 1000)
  uniqueNormalized(matchedResourceIds, `${label} matched resource IDs`)
  return {
    selector,
    matchedResourceIds,
    selectorResultDigest: digest(record, 'selectorResultDigest', label),
    maxMatches,
  }
}

const parseSupportingEvidence = (
  value: unknown,
  label: string,
  members: string[],
): CohortSupportingEvidence => {
  const record = asRecord(value, label)
  const signalType = requiredString(record, 'signalType', label, 64)
  if (!SIGNAL_TYPES.has(signalType as CohortSignalType)) {
    throw new Error(`Cohort API returned an invalid ${label}.signalType.`)
  }
  const memberResourceIds = stringArray(record.memberResourceIds, `${label}.memberResourceIds`, 1000)
  if (JSON.stringify(memberResourceIds) !== JSON.stringify(members)) {
    throw new Error(`Cohort API returned evidence not bound to the complete cohort.`)
  }
  return {
    signalType: signalType as CohortSignalType,
    signalValue: requiredString(record, 'signalValue', label, 2000),
    memberCount: memberResourceIds.length,
    evidenceRefCount: parseEvidenceRefs(record.evidenceRefs, `${label}.evidenceRefs`),
  }
}

const parseDissent = (value: unknown, label: string, members: Set<string>): CohortDissent => {
  const record = asRecord(value, label)
  const resourceId = requiredString(record, 'resourceId', label)
  const signalType = requiredString(record, 'signalType', label, 64)
  if (!members.has(resourceId) || !SIGNAL_TYPES.has(signalType as CohortSignalType)) {
    throw new Error(`Cohort API returned invalid ${label} membership or signal type.`)
  }
  return {
    resourceId,
    signalType: signalType as CohortSignalType,
    expectedValue: requiredString(record, 'expectedValue', label, 2000),
    observedValue: record.observedValue == null
      ? null
      : requiredString(record, 'observedValue', label, 2000),
    reason: requiredString(record, 'reason', label, 500),
    evidenceRefCount: parseEvidenceRefs(record.evidenceRefs ?? [], `${label}.evidenceRefs`),
  }
}

const parseRejected = (
  value: unknown,
  label: string,
  members: Set<string>,
): CohortRejectedCandidate => {
  const record = asRecord(value, label)
  const resourceId = requiredString(record, 'resourceId', label)
  if (members.has(resourceId)) {
    throw new Error(`Cohort API returned a member as rejected in ${label}.`)
  }
  const reasons = stringArray(record.reasons, `${label}.reasons`, 20, 64).map((reason) => {
    if (!REJECTION_REASONS.has(reason as CohortRejectionReason)) {
      throw new Error(`Cohort API returned an invalid ${label} reason.`)
    }
    return reason as CohortRejectionReason
  })
  if (reasons.length === 0) throw new Error(`Cohort API returned ${label} without a reason.`)
  return {
    resourceId,
    reasons,
    evidenceRefCount: parseEvidenceRefs(record.evidenceRefs ?? [], `${label}.evidenceRefs`),
  }
}

const parseProposal = (value: unknown, label: string): CohortProposal => {
  const record = asRecord(value, label)
  const proposalId = requiredString(record, 'proposalId', label, 25)
  if (!PROPOSAL_ID.test(proposalId)) throw new Error(`Cohort API returned an invalid ${label}.proposalId.`)
  const role = parseRole(record.role, `${label}.role`)
  if (role.status !== 'approved') {
    throw new Error(`Cohort API returned a non-approved role in ${label}.`)
  }
  const members = stringArray(record.members, `${label}.members`, 1000)
  uniqueNormalized(members, `${label} members`)
  sortedNormalized(members, `${label} members`)
  const memberSet = new Set(members)
  const confidence = record.confidence
  const confidenceBand = requiredString(record, 'confidenceBand', label, 16)
  if (
    typeof confidence !== 'number' ||
    confidence < 0 ||
    confidence > 1 ||
    !CONFIDENCE_BANDS.has(confidenceBand as ConfidenceBand)
  ) {
    throw new Error(`Cohort API returned invalid ${label} confidence.`)
  }
  const band = confidenceBand as ConfidenceBand
  const conflicts = asArray(record.conflicts ?? [], `${label}.conflicts`, 1000).map((conflict, index) =>
    parseConflict(conflict, `${label}.conflicts[${index}]`),
  )
  const dissent = asArray(record.dissent ?? [], `${label}.dissent`, 1000).map((item, index) =>
    parseDissent(item, `${label}.dissent[${index}]`, memberSet),
  )
  const selectorPreview = record.selectorPreview == null
    ? null
    : parseSelectorPreview(record.selectorPreview, `${label}.selectorPreview`)
  if (
    selectorPreview &&
    JSON.stringify(selectorPreview.matchedResourceIds) !== JSON.stringify(members)
  ) {
    throw new Error(`Cohort API returned a ${label} selector preview that does not match its members.`)
  }
  const bulkReviewEligible = requiredBoolean(record, 'bulkReviewEligible', label)
  const disposition = requiredString(record, 'disposition', label, 32)
  const high = band === 'high'
  if (
    bulkReviewEligible !== high ||
    disposition !== (high ? 'bulkHumanReview' : 'humanResolution') ||
    (high && (confidence < 0.8 || conflicts.length > 0 || dissent.length > 0 || !selectorPreview)) ||
    (band === 'medium' && (confidence < 0.6 || confidence >= 0.8)) ||
    ((band === 'low' || band === 'conflicting') && confidence >= 0.6) ||
    requiredBoolean(record, 'requiresHumanReview', label) !== true ||
    requiredBoolean(record, 'publicationAllowed', label) !== false ||
    requiredBoolean(record, 'manifestMutated', label) !== false
  ) {
    throw new Error(`Cohort API returned inconsistent review invariants for ${label}.`)
  }
  return {
    proposalId,
    scope: parseScope(record.scope, `${label}.scope`),
    role,
    members,
    confidence,
    confidenceBand: band,
    supportingEvidence: asArray(
      record.supportingEvidence ?? [],
      `${label}.supportingEvidence`,
      100,
    ).map((item, index) =>
      parseSupportingEvidence(item, `${label}.supportingEvidence[${index}]`, members),
    ),
    dissent,
    rejectedCandidates: asArray(
      record.rejectedCandidates ?? [],
      `${label}.rejectedCandidates`,
      1000,
    ).map((item, index) =>
      parseRejected(item, `${label}.rejectedCandidates[${index}]`, memberSet),
    ),
    conflicts,
    selectorPreview,
    snapshot: parseSnapshot(record.snapshot, `${label}.snapshot`),
    disposition: disposition as CohortProposal['disposition'],
    requiresHumanReview: true,
    bulkReviewEligible,
    publicationAllowed: false,
    manifestMutated: false,
  }
}

const sameScope = (left: CohortProposalScope, right: CohortProposalScope): boolean =>
  left.manifestId === right.manifestId &&
  left.manifestVersion === right.manifestVersion &&
  left.profileId === right.profileId &&
  left.profileType === right.profileType &&
  left.resolvedProfileDigest === right.resolvedProfileDigest

const sameSnapshot = (left: CohortProposalSnapshot, right: CohortProposalSnapshot): boolean =>
  left.snapshotId === right.snapshotId &&
  left.artifactDigest === right.artifactDigest &&
  left.semanticDigest === right.semanticDigest &&
  left.collectedAt === right.collectedAt &&
  left.expiresAt === right.expiresAt

export const parseCohortProposalBatch = (value: unknown): CohortProposalBatch => {
  const record = asRecord(value, 'proposal batch')
  const sourceDraft = parseDraftBinding(record.sourceDraft, 'proposal batch.sourceDraft')
  const scope = parseScope(record.scope, 'proposal batch.scope')
  const snapshot = parseSnapshot(record.snapshot, 'proposal batch.snapshot')
  const proposals = asArray(record.proposals, 'proposal batch.proposals', 200).map((proposal, index) =>
    parseProposal(proposal, `proposal batch.proposals[${index}]`),
  )
  uniqueNormalized(proposals.map((proposal) => proposal.proposalId), 'proposal IDs')
  const memberships = proposals.flatMap((proposal) => proposal.members)
  uniqueNormalized(memberships, 'proposal memberships')
  if (
    proposals.some((proposal) =>
      !sameScope(proposal.scope, scope) || !sameSnapshot(proposal.snapshot, snapshot),
    ) ||
    requiredBoolean(record, 'requiresHumanReview', 'proposal batch') !== true ||
    requiredBoolean(record, 'publicationAllowed', 'proposal batch') !== false ||
    requiredBoolean(record, 'manifestMutated', 'proposal batch') !== false
  ) {
    throw new Error('Cohort API returned a proposal batch with inconsistent scope or authority.')
  }
  return {
    sourceDraft,
    scope,
    snapshot,
    evaluatedAt: timestamp(record, 'evaluatedAt', 'proposal batch'),
    inputDigest: digest(record, 'inputDigest', 'proposal batch'),
    proposalSetDigest: digest(record, 'proposalSetDigest', 'proposal batch'),
    proposals,
    conflicts: asArray(record.conflicts ?? [], 'proposal batch.conflicts', 1000).map(
      (conflict, index) => parseConflict(conflict, `proposal batch.conflicts[${index}]`),
    ),
    requiresHumanReview: true,
    publicationAllowed: false,
    manifestMutated: false,
  }
}

const parseRoleUpdate = (value: unknown, label: string): CohortRoleUpdate => {
  const record = asRecord(value, label)
  const role = parseRole(record.role, `${label}.role`)
  const selectorPreviews = asArray(record.selectorPreviews, `${label}.selectorPreviews`, 20).map(
    (preview, index) => parseSelectorPreview(preview, `${label}.selectorPreviews[${index}]`),
  )
  const memberCount = requiredInteger(record, 'memberCount', label, 1, 1000)
  if (
    selectorPreviews.length === 0 ||
    role.selectors.length !== selectorPreviews.length ||
    role.selectors.some(
      (selector, index) =>
        JSON.stringify(selector) !== JSON.stringify(selectorPreviews[index]!.selector),
    ) ||
    memberCount > selectorPreviews.reduce((total, preview) => total + preview.maxMatches, 0)
  ) {
    throw new Error(`Cohort API returned an inconsistent ${label}.`)
  }
  return { role, selectorPreviews, memberCount }
}

export const parseCohortReviewCandidate = (
  value: unknown,
  request: CohortReviewPreviewRequest,
): CohortReviewCandidate => {
  const record = asRecord(value, 'cohort review candidate')
  const action = requiredString(record, 'action', 'cohort review candidate', 16)
  if (action !== request.action) throw new Error('Cohort API returned a different review action.')
  const scope = parseScope(record.scope, 'cohort review candidate.scope')
  const sourceDraft = parseDraftBinding(
    record.sourceDraft,
    'cohort review candidate.sourceDraft',
  )
  const sourceProposalIds = stringArray(
    record.sourceProposalIds,
    'cohort review candidate.sourceProposalIds',
    200,
    25,
  )
  const proposalSetDigest = digest(record, 'proposalSetDigest', 'cohort review candidate')
  const snapshot = parseSnapshot(record.snapshot, 'cohort review candidate.snapshot')
  const roleUpdates = asArray(record.roleUpdates, 'cohort review candidate.roleUpdates', 200).map(
    (update, index) => parseRoleUpdate(update, `cohort review candidate.roleUpdates[${index}]`),
  )
  uniqueNormalized(roleUpdates.map((update) => update.role.roleId), 'review candidate role updates')
  const replaceRoleRefs = stringArray(
    record.replaceRoleRefs,
    'cohort review candidate.replaceRoleRefs',
    200,
    128,
  )
  uniqueNormalized(replaceRoleRefs, 'review candidate replace role refs')
  const sourceRoleById = new Map(
    request.sourceRoles.map((role) => [role.roleId.normalize('NFC').toLowerCase(), role]),
  )
  const sourceRoleRefs = [...sourceRoleById.keys()].sort()
  const updateRoleRefs = roleUpdates
    .map((update) => update.role.roleId.normalize('NFC').toLowerCase())
    .sort()
  const normalizedReplacements = replaceRoleRefs
    .map((roleRef) => roleRef.normalize('NFC').toLowerCase())
    .sort()
  if (
    JSON.stringify(updateRoleRefs) !== JSON.stringify(sourceRoleRefs) ||
    JSON.stringify(normalizedReplacements) !== JSON.stringify(sourceRoleRefs) ||
    roleUpdates.some((update) => {
      const baseline = sourceRoleById.get(update.role.roleId.normalize('NFC').toLowerCase())
      return !baseline || JSON.stringify({
        kind: update.role.kind,
        cardinality: update.role.cardinality,
        ownerRef: update.role.ownerRef,
        status: update.role.status,
      }) !== JSON.stringify({
        kind: baseline.kind,
        cardinality: baseline.cardinality,
        ownerRef: baseline.ownerRef,
        status: baseline.status,
      })
    })
  ) {
    throw new Error('Cohort API attempted to change role authority outside bounded selectors.')
  }
  const generatedAt = timestamp(record, 'generatedAt', 'cohort review candidate')
  const expiresAt = timestamp(record, 'expiresAt', 'cohort review candidate')
  if (
    scope.manifestId !== request.workloadId ||
    scope.manifestVersion !== request.manifestVersion ||
    scope.profileId !== request.profileId ||
    sourceDraft.draftId !== request.sourceDraft.draftId ||
    sourceDraft.revision !== request.sourceDraft.revision ||
    sourceDraft.manifestDigest !== request.sourceDraft.manifestDigest ||
    JSON.stringify(sourceProposalIds) !== JSON.stringify(request.proposalIds) ||
    proposalSetDigest !== request.proposalSetDigest ||
    snapshot.artifactDigest !== request.snapshotArtifactDigest ||
    requiredString(record, 'resolution', 'cohort review candidate', 2000) !== request.resolution ||
    roleUpdates.length === 0 ||
    Date.parse(expiresAt) <= Date.parse(generatedAt) ||
    Date.parse(expiresAt) <= Date.now() ||
    requiredBoolean(record, 'requiresHumanReview', 'cohort review candidate') !== true ||
    requiredBoolean(record, 'publicationAllowed', 'cohort review candidate') !== false ||
    requiredBoolean(record, 'manifestMutated', 'cohort review candidate') !== false
  ) {
    throw new Error('Cohort API returned an inconsistent or authoritative review candidate.')
  }
  return {
    candidateId: (() => {
      const value = requiredString(record, 'candidateId', 'cohort review candidate', 128)
      if (!IDENTIFIER.test(value)) throw new Error('Cohort API returned an invalid review candidate ID.')
      return value
    })(),
    action,
    sourceDraft,
    scope,
    sourceProposalIds,
    proposalSetDigest,
    snapshot,
    roleUpdates,
    replaceRoleRefs,
    resolution: request.resolution,
    generatedAt,
    expiresAt,
    requiresHumanReview: true,
    publicationAllowed: false,
    manifestMutated: false,
  }
}

const safeError = async (response: Response): Promise<ContextApiRequestError> => {
  let message = `Cohort API request failed with status ${response.status}.`
  let code = response.status === 403 ? 'authorization_denied' : 'cohort_request_failed'
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
        // Keep the bounded generic message. Raw response and log bodies are never rendered.
      }
    }
  }
  return new ContextApiRequestError(message, response.status, code)
}

export const createCohortProposalApiClient = (
  options: CohortProposalApiOptions,
): CohortProposalApiPort => {
  if (!options.baseUrl?.trim() || !options.authPort || !options.session) {
    throw new Error('Cohort API client requires a base URL, AuthPort, and authenticated session.')
  }
  if (
    !IDENTIFIER.test(options.session.actorId) ||
    options.session.authorizedWorkloadIds.length === 0 ||
    options.session.authorizedWorkloadIds.some((id) => id === '*' || id.length > 128)
  ) {
    throw new Error('Cohort API client requires explicit authorized workload IDs.')
  }
  const baseUrl = options.baseUrl.replace(/\/+$/, '')
  const fetchImpl = options.fetchImpl ?? globalThis.fetch
  const createId = options.createId ?? (() => crypto.randomUUID())
  const authorized = new Set(options.session.authorizedWorkloadIds)

  const assertAuthorized = (workloadId: string): void => {
    if (!authorized.has(workloadId)) {
      throw new ContextApiRequestError(
        `Workload ${workloadId} is not authorized for this session.`,
        403,
        'authorization_denied',
      )
    }
  }

  const requestJson = async (
    path: string,
    init: RequestInit,
    idempotencyKey?: string,
  ): Promise<unknown> => {
    const token = (await options.authPort.acquireAccessToken(options.session))?.trim()
    if (!token) {
      throw new ContextApiRequestError(
        'Authentication is required before cohort proposals can be loaded.',
        401,
        'authentication_required',
      )
    }
    const headers = new Headers(init.headers)
    headers.set('Authorization', `Bearer ${token}`)
    if (init.body != null) headers.set('Content-Type', 'application/json')
    if (init.method && !['GET', 'HEAD'].includes(init.method.toUpperCase())) {
      const safeId = (idempotencyKey ?? `cohort-${createId()}`)
        .replace(/[^A-Za-z0-9._-]/g, '-')
        .slice(0, 128)
      if (!IDENTIFIER.test(safeId)) throw new Error('Cohort preview requires a valid idempotency key.')
      headers.set('Idempotency-Key', safeId)
    }
    const response = await fetchImpl(`${baseUrl}${path}`, { ...init, headers })
    if (!response.ok) throw await safeError(response)
    if (!response.headers.get('Content-Type')?.toLowerCase().includes('application/json')) {
      throw new Error('Cohort API returned an unsupported response content type.')
    }
    const declaredLength = Number(response.headers.get('Content-Length') ?? '0')
    if (declaredLength > MAX_RESPONSE_BODY) {
      throw new Error('Cohort API response exceeded the browser boundary limit.')
    }
    const body = await response.text()
    if (body.length > MAX_RESPONSE_BODY) {
      throw new Error('Cohort API response exceeded the browser boundary limit.')
    }
    try {
      return JSON.parse(body) as unknown
    } catch {
      throw new Error('Cohort API returned malformed bounded JSON.')
    }
  }

  return {
    auth: options.session,
    loadProposalBatch: async (request) => {
      assertAuthorized(request.workloadId)
      if (!VERSION.test(request.manifestVersion) || !IDENTIFIER.test(request.profileId)) {
        throw new Error('Cohort proposal request has an invalid version or profile.')
      }
      const query = new URLSearchParams({
        manifest_id: request.workloadId,
        manifest_version: request.manifestVersion,
        profile_id: request.profileId,
        draft_id: request.sourceDraft.draftId,
        expected_revision: String(request.sourceDraft.revision),
        expected_digest: request.sourceDraft.manifestDigest,
      })
      const batch = parseCohortProposalBatch(
        await requestJson(`/v1/cohort-proposals?${query.toString()}`, { method: 'GET' }),
      )
      if (Date.parse(batch.snapshot.expiresAt) <= Date.now()) {
        throw new Error('Cohort API returned an expired evidence snapshot.')
      }
      if (
        batch.scope.manifestId !== request.workloadId ||
        batch.scope.manifestVersion !== request.manifestVersion ||
        batch.scope.profileId !== request.profileId
        || batch.sourceDraft.draftId !== request.sourceDraft.draftId
        || batch.sourceDraft.revision !== request.sourceDraft.revision
        || batch.sourceDraft.manifestDigest !== request.sourceDraft.manifestDigest
      ) {
        throw new Error('Cohort API returned a batch outside the exact authorized request scope.')
      }
      return batch
    },
    previewReview: async (request) => {
      assertAuthorized(request.workloadId)
      if (request.action === 'split' && request.proposalIds.length !== 1) {
        throw new Error('A split preview requires exactly one proposal.')
      }
      if (request.action === 'merge' && request.proposalIds.length < 2) {
        throw new Error('A merge preview requires at least two proposals.')
      }
      uniqueNormalized(request.proposalIds, 'review request proposal IDs')
      const sourceRoles = request.sourceRoles.map((role, index) =>
        parseRole(role, `review request.sourceRoles[${index}]`),
      )
      uniqueNormalized(sourceRoles.map((role) => role.roleId), 'review request source role refs')
      if (sourceRoles.length === 0) {
        throw new Error('A cohort review preview requires source role references.')
      }
      const validatedRequest = { ...request, sourceRoles }
      const payload = {
        action: request.action,
        manifest_id: request.workloadId,
        manifest_version: request.manifestVersion,
        profile_id: request.profileId,
        draft_id: request.sourceDraft.draftId,
        expected_revision: request.sourceDraft.revision,
        expected_digest: request.sourceDraft.manifestDigest,
        proposal_ids: request.proposalIds,
        source_role_refs: sourceRoles.map((role) => role.roleId),
        proposal_set_digest: request.proposalSetDigest,
        snapshot_artifact_digest: request.snapshotArtifactDigest,
        resolution: request.resolution,
      }
      const response = await requestJson(
        '/v1/cohort-proposals/preview',
        { method: 'POST', body: JSON.stringify(payload) },
        `cohort-preview-${(await idempotencyDigest(JSON.stringify(payload))).slice(0, 32)}`,
      )
      return parseCohortReviewCandidate(response, validatedRequest)
    },
  }
}
