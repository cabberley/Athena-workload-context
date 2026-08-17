import type {
  CohortProposal,
  CohortProposalApiPort,
  CohortProposalBatch,
  CohortReviewCandidate,
  CohortReviewPreviewRequest,
  CohortSelectorPreview,
} from '../cohortTypes'
import type { AuthSession, CanonicalManifestRole } from '../types'
import { canonicalManifestFixture, mockAuthSession } from './mockClient'

const digest = (character: string): string => `sha256:${character.repeat(64)}`
const timestamp = '2026-08-17T00:00:00.000Z'
const expiry = '2027-08-17T00:00:00.000Z'
const subscription = '11111111-1111-1111-1111-111111111111'
const vmssId =
  `/subscriptions/${subscription}/resourcegroups/rg-wc012-synthetic/` +
  'providers/microsoft.compute/virtualmachinescalesets/wc012-workers'

const resourceId = (name: string): string =>
  `/subscriptions/${subscription}/resourcegroups/rg-wc012-synthetic/` +
  `providers/microsoft.compute/virtualmachines/${name}`

const scope = {
  manifestId: canonicalManifestFixture.manifestId,
  manifestVersion: canonicalManifestFixture.manifestVersion,
  profileId: 'production',
  profileType: 'production' as const,
  resolvedProfileDigest: digest('a'),
}

const snapshot = {
  snapshotId: 'snapshot-wc012-synthetic',
  artifactDigest: digest('b'),
  semanticDigest: digest('c'),
  collectedAt: timestamp,
  expiresAt: expiry,
}

const sourceDraft = {
  draftId: 'draft-synthetic-canonical',
  revision: 1,
  manifestDigest: canonicalManifestFixture.compatibility.artifactDigest,
}

const proposal = (
  proposalId: string,
  role: CanonicalManifestRole,
  members: string[],
  selectorPreview: CohortSelectorPreview,
  options: {
    confidence: number
    band: CohortProposal['confidenceBand']
    conflict?: boolean
    rejected?: boolean
  },
): CohortProposal => ({
  proposalId,
  scope,
  role,
  members,
  confidence: options.confidence,
  confidenceBand: options.band,
  supportingEvidence: [{
    signalType: selectorPreview.selector.selectorType === 'vmScaleSet' ? 'vmScaleSet' : 'namePredicate',
    signalValue: `${selectorPreview.selector.selectorId} from synthetic verified inventory`,
    memberCount: members.length,
    evidenceRefCount: members.length,
  }],
  dissent: options.conflict
    ? [{
        resourceId: members[0]!,
        signalType: 'approvedTags',
        expectedValue: 'production',
        observedValue: 'training',
        reason: 'Synthetic environment tag dissent for explicit resolution testing.',
        evidenceRefCount: 1,
      }]
    : [],
  rejectedCandidates: options.rejected
    ? [{
        resourceId: resourceId('wc012-cross-environment-rejected'),
        reasons: ['crossEnvironment'],
        evidenceRefCount: 1,
      }]
    : [],
  conflicts: options.conflict
    ? [{
        code: 'crossEnvironment',
        detail: 'A synthetic candidate carries a different environment tag.',
        resourceIds: [resourceId('wc012-cross-environment-rejected')],
        roleRefs: [role.roleId],
      }]
    : [],
  selectorPreview,
  snapshot,
  disposition: options.band === 'high' ? 'bulkHumanReview' : 'humanResolution',
  requiresHumanReview: true,
  bulkReviewEligible: options.band === 'high',
  publicationAllowed: false,
  manifestMutated: false,
})

const makeBatch = (): CohortProposalBatch => {
  const workerMembers = Array.from({ length: 1000 }, (_, index) =>
    `${vmssId}/virtualmachines/${String(index + 1).padStart(4, '0')}`,
  )
  const workerSelector: CohortSelectorPreview = {
    selector: {
      selectorType: 'vmScaleSet',
      selectorId: 'wc012-worker-vmss',
      scaleSetResourceId: vmssId,
      instanceIds: [],
      maxMatches: 1000,
    },
    matchedResourceIds: workerMembers,
    selectorResultDigest: digest('d'),
    maxMatches: 1000,
  }
  const workerRole = structuredClone(
    canonicalManifestFixture.roles.find((role) => role.roleId === 'worker')!,
  )
  workerRole.selectors = [structuredClone(workerSelector.selector)]

  const makeWeb = (
    suffix: 'a' | 'b',
    count: number,
    proposalId: string,
    conflict: boolean,
  ): CohortProposal => {
    const members = Array.from({ length: count }, (_, index) =>
      resourceId(`wc012-web-${suffix}-${String(index + 1).padStart(3, '0')}`),
    )
    const preview: CohortSelectorPreview = {
      selector: {
        selectorType: 'namePredicate',
        selectorId: `wc012-web-${suffix}`,
        prefix: `wc012-web-${suffix}-`,
        maxMatches: count,
      },
      matchedResourceIds: members,
      selectorResultDigest: digest(suffix === 'a' ? 'e' : 'f'),
      maxMatches: count,
    }
    const role = structuredClone(
      canonicalManifestFixture.roles.find((item) => item.roleId === 'web')!,
    )
    role.selectors = [structuredClone(preview.selector)]
    return proposal(proposalId, role, members, preview, {
      confidence: conflict ? 0.64 : 0.74,
      band: 'medium',
      conflict,
      rejected: conflict,
    })
  }

  return {
    sourceDraft,
    scope,
    snapshot,
    evaluatedAt: timestamp,
    inputDigest: digest('1'),
    proposalSetDigest: digest('2'),
    proposals: [
      proposal('proposal-1111111111111111', workerRole, workerMembers, workerSelector, {
        confidence: 0.94,
        band: 'high',
      }),
      makeWeb('a', 12, 'proposal-2222222222222222', true),
      makeWeb('b', 10, 'proposal-3333333333333333', false),
    ],
    conflicts: [],
    requiresHumanReview: true,
    publicationAllowed: false,
    manifestMutated: false,
  }
}

const splitPreview = (
  source: CohortProposal,
  request: CohortReviewPreviewRequest,
  batch: CohortProposalBatch,
): CohortReviewCandidate => {
  const midpoint = Math.ceil(source.members.length / 2)
  const partitions = [source.members.slice(0, midpoint), source.members.slice(midpoint)]
  const selectorPreviews = partitions.map((members, index): CohortSelectorPreview => ({
    selector: {
      selectorType: 'resourceIdList',
      selectorId: `${source.role.roleId}-split-${index + 1}`,
      resourceIds: members,
      maxMatches: Math.max(1, members.length),
    },
    matchedResourceIds: members,
    selectorResultDigest: digest(index === 0 ? '3' : '4'),
    maxMatches: Math.max(1, members.length),
  }))
  if (selectorPreviews.some((preview) => preview.matchedResourceIds.length > 200)) {
    throw new Error('Synthetic split fixture only supports cohorts of up to 400 members.')
  }
  return {
    candidateId: `candidate-split-${source.proposalId}`,
    action: 'split',
    sourceDraft: batch.sourceDraft,
    scope: batch.scope,
    sourceProposalIds: request.proposalIds,
    proposalSetDigest: batch.proposalSetDigest,
    snapshot: batch.snapshot,
    roleUpdates: [{
      role: { ...structuredClone(source.role), selectors: selectorPreviews.map((item) => item.selector) },
      selectorPreviews,
      memberCount: source.members.length,
    }],
    replaceRoleRefs: [source.role.roleId],
    resolution: request.resolution,
    generatedAt: timestamp,
    expiresAt: expiry,
    requiresHumanReview: true,
    publicationAllowed: false,
    manifestMutated: false,
  }
}

const mergePreview = (
  sources: CohortProposal[],
  request: CohortReviewPreviewRequest,
  batch: CohortProposalBatch,
): CohortReviewCandidate => {
  if (new Set(sources.map((source) => source.role.roleId)).size !== 1) {
    throw new Error('Synthetic merge requires proposals for the same role.')
  }
  const selectorPreviews = sources.map((source) => structuredClone(source.selectorPreview!))
  return {
    candidateId: `candidate-merge-${sources[0]!.role.roleId}`,
    action: 'merge',
    sourceDraft: batch.sourceDraft,
    scope: batch.scope,
    sourceProposalIds: request.proposalIds,
    proposalSetDigest: batch.proposalSetDigest,
    snapshot: batch.snapshot,
    roleUpdates: [{
      role: { ...structuredClone(sources[0]!.role), selectors: selectorPreviews.map((item) => item.selector) },
      selectorPreviews,
      memberCount: sources.reduce((total, source) => total + source.members.length, 0),
    }],
    replaceRoleRefs: [sources[0]!.role.roleId],
    resolution: request.resolution,
    generatedAt: timestamp,
    expiresAt: expiry,
    requiresHumanReview: true,
    publicationAllowed: false,
    manifestMutated: false,
  }
}

export interface MockCohortClientOptions {
  session?: AuthSession
  batch?: CohortProposalBatch
}

/** Explicit synthetic test adapter. Production composition never imports this module. */
export const createMockCohortProposalApiClient = (
  options: MockCohortClientOptions = {},
): CohortProposalApiPort => {
  const session = options.session ?? mockAuthSession
  const batch = options.batch ?? makeBatch()
  return {
    auth: session,
    loadProposalBatch: async (request) => {
      if (
        !session.authorizedWorkloadIds.includes(request.workloadId) ||
        request.workloadId !== batch.scope.manifestId ||
        request.manifestVersion !== batch.scope.manifestVersion ||
        request.profileId !== batch.scope.profileId
      ) {
        throw new Error('Synthetic cohort scope denied.')
      }
      return structuredClone({ ...batch, sourceDraft: request.sourceDraft })
    },
    previewReview: async (request) => {
      const sources = request.proposalIds.map((proposalId) => {
        const source = batch.proposals.find((item) => item.proposalId === proposalId)
        if (!source) throw new Error('Synthetic proposal not found.')
        return source
      })
      const preview = request.action === 'split'
        ? splitPreview(sources[0]!, request, batch)
        : mergePreview(sources, request, batch)
      return { ...preview, sourceDraft: request.sourceDraft }
    },
  }
}

export const syntheticCohortBatch = makeBatch()
