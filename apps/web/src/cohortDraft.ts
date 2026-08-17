import { caseFold as unicodeCaseFold } from 'unicode-case-folding'
import type {
  CohortProposal,
  CohortProposalBatch,
  CohortReviewCandidate,
} from './cohortTypes'
import type { CanonicalWorkloadManifest, WorkloadContext } from './types'

const normalized = (value: string): string => unicodeCaseFold(value.normalize('NFC'))

const uniqueNormalizedMembers = (values: string[], label: string): Set<string> => {
  const result = new Set<string>()
  for (const value of values) {
    const key = normalized(value)
    if (result.has(key)) {
      throw new Error(`${label} contains duplicate normalized resource members.`)
    }
    result.add(key)
  }
  return result
}

const sameMembers = (left: Set<string>, right: Set<string>): boolean =>
  left.size === right.size && [...left].every((member) => right.has(member))

export const proposalReviewCandidate = (
  proposal: CohortProposal,
  batch: CohortProposalBatch,
  resolution: string,
): CohortReviewCandidate => {
  if (!proposal.selectorPreview) {
    throw new Error('A bounded selector preview is required before a cohort can be drafted.')
  }
  if (
    proposal.scope.manifestId !== batch.scope.manifestId ||
    proposal.scope.manifestVersion !== batch.scope.manifestVersion ||
    proposal.scope.profileId !== batch.scope.profileId ||
    proposal.snapshot.artifactDigest !== batch.snapshot.artifactDigest
  ) {
    throw new Error('The cohort proposal is outside the exact loaded batch scope.')
  }
  const selector = structuredClone(proposal.selectorPreview.selector)
  return {
    candidateId: `review-${proposal.proposalId}`,
    action: 'approve',
    sourceDraft: structuredClone(batch.sourceDraft),
    scope: structuredClone(proposal.scope),
    sourceProposalIds: [proposal.proposalId],
    proposalSetDigest: batch.proposalSetDigest,
    snapshot: structuredClone(proposal.snapshot),
    roleUpdates: [{
      role: {
        ...structuredClone(proposal.role),
        selectors: [selector],
      },
      selectorPreviews: [structuredClone(proposal.selectorPreview)],
      memberCount: proposal.members.length,
    }],
    replaceRoleRefs: [proposal.role.roleId],
    resolution,
    generatedAt: batch.evaluatedAt,
    expiresAt: proposal.snapshot.expiresAt,
    requiresHumanReview: true,
    publicationAllowed: false,
    manifestMutated: false,
  }
}

export const applyCohortCandidateToDraft = (
  context: WorkloadContext,
  candidate: CohortReviewCandidate,
  batch: CohortProposalBatch,
  now: Date,
): CanonicalWorkloadManifest => {
  const draft = context.draft
  if (!draft || draft.state !== 'draft') {
    throw new Error('Cohort selector proposals can only update an active WC-007 draft.')
  }
  if (context.auth.kind !== 'human' || context.auth.role !== 'proposer') {
    throw new Error('A human WC-007 proposer is required to update cohort selectors.')
  }
  if (
    candidate.publicationAllowed ||
    candidate.manifestMutated ||
    !candidate.requiresHumanReview
  ) {
    throw new Error('The review candidate carries invalid authority flags.')
  }
  const sourceProposals = candidate.sourceProposalIds.map((proposalId) => {
    const proposal = batch.proposals.find((item) => item.proposalId === proposalId)
    if (!proposal) throw new Error('The review candidate references a proposal outside the exact batch.')
    return proposal
  })
  const sourceRoleRefs = [...new Set(sourceProposals.map((proposal) => normalized(proposal.role.roleId)))]
  const sourceMembers = uniqueNormalizedMembers(
    sourceProposals.flatMap((proposal) => proposal.members),
    'The source proposal union',
  )
  const replaceRoleRefs = [...new Set(candidate.replaceRoleRefs.map(normalized))]
  const updateRoleRefs = [...new Set(candidate.roleUpdates.map((update) => normalized(update.role.roleId)))]
  if (
    candidate.sourceProposalIds.length === 0 ||
    new Set(candidate.sourceProposalIds.map(normalized)).size !== candidate.sourceProposalIds.length ||
    candidate.proposalSetDigest !== batch.proposalSetDigest ||
    candidate.scope.manifestId !== batch.scope.manifestId ||
    candidate.scope.manifestVersion !== batch.scope.manifestVersion ||
    candidate.scope.profileId !== batch.scope.profileId ||
    candidate.scope.profileType !== batch.scope.profileType ||
    candidate.scope.resolvedProfileDigest !== batch.scope.resolvedProfileDigest ||
    candidate.snapshot.snapshotId !== batch.snapshot.snapshotId ||
    candidate.snapshot.artifactDigest !== batch.snapshot.artifactDigest ||
    candidate.snapshot.semanticDigest !== batch.snapshot.semanticDigest ||
    candidate.snapshot.collectedAt !== batch.snapshot.collectedAt ||
    candidate.snapshot.expiresAt !== batch.snapshot.expiresAt ||
    candidate.sourceDraft.draftId !== batch.sourceDraft.draftId ||
    candidate.sourceDraft.revision !== batch.sourceDraft.revision ||
    candidate.sourceDraft.manifestDigest !== batch.sourceDraft.manifestDigest ||
    JSON.stringify([...replaceRoleRefs].sort()) !== JSON.stringify([...sourceRoleRefs].sort()) ||
    JSON.stringify([...updateRoleRefs].sort()) !== JSON.stringify([...sourceRoleRefs].sort())
  ) {
    throw new Error('The review candidate is not bounded to the exact proposal batch and source roles.')
  }
  const resolutionRequired =
    candidate.action !== 'approve' ||
    sourceProposals.some(
      (proposal) =>
        proposal.confidenceBand !== 'high' ||
        proposal.dissent.length > 0 ||
        proposal.conflicts.length > 0 ||
        proposal.rejectedCandidates.some((item) => item.reasons.includes('crossEnvironment')),
    ) ||
    batch.conflicts.some(
      (conflict) =>
        conflict.roleRefs.length === 0 ||
        conflict.roleRefs.some((roleRef) => sourceRoleRefs.includes(normalized(roleRef))),
    )
  if (
    (candidate.action === 'approve' && sourceProposals.length !== 1) ||
    (candidate.action === 'split' && sourceProposals.length !== 1) ||
    (candidate.action === 'merge' && (sourceProposals.length < 2 || sourceRoleRefs.length !== 1)) ||
    (resolutionRequired && candidate.resolution.trim().length < 12)
  ) {
    throw new Error('The cohort action requires an exact source set and explicit human resolution.')
  }
  for (const update of candidate.roleUpdates) {
    const baseline = sourceProposals.find(
      (proposal) => normalized(proposal.role.roleId) === normalized(update.role.roleId),
    )?.role
    if (
      !baseline ||
      JSON.stringify({
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
    ) {
      throw new Error('A cohort review may change bounded selectors only, not role authority metadata.')
    }
  }
  if (
    candidate.scope.manifestId !== context.workloadId ||
    candidate.scope.manifestId !== draft.manifest.manifestId ||
    candidate.scope.manifestVersion !== draft.manifest.manifestVersion ||
    candidate.scope.profileType !== context.environment ||
    candidate.sourceDraft.draftId !== draft.draftId ||
    candidate.sourceDraft.revision !== draft.revision ||
    candidate.sourceDraft.manifestDigest !== draft.manifestDigest ||
    Date.parse(candidate.expiresAt) <= now.valueOf() ||
    candidate.snapshot.expiresAt !== candidate.expiresAt
  ) {
    throw new Error('The review candidate is stale or outside the exact workload, version, or environment.')
  }
  const profile = draft.manifest.profiles[candidate.scope.profileId]
  if (!profile || profile.profileType !== candidate.scope.profileType) {
    throw new Error('The review candidate profile is not present in the exact draft.')
  }
  if (candidate.roleUpdates.length === 0 || candidate.roleUpdates.length > 200) {
    throw new Error('The review candidate has an invalid number of role updates.')
  }
  const updateRoleIds = candidate.roleUpdates.map((update) => normalized(update.role.roleId))
  if (new Set(updateRoleIds).size !== updateRoleIds.length) {
    throw new Error('The review candidate has duplicate role updates.')
  }
  const selectedMembers = new Set<string>()
  for (const update of candidate.roleUpdates) {
    const updateMembers = new Set<string>()
    for (const preview of update.selectorPreviews) {
      if (
        preview.matchedResourceIds.length === 0 ||
        preview.matchedResourceIds.length > preview.maxMatches ||
        preview.maxMatches > 1000 ||
        preview.selector.maxMatches !== preview.maxMatches
      ) {
        throw new Error('The review candidate contains an unbounded selector membership.')
      }
      for (const resourceId of preview.matchedResourceIds) {
        const member = normalized(resourceId)
        if (updateMembers.has(member) || selectedMembers.has(member)) {
          throw new Error('The review candidate selector memberships are not a disjoint union.')
        }
        updateMembers.add(member)
        selectedMembers.add(member)
      }
    }
    if (
      update.memberCount < 1 ||
      update.memberCount > 1000 ||
      update.memberCount !== updateMembers.size ||
      update.selectorPreviews.length !== update.role.selectors.length ||
      update.selectorPreviews.some(
        (preview, index) =>
          JSON.stringify(preview.selector) !== JSON.stringify(update.role.selectors[index]),
      )
    ) {
      throw new Error('The review candidate contains an unbounded or mismatched selector.')
    }
  }
  if (!sameMembers(sourceMembers, selectedMembers)) {
    throw new Error(
      'The review candidate selector membership must exactly match the source proposal union.',
    )
  }

  const replaced = new Set([
    ...candidate.replaceRoleRefs.map(normalized),
    ...updateRoleIds,
  ])
  const replacement = structuredClone(draft.manifest)
  replacement.profiles[candidate.scope.profileId] = {
    ...replacement.profiles[candidate.scope.profileId]!,
    roles: [
      ...replacement.profiles[candidate.scope.profileId]!.roles.filter(
        (role) => !replaced.has(normalized(role.roleId)),
      ),
      ...candidate.roleUpdates.map((update) => structuredClone(update.role)),
    ],
  }
  return replacement
}

export const cohortDraftIdempotencyKey = (
  candidate: CohortReviewCandidate,
  revision: number,
): string =>
  `cohort-r${revision}-${candidate.candidateId}`
    .replace(/[^A-Za-z0-9._-]/g, '-')
    .slice(0, 128)
