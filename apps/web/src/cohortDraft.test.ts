import {
  applyCohortCandidateToDraft,
  cohortDraftIdempotencyKey,
  proposalReviewCandidate,
} from './cohortDraft'
import { createMockCohortProposalApiClient, syntheticCohortBatch } from './test/mockCohortClient'
import { createMockContextApiClient, mockAuthSession } from './test/mockClient'

const proposerSession = { ...mockAuthSession, role: 'proposer' as const }

describe('cohort draft binding', () => {
  it('writes only a profile-scoped bounded selector proposal', async () => {
    const contextClient = createMockContextApiClient({ session: proposerSession })
    const context = (await contextClient.loadAuthorizedWorkloads())[0]!
    const proposal = syntheticCohortBatch.proposals[0]!
    const candidate = proposalReviewCandidate(proposal, syntheticCohortBatch, '')

    const replacement = applyCohortCandidateToDraft(
      context,
      candidate,
      syntheticCohortBatch,
      new Date('2026-08-17T01:00:00.000Z'),
    )

    expect(replacement.roles).toEqual(context.draft!.manifest.roles)
    expect(replacement.profiles.development!.roles).toEqual(
      context.draft!.manifest.profiles.development!.roles,
    )
    expect(replacement.profiles.training!.roles).toEqual(
      context.draft!.manifest.profiles.training!.roles,
    )
    expect(replacement.profiles.production!.roles).toEqual([
      expect.objectContaining({
        roleId: 'worker',
        selectors: [
          expect.objectContaining({
            selectorType: 'vmScaleSet',
            maxMatches: 1000,
          }),
        ],
      }),
    ])
    expect(candidate.publicationAllowed).toBe(false)
    expect(candidate.manifestMutated).toBe(false)
    expect(cohortDraftIdempotencyKey(candidate, context.draft!.revision)).toMatch(
      /^cohort-r1-review-proposal-/,
    )
  })

  it('fails closed for stale draft binding, expiry, and environment mismatch', async () => {
    const contextClient = createMockContextApiClient({ session: proposerSession })
    const context = (await contextClient.loadAuthorizedWorkloads())[0]!
    const candidate = proposalReviewCandidate(
      syntheticCohortBatch.proposals[0]!,
      syntheticCohortBatch,
      '',
    )

    expect(() =>
      applyCohortCandidateToDraft(
        context,
        { ...candidate, sourceDraft: { ...candidate.sourceDraft, revision: 2 } },
        syntheticCohortBatch,
        new Date('2026-08-17T01:00:00.000Z'),
      ),
    ).toThrow(/stale|exact/i)
    expect(() =>
      applyCohortCandidateToDraft(
        context,
        candidate,
        syntheticCohortBatch,
        new Date('2028-08-17T01:00:00.000Z'),
      ),
    ).toThrow(/stale|exact/i)
    expect(() =>
      applyCohortCandidateToDraft(
        { ...context, environment: 'training' },
        candidate,
        syntheticCohortBatch,
        new Date('2026-08-17T01:00:00.000Z'),
      ),
    ).toThrow(/stale|exact/i)
    expect(() =>
      applyCohortCandidateToDraft(
        context,
        {
          ...candidate,
          roleUpdates: [{
            ...candidate.roleUpdates[0]!,
            role: {
              ...candidate.roleUpdates[0]!.role,
              ownerRef: 'fabricated-owner',
            },
          }],
        },
        syntheticCohortBatch,
        new Date('2026-08-17T01:00:00.000Z'),
      ),
    ).toThrow(/authority metadata/i)
    expect(() =>
      applyCohortCandidateToDraft(
        context,
        { ...candidate, replaceRoleRefs: ['database-primary'] },
        syntheticCohortBatch,
        new Date('2026-08-17T01:00:00.000Z'),
      ),
    ).toThrow(/source roles/i)
    const unresolved = proposalReviewCandidate(
      syntheticCohortBatch.proposals[1]!,
      syntheticCohortBatch,
      '',
    )
    expect(() =>
      applyCohortCandidateToDraft(
        context,
        unresolved,
        syntheticCohortBatch,
        new Date('2026-08-17T01:00:00.000Z'),
      ),
    ).toThrow(/explicit human resolution/i)
  })

  it('accepts only API-produced split and merge previews bound to the same draft', async () => {
    const context = (
      await createMockContextApiClient({ session: proposerSession }).loadAuthorizedWorkloads()
    )[0]!
    const cohortClient = createMockCohortProposalApiClient({ session: proposerSession })
    const batch = await cohortClient.loadProposalBatch({
      workloadId: context.workloadId,
      manifestVersion: context.draft!.manifest.manifestVersion,
      profileId: 'production',
      sourceDraft: {
        draftId: context.draft!.draftId,
        revision: context.draft!.revision,
        manifestDigest: context.draft!.manifestDigest,
      },
    })
    const source = batch.proposals[1]!
    const split = await cohortClient.previewReview({
      action: 'split',
      workloadId: context.workloadId,
      manifestVersion: context.draft!.manifest.manifestVersion,
      profileId: 'production',
      sourceDraft: batch.sourceDraft,
      proposalIds: [source.proposalId],
      sourceRoles: [source.role],
      sourceMembers: source.members,
      proposalSetDigest: batch.proposalSetDigest,
      snapshotArtifactDigest: batch.snapshot.artifactDigest,
      resolution: 'Synthetic explicit split rationale.',
    })

    const replacement = applyCohortCandidateToDraft(
      context,
      split,
      batch,
      new Date('2026-08-17T01:00:00.000Z'),
    )
    expect(replacement.profiles.production!.roles[0]!.selectors).toHaveLength(2)
    expect(replacement.profiles.production!.roles[0]!.selectors.every(
      (selector) => selector.maxMatches <= 1000,
    )).toBe(true)
  })

  it('rejects split preview member extras, omissions, normalized duplicates, count drift, and max overflow', async () => {
    const context = (
      await createMockContextApiClient({ session: proposerSession }).loadAuthorizedWorkloads()
    )[0]!
    const cohortClient = createMockCohortProposalApiClient({ session: proposerSession })
    const batch = await cohortClient.loadProposalBatch({
      workloadId: context.workloadId,
      manifestVersion: context.draft!.manifest.manifestVersion,
      profileId: 'production',
      sourceDraft: {
        draftId: context.draft!.draftId,
        revision: context.draft!.revision,
        manifestDigest: context.draft!.manifestDigest,
      },
    })
    const source = batch.proposals[1]!
    const split = await cohortClient.previewReview({
      action: 'split',
      workloadId: context.workloadId,
      manifestVersion: context.draft!.manifest.manifestVersion,
      profileId: 'production',
      sourceDraft: batch.sourceDraft,
      proposalIds: [source.proposalId],
      sourceRoles: [source.role],
      sourceMembers: source.members,
      proposalSetDigest: batch.proposalSetDigest,
      snapshotArtifactDigest: batch.snapshot.artifactDigest,
      resolution: 'Synthetic explicit split rationale.',
    })
    const apply = (candidate: typeof split): void => {
      applyCohortCandidateToDraft(
        context,
        candidate,
        batch,
        new Date('2026-08-17T01:00:00.000Z'),
      )
    }

    const unrelated = structuredClone(split)
    unrelated.roleUpdates[0]!.selectorPreviews[0]!.matchedResourceIds[0] =
      '/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/' +
      'rg-wc012-synthetic/providers/microsoft.compute/virtualmachines/unrelated-injection'
    expect(() => apply(unrelated)).toThrow(/exactly match the source proposal union/i)

    const omitted = structuredClone(split)
    omitted.roleUpdates[0]!.selectorPreviews[0]!.matchedResourceIds.pop()
    omitted.roleUpdates[0]!.memberCount -= 1
    expect(() => apply(omitted)).toThrow(/exactly match the source proposal union/i)

    const duplicate = structuredClone(split)
    duplicate.roleUpdates[0]!.selectorPreviews[1]!.matchedResourceIds[0] =
      duplicate.roleUpdates[0]!.selectorPreviews[0]!.matchedResourceIds[0]!.toUpperCase()
    expect(() => apply(duplicate)).toThrow(/not a disjoint union/i)

    const wrongCount = structuredClone(split)
    wrongCount.roleUpdates[0]!.memberCount -= 1
    expect(() => apply(wrongCount)).toThrow(/unbounded or mismatched selector/i)

    const overMaximum = structuredClone(split)
    const preview = overMaximum.roleUpdates[0]!.selectorPreviews[0]!
    preview.maxMatches = preview.matchedResourceIds.length - 1
    preview.selector.maxMatches = preview.maxMatches
    overMaximum.roleUpdates[0]!.role.selectors[0] = structuredClone(preview.selector)
    expect(() => apply(overMaximum)).toThrow(/unbounded selector membership/i)
  })

  it('rejects merge previews that inject, omit, or duplicate normalized source members', async () => {
    const context = (
      await createMockContextApiClient({ session: proposerSession }).loadAuthorizedWorkloads()
    )[0]!
    const cohortClient = createMockCohortProposalApiClient({ session: proposerSession })
    const batch = await cohortClient.loadProposalBatch({
      workloadId: context.workloadId,
      manifestVersion: context.draft!.manifest.manifestVersion,
      profileId: 'production',
      sourceDraft: {
        draftId: context.draft!.draftId,
        revision: context.draft!.revision,
        manifestDigest: context.draft!.manifestDigest,
      },
    })
    const sources = batch.proposals.slice(1, 3)
    const merge = await cohortClient.previewReview({
      action: 'merge',
      workloadId: context.workloadId,
      manifestVersion: context.draft!.manifest.manifestVersion,
      profileId: 'production',
      sourceDraft: batch.sourceDraft,
      proposalIds: sources.map((source) => source.proposalId),
      sourceRoles: [sources[0]!.role],
      sourceMembers: sources.flatMap((source) => source.members),
      proposalSetDigest: batch.proposalSetDigest,
      snapshotArtifactDigest: batch.snapshot.artifactDigest,
      resolution: 'Synthetic explicit merge rationale.',
    })
    const apply = (candidate: typeof merge): void => {
      applyCohortCandidateToDraft(
        context,
        candidate,
        batch,
        new Date('2026-08-17T01:00:00.000Z'),
      )
    }
    expect(() => apply(merge)).not.toThrow()

    const unrelated = structuredClone(merge)
    unrelated.roleUpdates[0]!.selectorPreviews[1]!.matchedResourceIds[0] =
      '/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/' +
      'rg-wc012-synthetic/providers/microsoft.compute/virtualmachines/unrelated-merge-injection'
    expect(() => apply(unrelated)).toThrow(/exactly match the source proposal union/i)

    const omitted = structuredClone(merge)
    omitted.roleUpdates[0]!.selectorPreviews[1]!.matchedResourceIds.pop()
    omitted.roleUpdates[0]!.memberCount -= 1
    expect(() => apply(omitted)).toThrow(/exactly match the source proposal union/i)

    const duplicate = structuredClone(merge)
    duplicate.roleUpdates[0]!.selectorPreviews[1]!.matchedResourceIds[0] =
      duplicate.roleUpdates[0]!.selectorPreviews[0]!.matchedResourceIds[0]!.toUpperCase()
    expect(() => apply(duplicate)).toThrow(/not a disjoint union/i)
  })
})
