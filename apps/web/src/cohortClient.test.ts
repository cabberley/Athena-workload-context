import {
  createCohortProposalApiClient,
  parseCohortProposalBatch,
} from './cohortClient'
import { ContextApiRequestError } from './client'
import { canonicalManifestFixture, mockAuthSession } from './test/mockClient'
import type {
  AuthPort,
  CanonicalManifestRole,
  CanonicalManifestSelector,
} from './types'

const digest = (character: string): string => `sha256:${character.repeat(64)}`
const member = (suffix: string): string =>
  `/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/rg-wc012-synthetic/` +
  `providers/microsoft.compute/virtualmachines/wc012-worker-${suffix}`
const members = [member('001'), member('002')]
const sourceDraft = {
  draftId: 'draft-synthetic-canonical',
  revision: 1,
  manifestDigest: canonicalManifestFixture.compatibility.artifactDigest,
}
const scope = {
  manifestId: canonicalManifestFixture.manifestId,
  manifestVersion: canonicalManifestFixture.manifestVersion,
  profileId: 'production',
  profileType: 'production',
  resolvedProfileDigest: digest('a'),
}
const snapshot = {
  snapshotId: 'snapshot-wc012-http',
  artifactDigest: digest('b'),
  semanticDigest: digest('c'),
  collectedAt: '2026-08-17T00:00:00.000Z',
  expiresAt: '2027-08-17T00:00:00.000Z',
}
const selector: CanonicalManifestSelector = {
  selectorType: 'namePredicate',
  selectorId: 'wc012-worker-name',
  prefix: 'wc012-worker-',
  maxMatches: 2,
}
const sourceRole: CanonicalManifestRole = {
  roleId: 'worker',
  kind: 'worker',
  cardinality: { cardinalityKind: 'oneOrMore' },
  selectors: [selector],
  ownerRef: 'ops-owner',
  status: 'approved',
}
const proposal = {
  proposalId: 'proposal-1111111111111111',
  scope,
  role: sourceRole,
  members,
  confidence: 0.94,
  confidenceBand: 'high',
  supportingEvidence: [{
    signalType: 'namePredicate',
    signalValue: 'wc012-worker-',
    memberResourceIds: members,
    evidenceRefs: [{ referenceType: 'item' }, { referenceType: 'item' }],
  }],
  dissent: [],
  rejectedCandidates: [{
    resourceId: member('rejected'),
    reasons: ['differentCohortSignal'],
    evidenceRefs: [{ referenceType: 'item' }],
  }],
  conflicts: [],
  selectorPreview: {
    selector,
    matchedResourceIds: members,
    selectorResultDigest: digest('d'),
    maxMatches: 2,
  },
  snapshot,
  disposition: 'bulkHumanReview',
  requiresHumanReview: true,
  bulkReviewEligible: true,
  publicationAllowed: false,
  manifestMutated: false,
}
const wireBatch = {
  sourceDraft,
  scope,
  snapshot,
  evaluatedAt: '2026-08-17T00:01:00.000Z',
  inputDigest: digest('e'),
  proposalSetDigest: digest('f'),
  proposals: [proposal],
  conflicts: [],
  requiresHumanReview: true,
  publicationAllowed: false,
  manifestMutated: false,
}
const routeCandidate = (
  action: 'split' | 'merge',
  sourceProposalIds: string[],
  selectedMembers = members,
) => {
  const selectorPreviews = selectedMembers.map((resourceId, index) => {
    const boundedSelector: CanonicalManifestSelector = {
      selectorType: 'resourceIdList',
      selectorId: `preview-${action}-${index + 1}`,
      resourceIds: [resourceId],
      maxMatches: 1,
    }
    return {
      selector: boundedSelector,
      matchedResourceIds: [resourceId],
      selectorResultDigest: digest(String(index + 1)),
      maxMatches: 1,
    }
  })
  return {
    candidateId: `candidate-wc012-${action}`,
    action,
    sourceDraft,
    scope,
    sourceProposalIds,
    proposalSetDigest: wireBatch.proposalSetDigest,
    snapshot,
    roleUpdates: [{
      role: {
        ...sourceRole,
        selectors: selectorPreviews.map((preview) => preview.selector),
      },
      selectorPreviews,
      memberCount: selectedMembers.length,
    }],
    replaceRoleRefs: ['worker'],
    resolution: `Explicit synthetic ${action} resolution.`,
    generatedAt: '2026-08-17T00:02:00.000Z',
    expiresAt: '2027-08-17T00:00:00.000Z',
    requiresHumanReview: true,
    publicationAllowed: false,
    manifestMutated: false,
  }
}
const loadRequest = {
  workloadId: canonicalManifestFixture.manifestId,
  manifestVersion: canonicalManifestFixture.manifestVersion,
  profileId: 'production',
  sourceDraft,
}
const authPort: AuthPort = {
  acquireSession: vi.fn(async () => mockAuthSession),
  acquireAccessToken: vi.fn(async () => 'synthetic-cohort-token'),
}
const response = (body: unknown, status = 200, headers?: HeadersInit): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })

describe('typed cohort proposal HTTP adapter', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('loads only the exact authorized workload, draft revision, digest, version, and profile', async () => {
    const fetchMock = vi.fn(async (...request: Parameters<typeof fetch>) => {
      void request
      return response(wireBatch)
    })
    const client = createCohortProposalApiClient({
      baseUrl: 'https://cohorts.invalid/',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as typeof fetch,
    })

    const result = await client.loadProposalBatch(loadRequest)

    expect(result.sourceDraft).toEqual(sourceDraft)
    expect(result.proposals[0]).toMatchObject({
      proposalId: proposal.proposalId,
      confidenceBand: 'high',
      supportingEvidence: [{ memberCount: 2, evidenceRefCount: 2 }],
      rejectedCandidates: [{ evidenceRefCount: 1 }],
    })
    const [url, init] = fetchMock.mock.calls[0]!
    expect(String(url)).toContain('/v1/cohort-proposals?')
    expect(String(url)).toContain(`manifest_id=${canonicalManifestFixture.manifestId}`)
    expect(String(url)).toContain('draft_id=draft-synthetic-canonical')
    expect(String(url)).toContain('expected_revision=1')
    expect(String(url)).toContain('expected_digest=sha256%3A')
    const headers = new Headers(init?.headers)
    expect(headers.get('Authorization')).toBe('Bearer synthetic-cohort-token')
    expect(headers.has('Idempotency-Key')).toBe(false)
  })

  it('posts a non-authoritative split preview with stable idempotency and exact source binding', async () => {
    const candidate = routeCandidate('split', [proposal.proposalId])
    const fetchMock = vi.fn(async (...request: Parameters<typeof fetch>) => {
      void request
      return response(candidate)
    })
    const client = createCohortProposalApiClient({
      baseUrl: 'https://cohorts.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as typeof fetch,
    })

    const result = await client.previewReview({
      ...loadRequest,
      action: 'split',
      proposalIds: [proposal.proposalId],
      sourceRoles: [proposal.role],
      sourceMembers: proposal.members,
      proposalSetDigest: wireBatch.proposalSetDigest,
      snapshotArtifactDigest: snapshot.artifactDigest,
      resolution: candidate.resolution,
    })

    expect(result.publicationAllowed).toBe(false)
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('https://cohorts.invalid/v1/cohort-proposals/preview')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      action: 'split',
      manifest_id: canonicalManifestFixture.manifestId,
      manifest_version: canonicalManifestFixture.manifestVersion,
      profile_id: 'production',
      draft_id: sourceDraft.draftId,
      expected_revision: sourceDraft.revision,
      expected_digest: sourceDraft.manifestDigest,
      proposal_ids: [proposal.proposalId],
      source_role_refs: ['worker'],
      proposal_set_digest: wireBatch.proposalSetDigest,
      snapshot_artifact_digest: snapshot.artifactDigest,
      resolution: candidate.resolution,
    })
    expect(new Headers(init?.headers).get('Idempotency-Key')).toMatch(
      /^cohort-preview-[a-f0-9]{32}$/,
    )
  })

  it('accepts exact merged-route split and merge unions and rejects injected unions', async () => {
    const mergeProposalIds = [
      proposal.proposalId,
      'proposal-2222222222222222',
    ]
    const request = (action: 'split' | 'merge') => ({
      ...loadRequest,
      action,
      proposalIds: action === 'split' ? [proposal.proposalId] : mergeProposalIds,
      sourceRoles: [proposal.role],
      sourceMembers: members,
      proposalSetDigest: wireBatch.proposalSetDigest,
      snapshotArtifactDigest: snapshot.artifactDigest,
      resolution: `Explicit synthetic ${action} resolution.`,
    })
    const clientFor = (candidate: unknown) => createCohortProposalApiClient({
      baseUrl: 'https://cohorts.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: vi.fn(async () => response(candidate)) as typeof fetch,
    })

    await expect(
      clientFor(routeCandidate('split', [proposal.proposalId]))
        .previewReview(request('split')),
    ).resolves.toMatchObject({ action: 'split' })
    await expect(
      clientFor(routeCandidate('merge', mergeProposalIds))
        .previewReview(request('merge')),
    ).resolves.toMatchObject({ action: 'merge' })

    await expect(
      clientFor(routeCandidate('split', [proposal.proposalId], [
        members[0]!,
        member('injected'),
      ])).previewReview(request('split')),
    ).rejects.toThrow(/inconsistent or authoritative/i)
    await expect(
      clientFor(routeCandidate('merge', mergeProposalIds, [members[0]!]))
        .previewReview(request('merge')),
    ).rejects.toThrow(/inconsistent or authoritative/i)
  })

  it('rejects authority fabrication, malformed previews, and oversized responses', async () => {
    expect(() =>
      parseCohortProposalBatch({ ...wireBatch, publicationAllowed: true }),
    ).toThrow(/authority|inconsistent/i)
    expect(() =>
      parseCohortProposalBatch({
        ...wireBatch,
        proposals: [{
          ...proposal,
          selectorPreview: {
            ...proposal.selectorPreview,
            matchedResourceIds: [members[0]],
          },
        }],
      }),
    ).toThrow(/does not match/i)

    const oversizedFetch = vi.fn(async () =>
      response({}, 200, { 'Content-Length': String(9 * 1024 * 1024) }),
    )
    const client = createCohortProposalApiClient({
      baseUrl: 'https://cohorts.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: oversizedFetch as typeof fetch,
    })
    await expect(client.loadProposalBatch(loadRequest)).rejects.toThrow(/boundary limit/i)

    const malformedClient = createCohortProposalApiClient({
      baseUrl: 'https://cohorts.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: vi.fn(async () =>
        new Response('synthetic-raw-log-body-must-not-render', {
          headers: { 'Content-Type': 'application/json' },
        })) as typeof fetch,
    })
    const malformedError = await malformedClient.loadProposalBatch(loadRequest)
      .catch((error: unknown) => error)
    expect(malformedError).toBeInstanceOf(Error)
    expect((malformedError as Error).message).toBe('Cohort API returned malformed bounded JSON.')
    expect((malformedError as Error).message).not.toContain('raw-log-body')
  })

  it('rejects unknown workload scope before token acquisition or HTTP', async () => {
    const fetchMock = vi.fn()
    const client = createCohortProposalApiClient({
      baseUrl: 'https://cohorts.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as unknown as typeof fetch,
    })

    await expect(client.loadProposalBatch({
      ...loadRequest,
      workloadId: 'not-authorized',
    })).rejects.toEqual(expect.objectContaining<Partial<ContextApiRequestError>>({
      status: 403,
      code: 'authorization_denied',
    }))
    expect(authPort.acquireAccessToken).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
