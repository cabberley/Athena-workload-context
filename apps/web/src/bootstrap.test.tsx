import { act, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { bootstrapContextStudio } from './bootstrap'
import { refreshCanonicalManifestDigests } from './canonical'
import { canonicalManifestFixture, mockAuthSession } from './test/mockClient'
import type {
  AuthPort,
  CanonicalWorkloadManifest,
  WireDraftRecord,
  WirePublishedManifest,
} from './types'

const actor = { actor_id: mockAuthSession.actorId, kind: mockAuthSession.kind }
const wirePublished: WirePublishedManifest = {
  manifest_id: canonicalManifestFixture.manifestId,
  manifest_version: canonicalManifestFixture.manifestVersion,
  manifest_digest: canonicalManifestFixture.compatibility.artifactDigest,
  manifest: canonicalManifestFixture,
  source_draft_id: 'draft-startup',
  source_draft_revision: 5,
  approval: {
    decision_id: 'approval-startup',
    approved_by: actor,
    approved_at: '2026-08-17T00:00:00.000Z',
    approved_revision: 4,
    manifest_version: canonicalManifestFixture.manifestVersion,
    manifest_digest: canonicalManifestFixture.compatibility.artifactDigest,
    reason: 'Synthetic startup approval.',
  },
  published_by: actor,
  published_at: '2026-08-17T00:00:00.000Z',
  publication_authorized_by: { actor_id: 'athena-context-api', kind: 'service' },
  publication_authorized_at: '2026-08-17T00:00:00.000Z',
  reason: 'Synthetic startup publication.',
}
const wireDraft: WireDraftRecord = {
  draft_id: 'draft-synthetic-canonical',
  manifest_id: canonicalManifestFixture.manifestId,
  state: 'draft',
  revision: 1,
  manifest: canonicalManifestFixture,
  manifest_digest: canonicalManifestFixture.compatibility.artifactDigest,
  created_by: actor,
  created_at: '2026-08-17T00:00:00.000Z',
  updated_by: actor,
  updated_at: '2026-08-17T00:00:00.000Z',
  reason: 'Synthetic production adapter draft.',
}
const cohortDigest = (character: string): string => `sha256:${character.repeat(64)}`
const cohortMembers = [
  '/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/rg-wc012-synthetic/' +
    'providers/microsoft.compute/virtualmachines/wc012-worker-001',
  '/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/rg-wc012-synthetic/' +
    'providers/microsoft.compute/virtualmachines/wc012-worker-002',
]
const cohortSelector = {
  selectorType: 'namePredicate',
  selectorId: 'wc012-worker-name',
  prefix: 'wc012-worker-',
  maxMatches: 2,
}
const cohortRole = {
  ...structuredClone(canonicalManifestFixture.roles.find((role) => role.roleId === 'worker')!),
  selectors: [cohortSelector],
}
const cohortSnapshot = {
  snapshotId: 'snapshot-wc012-http',
  artifactDigest: cohortDigest('b'),
  semanticDigest: cohortDigest('c'),
  collectedAt: '2026-08-17T00:00:00.000Z',
  expiresAt: '2027-08-17T00:00:00.000Z',
}
const wireCohortBatch = {
  sourceDraft: {
    draftId: wireDraft.draft_id,
    revision: wireDraft.revision,
    manifestDigest: wireDraft.manifest_digest,
  },
  scope: {
    manifestId: wireDraft.manifest_id,
    manifestVersion: wireDraft.manifest.manifestVersion,
    profileId: 'production',
    profileType: 'production',
    resolvedProfileDigest: cohortDigest('a'),
  },
  snapshot: cohortSnapshot,
  evaluatedAt: '2026-08-17T00:01:00.000Z',
  inputDigest: cohortDigest('e'),
  proposalSetDigest: cohortDigest('f'),
  proposals: [{
    proposalId: 'proposal-1111111111111111',
    scope: {
      manifestId: wireDraft.manifest_id,
      manifestVersion: wireDraft.manifest.manifestVersion,
      profileId: 'production',
      profileType: 'production',
      resolvedProfileDigest: cohortDigest('a'),
    },
    role: cohortRole,
    members: cohortMembers,
    confidence: 0.94,
    confidenceBand: 'high',
    supportingEvidence: [{
      signalType: 'namePredicate',
      signalValue: 'wc012-worker-',
      memberResourceIds: cohortMembers,
      evidenceRefs: [{ referenceType: 'item' }, { referenceType: 'item' }],
    }],
    dissent: [],
    rejectedCandidates: [],
    conflicts: [],
    selectorPreview: {
      selector: cohortSelector,
      matchedResourceIds: cohortMembers,
      selectorResultDigest: cohortDigest('d'),
      maxMatches: 2,
    },
    snapshot: cohortSnapshot,
    disposition: 'bulkHumanReview',
    requiresHumanReview: true,
    bulkReviewEligible: true,
    publicationAllowed: false,
    manifestMutated: false,
  }],
  conflicts: [],
  requiresHumanReview: true,
  publicationAllowed: false,
  manifestMutated: false,
}

const response = (body: unknown): Response =>
  new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } })

describe('production startup', () => {
  it('awaits injected per-user auth and exact authorized workload HTTP routes', async () => {
    const authPort: AuthPort = {
      acquireSession: vi.fn(async () => mockAuthSession),
      acquireAccessToken: vi.fn(async () => 'per-user-runtime-token'),
    }
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input).includes('/v1/drafts?') ? response([]) : response([{ published: wirePublished }]),
    )
    const rootElement = document.createElement('div')
    document.body.append(rootElement)

    let root: Awaited<ReturnType<typeof bootstrapContextStudio>>
    await act(async () => {
      root = await bootstrapContextStudio(
        {
          apiBaseUrl: 'https://context.invalid',
          authPort,
          fetchImpl: fetchMock as typeof fetch,
        },
        rootElement,
      )
    })

    expect(authPort.acquireSession).toHaveBeenCalledOnce()
    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
      `https://context.invalid/v1/drafts?manifest_id=${canonicalManifestFixture.manifestId}`,
      `https://context.invalid/v1/manifests/${canonicalManifestFixture.manifestId}/versions`,
    ])
    expect(await screen.findByRole('heading', { name: /athena context studio/i })).toBeInTheDocument()
    await act(async () => root.unmount())
  })

  it('fails closed before HTTP when no authenticated session exists', async () => {
    const authPort: AuthPort = {
      acquireSession: vi.fn(async () => null),
      acquireAccessToken: vi.fn(async () => null),
    }
    const fetchMock = vi.fn()
    const rootElement = document.createElement('div')
    document.body.append(rootElement)

    await expect(
      act(async () => {
        await bootstrapContextStudio(
          {
            apiBaseUrl: 'https://context.invalid',
            authPort,
            fetchImpl: fetchMock as unknown as typeof fetch,
          },
          rootElement,
        )
      }),
    ).rejects.toThrow(/authenticated session/i)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('loads the merged cohort route through the production HTTP adapter', async () => {
    const authPort: AuthPort = {
      acquireSession: vi.fn(async () => ({ ...mockAuthSession, role: 'proposer' as const })),
      acquireAccessToken: vi.fn(async () => 'per-user-runtime-token'),
    }
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      void init
      const url = String(input)
      if (url.includes('/v1/drafts?')) return response([wireDraft])
      if (url.includes('/v1/cohort-proposals?')) return response(wireCohortBatch)
      return response([])
    })
    const rootElement = document.createElement('div')
    document.body.append(rootElement)

    let root: Awaited<ReturnType<typeof bootstrapContextStudio>>
    await act(async () => {
      root = await bootstrapContextStudio(
        {
          apiBaseUrl: 'https://context.invalid',
          cohortApiBaseUrl: 'https://cohorts.invalid',
          authPort,
          fetchImpl: fetchMock as typeof fetch,
        },
        rootElement,
      )
    })
    await userEvent.setup().click(screen.getByRole('button', { name: 'Cohorts' }))

    expect(await screen.findByText('high · 94%')).toBeInTheDocument()
    expect(screen.getByText(/blocked until the issue #34 decision API is merged/i))
      .toBeInTheDocument()
    expect(screen.getByLabelText(/resolution rationale/i)).toBeDisabled()
    expect(screen.getByRole('button', { name: /approve bounded cohort to draft/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /^reject proposal$/i })).toBeDisabled()
    const cohortCall = fetchMock.mock.calls.find((call) =>
      String(call[0]).startsWith('https://cohorts.invalid/v1/cohort-proposals?'),
    )
    expect(cohortCall).toBeDefined()
    expect(String(cohortCall![0])).toContain('expected_revision=1')
    expect(new Headers((cohortCall![1] as RequestInit).headers).get('Authorization'))
      .toBe('Bearer per-user-runtime-token')
    expect(screen.queryByText(/not implemented/i)).not.toBeInTheDocument()
    await act(async () => root.unmount())
  })

  it('starts and renders an exact canonical exception relationship without endpoint fields', async () => {
    const exceptionManifest = structuredClone(canonicalManifestFixture) as CanonicalWorkloadManifest
    exceptionManifest.profiles.production!.relationships.push({
      relationshipClass: 'exception',
      exceptionId: 'exception-db-zone-loss',
      appliesToClauseRef: 'db-zone-loss-spof',
      riskAcceptanceRef: 'ra-db-zone-loss-production',
      governanceScope: {
        governanceScopeType: 'clause',
        manifestId: exceptionManifest.manifestId,
        profileId: 'production',
        clausePath: '/constraints/db-zone-loss-spof',
        ownerRef: 'ops-owner',
      },
      ownerRef: 'ops-owner',
      rationale: 'Synthetic exception requiring explicit acceptance.',
      expiresAt: '2027-12-31T00:00:00.000Z',
    })
    const canonicalExceptionManifest = await refreshCanonicalManifestDigests(exceptionManifest)
    const exceptionPublication: WirePublishedManifest = {
      ...wirePublished,
      manifest: canonicalExceptionManifest,
      manifest_digest: canonicalExceptionManifest.compatibility.artifactDigest,
    }
    const authPort: AuthPort = {
      acquireSession: vi.fn(async () => mockAuthSession),
      acquireAccessToken: vi.fn(async () => 'per-user-runtime-token'),
    }
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input).includes('/v1/drafts?')
        ? response([])
        : response([{ published: exceptionPublication }]),
    )
    const rootElement = document.createElement('div')
    document.body.append(rootElement)

    let root: Awaited<ReturnType<typeof bootstrapContextStudio>>
    await act(async () => {
      root = await bootstrapContextStudio(
        {
          apiBaseUrl: 'https://context.invalid',
          authPort,
          fetchImpl: fetchMock as typeof fetch,
        },
        rootElement,
      )
    })

    expect(screen.getByText('exception-db-zone-loss')).toBeInTheDocument()
    expect(screen.getByText(/exception target: clause db-zone-loss-spof/i)).toBeInTheDocument()
    expect(screen.getByText(/synthetic exception requiring explicit acceptance/i)).toBeInTheDocument()
    expect(screen.getByText(/scope:.*\/constraints\/db-zone-loss-spof/i)).toBeInTheDocument()
    expect(screen.queryByText(/undefined/i)).not.toBeInTheDocument()
    await act(async () => root.unmount())
  })
})
