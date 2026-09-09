import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { bootstrapContextStudio } from './bootstrap'
import { refreshCanonicalManifestDigests } from './canonical'
import {
  computeOperationalBindingDigest,
  computeOperationalContentDigest,
  computeOperationalEvidenceInventoryDigest,
  computeOperationalReceiptId,
  computeOperationalReceiptDigest,
} from './operationalContext'
import { canonicalManifestFixture, mockAuthSession } from './test/mockClient'
import type {
  AuthPort,
  CanonicalWorkloadManifest,
  OperationalContextRequest,
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
    operational_context_receipt_id: 'operational-approval-startup',
    reason: 'Synthetic startup approval.',
  },
  published_by: actor,
  published_at: '2026-08-17T00:00:00.000Z',
  publication_authorized_by: { actor_id: 'athena-context-api', kind: 'service' },
  publication_authorized_at: '2026-08-17T00:00:00.000Z',
  operational_context_receipt_id: 'operational-publication-startup',
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
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/v1/drafts?')) return response([])
      if (url.includes('/profiles/production/authority')) {
        return response({
          manifest_id: canonicalManifestFixture.manifestId,
          manifest_version: canonicalManifestFixture.manifestVersion,
          profile_id: 'production',
          resolved_profile_digest: `sha256:${'7'.repeat(64)}`,
        })
      }
      return response([{ published: wirePublished }])
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
            cohortApiBaseUrl: 'https://cohorts.invalid',
            authPort,
            fetchImpl: fetchMock as unknown as typeof fetch,
          },
          rootElement,
        )
      }),
    ).rejects.toThrow(/authenticated session/i)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('binds operational relationships and findings to the exact active context', async () => {
    const authPort: AuthPort = {
      acquireSession: vi.fn(async () => mockAuthSession),
      acquireAccessToken: vi.fn(async () => 'per-user-runtime-token'),
    }
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/v1/drafts?')) return response([])
      if (url.includes('/profiles/production/authority')) {
        return response({
          manifest_id: canonicalManifestFixture.manifestId,
          manifest_version: canonicalManifestFixture.manifestVersion,
          profile_id: 'production',
          resolved_profile_digest: `sha256:${'7'.repeat(64)}`,
        })
      }
      return response([{ published: wirePublished }])
    })
    const operationalContextPort = {
      loadOperationalContext: vi.fn(async (request: OperationalContextRequest) => {
        const evidenceInventory = [{
          evidenceRef: 'flow-evidence-001',
          evidenceDigest: `sha256:${'2'.repeat(64)}`,
        }]
        const evidenceInventoryDigest =
          await computeOperationalEvidenceInventoryDigest(evidenceInventory)
        const asOf = Date.parse(request.asOf)
        const collectedAt = new Date(asOf - 60_000).toISOString()
        const expiresAt = new Date(asOf + 3_600_000).toISOString()
        const snapshotId = 'snapshot-operational-001'
        const evidenceSource = 'Signed WC-026 correlation snapshot'
        const snapshotConfidence = 0.88
        const relationships = [{
          id: 'observed-production-web-worker',
          kind: 'observed' as const,
          source: 'web',
          target: 'worker',
          evidenceRefs: ['flow-evidence-001'],
          observedAt: '2026-09-08T00:00:00.000Z',
          confidence: 0.96,
          profileId: 'production',
        }]
        const findings = [{
          id: 'finding-production-connectivity',
          verdict: 'humanReviewRequired',
          summary: 'Synthetic connectivity evidence requires operator review.',
          manifestVersion: canonicalManifestFixture.manifestVersion,
          profileId: 'production',
          clause: '/profiles/production/relationships/0',
          evidenceRefs: ['flow-evidence-001'],
          residualRisk: 'Connectivity intent is not yet confirmed.',
          controlState: 'unknown',
          confidence: 0.72,
        }]
        const contentDigest = await computeOperationalContentDigest({
          evidenceSource,
          confidence: snapshotConfidence,
          relationships,
          findings,
        })
        const bindingDigest = await computeOperationalBindingDigest({
          workloadId: request.workloadId,
          manifestVersion: request.manifestVersion,
          profileId: request.profileId,
          draftId: request.draftId,
          draftRevision: request.draftRevision,
          manifestDigest: request.manifestDigest,
          profileDigest: request.profileDigest,
          snapshotId,
          collectedAt,
          expiresAt,
          evidenceInventoryDigest,
          contentDigest,
        })
        const receiptBase = {
          schemaVersion:
            'athena.context-api.operational-context-receipt.v1' as const,
          receiptId: 'operational-placeholder',
          issuedBy: {
            actorId: 'operational-context-service',
            kind: 'service' as const,
          },
          issuedAt: new Date(asOf - 30_000).toISOString(),
          manifestId: request.workloadId,
          manifestVersion: request.manifestVersion,
          profileId: request.profileId,
          draftId: request.draftId,
          draftRevision: request.draftRevision,
          manifestDigest: request.manifestDigest,
          profileDigest: request.profileDigest,
          snapshotId,
          collectedAt,
          expiresAt,
          evidenceCount: evidenceInventory.length,
          evidenceInventoryDigest,
          contentDigest,
          bindingDigest,
          receiptDigest: `sha256:${'0'.repeat(64)}`,
        }
        const receipt = {
          ...receiptBase,
          receiptId: await computeOperationalReceiptId(receiptBase),
        }
        receipt.receiptDigest =
          await computeOperationalReceiptDigest(receipt)
        return {
        schemaVersion: 'athena.contextStudio.operationalContext.v1',
        workloadId: request.workloadId,
        manifestVersion: request.manifestVersion,
        profileId: request.profileId,
        draftId: request.draftId,
        draftRevision: request.draftRevision,
        manifestDigest: request.manifestDigest,
        profileDigest: request.profileDigest,
        receiptId: receipt.receiptId,
        snapshotId,
        collectedAt,
        expiresAt,
        evidenceSource,
        confidence: snapshotConfidence,
        evidenceInventory,
        evidenceInventoryDigest,
        contentDigest,
        bindingDigest,
        receipt: {
          schema_version: receipt.schemaVersion,
          receipt_id: receipt.receiptId,
          issued_by: {
            actor_id: receipt.issuedBy.actorId,
            kind: receipt.issuedBy.kind,
          },
          issued_at: receipt.issuedAt,
          manifest_id: receipt.manifestId,
          manifest_version: receipt.manifestVersion,
          profile_id: receipt.profileId,
          draft_id: receipt.draftId,
          draft_revision: receipt.draftRevision,
          manifest_digest: receipt.manifestDigest,
          profile_digest: receipt.profileDigest,
          snapshot_id: receipt.snapshotId,
          collected_at: receipt.collectedAt,
          expires_at: receipt.expiresAt,
          evidence_count: receipt.evidenceCount,
          evidence_inventory_digest: receipt.evidenceInventoryDigest,
          content_digest: receipt.contentDigest,
          binding_digest: receipt.bindingDigest,
          receipt_digest: receipt.receiptDigest,
        },
        relationships,
        findings,
        }
      }),
    }
    const rootElement = document.createElement('div')
    document.body.append(rootElement)

    let root: Awaited<ReturnType<typeof bootstrapContextStudio>>
    await act(async () => {
      root = await bootstrapContextStudio(
        {
          apiBaseUrl: 'https://context.invalid',
          cohortApiBaseUrl: 'https://cohorts.invalid',
          authPort,
          operationalContextPort,
          fetchImpl: fetchMock as typeof fetch,
        },
        rootElement,
      )
    })

    expect(operationalContextPort.loadOperationalContext).toHaveBeenCalledWith({
      workloadId: canonicalManifestFixture.manifestId,
      manifestVersion: canonicalManifestFixture.manifestVersion,
      profileId: 'production',
      draftId: wirePublished.source_draft_id,
      draftRevision: wirePublished.source_draft_revision,
      manifestDigest: wirePublished.manifest_digest,
      profileDigest: expect.stringMatching(/^sha256:/),
      asOf: expect.any(String),
    })
    expect(screen.getByText('observed')).toBeInTheDocument()
    expect(screen.getByText(/synthetic connectivity evidence/i)).toBeInTheDocument()
    expect(screen.getByText(/signed wc-026 correlation snapshot/i)).toBeInTheDocument()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Manifest' }))
    await user.click(screen.getByRole('button', { name: /reload scoped context/i }))
    await waitFor(() =>
      expect(operationalContextPort.loadOperationalContext).toHaveBeenCalledTimes(2),
    )
    expect(screen.getByText(/signed wc-026 correlation snapshot/i)).toBeInTheDocument()
    await act(async () => root.unmount())
  })

  it('sanitizes operational adapter failures without exposing raw evidence', async () => {
    const authPort: AuthPort = {
      acquireSession: vi.fn(async () => mockAuthSession),
      acquireAccessToken: vi.fn(async () => 'per-user-runtime-token'),
    }
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/v1/drafts?')) return response([])
      if (url.includes('/profiles/production/authority')) {
        return response({
          manifest_id: canonicalManifestFixture.manifestId,
          manifest_version: canonicalManifestFixture.manifestVersion,
          profile_id: 'production',
          resolved_profile_digest: `sha256:${'7'.repeat(64)}`,
        })
      }
      return response([{ published: wirePublished }])
    })
    const rootElement = document.createElement('div')
    document.body.append(rootElement)

    let caught: unknown
    await act(async () => {
      try {
        await bootstrapContextStudio(
          {
            apiBaseUrl: 'https://context.invalid',
            cohortApiBaseUrl: 'https://cohorts.invalid',
            authPort,
            operationalContextPort: {
              loadOperationalContext: async () => {
                throw new Error('synthetic raw monitoring payload')
              },
            },
            fetchImpl: fetchMock as typeof fetch,
          },
          rootElement,
        )
      } catch (error) {
        caught = error
      }
    })

    expect(caught).toEqual(expect.objectContaining({
      message:
        'Trusted operational context could not be loaded for the exact lifecycle binding.',
    }))
    expect(String(caught)).not.toMatch(/raw monitoring payload/i)
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
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Cohorts' }))

    expect(await screen.findByText('high · 94%')).toBeInTheDocument()
    expect(await screen.findByText(/loaded 1 proposals and their durable decision state/i))
      .toBeInTheDocument()
    const rationale = screen.getByLabelText(/resolution rationale/i)
    expect(rationale).toBeEnabled()
    await user.type(rationale, 'Explicit production adapter decision rationale.')
    expect(screen.getByRole('button', { name: /approve bounded cohort to draft/i })).toBeEnabled()
    expect(screen.getByRole('button', { name: /^reject proposal$/i })).toBeEnabled()
    const cohortCall = fetchMock.mock.calls.find((call) =>
      String(call[0]).startsWith('https://cohorts.invalid/v1/cohort-proposals?'),
    )
    expect(cohortCall).toBeDefined()
    expect(String(cohortCall![0])).toContain('expected_revision=1')
    expect(fetchMock.mock.calls.some((call) =>
      String(call[0]).startsWith(
        'https://cohorts.invalid/v1/cohort-proposals/decisions?',
      ),
    )).toBe(true)
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
      approval: {
        ...wirePublished.approval,
        manifest_digest: canonicalExceptionManifest.compatibility.artifactDigest,
      },
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
          cohortApiBaseUrl: 'https://cohorts.invalid',
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
