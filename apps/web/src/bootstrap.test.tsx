import { act, screen } from '@testing-library/react'
import { bootstrapContextStudio } from './bootstrap'
import { canonicalManifestFixture, mockAuthSession } from './test/mockClient'
import type { AuthPort, WirePublishedManifest } from './types'

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
})
