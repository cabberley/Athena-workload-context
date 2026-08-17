import { createContextApiClient, ContextApiRequestError } from './client'
import { canonicalManifestFixture, mockAuthSession } from './test/mockClient'
import type {
  AuthPort,
  CanonicalWorkloadManifest,
  WireDraftRecord,
  WirePublishedManifest,
  WirePublishedManifestView,
} from './types'

const token = 'synthetic-runtime-access-token'
const authPort: AuthPort = {
  acquireSession: vi.fn(async () => mockAuthSession),
  acquireAccessToken: vi.fn(async () => token),
}

const actor = { actor_id: mockAuthSession.actorId, kind: mockAuthSession.kind }

const published = (manifest: CanonicalWorkloadManifest = canonicalManifestFixture): WirePublishedManifest => ({
  manifest_id: manifest.manifestId,
  manifest_version: manifest.manifestVersion,
  manifest_digest: manifest.compatibility.artifactDigest,
  manifest,
  source_draft_id: 'draft-published-canonical',
  source_draft_revision: 5,
  approval: {
    decision_id: 'approval-published-canonical',
    approved_by: actor,
    approved_at: '2026-08-17T00:00:00.000Z',
    approved_revision: 4,
    manifest_version: manifest.manifestVersion,
    manifest_digest: manifest.compatibility.artifactDigest,
    reason: 'Synthetic contract approval.',
  },
  published_by: actor,
  published_at: '2026-08-17T00:00:00.000Z',
  publication_authorized_by: { actor_id: 'athena-context-api', kind: 'service' },
  publication_authorized_at: '2026-08-17T00:00:00.000Z',
  reason: 'Synthetic contract publication.',
})

const draft = (manifest: CanonicalWorkloadManifest): WireDraftRecord => ({
  draft_id: 'draft-successor-canonical',
  manifest_id: manifest.manifestId,
  state: 'draft',
  revision: 1,
  manifest,
  manifest_digest: manifest.compatibility.artifactDigest,
  previous_version: canonicalManifestFixture.manifestVersion,
  created_by: actor,
  created_at: '2026-08-17T00:00:00.000Z',
  updated_by: actor,
  updated_at: '2026-08-17T00:00:00.000Z',
  reason: 'Synthetic successor.',
})

const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })

const requestHeaders = (call: unknown[]): Headers => new Headers((call[1] as RequestInit).headers)

describe('WC-007 HTTP client', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('bootstraps only authorized IDs through exact scoped GET routes and unwraps version views', async () => {
    const supersededManifest = structuredClone(canonicalManifestFixture)
    supersededManifest.manifestVersion = '0.9.0'
    const views: WirePublishedManifestView[] = [
      {
        published: published(supersededManifest),
        supersession: {
          manifest_id: canonicalManifestFixture.manifestId,
          superseded_version: '0.9.0',
          replacement_version: canonicalManifestFixture.manifestVersion,
          superseded_by: actor,
          superseded_at: '2026-08-17T00:00:00.000Z',
          reason: 'Synthetic replacement.',
        },
      },
      { published: published() },
    ]
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input).includes('/v1/drafts?') ? jsonResponse([]) : jsonResponse(views),
    )
    const client = createContextApiClient({
      baseUrl: 'https://context.invalid/',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as typeof fetch,
      createId: () => 'fixed-id',
    })

    const contexts = await client.loadAuthorizedWorkloads()

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[0]![0]).toBe(
      `https://context.invalid/v1/drafts?manifest_id=${canonicalManifestFixture.manifestId}`,
    )
    expect(fetchMock.mock.calls[1]![0]).toBe(
      `https://context.invalid/v1/manifests/${canonicalManifestFixture.manifestId}/versions`,
    )
    for (const call of fetchMock.mock.calls) {
      const headers = requestHeaders(call)
      expect(headers.get('Authorization')).toBe(`Bearer ${token}`)
      expect(headers.has('Content-Type')).toBe(false)
      expect(headers.has('Idempotency-Key')).toBe(false)
    }
    expect(contexts[0]!.published?.manifestVersion).toBe(canonicalManifestFixture.manifestVersion)
    expect(contexts[0]!.confidence).toBeNull()
  })

  it('creates an exact successor request with fresh canonical digests and no manifestDigest member', async () => {
    const createIds = ['candidate-id', 'idempotency-id']
    let requestBody: Record<string, unknown> | null = null
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/v1/drafts?')) return jsonResponse([])
      if (url.endsWith('/versions')) return jsonResponse([{ published: published() }])
      requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>
      return jsonResponse(draft(requestBody.manifest as CanonicalWorkloadManifest), 201)
    })
    const client = createContextApiClient({
      baseUrl: 'https://context.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as typeof fetch,
      createId: () => createIds.shift() ?? 'unused-id',
    })

    const created = await client.createSuccessorDraft(canonicalManifestFixture.manifestId, 'Create exact successor.')

    expect(created.previousVersion).toBe('1.0.0')
    expect(requestBody).not.toBeNull()
    expect(Object.keys(requestBody!)).toEqual([
      'draft_id',
      'manifest',
      'manifest_digest',
      'previous_version',
      'reason',
    ])
    expect(requestBody!.previous_version).toBe('1.0.0')
    expect((requestBody!.manifest as CanonicalWorkloadManifest).manifestVersion).toBe('1.0.1')
    expect((requestBody!.manifest as Record<string, unknown>).manifestDigest).toBeUndefined()
    expect(requestBody!.manifest_digest).toBe(
      (requestBody!.manifest as CanonicalWorkloadManifest).compatibility.artifactDigest,
    )
    expect(requestBody!.manifest_digest).not.toBe(canonicalManifestFixture.compatibility.artifactDigest)

    const postCall = fetchMock.mock.calls[2]!
    expect(postCall[0]).toBe('https://context.invalid/v1/drafts')
    const headers = requestHeaders(postCall)
    expect(headers.get('Authorization')).toBe(`Bearer ${token}`)
    expect(headers.get('Content-Type')).toBe('application/json')
    expect(headers.get('Idempotency-Key')).toBe('mutation-idempotency-id')
  })

  it('fails closed on 403 without rendering an unrestricted response body', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ error: { code: 'authorization_denied', message: 'Scoped access denied.' } }, 403),
    )
    const client = createContextApiClient({
      baseUrl: 'https://context.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as typeof fetch,
    })

    await expect(client.loadAuthorizedWorkloads()).rejects.toEqual(
      expect.objectContaining<Partial<ContextApiRequestError>>({
        status: 403,
        code: 'authorization_denied',
        message: 'Scoped access denied.',
      }),
    )
  })

  it('rejects unknown workloads before token acquisition or fetch', async () => {
    const fetchMock = vi.fn()
    const client = createContextApiClient({
      baseUrl: 'https://context.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as unknown as typeof fetch,
    })

    await expect(client.loadWorkloadContext('unknown-workload')).rejects.toMatchObject({
      status: 403,
      code: 'authorization_denied',
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
