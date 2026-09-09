import {
  createContextApiClient,
  ContextApiRequestError,
  SupersessionRecoveryRequiredError,
} from './client'
import { refreshCanonicalManifestDigests } from './canonical'
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

const published = (
  manifest: CanonicalWorkloadManifest = canonicalManifestFixture,
  options: {
    sourceDraftId?: string
    sourceDraftRevision?: number
    previousVersion?: string
  } = {},
): WirePublishedManifest => ({
  manifest_id: manifest.manifestId,
  manifest_version: manifest.manifestVersion,
  manifest_digest: manifest.compatibility.artifactDigest,
  manifest,
  source_draft_id: options.sourceDraftId ?? 'draft-published-canonical',
  source_draft_revision: options.sourceDraftRevision ?? 5,
  previous_version: options.previousVersion,
  approval: {
    decision_id: 'approval-published-canonical',
    approved_by: actor,
    approved_at: '2026-08-17T00:00:00.000Z',
    approved_revision: 4,
    manifest_version: manifest.manifestVersion,
    manifest_digest: manifest.compatibility.artifactDigest,
    operational_context_receipt_id: 'operational-approval-published',
    reason: 'Synthetic contract approval.',
  },
  published_by: actor,
  published_at: '2026-08-17T00:00:00.000Z',
  publication_authorized_by: { actor_id: 'athena-context-api', kind: 'service' },
  publication_authorized_at: '2026-08-17T00:00:00.000Z',
  operational_context_receipt_id: 'operational-publication-published',
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
    const canonicalSuperseded = await refreshCanonicalManifestDigests(
      supersededManifest,
    )
    const views: WirePublishedManifestView[] = [
      {
        published: published(canonicalSuperseded),
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

  it('selects the exact profile ID instead of the first matching profile type', async () => {
    const manifest = structuredClone(canonicalManifestFixture)
    manifest.workload.environments = [
      'development',
      'production',
      'training',
    ]
    manifest.profiles['prod-east'] = {
      ...structuredClone(manifest.profiles.production!),
      profileId: 'prod-east',
    }
    const canonical = await refreshCanonicalManifestDigests(manifest)
    const publication = published(canonical)
    const fetchMock = vi.fn(async (input: RequestInfo | URL) =>
      String(input).includes('/v1/drafts?')
        ? jsonResponse([])
        : jsonResponse([{ published: publication }]),
    )
    const client = createContextApiClient({
      baseUrl: 'https://context.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as typeof fetch,
    })

    const context = await client.loadWorkloadContext(canonical.manifestId)

    expect(context.environment).toBe('production')
    expect(context.profileId).toBe('production')
  })

  it('creates an exact successor request with fresh canonical digests and no manifestDigest member', async () => {
    const createIds = ['candidate-id', 'idempotency-id']
    let requestBody: Record<string, unknown> | null = null
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/v1/drafts?')) return jsonResponse([])
      if (url.endsWith('/versions')) return jsonResponse([{ published: published() }])
      requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>
      return jsonResponse({
        ...draft(requestBody.manifest as CanonicalWorkloadManifest),
        draft_id: requestBody.draft_id,
        previous_version: requestBody.previous_version,
      }, 201)
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

  it('integrates create successor, publish, supersede and reload with one active version', async () => {
    let successorDraft: WireDraftRecord | null = null
    let successorPublished: WirePublishedManifest | null = null
    const predecessorView: WirePublishedManifestView = { published: published() }
    const views: WirePublishedManifestView[] = [predecessorView]
    let supersedeBody: Record<string, unknown> | null = null
    let generatedId = 0

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      if (method === 'GET' && url.includes('/v1/drafts?')) {
        return jsonResponse(successorDraft ? [successorDraft] : [])
      }
      if (method === 'GET' && url.endsWith('/versions')) {
        return jsonResponse(views)
      }
      if (method === 'POST' && url.endsWith('/v1/drafts')) {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>
        successorDraft = {
          ...draft(body.manifest as CanonicalWorkloadManifest),
          draft_id: String(body.draft_id),
          manifest_digest: String(body.manifest_digest),
          previous_version: String(body.previous_version),
          reason: String(body.reason),
        }
        return jsonResponse(successorDraft, 201)
      }
      if (method === 'POST' && /\/(validate|submit|review|approve)$/.test(url)) {
        const current = successorDraft!
        const operation = url.split('/').at(-1)!
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>
        const state =
          operation === 'validate'
            ? 'validated'
            : operation === 'approve'
              ? 'approved'
              : 'in_review'
        successorDraft = {
          ...current,
          state,
          revision: current.revision + 1,
          review_decisions:
            operation === 'review'
              ? [
                  ...(current.review_decisions ?? []),
                  {
                    decision_id: 'review-successor',
                    decision: String(body.decision) as 'approved',
                    reviewed_by: actor,
                    reviewed_at: '2026-08-17T00:00:03.000Z',
                    reviewed_revision: current.revision + 1,
                    manifest_version: current.manifest.manifestVersion,
                    manifest_digest: current.manifest_digest,
                    comments: String(body.comments),
                    rejected_fields: body.rejected_fields as string[],
                    required_corrections:
                      body.required_corrections as string[],
                  },
                ]
              : current.review_decisions,
          approval: state === 'approved'
            ? {
                decision_id: 'approval-successor',
                approved_by: actor,
                approved_at: '2026-08-17T00:00:04.000Z',
                approved_revision: current.revision + 1,
                manifest_version: current.manifest.manifestVersion,
                manifest_digest: current.manifest_digest,
                operational_context_receipt_id: String(
                  body.operational_context_receipt_id,
                ),
                reason: 'Synthetic exact approval.',
              }
            : undefined,
        }
        return jsonResponse(successorDraft)
      }
      if (method === 'POST' && url.endsWith('/publish')) {
        const current = successorDraft!
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>
        successorDraft = { ...current, state: 'published', revision: current.revision + 1 }
        successorPublished = published(current.manifest, {
          sourceDraftId: current.draft_id,
          sourceDraftRevision: successorDraft.revision,
          previousVersion: current.previous_version ?? undefined,
        })
        successorPublished.approval = current.approval!
        successorPublished.operational_context_receipt_id = String(
          body.operational_context_receipt_id,
        )
        views.push({ published: successorPublished })
        return jsonResponse(successorPublished, 201)
      }
      if (method === 'POST' && url.endsWith('/versions/1.0.0/supersede')) {
        supersedeBody = JSON.parse(String(init?.body)) as Record<string, unknown>
        predecessorView.supersession = {
          manifest_id: canonicalManifestFixture.manifestId,
          superseded_version: '1.0.0',
          replacement_version: successorPublished!.manifest_version,
          superseded_by: actor,
          superseded_at: '2026-08-17T00:00:06.000Z',
          reason: String(supersedeBody.reason),
        }
        return jsonResponse(predecessorView.supersession)
      }
      throw new Error(`Unexpected request: ${method} ${url}`)
    })
    const client = createContextApiClient({
      baseUrl: 'https://context.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as typeof fetch,
      createId: () => `id-${++generatedId}`,
    })

    let current = await client.createSuccessorDraft(
      canonicalManifestFixture.manifestId,
      'Create integrated successor.',
    )
    current = await client.validateDraft({
      workloadId: current.manifestId,
      draftId: current.draftId,
      expectedRevision: current.revision,
      expectedManifestVersion: current.manifest.manifestVersion,
      expectedDigest: current.manifestDigest,
      reason: 'Validate integrated successor.',
    })
    current = await client.submitForReview({
      workloadId: current.manifestId,
      draftId: current.draftId,
      expectedRevision: current.revision,
      expectedManifestVersion: current.manifest.manifestVersion,
      expectedDigest: current.manifestDigest,
      reason: 'Submit integrated successor.',
    })
    current = await client.reviewDraft({
      workloadId: current.manifestId,
      draftId: current.draftId,
      expectedRevision: current.revision,
      expectedManifestVersion: current.manifest.manifestVersion,
      expectedDigest: current.manifestDigest,
      decision: 'approved',
      comments: 'Review integrated successor.',
      rejectedFields: [],
      requiredCorrections: [],
      reason: 'Record integrated review.',
    })
    current = await client.approveDraft({
      workloadId: current.manifestId,
      draftId: current.draftId,
      expectedRevision: current.revision,
      expectedManifestVersion: current.manifest.manifestVersion,
      expectedDigest: current.manifestDigest,
      operationalContextReceiptId: 'operational-approval-successor',
      reason: 'Approve integrated successor.',
    })
    const result = await client.publishDraft({
      workloadId: current.manifestId,
      draftId: current.draftId,
      expectedRevision: current.revision,
      expectedManifestVersion: current.manifest.manifestVersion,
      expectedDigest: current.manifestDigest,
      approvalId: current.approval!.decisionId,
      operationalContextReceiptId: 'operational-publication-successor',
      reason: 'Publish integrated successor.',
    })
    const reloaded = await client.loadWorkloadContext(canonicalManifestFixture.manifestId)

    expect(result.manifestVersion).toBe('1.0.1')
    expect(reloaded.published?.manifestVersion).toBe('1.0.1')
    expect(supersedeBody).toEqual({
      expected_revision: 5,
      expected_manifest_version: '1.0.0',
      expected_digest: canonicalManifestFixture.compatibility.artifactDigest,
      replacement_version: '1.0.1',
      replacement_digest: result.manifestDigest,
      reason: 'Supersede 1.0.0 with published successor 1.0.1.',
    })
    const supersedeCall = fetchMock.mock.calls.find((call) =>
      String(call[0]).endsWith(
        `/v1/manifests/${canonicalManifestFixture.manifestId}/versions/1.0.0/supersede`,
      ),
    )!
    expect((supersedeCall[1] as RequestInit).method).toBe('POST')
    expect(requestHeaders(supersedeCall).get('Authorization')).toBe(`Bearer ${token}`)
    expect(requestHeaders(supersedeCall).get('Idempotency-Key')).toMatch(/^supersede-/)
    expect(views.filter((view) => !view.supersession)).toHaveLength(1)
  })

  it('returns a blocking recoverable state when successor publish succeeds but supersede fails', async () => {
    const successor = structuredClone(canonicalManifestFixture)
    successor.manifestVersion = '1.0.1'
    const canonicalSuccessor = await refreshCanonicalManifestDigests(successor)
    const approvedDraft: WireDraftRecord = {
      ...draft(canonicalSuccessor),
      state: 'approved',
      revision: 4,
      approval: {
        decision_id: 'approval-partial',
        approved_by: actor,
        approved_at: '2026-08-17T00:00:04.000Z',
        approved_revision: 4,
        manifest_version: '1.0.1',
        manifest_digest: canonicalSuccessor.compatibility.artifactDigest,
        operational_context_receipt_id: 'operational-approval-partial',
        reason: 'Synthetic partial approval.',
      },
      review_decisions: [{
        decision_id: 'review-partial',
        decision: 'approved',
        reviewed_by: actor,
        reviewed_at: '2026-08-17T00:00:03.000Z',
        reviewed_revision: 3,
        manifest_version: '1.0.1',
        manifest_digest: canonicalSuccessor.compatibility.artifactDigest,
        comments: 'Synthetic partial review.',
        rejected_fields: [],
        required_corrections: [],
      }],
    }
    const successorPublication = {
      ...published(canonicalSuccessor, {
        sourceDraftId: approvedDraft.draft_id,
        sourceDraftRevision: 5,
        previousVersion: '1.0.0',
      }),
      approval: approvedDraft.approval!,
    }
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if ((init?.method ?? 'GET') === 'GET' && url.includes('/v1/drafts?')) {
        return jsonResponse([approvedDraft])
      }
      if ((init?.method ?? 'GET') === 'GET' && url.endsWith('/versions')) {
        return jsonResponse([{ published: published() }])
      }
      if (url.endsWith('/publish')) return jsonResponse(successorPublication, 201)
      if (url.endsWith('/supersede')) {
        return jsonResponse(
          { error: { code: 'authorization_denied', message: 'Supersede permission is required.' } },
          403,
        )
      }
      throw new Error(`Unexpected request: ${url}`)
    })
    const client = createContextApiClient({
      baseUrl: 'https://context.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as typeof fetch,
      createId: () => 'partial-id',
    })

    const publication = client.publishDraft({
      workloadId: approvedDraft.manifest_id,
      draftId: approvedDraft.draft_id,
      expectedRevision: approvedDraft.revision,
      expectedManifestVersion: approvedDraft.manifest.manifestVersion,
      expectedDigest: approvedDraft.manifest_digest,
      approvalId: approvedDraft.approval!.decision_id,
      operationalContextReceiptId:
        successorPublication.operational_context_receipt_id!,
      reason: 'Publish partial successor.',
    })

    const error = await publication.catch((reason: unknown) => reason)
    expect(error).toBeInstanceOf(SupersessionRecoveryRequiredError)
    const recoveryError = error as SupersessionRecoveryRequiredError
    expect(recoveryError.published.manifestVersion).toBe('1.0.1')
    expect(recoveryError.recovery).toMatchObject({
      predecessorVersion: '1.0.0',
      successorVersion: '1.0.1',
    })
  })

  it('reconstructs pending supersession recovery after a browser reload', async () => {
    const successor = structuredClone(canonicalManifestFixture)
    successor.manifestVersion = '1.0.1'
    const canonicalSuccessor = await refreshCanonicalManifestDigests(successor)
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/v1/drafts?')) return jsonResponse([])
      if (url.endsWith('/versions')) {
        return jsonResponse([
          { published: published() },
          {
            published: published(canonicalSuccessor, {
              sourceDraftId: 'draft-pending-successor',
              sourceDraftRevision: 5,
              previousVersion: '1.0.0',
            }),
          },
        ])
      }
      throw new Error(`Unexpected request: ${url}`)
    })
    const client = createContextApiClient({
      baseUrl: 'https://context.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as typeof fetch,
    })

    const context = await client.loadWorkloadContext(
      canonicalManifestFixture.manifestId,
    )

    expect(context.published?.manifestVersion).toBe('1.0.1')
    expect(context.pendingSupersessionRecovery).toMatchObject({
      predecessorVersion: '1.0.0',
      successorVersion: '1.0.1',
    })
  })

  it('compares exact published versions and creates rollback as a new successor draft', async () => {
    const older = structuredClone(canonicalManifestFixture)
    older.manifestVersion = '0.9.0'
    older.workload.displayName = 'Synthetic older workload name'
    const canonicalOlder = await refreshCanonicalManifestDigests(older)
    const views: WirePublishedManifestView[] = [
      {
        published: published(canonicalOlder),
        supersession: {
          manifest_id: canonicalManifestFixture.manifestId,
          superseded_version: '0.9.0',
          replacement_version: '1.0.0',
          superseded_by: actor,
          superseded_at: '2026-08-17T00:00:01.000Z',
          reason: 'Synthetic supersession.',
        },
      },
      { published: published() },
    ]
    let postedDraft: Record<string, unknown> | null = null
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if ((init?.method ?? 'GET') === 'GET' && url.includes('/v1/drafts?')) {
        return jsonResponse([])
      }
      if ((init?.method ?? 'GET') === 'GET' && url.endsWith('/versions')) {
        return jsonResponse(views)
      }
      if ((init?.method ?? 'GET') === 'GET' && url.includes('/compare?')) {
        return jsonResponse({
          manifest_id: canonicalManifestFixture.manifestId,
          from_version: '0.9.0',
          to_version: '1.0.0',
          from_digest: canonicalOlder.compatibility.artifactDigest,
          to_digest: canonicalManifestFixture.compatibility.artifactDigest,
          equivalent: false,
          changed_paths: ['/manifestVersion', '/workload/displayName'],
        })
      }
      if (url.endsWith('/v1/drafts') && init?.method === 'POST') {
        postedDraft = JSON.parse(String(init.body)) as Record<string, unknown>
        const candidate = postedDraft.manifest as CanonicalWorkloadManifest
        return jsonResponse({
          ...draft(candidate),
          draft_id: postedDraft.draft_id,
          previous_version: postedDraft.previous_version,
          rollback_source_version: postedDraft.rollback_source_version,
          reason: postedDraft.reason,
        }, 201)
      }
      throw new Error(`Unexpected request: ${url}`)
    })
    const client = createContextApiClient({
      baseUrl: 'https://context.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: fetchMock as typeof fetch,
      createId: () => 'rollback-id',
    })

    const comparison = await client.comparePublishedVersions(
      canonicalManifestFixture.manifestId,
      '0.9.0',
      '1.0.0',
    )
    const rollback = await client.createRollbackDraft(
      canonicalManifestFixture.manifestId,
      '0.9.0',
      'Create reviewed rollback-by-new-version.',
    )

    expect(comparison.changedPaths).toEqual(['/manifestVersion', '/workload/displayName'])
    expect(rollback.previousVersion).toBe('1.0.0')
    expect(rollback.manifest.manifestVersion).toBe('1.0.1')
    expect(rollback.manifest.workload.displayName).toBe('Synthetic older workload name')
    expect(postedDraft).toMatchObject({
      previous_version: '1.0.0',
      rollback_source_version: '0.9.0',
      reason: 'Create reviewed rollback-by-new-version.',
    })
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

  it('rejects internally inconsistent lifecycle and comparison responses', async () => {
    const mismatchedPublished = {
      ...published(),
      manifest_version: '9.9.9',
    }
    const lifecycleClient = createContextApiClient({
      baseUrl: 'https://context.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: vi.fn(async (input: RequestInfo | URL) =>
        String(input).includes('/v1/drafts?')
          ? jsonResponse([])
          : jsonResponse([{ published: mismatchedPublished }]),
      ) as typeof fetch,
    })

    await expect(
      lifecycleClient.loadWorkloadContext(canonicalManifestFixture.manifestId),
    ).rejects.toThrow(/internally inconsistent/i)

    const comparisonTarget = structuredClone(canonicalManifestFixture)
    comparisonTarget.manifestVersion = '1.0.1'
    const canonicalComparisonTarget = await refreshCanonicalManifestDigests(
      comparisonTarget,
    )
    const comparisonClient = createContextApiClient({
      baseUrl: 'https://context.invalid',
      authPort,
      session: mockAuthSession,
      fetchImpl: vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/v1/drafts?')) return jsonResponse([])
        if (url.endsWith('/versions')) {
          return jsonResponse([
            { published: published() },
            { published: published(canonicalComparisonTarget) },
          ])
        }
        return jsonResponse({
          manifest_id: canonicalManifestFixture.manifestId,
          from_version: '8.8.8',
          to_version: '9.9.9',
          from_digest: canonicalManifestFixture.compatibility.artifactDigest,
          to_digest: canonicalComparisonTarget.compatibility.artifactDigest,
          equivalent: false,
          changed_paths: ['/manifestVersion'],
        })
      }) as typeof fetch,
    })

    await expect(comparisonClient.comparePublishedVersions(
      canonicalManifestFixture.manifestId,
      '1.0.0',
      '1.0.1',
    )).rejects.toThrow(/different versions/i)
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
