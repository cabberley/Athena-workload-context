import { authFixture, wc007DraftApiFixture, wc007PublishedApiFixture, workloadFixtureMap } from './data/fixtures'
import type {
  ApprovalDecision,
  AuthState,
  CatalogItem,
  ContextApiClientOptions,
  ContextApiClientPort,
  DraftRecord,
  ManifestDraft,
  PublicationCandidate,
  PublishRequest,
  PublishedManifest,
  WorkloadContext,
} from './types'

const draftStore = new Map<string, DraftRecord>()
const publishedStore = new Map<string, PublishedManifest>()

const getDefaultBaseUrl = (): string => {
  const envUrl = typeof import.meta !== 'undefined' && import.meta.env ? import.meta.env.VITE_CONTEXT_API_URL : undefined
  return typeof envUrl === 'string' && envUrl.length > 0 ? envUrl : 'http://localhost:8000'
}

const cloneManifest = (manifest: ManifestDraft): ManifestDraft => ({
  ...manifest,
  requiredRelationships: [...manifest.requiredRelationships],
  optionalRelationships: [...manifest.optionalRelationships],
  controls: manifest.controls.map((control) => ({ ...control })),
  riskAcceptances: manifest.riskAcceptances.map((acceptance) => ({ ...acceptance })),
  compatibility: manifest.compatibility ? { ...manifest.compatibility, requiresCapabilities: [...manifest.compatibility.requiresCapabilities] } : undefined,
})

const resolveManifestDigest = (manifest?: ManifestDraft | null): string => {
  if (!manifest) {
    return ''
  }
  return manifest.manifestDigest ?? manifest.compatibility?.artifactDigest ?? ''
}

const canonicalManifestPayload = (manifest: ManifestDraft): Record<string, unknown> => ({
  manifestId: manifest.manifestId,
  manifestVersion: manifest.manifestVersion,
  workloadName: manifest.workloadName,
  environment: manifest.environment,
  businessOwner: manifest.businessOwner,
  runbook: manifest.runbook,
  requiredRelationships: [...manifest.requiredRelationships],
  optionalRelationships: [...manifest.optionalRelationships],
  controls: manifest.controls.map((control) => ({ ...control })),
  riskAcceptances: manifest.riskAcceptances.map((acceptance) => ({ ...acceptance })),
  compatibility: {
    artifactKind: 'workloadManifest',
    artifactDigest: resolveManifestDigest(manifest),
    semanticDigest: manifest.compatibility?.semanticDigest ?? resolveManifestDigest(manifest),
    schemaVersion: manifest.compatibility?.schemaVersion ?? '1.0.0',
    semanticContractVersion: manifest.compatibility?.semanticContractVersion ?? '1.0.0',
    policyContractVersion: manifest.compatibility?.policyContractVersion ?? '1.0.0',
    minimumReaderVersion: manifest.compatibility?.minimumReaderVersion ?? '1.0.0',
    requiresCapabilities: manifest.compatibility?.requiresCapabilities ?? [],
  },
})

const toWorkloadContext = (workloadId: string, draftOverride?: DraftRecord | null): WorkloadContext => {
  const seed = workloadFixtureMap[workloadId] ?? workloadFixtureMap['atlas-api']
  const currentDraft = draftOverride ?? draftStore.get(`draft-${workloadId}`) ?? null
  const published = publishedStore.get(workloadId) ?? null
  const manifestVersion = currentDraft?.manifest.manifestVersion ?? seed.manifest.manifestVersion
  const approvalState = currentDraft?.state ?? seed.approvalState

  return {
    ...seed,
    workloadId,
    auth: authFixture,
    manifestVersion,
    approvalState,
    manifest: currentDraft?.manifest ?? seed.manifest,
    draft: currentDraft,
    published,
  }
}

const resolveWorkloads = async (): Promise<CatalogItem[]> => {
  return Object.values(workloadFixtureMap).map((entry) => entry.workloadCatalogue[0] ?? {
    id: entry.workloadId,
    name: entry.manifest.workloadName,
    owner: entry.manifest.businessOwner,
    criticality: 'Tier-1',
    zoneCount: 2,
    status: 'Healthy',
  })
}

const requestJson = async <T>(
  baseUrl: string,
  path: string,
  requestInit: RequestInit,
  authState: AuthState,
  fetchImpl: typeof fetch,
): Promise<T> => {
  const headers = new Headers(requestInit.headers ?? {})
  if (!headers.has('Content-Type') && requestInit.body != null) {
    headers.set('Content-Type', 'application/json')
  }
  if (authState.bearerToken) {
    headers.set('Authorization', `Bearer ${authState.bearerToken}`)
}
  if (
    requestInit.method &&
    !['GET', 'HEAD'].includes(requestInit.method.toUpperCase()) &&
    !headers.has('X-Idempotency-Key')
  ) {
    headers.set('X-Idempotency-Key', crypto.randomUUID())
  }

  const response = await fetchImpl(`${baseUrl.replace(/\/+$/, '')}${path}`, {
    ...requestInit,
    headers,
  })

  if (!response.ok) {
    const errorBody = await response.text().catch(() => '')
    let errorMessage = `Request failed (${response.status})`
    if (errorBody) {
      try {
        const parsed = JSON.parse(errorBody) as { error?: { message?: string }; message?: string }
        errorMessage = parsed?.error?.message ?? parsed?.message ?? errorMessage
      } catch {
        errorMessage = errorBody || errorMessage
      }
    }
    throw new Error(errorMessage)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}

const buildHttpClient = (options: ContextApiClientOptions = {}): ContextApiClientPort => {
  const authState = options.auth ?? authFixture
  const baseUrl = options.baseUrl ?? getDefaultBaseUrl()
  const fetchImpl = options.fetchImpl ?? globalThis.fetch

  return {
    auth: authState,
    loadWorkloads: async () => resolveWorkloads(),
    loadWorkloadContext: async (workloadId: string) => toWorkloadContext(workloadId),
    loadWorkloadSync: (workloadId: string) => toWorkloadContext(workloadId),
    reloadWorkload: async (workloadId: string) => toWorkloadContext(workloadId),
    createDraft: async (workloadId: string, manifest: ManifestDraft, reason: string) => {
      const draftId = `draft-${workloadId}`
      const manifestPayload = canonicalManifestPayload(manifest)
      const response = await requestJson<DraftRecord>(
        baseUrl,
        '/v1/drafts',
        {
          method: 'POST',
          body: JSON.stringify({
            draft_id: draftId,
            manifest: manifestPayload,
            manifest_digest: resolveManifestDigest(manifest),
            previous_version: null,
            reason,
          }),
        },
        authState,
        fetchImpl,
      )
      draftStore.set(draftId, response)
      return response
    },
    updateDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, replacementManifest, reason }) => {
      const response = await requestJson<DraftRecord>(
        baseUrl,
        `/v1/drafts/${draftId}`,
        {
          method: 'PUT',
          body: JSON.stringify({
            expected_revision: expectedRevision,
            expected_manifest_version: expectedManifestVersion,
            expected_digest: expectedDigest,
            replacement_manifest: canonicalManifestPayload(replacementManifest),
            replacement_digest: resolveManifestDigest(replacementManifest),
            reason,
          }),
        },
        authState,
        fetchImpl,
      )
      draftStore.set(draftId, response)
      return response
    },
    validateDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
      const response = await requestJson<DraftRecord>(
        baseUrl,
        `/v1/drafts/${draftId}/validate`,
        {
          method: 'POST',
          body: JSON.stringify({
            expected_revision: expectedRevision,
            expected_manifest_version: expectedManifestVersion,
            expected_digest: expectedDigest,
            reason,
          }),
        },
        authState,
        fetchImpl,
      )
      draftStore.set(draftId, response)
      return response
    },
    submitForReview: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
      const response = await requestJson<DraftRecord>(
        baseUrl,
        `/v1/drafts/${draftId}/submit`,
        {
          method: 'POST',
          body: JSON.stringify({
            expected_revision: expectedRevision,
            expected_manifest_version: expectedManifestVersion,
            expected_digest: expectedDigest,
            reason,
          }),
        },
        authState,
        fetchImpl,
      )
      draftStore.set(draftId, response)
      return response
    },
    approveDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
      const response = await requestJson<DraftRecord>(
        baseUrl,
        `/v1/drafts/${draftId}/approve`,
        {
          method: 'POST',
          body: JSON.stringify({
            expected_revision: expectedRevision,
            expected_manifest_version: expectedManifestVersion,
            expected_digest: expectedDigest,
            reason,
          }),
        },
        authState,
        fetchImpl,
      )
      draftStore.set(draftId, response)
      return response
    },
    publishDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, approvalId, reason }) => {
      const response = await requestJson<PublishedManifest>(
        baseUrl,
        `/v1/drafts/${draftId}/publish`,
        {
          method: 'POST',
          body: JSON.stringify({
            expected_revision: expectedRevision,
            expected_manifest_version: expectedManifestVersion,
            expected_digest: expectedDigest,
            approval_id: approvalId,
            reason,
          }),
        },
        authState,
        fetchImpl,
      )
      publishedStore.set(response.manifestId, response)
      if (response.sourceDraftId) {
        const currentDraft = draftStore.get(response.sourceDraftId)
        if (currentDraft) {
          draftStore.set(response.sourceDraftId, { ...currentDraft, state: 'published', approval: response.approval })
        }
      }
      return response
    },
  }
}

export const createContextApiClient = (options: ContextApiClientOptions = {}): ContextApiClientPort => {
  return buildHttpClient(options)
}

export const createMockContextApiClient = (authState: AuthState = authFixture): ContextApiClientPort => {
  const localDraftStore = new Map<string, DraftRecord>()
  const localPublishedStore = new Map<string, PublishedManifest>()

  const toContext = (workloadId: string): WorkloadContext => {
    const seed = workloadFixtureMap[workloadId] ?? workloadFixtureMap['atlas-api']
    const currentDraft = localDraftStore.get(`draft-${workloadId}`) ?? null
    const published = localPublishedStore.get(workloadId) ?? null
    const manifestVersion = currentDraft?.manifest.manifestVersion ?? seed.manifest.manifestVersion
    return {
      ...seed,
      workloadId,
      auth: authState,
      manifestVersion,
      approvalState: currentDraft?.state ?? seed.approvalState,
      manifest: currentDraft?.manifest ?? seed.manifest,
      draft: currentDraft,
      published,
    }
  }

  return {
    auth: authState,
    loadWorkloads: async () => resolveWorkloads(),
    loadWorkloadContext: async (workloadId: string) => toContext(workloadId),
    loadWorkloadSync: (workloadId: string) => toContext(workloadId),
    reloadWorkload: async (workloadId: string) => toContext(workloadId),
    createDraft: async (workloadId: string, manifest: ManifestDraft, reason: string) => {
      const key = `draft-${workloadId}`
      if (localDraftStore.has(key)) {
        throw new Error('A draft already exists for this workload; reload and update it instead.')
      }
      const created: DraftRecord = {
        draftId: key,
        manifestId: workloadId,
        state: 'draft',
        revision: 1,
        manifest: cloneManifest(manifest),
        manifestDigest: resolveManifestDigest(manifest) || wc007DraftApiFixture.manifest_digest || '',
        previousVersion: null,
        createdBy: { actorId: authState.actorId, kind: authState.kind },
        createdAt: '2026-08-17T00:00:00.000Z',
        updatedBy: { actorId: authState.actorId, kind: authState.kind },
        updatedAt: '2026-08-17T00:00:00.000Z',
        reason,
        validation: null,
        review: null,
        publicationCandidate: null,
        approval: null,
      }
      localDraftStore.set(key, created)
      return created
    },
    updateDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, replacementManifest, reason }) => {
      const current = localDraftStore.get(draftId)
      if (!current) {
        throw new Error('Draft not found; create a new draft before updating.')
      }
      if (
        current.revision !== expectedRevision ||
        current.manifest.manifestVersion !== expectedManifestVersion ||
        current.manifestDigest !== expectedDigest
      ) {
        throw new Error('Concurrent change detected. Reload the draft and apply your edit against the latest revision.')
      }
      const nextDraft: DraftRecord = {
        ...current,
        revision: current.revision + 1,
        manifest: cloneManifest(replacementManifest),
        manifestDigest: resolveManifestDigest(replacementManifest) || expectedDigest,
        updatedBy: { actorId: authState.actorId, kind: authState.kind },
        updatedAt: '2026-08-17T00:00:00.000Z',
        reason,
        validation: null,
        review: null,
        publicationCandidate: null,
        approval: null,
        state: 'draft',
      }
      localDraftStore.set(draftId, nextDraft)
      return nextDraft
    },
    validateDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
      const current = localDraftStore.get(draftId)
      if (!current) {
        throw new Error('Draft not found while validating.')
      }
      if (
        current.revision !== expectedRevision ||
        current.manifest.manifestVersion !== expectedManifestVersion ||
        current.manifestDigest !== expectedDigest
      ) {
        throw new Error('Concurrent change detected. Reload the draft before validation.')
      }
      const updated: DraftRecord = {
        ...current,
        state: 'validated',
        revision: current.revision + 1,
        updatedBy: { actorId: authState.actorId, kind: authState.kind },
        updatedAt: '2026-08-17T00:00:00.000Z',
        reason,
        validation: {
          validatedBy: { actorId: authState.actorId, kind: authState.kind },
          validatedAt: '2026-08-17T00:00:00.000Z',
          validatedRevision: current.revision + 1,
          manifestDigest: current.manifestDigest,
        },
        publicationCandidate: null,
      }
      localDraftStore.set(draftId, updated)
      return updated
    },
    submitForReview: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
      const current = localDraftStore.get(draftId)
      if (!current) {
        throw new Error('Draft not found while submitting for review.')
      }
      if (
        current.revision !== expectedRevision ||
        current.manifest.manifestVersion !== expectedManifestVersion ||
        current.manifestDigest !== expectedDigest
      ) {
        throw new Error('Concurrent change detected. Reload the draft before review submission.')
      }
      const updated: DraftRecord = {
        ...current,
        state: 'in_review',
        revision: current.revision + 1,
        updatedBy: { actorId: authState.actorId, kind: authState.kind },
        updatedAt: '2026-08-17T00:00:00.000Z',
        reason,
        review: {
          submittedBy: { actorId: authState.actorId, kind: authState.kind },
          submittedAt: '2026-08-17T00:00:00.000Z',
          submittedRevision: current.revision + 1,
          publicationCandidateDigest: current.manifestDigest,
          reason,
        },
        publicationCandidate: null,
      }
      localDraftStore.set(draftId, updated)
      return updated
    },
    approveDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
      const current = localDraftStore.get(draftId)
      if (!current) {
        throw new Error('Draft not found while approving.')
      }
      if (
        current.revision !== expectedRevision ||
        current.manifest.manifestVersion !== expectedManifestVersion ||
        current.manifestDigest !== expectedDigest
      ) {
        throw new Error('Concurrent change detected. Reload the draft before approval.')
      }
      const approval: ApprovalDecision = {
        decisionId: `approval-${draftId}`,
        approvedBy: { actorId: 'human-approver', kind: 'human' as const },
        approvedAt: '2026-08-17T00:00:00.000Z',
        approvedRevision: current.revision + 1,
        manifestVersion: current.manifest.manifestVersion,
        manifestDigest: current.manifestDigest,
        reason,
      }
      const publicationCandidate: PublicationCandidate = {
        finalizedBy: { actorId: 'human-approver', kind: 'human' as const },
        finalizedAt: '2026-08-17T00:00:00.000Z',
        manifestVersion: current.manifest.manifestVersion,
        manifestDigest: current.manifestDigest,
        semanticDigest: current.manifestDigest,
        approvalStatus: 'approved',
      }
      const updated: DraftRecord = {
        ...current,
        state: 'approved',
        revision: current.revision + 1,
        updatedBy: { actorId: 'human-approver', kind: 'human' as const },
        updatedAt: '2026-08-17T00:00:00.000Z',
        reason,
        approval,
        publicationCandidate,
      }
      localDraftStore.set(draftId, updated)
      return updated
    },
    publishDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, approvalId, reason }) => {
      const draft = localDraftStore.get(draftId)
      if (!draft) {
        throw new Error('Draft not found before publication.')
      }
      if (
        draft.revision !== expectedRevision ||
        draft.manifest.manifestVersion !== expectedManifestVersion ||
        draft.manifestDigest !== expectedDigest
      ) {
        throw new Error('Concurrent change detected. Reload the draft before publication.')
      }
      if (!draft.approval) {
        throw new Error('Publication requires a server-derived approval decision.')
      }
      if (draft.approval.decisionId !== approvalId) {
        throw new Error('The approval record is invalid for this draft revision.')
      }
      const published: PublishedManifest = {
        manifestId: draft.manifestId,
        manifestVersion: draft.manifest.manifestVersion,
        manifestDigest: draft.manifestDigest,
        manifest: cloneManifest(draft.manifest),
        sourceDraftId: draftId,
        sourceDraftRevision: draft.revision + 1,
        previousVersion: null,
        approval: draft.approval,
        publishedBy: { actorId: 'human-publisher', kind: 'human' as const },
        publishedAt: '2026-08-17T00:00:00.000Z',
        publicationAuthorizedBy: { actorId: 'athena-context-api', kind: 'service' as const },
        publicationAuthorizedAt: '2026-08-17T00:00:00.000Z',
        reason,
      }
      localDraftStore.set(draftId, { ...draft, state: 'published', revision: draft.revision + 1 })
      localPublishedStore.set(draft.manifestId, published)
      return published
    },
  }
}

export { wc007DraftApiFixture, wc007PublishedApiFixture }
export type { PublishRequest }
