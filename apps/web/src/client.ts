import { authFixture, wc007DraftApiFixture, wc007PublishedApiFixture, workloadFixtureMap } from './data/fixtures'
import type {
  ApprovalDecision,
  AuthState,
  CatalogItem,
  ComparisonRow,
  ContextApiClientOptions,
  ContextApiClientPort,
  DraftRecord,
  ManifestDraft,
  PublishRequest,
  PublishedManifest,
  TopologyRelationship,
  WorkloadContext,
  WireDraftRecord,
  WirePublishedManifest,
} from './types'

const cloneManifest = (manifest: ManifestDraft): ManifestDraft => ({
  ...manifest,
  requiredRelationships: [...manifest.requiredRelationships],
  optionalRelationships: [...manifest.optionalRelationships],
  controls: manifest.controls.map((control) => ({ ...control })),
  riskAcceptances: manifest.riskAcceptances.map((acceptance) => ({ ...acceptance })),
  compatibility: manifest.compatibility
    ? {
        ...manifest.compatibility,
        requiresCapabilities: [...manifest.compatibility.requiresCapabilities],
      }
    : undefined,
})

const resolveManifestDigest = (manifest?: ManifestDraft | null): string => {
  if (!manifest) {
    return ''
  }
  return manifest.manifestDigest ?? manifest.compatibility?.artifactDigest ?? ''
}

const compareRows = (environment: string): ComparisonRow[] => {
  const envName = environment === 'Production' ? 'Production' : environment
  return [
    {
      environment: 'Production',
      topology: envName === 'Production'
        ? 'Web tier spans two zones; database VM remains singleton in one zone.'
        : 'Production profile keeps the fail-safe topology and private data plane.',
      policy: 'Protect recovery posture; no unsupported HA recommendation.',
      residualRisk: 'Single-zone database loss remains accepted with restore and failover posture.',
      confidence: 0.93,
    },
    {
      environment: 'Development',
      topology: 'One-zone web and singleton database remain acceptable for the lower-risk profile.',
      policy: 'Developer operations stay in the sandbox profile and do not assume production continuity.',
      residualRisk: 'Residual risk is limited to the control-tested local sandbox range.',
      confidence: 0.89,
    },
    {
      environment: 'Training',
      topology: 'Synthetic training data remains isolated and reset to a known-good baseline.',
      policy: 'No production continuity expectation and no customer data persistence are allowed.',
      residualRisk: 'Training residual risk is intentionally disposable and limited to synthetic scope.',
      confidence: 0.94,
    },
  ]
}

const buildRelationships = (manifest: ManifestDraft): TopologyRelationship[] => {
  const declared = manifest.requiredRelationships.map((item, index) => ({
    kind: 'declared' as const,
    title: item,
    detail: `Declared intent ${index + 1} for ${manifest.workloadName}.`,
    clause: `intent.${manifest.manifestId}.${index + 1}`,
  }))

  const observed = manifest.optionalRelationships.map((item, index) => ({
    kind: 'observed' as const,
    title: item,
    detail: `Observed context record for ${manifest.workloadName}.`,
    clause: `observed.${manifest.manifestId}.${index + 1}`,
  }))

  return [
    ...declared,
    ...observed,
    {
      kind: 'inferred',
      title: 'Residual risk remains visible and bounded by explicit risk acceptance.',
      detail: 'The policy engine retains real residual risk without inventing unsupported HA advice.',
      clause: 'risk.residual.visible',
    },
    {
      kind: 'exception',
      title: 'Unsupported generic high-availability advice is suppressed.',
      detail: 'Athena preserves the actual risk posture and avoids spurious production guidance.',
      clause: 'context.policy.no_generic_ha',
    },
  ]
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
  manifestDigest: resolveManifestDigest(manifest),
  compatibility: manifest.compatibility
    ? {
        artifactKind: manifest.compatibility.artifactKind,
        artifactDigest: manifest.compatibility.artifactDigest,
        semanticDigest: manifest.compatibility.semanticDigest,
        schemaVersion: manifest.compatibility.schemaVersion,
        semanticContractVersion: manifest.compatibility.semanticContractVersion,
        policyContractVersion: manifest.compatibility.policyContractVersion,
        minimumReaderVersion: manifest.compatibility.minimumReaderVersion,
        requiresCapabilities: [...manifest.compatibility.requiresCapabilities],
      }
    : undefined,
})

const toViewActor = (actor: { actor_id: string; kind: 'human' | 'agent' | 'service' }): { actorId: string; kind: 'human' | 'agent' | 'service' } => ({
  actorId: actor.actor_id,
  kind: actor.kind,
})

const toViewManifest = (manifest: ManifestDraft): ManifestDraft => ({
  ...cloneManifest(manifest),
  requiredRelationships: [...manifest.requiredRelationships],
  optionalRelationships: [...manifest.optionalRelationships],
  controls: manifest.controls.map((control) => ({ ...control })),
  riskAcceptances: manifest.riskAcceptances.map((acceptance) => ({ ...acceptance })),
})

const toViewDraft = (wire: WireDraftRecord): DraftRecord => ({
  draftId: wire.draft_id,
  manifestId: wire.manifest_id,
  state: wire.state,
  revision: wire.revision,
  manifest: toViewManifest(wire.manifest),
  manifestDigest: wire.manifest_digest,
  previousVersion: wire.previous_version,
  createdBy: toViewActor(wire.created_by),
  createdAt: wire.created_at,
  updatedBy: toViewActor(wire.updated_by),
  updatedAt: wire.updated_at,
  reason: wire.reason,
  validation: wire.validation
    ? {
        validatedBy: toViewActor(wire.validation.validated_by),
        validatedAt: wire.validation.validated_at,
        validatedRevision: wire.validation.validated_revision,
        manifestDigest: wire.validation.manifest_digest,
      }
    : null,
  review: wire.review
    ? {
        submittedBy: toViewActor(wire.review.submitted_by),
        submittedAt: wire.review.submitted_at,
        submittedRevision: wire.review.submitted_revision,
        publicationCandidateDigest: wire.review.publication_candidate_digest,
        reason: wire.review.reason,
      }
    : null,
  publicationCandidate: wire.publication_candidate
    ? {
        finalizedBy: toViewActor(wire.publication_candidate.finalized_by),
        finalizedAt: wire.publication_candidate.finalized_at,
        manifestVersion: wire.publication_candidate.manifest_version,
        manifestDigest: wire.publication_candidate.manifest_digest,
        semanticDigest: wire.publication_candidate.semantic_digest,
        approvalStatus: 'approved',
      }
    : null,
  approval: wire.approval
    ? {
        decisionId: wire.approval.decision_id,
        approvedBy: toViewActor(wire.approval.approved_by),
        approvedAt: wire.approval.approved_at,
        approvedRevision: wire.approval.approved_revision,
        manifestVersion: wire.approval.manifest_version,
        manifestDigest: wire.approval.manifest_digest,
        reason: wire.approval.reason,
      }
    : null,
})

const toViewPublished = (wire: WirePublishedManifest): PublishedManifest => ({
  manifestId: wire.manifest_id,
  manifestVersion: wire.manifest_version,
  manifestDigest: wire.manifest_digest,
  manifest: toViewManifest(wire.manifest),
  sourceDraftId: wire.source_draft_id,
  sourceDraftRevision: wire.source_draft_revision,
  previousVersion: wire.previous_version,
  approval: {
    decisionId: wire.approval.decision_id,
    approvedBy: toViewActor(wire.approval.approved_by),
    approvedAt: wire.approval.approved_at,
    approvedRevision: wire.approval.approved_revision,
    manifestVersion: wire.approval.manifest_version,
    manifestDigest: wire.approval.manifest_digest,
    reason: wire.approval.reason,
  },
  publishedBy: toViewActor(wire.published_by),
  publishedAt: wire.published_at,
  publicationAuthorizedBy: toViewActor(wire.publication_authorized_by),
  publicationAuthorizedAt: wire.publication_authorized_at,
  reason: wire.reason,
})

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
    !headers.has('Idempotency-Key')
  ) {
    headers.set('Idempotency-Key', crypto.randomUUID())
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

const ensureHttpClientOptions = (options: ContextApiClientOptions): ContextApiClientOptions => {
  if (!options || !options.auth || !options.baseUrl) {
    throw new Error('Context API client requires an injected auth state and baseUrl. Do not use fixture defaults in runtime.')
  }
  if (typeof options.baseUrl !== 'string' || !options.baseUrl.trim()) {
    throw new Error('Context API client baseUrl must be configured explicitly.')
  }
  if (!options.auth.bearerToken || !options.auth.actorId) {
    throw new Error('Context API client requires an authenticated actor and bearer token.')
  }
  return options
}

export const createContextApiClient = (options: ContextApiClientOptions): ContextApiClientPort => {
  const config = ensureHttpClientOptions(options)
  const authState = config.auth
  const baseUrl = config.baseUrl
  const fetchImpl = config.fetchImpl ?? globalThis.fetch
  const draftStore = new Map<string, DraftRecord>()
  const publishedStore = new Map<string, PublishedManifest>()
  const contextCache = new Map<string, WorkloadContext>()

  const buildWorkloadCatalogue = async (): Promise<CatalogItem[]> => {
    const drafts = await requestJson<WireDraftRecord[]>(baseUrl, '/v1/drafts', { method: 'GET' }, authState, fetchImpl)
    const workloadIds = Array.from(
      new Set(drafts.map((draft) => draft.manifest_id)),
    )

    if (workloadIds.length === 0) {
      return []
    }

    return workloadIds.map((workloadId) => {
      const source = drafts.find((draft) => draft.manifest_id === workloadId)
      const manifest = source?.manifest
      return {
        id: workloadId,
        name: manifest?.workloadName ?? workloadId,
        owner: manifest?.businessOwner ?? 'Service owner',
        criticality: 'Tier-1',
        zoneCount: 2,
        status: 'Healthy',
      }
    })
  }

  const buildContext = async (workloadId: string): Promise<WorkloadContext> => {
    const drafts = await requestJson<WireDraftRecord[]>(
      baseUrl,
      `/v1/drafts?manifest_id=${encodeURIComponent(workloadId)}`,
      { method: 'GET' },
      authState,
      fetchImpl,
    )
    const publishedVersions = await requestJson<WirePublishedManifest[]>(
      baseUrl,
      `/v1/manifests/${encodeURIComponent(workloadId)}/versions`,
      { method: 'GET' },
      authState,
      fetchImpl,
    )

    if (drafts.length === 0 && publishedVersions.length === 0) {
      throw new Error(`Unknown workload or no lifecycle state available for ${workloadId}.`)
    }

    const draft = drafts.length > 0
      ? toViewDraft(drafts.reduce((current, candidate) => (candidate.revision > current.revision ? candidate : current)))
      : null

    const published = publishedVersions.length > 0
      ? toViewPublished(publishedVersions.reduce((current, candidate) => (candidate.source_draft_revision > current.source_draft_revision ? candidate : current)))
      : null

    const manifest = draft?.manifest ?? published?.manifest ?? null
    if (!manifest) {
      throw new Error(`No manifest payload was returned for ${workloadId}.`)
    }

    const catalogue = await buildWorkloadCatalogue()
    const workloadCatalogue = catalogue.length > 0
      ? catalogue
      : [{
          id: workloadId,
          name: manifest.workloadName,
          owner: manifest.businessOwner,
          criticality: 'Tier-1',
          zoneCount: 2,
          status: 'Healthy',
        }]

    const lookupDraft = draft ?? null
    const nextContext: WorkloadContext = {
      workloadId,
      auth: authState,
      environment: manifest.environment,
      evidenceSource: published ? 'WC-007 published manifest' : 'WC-007 draft state',
      confidence: published ? 0.96 : 0.91,
      manifestVersion: manifest.manifestVersion,
      approvalState: lookupDraft?.state ?? 'draft',
      workloadCatalogue,
      comparison: compareRows(manifest.environment),
      relationships: buildRelationships(manifest),
      manifest,
      controls: manifest.controls,
      riskAcceptances: manifest.riskAcceptances,
      provenance: [{
        id: `prov-${workloadId}`,
        source: 'WC-007 Context API',
        summary: 'Manifest and draft lifecycle state were loaded from the authenticated context API.',
        clause: 'context.lifecycle.api',
        manifestVersion: manifest.manifestVersion,
        confidence: 0.94,
      }],
      validationMessages: lookupDraft?.validation ? [] : ['Draft requires validation before review.'],
      draft: lookupDraft,
      published,
    }

    contextCache.set(workloadId, nextContext)
    if (draft) {
      draftStore.set(draft.draftId, draft)
    }
    if (published) {
      publishedStore.set(workloadId, published)
    }

    return nextContext
  }

  return {
    auth: authState,
    loadWorkloads: async () => buildWorkloadCatalogue(),
    loadWorkloadContext: async (workloadId: string) => buildContext(workloadId),
    loadWorkloadSync: (workloadId: string) => {
      const cached = contextCache.get(workloadId)
      if (!cached) {
        throw new Error(`Workload ${workloadId} has not been loaded yet.`)
      }
      return cached
    },
    reloadWorkload: async (workloadId: string) => buildContext(workloadId),
    createDraft: async (workloadId: string, manifest: ManifestDraft, reason: string) => {
      const draftId = `draft-${workloadId}-${Date.now()}`
      const activePublished = publishedStore.get(workloadId)
      const previousVersion = activePublished?.manifestVersion ?? null
      const manifestVersion = manifest.manifestVersion || '1.0.0'
      const targetDraftManifest: ManifestDraft = {
        ...cloneManifest(manifest),
        manifestVersion,
        manifestDigest: resolveManifestDigest(manifest) || manifest.compatibility?.artifactDigest || 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
      }

      const response = await requestJson<WireDraftRecord>(
        baseUrl,
        '/v1/drafts',
        {
          method: 'POST',
          body: JSON.stringify({
            draft_id: draftId,
            manifest: canonicalManifestPayload(targetDraftManifest),
            manifest_digest: resolveManifestDigest(targetDraftManifest),
            previous_version: previousVersion,
            reason,
          }),
        },
        authState,
        fetchImpl,
      )

      const draft = toViewDraft(response)
      draftStore.set(draft.draftId, draft)
      const nextContext = await buildContext(workloadId)
      contextCache.set(workloadId, nextContext)
      return draft
    },
    updateDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, replacementManifest, reason }) => {
      const response = await requestJson<WireDraftRecord>(
        baseUrl,
        `/v1/drafts/${encodeURIComponent(draftId)}`,
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
      const draft = toViewDraft(response)
      draftStore.set(draft.draftId, draft)
      return draft
    },
    validateDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
      const response = await requestJson<WireDraftRecord>(
        baseUrl,
        `/v1/drafts/${encodeURIComponent(draftId)}/validate`,
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
      const draft = toViewDraft(response)
      draftStore.set(draft.draftId, draft)
      return draft
    },
    submitForReview: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
      const response = await requestJson<WireDraftRecord>(
        baseUrl,
        `/v1/drafts/${encodeURIComponent(draftId)}/submit`,
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
      const draft = toViewDraft(response)
      draftStore.set(draft.draftId, draft)
      return draft
    },
    approveDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
      const response = await requestJson<WireDraftRecord>(
        baseUrl,
        `/v1/drafts/${encodeURIComponent(draftId)}/approve`,
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
      const draft = toViewDraft(response)
      draftStore.set(draft.draftId, draft)
      return draft
    },
    publishDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, approvalId, reason }) => {
      const response = await requestJson<WirePublishedManifest>(
        baseUrl,
        `/v1/drafts/${encodeURIComponent(draftId)}/publish`,
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
      const published = toViewPublished(response)
      publishedStore.set(published.manifestId, published)
      return published
    },
  }
}

export const createMockContextApiClient = (authState: AuthState = authFixture): ContextApiClientPort => {
  const localDraftStore = new Map<string, DraftRecord>()
  const localPublishedStore = new Map<string, PublishedManifest>()
  const localContextCache = new Map<string, WorkloadContext>()

  const toContext = (workloadId: string): WorkloadContext => {
    const seed = workloadFixtureMap[workloadId] ?? workloadFixtureMap['atlas-api']
    const currentDraft = localDraftStore.get(`draft-${workloadId}`) ?? null
    const published = localPublishedStore.get(workloadId) ?? null
    const manifest = currentDraft?.manifest ?? published?.manifest ?? seed.manifest
    const manifestVersion = currentDraft?.manifest.manifestVersion ?? published?.manifestVersion ?? seed.manifest.manifestVersion
    const comparison = compareRows(manifest.environment)
    const relationships = buildRelationships(manifest)
    const context: WorkloadContext = {
      ...seed,
      workloadId,
      auth: authState,
      environment: manifest.environment,
      evidenceSource: published ? 'WC-007 published manifest' : 'WC-007 fixture draft',
      confidence: 0.92,
      manifestVersion,
      approvalState: currentDraft?.state ?? seed.approvalState,
      workloadCatalogue: seed.workloadCatalogue,
      comparison,
      relationships,
      manifest,
      controls: manifest.controls,
      riskAcceptances: manifest.riskAcceptances,
      provenance: [
        {
          id: `prov-${workloadId}`,
          source: 'Synthetic fixture snapshot',
          summary: 'Synthetic fixture data is clearly fake and isolated to the WC-011 prototype.',
          clause: 'synthetic.fixture.wc-011',
          manifestVersion: manifest.manifestVersion,
          confidence: 0.9,
        },
      ],
      validationMessages: currentDraft?.validation ? [] : ['Draft requires validation before human review.'],
      draft: currentDraft,
      published,
    }
    localContextCache.set(workloadId, context)
    return context
  }

  return {
    auth: authState,
    loadWorkloads: async () => Object.values(workloadFixtureMap).map((entry) => entry.workloadCatalogue[0] ?? {
      id: entry.workloadId,
      name: entry.manifest.workloadName,
      owner: entry.manifest.businessOwner,
      criticality: 'Tier-1',
      zoneCount: 2,
      status: 'Healthy',
    }),
    loadWorkloadContext: async (workloadId: string) => toContext(workloadId),
    loadWorkloadSync: (workloadId: string) => {
      const cached = localContextCache.get(workloadId)
      if (!cached) {
        return toContext(workloadId)
      }
      return cached
    },
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
        previousVersion: localPublishedStore.get(workloadId)?.manifestVersion ?? null,
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
      const publicationCandidate = {
        finalizedBy: { actorId: 'human-approver', kind: 'human' as const },
        finalizedAt: '2026-08-17T00:00:00.000Z',
        manifestVersion: current.manifest.manifestVersion,
        manifestDigest: current.manifestDigest,
        semanticDigest: current.manifestDigest,
        approvalStatus: 'approved' as const,
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
        previousVersion: draft.previousVersion,
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
