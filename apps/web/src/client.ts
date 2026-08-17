import { authFixture, workloadFixtureMap } from './data/fixtures'
import type {
  ApprovalDecision,
  AuthState,
  CatalogItem,
  ContextApiClientPort,
  DraftRecord,
  ManifestDraft,
  PublishRequest,
  PublishedManifest,
  RoleName,
  WorkloadContext,
} from './types'

const draftStore = new Map<string, DraftRecord>()
const publishedStore = new Map<string, PublishedManifest>()

function stableStringify(value: unknown): string {
  return JSON.stringify(value, (_key, nestedValue) => {
    if (nestedValue && typeof nestedValue === 'object' && !Array.isArray(nestedValue)) {
      return Object.fromEntries(Object.entries(nestedValue).sort(([left], [right]) => left.localeCompare(right)))
    }
    return nestedValue
  })
}

function stableDigest(value: string): string {
  let hash = 2166136261
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return `sha256:${(hash >>> 0).toString(16).padStart(64, '0')}`
}

function digestManifest(manifest: ManifestDraft): string {
  return stableDigest(stableStringify(manifest))
}

function currentIso(): string {
  return new Date().toISOString()
}

function buildActor(role: RoleName): AuthState {
  return {
    ...authFixture,
    role,
    actorId: `human-${role}`,
    userLabel: `Human ${role}`,
  }
}

function toWorkloadContext(workloadId: string, draftOverride?: DraftRecord | null): WorkloadContext {
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

async function resolveWorkloads(): Promise<CatalogItem[]> {
  return Promise.resolve(Object.values(workloadFixtureMap).map((entry) => entry.workloadCatalogue[0] ?? {
    id: entry.workloadId,
    name: entry.manifest.workloadName,
    owner: entry.manifest.businessOwner,
    criticality: 'Tier-1',
    zoneCount: 2,
    status: 'Healthy',
  }))
}

export const createContextApiClient = (): ContextApiClientPort => ({
  auth: authFixture,
  loadWorkloads: async () => resolveWorkloads(),
  loadWorkloadContext: async (workloadId: string) => toWorkloadContext(workloadId),
  loadWorkloadSync: (workloadId: string) => toWorkloadContext(workloadId),
  reloadWorkload: async (workloadId: string) => toWorkloadContext(workloadId),
  createDraft: async (workloadId, manifest, reason) => {
    const current = draftStore.get(`draft-${workloadId}`)
    if (current) {
      throw new Error('A draft already exists for this workload; reload and update it instead.')
    }

    const created: DraftRecord = {
      draftId: `draft-${workloadId}`,
      manifestId: workloadId,
      state: 'draft',
      revision: 1,
      manifest,
      manifestDigest: digestManifest(manifest),
      previousVersion: null,
      createdBy: buildActor('proposer'),
      createdAt: currentIso(),
      updatedBy: buildActor('proposer'),
      updatedAt: currentIso(),
      reason,
      validation: null,
      review: null,
      approval: null,
    }

    draftStore.set(created.draftId, created)
    return created
  },
  updateDraft: async ({
    draftId,
    expectedRevision,
    expectedManifestVersion,
    expectedDigest,
    replacementManifest,
    reason,
  }) => {
    const current = draftStore.get(draftId)
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
    if (replacementManifest.manifestId !== current.manifestId) {
      throw new Error('Manifest identity mismatch is not permitted for publication or save operations.')
    }

    const nextDraft: DraftRecord = {
      ...current,
      revision: current.revision + 1,
      manifest: replacementManifest,
      manifestDigest: digestManifest(replacementManifest),
      updatedBy: buildActor('proposer'),
      updatedAt: currentIso(),
      reason,
      validation: null,
      review: null,
      approval: null,
      state: 'draft',
    }

    draftStore.set(draftId, nextDraft)
    return nextDraft
  },
  validateDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
    const current = draftStore.get(draftId)
    if (!current) {
      throw new Error('Draft not found while validating.')
    }
    if (
      current.revision !== expectedRevision ||
      current.manifest.manifestVersion !== expectedManifestVersion ||
      current.manifestDigest !== expectedDigest
    ) {
      throw new Error('Validation was rejected because the draft changed during review.')
    }

    const updated: DraftRecord = {
      ...current,
      state: 'validated',
      revision: current.revision + 1,
      updatedBy: buildActor('proposer'),
      updatedAt: currentIso(),
      reason,
      validation: {
        validatedBy: buildActor('proposer'),
        validatedAt: currentIso(),
        validatedRevision: current.revision + 1,
        manifestDigest: current.manifestDigest,
      },
    }
    draftStore.set(draftId, updated)
    return updated
  },
  submitForReview: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
    const current = draftStore.get(draftId)
    if (!current) {
      throw new Error('Draft not found while submitting for review.')
    }
    if (
      current.revision !== expectedRevision ||
      current.manifest.manifestVersion !== expectedManifestVersion ||
      current.manifestDigest !== expectedDigest
    ) {
      throw new Error('Submit for review failed because the draft revision is stale.')
    }
    const updated: DraftRecord = {
      ...current,
      state: 'in_review',
      revision: current.revision + 1,
      updatedBy: buildActor('proposer'),
      updatedAt: currentIso(),
      reason,
      review: {
        submittedBy: buildActor('proposer'),
        submittedAt: currentIso(),
        submittedRevision: current.revision + 1,
        reason,
      },
    }
    draftStore.set(draftId, updated)
    return updated
  },
  approveDraft: async ({ draftId, expectedRevision, expectedManifestVersion, expectedDigest, reason }) => {
    const current = draftStore.get(draftId)
    if (!current) {
      throw new Error('Draft not found while approving.')
    }
    if (
      current.revision !== expectedRevision ||
      current.manifest.manifestVersion !== expectedManifestVersion ||
      current.manifestDigest !== expectedDigest
    ) {
      throw new Error('Approval requires the latest manifest revision and digest.')
    }
    const approval: ApprovalDecision = {
      decisionId: `approval-${draftId}`,
      approvedBy: buildActor('approver'),
      approvedAt: currentIso(),
      approvedRevision: current.revision + 1,
      manifestVersion: current.manifest.manifestVersion,
      manifestDigest: current.manifestDigest,
      reason,
    }
    const updated: DraftRecord = {
      ...current,
      state: 'approved',
      revision: current.revision + 1,
      updatedBy: buildActor('approver'),
      updatedAt: currentIso(),
      reason,
      approval,
    }
    draftStore.set(draftId, updated)
    return updated
  },
  publishDraft: async ({
    workloadId,
    draftId,
    manifestId,
    expectedRevision,
    expectedManifestVersion,
    expectedDigest,
    approvalId,
    reason,
  }) => {
    const draft = draftStore.get(draftId)
    if (!draft) {
      throw new Error('Draft not found before publication.')
    }
    if (draft.manifestId !== manifestId || workloadId !== manifestId) {
      throw new Error('Workload identity mismatch prevented publication.')
    }
    if (draft.revision !== expectedRevision) {
      throw new Error('The publication revision is stale; reload the draft and retry.')
    }
    if (
      draft.manifest.manifestVersion !== expectedManifestVersion ||
      draft.manifestDigest !== expectedDigest
    ) {
      throw new Error('The expected manifest version or digest does not match the current draft.')
    }
    if (!draft.approval) {
      throw new Error('Publication requires a server-derived approval decision.')
    }
    if (draft.approval.decisionId !== approvalId) {
      throw new Error('The approval record is invalid for this draft revision.')
    }

    const published: PublishedManifest = {
      manifestId,
      manifestVersion: draft.manifest.manifestVersion,
      manifestDigest: draft.manifestDigest,
      sourceDraftId: draftId,
      sourceDraftRevision: draft.revision + 1,
      previousVersion: null,
      approval: draft.approval,
      publishedBy: buildActor('publisher'),
      publishedAt: currentIso(),
      reason,
    }

    const updatedDraft: DraftRecord = {
      ...draft,
      state: 'published',
      revision: draft.revision + 1,
      updatedBy: buildActor('publisher'),
      updatedAt: currentIso(),
      reason,
    }

    draftStore.set(draftId, updatedDraft)
    publishedStore.set(workloadId, published)
    return published
  },
})

export type { PublishRequest }
