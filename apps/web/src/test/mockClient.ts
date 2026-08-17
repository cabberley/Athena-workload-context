import canonicalFixture from '../../../../src/athena_context/data/fixtures/canonical-manifest.json'
import { refreshCanonicalManifestDigests } from '../canonical'
import type {
  ApprovalDecision,
  AuthSession,
  CanonicalWorkloadManifest,
  ConcurrencyRequest,
  ContextApiClientPort,
  DraftRecord,
  PublishRequest,
  PublishedManifest,
  WorkloadContext,
} from '../types'

const manifest = canonicalFixture as unknown as CanonicalWorkloadManifest

const defaultSession: AuthSession = {
  actorId: 'human-publisher',
  kind: 'human',
  role: 'publisher',
  userLabel: 'Synthetic human publisher',
  port: 'explicit-test-adapter',
  authorizedWorkloadIds: [manifest.manifestId],
}

const actor = (session: AuthSession) => ({ actorId: session.actorId, kind: session.kind })
const timestamp = '2026-08-17T00:00:00.000Z'

const assertConcurrency = (draft: DraftRecord | null, request: ConcurrencyRequest): DraftRecord => {
  if (!draft) throw new Error('Synthetic draft not found.')
  if (
    draft.draftId !== request.draftId ||
    draft.revision !== request.expectedRevision ||
    draft.manifest.manifestVersion !== request.expectedManifestVersion ||
    draft.manifestDigest !== request.expectedDigest
  ) {
    throw new Error('Synthetic concurrent change detected.')
  }
  return draft
}

const makeContext = (
  session: AuthSession,
  currentDraft: DraftRecord | null,
  published: PublishedManifest | null,
): WorkloadContext => {
  const selectedManifest = currentDraft?.manifest ?? published?.manifest ?? manifest
  const activeDraft = currentDraft && !['published', 'superseded'].includes(currentDraft.state) ? currentDraft : null
  const owner = selectedManifest.ownership[0]?.ownerRef ?? null
  return {
    workloadId: selectedManifest.manifestId,
    auth: session,
    environment: selectedManifest.workload.environments[0]!,
    evidenceSource: 'Explicit synthetic test adapter; not a production evidence source.',
    confidence: null,
    manifestVersion: selectedManifest.manifestVersion,
    approvalState: activeDraft?.state ?? (published ? 'published' : 'draft'),
    catalogueItem: {
      id: selectedManifest.manifestId,
      name: selectedManifest.workload.displayName,
      owner,
      criticality: null,
      zoneCount: null,
      status: activeDraft?.state ?? (published ? 'published' : 'draft'),
    },
    comparison: ['production', 'development', 'training'].map((profileId) => {
      const profile = selectedManifest.profiles[profileId]!
      return {
        environment: profile.profileType,
        topology: `${profile.roles.length} profile roles and ${profile.relationships.length} profile relationships declared.`,
        policy: `${profile.constraints.length} constraints and ${profile.controls.length} controls declared.`,
        residualRisk: profile.riskAcceptances.map((risk) => risk.residualRiskStatement).join(' '),
        confidence: null,
        relationshipKind: 'declared' as const,
      }
    }),
    relationships: selectedManifest.relationships.map((relationship) => {
      if (relationship.relationshipClass === 'exception') {
        const targetRef = relationship.appliesToRelationshipRef ?? relationship.appliesToClauseRef!
        return {
          id: relationship.exceptionId,
          kind: 'exception' as const,
          targetType: relationship.appliesToRelationshipRef ? 'relationship' as const : 'clause' as const,
          targetRef,
          riskAcceptanceRef: relationship.riskAcceptanceRef,
          governanceScope: structuredClone(relationship.governanceScope),
          ownerRef: relationship.ownerRef,
          rationale: relationship.rationale,
          expiresAt: relationship.expiresAt,
          profileId: null,
        }
      }
      const endpoint = (value: typeof relationship.source): string =>
        value.endpointType === 'role' ? value.roleRef : value.externalRef
      return {
        id: relationship.relationshipId,
        kind: 'declared' as const,
        relationshipType: relationship.kind,
        source: endpoint(relationship.source),
        target: endpoint(relationship.target),
        ownerRef: relationship.ownerRef,
        clause: relationship.sourceClause,
        profileId: null,
      }
    }),
    manifest: structuredClone(selectedManifest),
    controls: Object.values(selectedManifest.profiles).flatMap((profile) =>
      profile.controls.map((control) => ({
        id: control.controlId,
        ownerRef: control.ownerRef,
        health: control.health,
        runbookRef: control.runbookRef ?? null,
        profiles: [...control.profiles],
      })),
    ),
    riskAcceptances: Object.values(selectedManifest.profiles).flatMap((profile) =>
      profile.riskAcceptances.map((risk) => ({
        id: risk.riskAcceptanceId,
        residualRiskStatement: risk.residualRiskStatement,
        ownedBy: risk.ownedBy,
        status: risk.status,
        profiles: [...risk.profiles],
      })),
    ),
    provenance: [{
      id: 'synthetic-canonical-audit',
      source: 'Canonical manifest audit fixture',
      summary: `Published by ${selectedManifest.audit.publishedBy} at ${selectedManifest.audit.publishedAt}.`,
      clause: '/audit',
      manifestVersion: selectedManifest.manifestVersion,
      confidence: null,
    }],
    validationMessages: activeDraft?.validation ? [] : ['No WC-007 validation record exists for the active draft.'],
    draft: activeDraft,
    published,
  }
}

export interface MockClientOptions {
  session?: AuthSession
  publishedOnly?: boolean
}

/** Explicit test-only adapter. Production code never imports this module. */
export const createMockContextApiClient = (options: MockClientOptions = {}): ContextApiClientPort => {
  const session = options.session ?? defaultSession
  let draft: DraftRecord | null = options.publishedOnly
    ? null
    : {
        draftId: 'draft-synthetic-canonical',
        manifestId: manifest.manifestId,
        state: 'draft',
        revision: 1,
        manifest: structuredClone(manifest),
        manifestDigest: manifest.compatibility.artifactDigest,
        previousVersion: null,
        createdBy: actor(session),
        createdAt: timestamp,
        updatedBy: actor(session),
        updatedAt: timestamp,
        reason: 'Explicit synthetic test draft.',
        validation: null,
        review: null,
        publicationCandidate: null,
        approval: null,
      }
  let published: PublishedManifest | null = options.publishedOnly
    ? {
        manifestId: manifest.manifestId,
        manifestVersion: manifest.manifestVersion,
        manifestDigest: manifest.compatibility.artifactDigest,
        manifest: structuredClone(manifest),
        sourceDraftId: 'draft-synthetic-published',
        sourceDraftRevision: 5,
        previousVersion: null,
        approval: {
          decisionId: 'approval-synthetic-published',
          approvedBy: actor(session),
          approvedAt: timestamp,
          approvedRevision: 4,
          manifestVersion: manifest.manifestVersion,
          manifestDigest: manifest.compatibility.artifactDigest,
          reason: 'Explicit synthetic approval.',
        },
        publishedBy: actor(session),
        publishedAt: timestamp,
        publicationAuthorizedBy: { actorId: 'athena-context-api', kind: 'service' },
        publicationAuthorizedAt: timestamp,
        reason: 'Explicit synthetic publication.',
      }
    : null

  const context = () => makeContext(session, draft, published)

  const transition = (
    request: ConcurrencyRequest,
    state: DraftRecord['state'],
  ): DraftRecord => {
    const current = assertConcurrency(draft, request)
    draft = {
      ...current,
      state,
      revision: current.revision + 1,
      updatedBy: actor(session),
      updatedAt: timestamp,
      reason: request.reason,
    }
    return draft
  }

  return {
    auth: session,
    loadAuthorizedWorkloads: async () => [context()],
    loadWorkloadContext: async (workloadId) => {
      if (!session.authorizedWorkloadIds.includes(workloadId)) throw new Error('Synthetic authorization denied.')
      return context()
    },
    createSuccessorDraft: async (workloadId, reason) => {
      if (!published || draft) throw new Error('A unique published predecessor without an active draft is required.')
      const [major, minor, patch] = published.manifestVersion.split('.').map(Number)
      const candidate = structuredClone(published.manifest)
      candidate.manifestVersion = `${major}.${minor}.${patch + 1}`
      const canonical = await refreshCanonicalManifestDigests(candidate)
      draft = {
        draftId: 'draft-synthetic-successor',
        manifestId: workloadId,
        state: 'draft',
        revision: 1,
        manifest: canonical,
        manifestDigest: canonical.compatibility.artifactDigest,
        previousVersion: published.manifestVersion,
        createdBy: actor(session),
        createdAt: timestamp,
        updatedBy: actor(session),
        updatedAt: timestamp,
        reason,
        validation: null,
        review: null,
        publicationCandidate: null,
        approval: null,
      }
      return draft
    },
    updateDraft: async (request) => {
      const current = assertConcurrency(draft, request)
      const replacement = await refreshCanonicalManifestDigests(request.replacementManifest)
      draft = {
        ...current,
        revision: current.revision + 1,
        manifest: replacement,
        manifestDigest: replacement.compatibility.artifactDigest,
        reason: request.reason,
        validation: null,
        review: null,
        publicationCandidate: null,
        approval: null,
      }
      return draft
    },
    validateDraft: async (request) => {
      const updated = transition(request, 'validated')
      draft = {
        ...updated,
        validation: {
          validatedBy: actor(session),
          validatedAt: timestamp,
          validatedRevision: updated.revision,
          manifestDigest: updated.manifestDigest,
        },
      }
      return draft
    },
    submitForReview: async (request) => {
      const updated = transition(request, 'in_review')
      draft = {
        ...updated,
        review: {
          submittedBy: actor(session),
          submittedAt: timestamp,
          submittedRevision: updated.revision,
          publicationCandidateDigest: updated.manifestDigest,
          reason: request.reason,
        },
      }
      return draft
    },
    approveDraft: async (request) => {
      const updated = transition(request, 'approved')
      const approval: ApprovalDecision = {
        decisionId: 'approval-synthetic-candidate',
        approvedBy: actor(session),
        approvedAt: timestamp,
        approvedRevision: updated.revision,
        manifestVersion: updated.manifest.manifestVersion,
        manifestDigest: updated.manifestDigest,
        reason: request.reason,
      }
      draft = {
        ...updated,
        approval,
        publicationCandidate: {
          finalizedBy: actor(session),
          finalizedAt: timestamp,
          manifestVersion: updated.manifest.manifestVersion,
          manifestDigest: updated.manifestDigest,
          semanticDigest: updated.manifest.compatibility.semanticDigest,
          approvalStatus: 'approved',
        },
      }
      return draft
    },
    publishDraft: async (request: PublishRequest) => {
      const current = assertConcurrency(draft, request)
      if (!current.approval || current.approval.decisionId !== request.approvalId) {
        throw new Error('Synthetic approval mismatch.')
      }
      published = {
        manifestId: current.manifestId,
        manifestVersion: current.manifest.manifestVersion,
        manifestDigest: current.manifestDigest,
        manifest: structuredClone(current.manifest),
        sourceDraftId: current.draftId,
        sourceDraftRevision: current.revision + 1,
        previousVersion: current.previousVersion,
        approval: current.approval,
        publishedBy: actor(session),
        publishedAt: timestamp,
        publicationAuthorizedBy: { actorId: 'athena-context-api', kind: 'service' },
        publicationAuthorizedAt: timestamp,
        reason: request.reason,
      }
      draft = { ...current, state: 'published', revision: current.revision + 1 }
      return published
    },
    completeSupersession: async (recovery) => ({
      manifestId: recovery.workloadId,
      supersededVersion: recovery.predecessorVersion,
      replacementVersion: recovery.successorVersion,
      supersededBy: actor(session),
      supersededAt: timestamp,
      reason: recovery.reason,
    }),
  }
}

export const canonicalManifestFixture = manifest
export const mockAuthSession = defaultSession
