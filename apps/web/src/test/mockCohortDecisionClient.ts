import type {
  CohortDecisionApiPort,
  CohortDecisionRecord,
  CohortDecisionSubmitRequest,
} from '../cohortTypes'
import type { AuthSession } from '../types'
import { mockAuthSession } from './mockClient'

const timestamp = '2026-08-17T08:00:00.000Z'
const draftDigest = `sha256:${'9'.repeat(64)}`

const sameValues = (left: string[], right: string[]): boolean =>
  JSON.stringify(left) === JSON.stringify(right)

const exactBinding = (
  record: CohortDecisionRecord,
  request: Parameters<CohortDecisionApiPort['loadDecisions']>[0],
): boolean =>
  record.scope.manifestId === request.workloadId &&
  record.scope.manifestVersion === request.manifestVersion &&
  record.scope.profileId === request.profileId &&
  record.scope.profileType === request.scope.profileType &&
  record.scope.resolvedProfileDigest === request.scope.resolvedProfileDigest &&
  record.sourceDraft.draftId === request.sourceDraft.draftId &&
  record.sourceDraft.revision === request.sourceDraft.revision &&
  record.sourceDraft.manifestDigest === request.sourceDraft.manifestDigest &&
  record.proposalSetDigest === request.proposalSetDigest &&
  record.snapshotArtifactDigest === request.snapshotArtifactDigest

export interface MockCohortDecisionStore {
  records: CohortDecisionRecord[]
  nextDecision: number
}

export const createMockCohortDecisionStore = (): MockCohortDecisionStore => ({
  records: [],
  nextDecision: 1,
})

export interface MockCohortDecisionClientOptions {
  session?: AuthSession
  store?: MockCohortDecisionStore
}

/**
 * Explicit in-memory decision adapter for UI tests only. Production must wait
 * for issue #34's merged authenticated wire contract.
 */
export const createMockCohortDecisionApiClient = (
  options: MockCohortDecisionClientOptions = {},
): CohortDecisionApiPort => {
  const session = options.session ?? mockAuthSession
  const store = options.store ?? createMockCohortDecisionStore()

  const assertScope = (workloadId: string): void => {
    if (
      session.kind !== 'human' ||
      !session.authorizedWorkloadIds.includes(workloadId) ||
      session.authorizedWorkloadIds.includes('*')
    ) {
      throw new Error('Synthetic cohort decision scope denied.')
    }
  }

  return {
    auth: session,
    loadDecisions: async (request) => {
      assertScope(request.workloadId)
      return structuredClone(store.records.filter((record) =>
        exactBinding(record, request) &&
        record.proposalIds.some((proposalId) => request.proposalIds.includes(proposalId)),
      ))
    },
    submitDecision: async (request: CohortDecisionSubmitRequest) => {
      assertScope(request.workloadId)
      if (
        request.rationale !== request.rationale.trim() ||
        request.rationale.length < 1 ||
        request.rationale.length > 2000 ||
        request.proposalIds.length < 1 ||
        new Set(request.proposalIds).size !== request.proposalIds.length ||
        request.scope.manifestId !== request.workloadId ||
        request.scope.manifestVersion !== request.manifestVersion ||
        request.scope.profileId !== request.profileId
      ) {
        throw new Error('Synthetic cohort decision request is invalid.')
      }
      const candidate = request.candidate
      if (
        (request.action === 'reject' && candidate !== null) ||
        (request.action !== 'reject' && (
          candidate === null ||
          candidate.action !== request.action ||
          candidate.resolution !== request.rationale ||
          !sameValues(candidate.sourceProposalIds, request.proposalIds) ||
          candidate.proposalSetDigest !== request.proposalSetDigest ||
          candidate.snapshot.artifactDigest !== request.snapshotArtifactDigest ||
          candidate.sourceDraft.draftId !== request.sourceDraft.draftId ||
          candidate.sourceDraft.revision !== request.sourceDraft.revision ||
          candidate.sourceDraft.manifestDigest !== request.sourceDraft.manifestDigest ||
          candidate.scope.manifestId !== request.scope.manifestId ||
          candidate.scope.manifestVersion !== request.scope.manifestVersion ||
          candidate.scope.profileId !== request.scope.profileId ||
          candidate.scope.profileType !== request.scope.profileType ||
          candidate.scope.resolvedProfileDigest !== request.scope.resolvedProfileDigest
        ))
      ) {
        throw new Error('Synthetic cohort decision candidate binding is invalid.')
      }
      const rejected = store.records.find((record) =>
        exactBinding(record, request) &&
        record.state === 'rejected' &&
        record.proposalIds.some((proposalId) => request.proposalIds.includes(proposalId)),
      )
      if (rejected) {
        if (
          request.action === 'reject' &&
          sameValues(rejected.proposalIds, request.proposalIds) &&
          rejected.rationale === request.rationale
        ) {
          return structuredClone(rejected)
        }
        throw new Error('A durable rejection blocks later cohort decisions for this proposal set.')
      }

      const sequence = String(store.nextDecision).padStart(4, '0')
      store.nextDecision += 1
      const record: CohortDecisionRecord = {
        decisionId: `decision-wc012-${sequence}`,
        action: request.action,
        sourceDraft: structuredClone(request.sourceDraft),
        scope: structuredClone(request.scope),
        proposalIds: [...request.proposalIds],
        proposalSetDigest: request.proposalSetDigest,
        snapshotArtifactDigest: request.snapshotArtifactDigest,
        candidateId: candidate?.candidateId ?? null,
        rationale: request.rationale,
        state: request.action === 'reject' ? 'rejected' : 'applied',
        decidedBy: session.actorId,
        decidedAt: timestamp,
        draftResult: request.action === 'reject'
          ? null
          : {
              draftId: request.sourceDraft.draftId,
              revision: request.sourceDraft.revision + 1,
              manifestDigest: draftDigest,
            },
        publicationAllowed: false,
      }
      store.records.push(structuredClone(record))
      return record
    },
  }
}
