import { contextStudioFixture } from './data/fixtures'
import type { ApprovalState, ContextStudioSnapshot, EnvironmentName } from './types'

export interface PublishRequest {
  workloadId: string
  environment: EnvironmentName
  humanAuthorityApproved: boolean
}

export interface PublishResponse {
  allowed: boolean
  state: ApprovalState
  reason: string
}

export interface ContextApiClientPort {
  fetchSnapshot: () => Promise<ContextStudioSnapshot>
  publishProposal: (request: PublishRequest) => Promise<PublishResponse>
}

const contextApiBaseUrl =
  typeof import.meta.env.VITE_CONTEXT_API_BASE_URL === 'string'
    ? import.meta.env.VITE_CONTEXT_API_BASE_URL
    : 'https://context-api-demo.local'

export const createContextApiClient = (): ContextApiClientPort => ({
  fetchSnapshot: async () => ({
    ...contextStudioFixture,
    auth: {
      ...contextStudioFixture.auth,
      port: `${contextApiBaseUrl}/context/v1`,
    },
  }),
  publishProposal: async ({ humanAuthorityApproved }) => {
    if (!humanAuthorityApproved) {
      return {
        allowed: false,
        state: 'draft',
        reason: 'Human authority approval is required before publication.',
      }
    }

    return {
      allowed: true,
      state: 'published',
      reason: 'Published through the demo context API port; no production backend was used.',
    }
  },
})
