import { StrictMode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import App from './App'
import { createContextApiClient } from './client'
import { createCohortProposalApiClient } from './cohortClient'
import {
  validateOperationalContext,
} from './operationalContext'
import type {
  AuthSession,
  ContextApiClientPort,
  ContextStudioRuntime,
  WorkloadContext,
} from './types'

const validSession = (session: AuthSession | null): session is AuthSession =>
  session !== null &&
  session.actorId.trim().length > 0 &&
  session.userLabel.trim().length > 0 &&
  session.port.trim().length > 0 &&
  session.authorizedWorkloadIds.length > 0

export const renderStartupFailure = (root: Root, message: string): void => {
  root.render(
    <main className="startup-failure" aria-labelledby="startup-failure-title">
      <div>
        <h1 id="startup-failure-title">Athena Context Studio is unavailable</h1>
        <p role="alert">{message}</p>
        <p>No workload context was loaded. Authenticate through the approved host integration and try again.</p>
      </div>
    </main>,
  )
}

/**
 * Production composition root. Authentication and authorized workload scope
 * are resolved before any WC-007 request or application content is rendered.
 */
export const bootstrapContextStudio = async (
  runtime: ContextStudioRuntime,
  rootElement: HTMLElement,
): Promise<Root> => {
  const root = createRoot(rootElement)
  root.render(
    <div className="loading-state" role="status">
      Authenticating Athena Context Studio…
    </div>,
  )

  if (
    !runtime?.apiBaseUrl?.trim() ||
    !runtime.cohortApiBaseUrl?.trim() ||
    !runtime.authPort
  ) {
    throw new Error(
      'Runtime Context API, cohort API, and AuthPort configuration are required.',
    )
  }
  const session = await runtime.authPort.acquireSession()
  if (!validSession(session)) {
    throw new Error('An authenticated session with explicit authorized workload IDs is required.')
  }

  const client = createContextApiClient({
    baseUrl: runtime.apiBaseUrl,
    authPort: runtime.authPort,
    session,
    fetchImpl: runtime.fetchImpl,
    createId: runtime.createId,
  })
  const cohortClient = createCohortProposalApiClient({
    baseUrl: runtime.cohortApiBaseUrl,
    authPort: runtime.authPort,
    session,
    fetchImpl: runtime.fetchImpl,
    createId: runtime.createId,
  })
  const enrichContext = async (context: WorkloadContext): Promise<WorkloadContext> => {
    const profile = context.manifest.profiles[context.profileId]
    if (!profile || profile.profileType !== context.environment) {
      throw new Error('The exact active environment profile is unavailable.')
    }
    if (!runtime.operationalContextPort) {
      return {
        ...context,
        operationalContextRequired: false,
        validationMessages: [
          ...context.validationMessages,
          'Operational relationships and findings are unavailable because the trusted WC-026/WC-028 port is not configured.',
        ],
      }
    }
    const authority = context.draft
      ? {
          draftId: context.draft.draftId,
          draftRevision: context.draft.revision,
          manifestDigest: context.draft.manifestDigest,
        }
      : context.published
        ? {
            draftId: context.published.sourceDraftId,
            draftRevision: context.published.sourceDraftRevision,
            manifestDigest: context.published.manifestDigest,
          }
        : null
    if (!authority) {
      throw new Error('Operational context requires an exact lifecycle authority record.')
    }
    const request = {
      workloadId: context.workloadId,
      manifestVersion: context.manifestVersion,
      profileId: profile.profileId,
      ...authority,
      profileDigest: await client.loadResolvedProfileDigest(context),
      asOf: new Date().toISOString(),
    }
    let operational: Awaited<ReturnType<typeof validateOperationalContext>>
    try {
      operational = await validateOperationalContext(
        await runtime.operationalContextPort.loadOperationalContext(request),
        request,
      )
    } catch {
      throw new Error(
        'Trusted operational context could not be loaded for the exact lifecycle binding.',
      )
    }
    const existingRelationshipIds = new Set(
      context.relationships.map((relationship) => relationship.id),
    )
    if (
      operational.relationships.some((relationship) =>
        existingRelationshipIds.has(relationship.id)
      )
    ) {
      throw new Error(
        'Operational context relationship identifiers collide with declared authority.',
      )
    }
    return {
      ...context,
      evidenceSource: operational.evidenceSource,
      confidence: operational.confidence,
      relationships: [...context.relationships, ...operational.relationships],
      findings: operational.findings,
      operationalContext: operational,
      operationalContextRequired: true,
      provenance: [
        ...context.provenance,
        {
          id: `operational-${operational.snapshotId}`,
          source: operational.evidenceSource,
          summary:
            `Exact operational snapshot ${operational.snapshotId} bound to ` +
            `${operational.manifestVersion}/${operational.profileId}.`,
          clause: `/operational-context/${operational.snapshotId}`,
          manifestVersion: operational.manifestVersion,
          confidence: operational.confidence,
        },
      ],
    }
  }
  const enrichedClient: ContextApiClientPort = {
    ...client,
    loadAuthorizedWorkloads: async () =>
      Promise.all((await client.loadAuthorizedWorkloads()).map(enrichContext)),
    loadWorkloadContext: async (workloadId) =>
      enrichContext(await client.loadWorkloadContext(workloadId)),
  }
  const initialContexts = await enrichedClient.loadAuthorizedWorkloads()
  if (initialContexts.length === 0) {
    throw new Error('The authenticated session has no active authorized workload context.')
  }

  root.render(
    <StrictMode>
      <App
        client={enrichedClient}
        cohortClient={cohortClient}
        decisionClient={cohortClient}
        initialContexts={initialContexts}
      />
    </StrictMode>,
  )
  return root
}
