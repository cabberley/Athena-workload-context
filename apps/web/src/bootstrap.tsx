import { StrictMode } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import App from './App'
import { createContextApiClient } from './client'
import type { AuthSession, ContextStudioRuntime } from './types'

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

  if (!runtime?.apiBaseUrl?.trim() || !runtime.authPort) {
    throw new Error('Runtime API configuration and AuthPort injection are required.')
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
  const initialContexts = await client.loadAuthorizedWorkloads()
  if (initialContexts.length === 0) {
    throw new Error('The authenticated session has no active authorized workload context.')
  }

  root.render(
    <StrictMode>
      <App client={client} initialContexts={initialContexts} />
    </StrictMode>,
  )
  return root
}
