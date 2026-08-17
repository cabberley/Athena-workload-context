import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { createContextApiClient } from './client'

const baseUrl = import.meta.env.VITE_CONTEXT_API_BASE_URL?.trim() ?? ''
const actorId = import.meta.env.VITE_CONTEXT_API_ACTOR_ID?.trim() ?? ''
const token = import.meta.env.VITE_CONTEXT_API_BEARER_TOKEN?.trim() ?? ''

if (!baseUrl || !actorId || !token) {
  throw new Error('Runtime configuration requires VITE_CONTEXT_API_BASE_URL, VITE_CONTEXT_API_ACTOR_ID, and VITE_CONTEXT_API_BEARER_TOKEN.')
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App
      client={createContextApiClient({
        baseUrl,
        auth: {
          actorId,
          kind: 'human',
          role: 'reviewer',
          userLabel: 'Authenticated operator',
          port: 'context-studio',
          bearerToken: token,
        },
      })}
    />
  </StrictMode>,
)
