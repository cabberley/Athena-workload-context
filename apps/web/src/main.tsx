import { createRoot } from 'react-dom/client'
import './index.css'
import { bootstrapContextStudio, renderStartupFailure } from './bootstrap'

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('Athena Context Studio root element is missing.')
}

const runtime = window.athenaContextStudioRuntime
if (!runtime) {
  const root = createRoot(rootElement)
  renderStartupFailure(root, 'The approved runtime authentication integration is not configured.')
} else {
  void bootstrapContextStudio(runtime, rootElement).catch((error: unknown) => {
    const replacement = rootElement.cloneNode(false) as HTMLElement
    rootElement.replaceWith(replacement)
    const root = createRoot(replacement)
    const message = error instanceof Error ? error.message : 'Startup failed closed.'
    renderStartupFailure(root, message)
  })
}
