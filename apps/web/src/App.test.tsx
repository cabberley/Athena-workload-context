import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import App from './App'
import { createMockContextApiClient, mockAuthSession } from './test/mockClient'

const renderStudio = async (client = createMockContextApiClient()) => {
  const initialContexts = await client.loadAuthorizedWorkloads()
  return {
    client,
    ...render(<App client={client} initialContexts={initialContexts} />),
  }
}

describe('Context Studio', () => {
  it('renders scoped session, manifest, evidence and approval metadata', async () => {
    await renderStudio()

    expect(screen.getByRole('heading', { name: /athena context studio/i })).toBeInTheDocument()
    expect(screen.getByText(/authenticated, workload-scoped session/i)).toBeInTheDocument()
    expect(screen.getByText(/manifest version:/i)).toBeInTheDocument()
    expect(screen.getByText(/evidence source:/i)).toBeInTheDocument()
    expect(screen.getAllByText(/confidence: not provided/i).length).toBeGreaterThan(0)
    expect(screen.getByRole('table', { name: /production, development and training comparison/i })).toBeInTheDocument()
  })

  it('moves keyboard focus to route-specific content', async () => {
    const user = userEvent.setup()
    await renderStudio()

    const controls = screen.getByRole('button', { name: 'Controls' })
    controls.focus()
    await user.keyboard('{Enter}')
    const controlsHeading = screen.getByRole('heading', { name: /controls and lifecycle provenance/i })
    await waitFor(() => expect(controlsHeading).toHaveFocus())

    const manifest = screen.getByRole('button', { name: 'Manifest' })
    manifest.focus()
    await user.keyboard('{Enter}')
    const manifestHeading = screen.getByRole('heading', { name: /structured manifest editor/i })
    await waitFor(() => expect(manifestHeading).toHaveFocus())
    expect(screen.getByLabelText(/workload display name/i)).toBeEnabled()
  })

  it('requires explicit review before approval and publication', async () => {
    const user = userEvent.setup()
    await renderStudio()

    await user.click(screen.getByRole('button', { name: /validate draft/i }))
    await waitFor(() => expect(screen.getByText(/validated draft/i)).toBeInTheDocument())

    await user.click(screen.getByRole('button', { name: /submit for review/i }))
    await waitFor(() => expect(screen.getByText(/awaiting explicit human review/i)).toBeInTheDocument())

    const approve = screen.getByRole('button', { name: /approve reviewed candidate/i })
    expect(approve).toBeDisabled()
    await user.click(screen.getByRole('checkbox', { name: /reviewed this exact candidate digest/i }))
    expect(approve).toBeEnabled()
    await user.click(approve)
    await waitFor(() => expect(screen.getByText(/server approval approval-/i)).toBeInTheDocument())

    const publish = screen.getByRole('button', { name: /publish reviewed candidate/i })
    expect(publish).toBeEnabled()
    await user.click(publish)
    await waitFor(() => expect(screen.getByText(/published version .*wl-athena/i)).toBeInTheDocument())
  })

  it('keeps agent proposals non-authoritative', async () => {
    const agentClient = createMockContextApiClient({
      session: {
        ...mockAuthSession,
        actorId: 'proposal-agent',
        kind: 'agent',
        role: 'proposer',
        userLabel: 'Synthetic proposal agent',
      },
    })
    const user = userEvent.setup()
    await renderStudio(agentClient)
    await user.click(screen.getByRole('button', { name: /validate draft/i }))
    await user.click(await screen.findByRole('button', { name: /submit for review/i }))

    expect(screen.getByRole('checkbox', { name: /reviewed this exact candidate digest/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /approve reviewed candidate/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /publish reviewed candidate/i })).toBeDisabled()
  })

  it('provides visible mobile cell labels and programmatic cell labels', async () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 699 })
    window.dispatchEvent(new Event('resize'))
    const { container } = await renderStudio()

    expect(container.querySelectorAll('.mobile-cell-label')).toHaveLength(12)
    expect(screen.getAllByRole('cell', { name: /residual risk:/i })).toHaveLength(3)
  })

  it('passes automated accessibility checks', async () => {
    const { container } = await renderStudio()
    expect((await axe(container)).violations).toHaveLength(0)
  })
})
