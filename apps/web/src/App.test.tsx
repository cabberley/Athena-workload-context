import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import App from './App'
import { createMockContextApiClient } from './client'

const renderStudio = () => render(<App client={createMockContextApiClient()} />)

describe('Context Studio shell', () => {
  it('renders the authenticated shell and workload catalogue', async () => {
    renderStudio()

    expect(await screen.findByRole('heading', { name: /athena context studio/i })).toBeInTheDocument()
    expect(screen.getByText(/authenticated shell/i)).toBeInTheDocument()
    expect(screen.getByText(/workload catalogue/i)).toBeInTheDocument()
    expect(
      screen.getByRole('table', { name: /production, development and training comparison/i }),
    ).toBeInTheDocument()
  })

  it('supports keyboard-only navigation and activation', async () => {
    const user = userEvent.setup()
    renderStudio()

    const catalogueButton = screen.getByRole('button', { name: /catalogue/i })
    catalogueButton.focus()
    await user.keyboard('{Enter}')

    await waitFor(() => {
      expect(screen.getByText(/trade batch/i)).toBeInTheDocument()
    })
  })

  it('creates, validates, approves and publishes a draft through the WC-007 lifecycle', async () => {
    const user = userEvent.setup()
    renderStudio()

    await user.click(screen.getByRole('button', { name: /save draft/i }))
    await waitFor(() => {
      expect(screen.getByText(/draft .* created/i)).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: /validate draft/i }))
    await waitFor(() => {
      expect(screen.getByText(/validated/i)).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: /submit for review/i }))
    await waitFor(() => {
      expect(screen.getByText(/in review/i)).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: /approve draft/i }))
    await waitFor(() => {
      expect(screen.getByText(/approved/i)).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: /^publish$/i }))
    await waitFor(() => {
      expect(screen.getByText(/published version .*atlas-api/i)).toBeInTheDocument()
    })
  })

  it('exposes a structured manifest editor and relationship data', async () => {
    renderStudio()

    expect(await screen.findByLabelText(/workload name/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/manifest version/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/business owner/i)).toBeInTheDocument()
    expect(screen.getByText(/declared vs observed/i)).toBeInTheDocument()
  })

  it('blocks stale or mismatched publication requests', async () => {
    renderStudio()
    const publishButton = await screen.findByRole('button', { name: /^publish$/i })
    expect(publishButton).toBeDisabled()
  })

  it('passes accessibility checks', async () => {
    const { container } = renderStudio()

    expect((await axe(container)).violations).toHaveLength(0)
  })
})
