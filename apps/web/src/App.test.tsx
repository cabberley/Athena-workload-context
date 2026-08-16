import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import App from './App'

describe('Context Studio shell', () => {
  it('renders the primary context studio flow', async () => {
    render(<App />)

    expect(await screen.findByRole('heading', { name: /athena context studio/i })).toBeInTheDocument()
    expect(screen.getByText(/authenticated shell/i)).toBeInTheDocument()
    expect(screen.getByText(/workload catalogue/i)).toBeInTheDocument()
    expect(
      screen.getByRole('table', { name: /production, development and training comparison/i }),
    ).toBeInTheDocument()
  })

  it('blocks publication until human authority approval is present', async () => {
    render(<App />)

    const publishButton = await screen.findByRole('button', { name: /publish proposal/i })
    expect(publishButton).toBeDisabled()

    const checkbox = screen.getByRole('checkbox', { name: /human authority approved/i })
    await userEvent.click(checkbox)

    await waitFor(() => {
      expect(publishButton).not.toBeDisabled()
    })
  })

  it('publishes the proposal only after explicit approval', async () => {
    const user = userEvent.setup()
    render(<App />)

    const checkbox = await screen.findByRole('checkbox', { name: /human authority approved/i })
    await user.click(checkbox)

    const publishButton = await screen.findByRole('button', { name: /publish proposal/i })
    await user.click(publishButton)

    await waitFor(() => {
      expect(screen.getByText(/published through the demo context api port/i)).toBeInTheDocument()
    })
  })

  it('exposes a structured manifest editor and relationship data', async () => {
    render(<App />)

    expect(await screen.findByLabelText(/workload name/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/manifest version/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/business owner/i)).toBeInTheDocument()
    expect(screen.getByText(/declared vs observed/i)).toBeInTheDocument()
  })

  it('passes accessibility checks', async () => {
    const { container } = render(<App />)

    expect((await axe(container)).violations).toHaveLength(0)
  })
})
