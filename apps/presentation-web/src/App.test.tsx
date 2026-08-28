import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import App from './App'
import { createVerifiedLifecycle } from './test/fixtures'
import type { VerifiedLifecycle } from './verification'

describe('standalone Athena presentation', () => {
  it('withholds all lifecycle data until the complete set verifies', async () => {
    let resolveLifecycle: ((value: VerifiedLifecycle) => void) | undefined
    const lifecyclePromise = new Promise<VerifiedLifecycle>((resolve) => {
      resolveLifecycle = resolve
    })
    const loader = vi.fn(() => lifecyclePromise)
    render(<App loader={loader} />)

    expect(
      screen.getByRole('heading', { name: /verifying reviewed lifecycle assets/i }),
    ).toBeInTheDocument()
    expect(screen.queryByText(/redundant web tier is healthy/i)).not.toBeInTheDocument()

    resolveLifecycle?.(await createVerifiedLifecycle())
    expect(
      await screen.findByRole('heading', { name: /verified web-node lifecycle/i }),
    ).toBeInTheDocument()
  })

  it('renders verified baseline, faulted and recovered phases', async () => {
    const user = userEvent.setup()
    render(<App loader={() => createVerifiedLifecycle()} />)

    expect(
      await screen.findByRole('heading', { name: /redundant web tier is healthy/i }),
    ).toBeInTheDocument()
    expect(screen.getByText('None active')).toBeInTheDocument()
    expect(screen.getByText(/availability/i).nextElementSibling).toHaveTextContent('normal')

    await user.click(screen.getByRole('button', { name: /fault contained/i }))
    expect(
      screen.getByRole('heading', { name: /one web node is faulted/i }),
    ).toBeInTheDocument()
    expect(screen.getByText('Contained to web tier')).toBeInTheDocument()
    expect(screen.getByText(/synthetic-vm-a32894/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /recovery verified/i }))
    expect(
      screen.getByRole('heading', { name: /web-tier redundancy is restored/i }),
    ).toBeInTheDocument()
    expect(screen.getByText('Resolved')).toBeInTheDocument()
  })

  it('supports keyboard lifecycle navigation and moves focus to changed content', async () => {
    const user = userEvent.setup()
    render(<App loader={() => createVerifiedLifecycle()} />)
    const baselineButton = await screen.findByRole('button', { name: /baseline/i })
    baselineButton.focus()
    await user.keyboard('{ArrowRight}')

    const heading = screen.getByRole('heading', { name: /one web node is faulted/i })
    await waitFor(() => expect(heading).toHaveFocus())
  })

  it('fails closed with a safe announcement and no partial trusted rendering', async () => {
    render(<App loader={() => Promise.reject(new Error('sensitive internal detail'))} />)

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent(/no partial lifecycle data was rendered/i)
    expect(alert).not.toHaveTextContent(/sensitive internal detail/i)
    expect(screen.queryByText(/synthetic-manifest-/i)).not.toBeInTheDocument()
  })

  it('labels synthetic data, explains bounded inference, and passes accessibility checks', async () => {
    const { container } = render(<App loader={() => createVerifiedLifecycle()} />)
    expect(await screen.findByLabelText(/synthetic demo data/i)).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: /how athena determined this/i }),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/no database, worker, load balancer, geographic, or customer impact/i),
    ).toBeInTheDocument()
    expect((await axe(container)).violations).toHaveLength(0)
  })
})
