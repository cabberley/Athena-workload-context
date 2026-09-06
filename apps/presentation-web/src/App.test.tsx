import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import App from './App'
import {
  createLiveVerifiedLifecycle,
  createVerifiedLifecycle,
} from './test/fixtures'
import type { VerifiedLifecycle } from './verification'
import type { VerifiedIncident, VerifiedIncidentFeed } from './incidents'

const incidentFixture = (
  scenario: VerifiedIncident['state']['scenario'],
  updatedAt: string,
): VerifiedIncidentFeed => ({
  publishedAt: updatedAt,
  keyFingerprint:
    'sha256:7e0b51de2b9968f6f1ae9df0ee981154dc8fe9ee463055031b556ee075351964',
  incidents: [{
    publishedAt: updatedAt,
    keyFingerprint:
      'sha256:7e0b51de2b9968f6f1ae9df0ee981154dc8fe9ee463055031b556ee075351964',
    state: {
    schemaVersion: 'athena.incidentState.v1',
    incidentId: 'inc-123456789abc',
    transitionId: `wc016-${'1'.repeat(64)}`,
    scenario,
    lifecycle: 'active',
    workloadRole:
      scenario === 'singletonDatabaseFailure'
        ? 'database-primary'
        : scenario === 'webServerFailure'
          ? 'web'
          : 'load-balancer',
    detectedAt: '2026-09-04T03:40:00Z',
    updatedAt,
    targetBinding:
      'sha256:1111111111111111111111111111111111111111111111111111111111111111',
    availability: 'critical',
    blastRadius: scenario === 'loadBalancerFailure' ? 'ingress-edge' : 'whole-workload',
    operatorAttention: 'urgent',
    findings: [
      {
        clauseId: 'synthetic-operational-health',
        verdict: 'fail',
        summary: 'The approved synthetic role is unavailable.',
        evidenceRefs: ['synthetic-monitor-alert-001'],
      },
    ],
    reasoning: ['Azure Monitor reported the approved workload role as unavailable.'],
    notificationStatus: 'pendingDispatch',
    resultDigest:
      'sha256:2222222222222222222222222222222222222222222222222222222222222222',
    noAutoRemediation: true,
    },
  }],
})

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

  it('labels live workload publication scope and signed result derivations', async () => {
    render(<App loader={() => createLiveVerifiedLifecycle()} />)

    expect(await screen.findByLabelText(/live workload evaluation/i)).toBeInTheDocument()
    expect(screen.getByText('rg-athena-demo-workload')).toBeInTheDocument()
    expect(screen.getByText('synthetic-run-live-001')).toBeInTheDocument()
    expect(screen.getByText('2026-09-02T00:00:00Z')).toBeInTheDocument()
    expect(
      screen.getAllByText(/signed control\/evidence-plane results/i).length,
    ).toBeGreaterThan(0)
    expect(
      screen.getByText(/private managed-identity sidecar reads the allowlisted blob assets/i),
    ).toBeInTheDocument()
  })

  it('renders a separately verified database, web, or load balancer incident', async () => {
    const incident: VerifiedIncident = {
      publishedAt: '2026-09-04T03:40:03Z',
      keyFingerprint:
        'sha256:7e0b51de2b9968f6f1ae9df0ee981154dc8fe9ee463055031b556ee075351964',
      state: {
        schemaVersion: 'athena.incidentState.v1',
        incidentId: 'inc-123456789abc',
        transitionId: `wc016-${'1'.repeat(64)}`,
        scenario: 'loadBalancerFailure',
        lifecycle: 'active',
        workloadRole: 'load-balancer',
        detectedAt: '2026-09-04T03:40:00Z',
        updatedAt: '2026-09-04T03:40:03Z',
        targetBinding:
          'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        availability: 'critical',
        blastRadius: 'ingress-edge',
        operatorAttention: 'urgent',
        findings: [
          {
            clauseId: 'synthetic-load-balancer-health',
            verdict: 'fail',
            summary: 'The synthetic ingress load balancer is unavailable.',
            evidenceRefs: ['synthetic-monitor-alert-001'],
          },
        ],
        reasoning: [
          'Azure Monitor reported failed VIP availability.',
          'Approved context binds the resource to the workload ingress edge.',
        ],
        notificationStatus: 'pendingDispatch',
        resultDigest:
          'sha256:2222222222222222222222222222222222222222222222222222222222222222',
        noAutoRemediation: true,
      },
    }
    render(
      <App
        loader={() => createLiveVerifiedLifecycle()}
        incidentLoader={() =>
          Promise.resolve({
            incidents: [incident],
            publishedAt: incident.publishedAt,
            keyFingerprint: incident.keyFingerprint,
          })
        }
      />,
    )

    expect(
      await screen.findByRole('heading', {
        name: /verified incident: azure load balancer failure/i,
      }),
    ).toBeInTheDocument()
    expect(screen.getByText('ingress-edge')).toBeInTheDocument()
    expect(screen.getByText(/does not remediate automatically/i)).toBeInTheDocument()
  })

  it('does not replace a newer incident with an older poll response', async () => {
    const incidentLoader = vi
      .fn()
      .mockResolvedValueOnce(incidentFixture('loadBalancerFailure', '2026-09-04T03:40:03Z'))
      .mockResolvedValue(incidentFixture('singletonDatabaseFailure', '2026-09-04T03:40:02Z'))
    render(
      <App
        loader={() => createLiveVerifiedLifecycle()}
        incidentLoader={incidentLoader}
        incidentPollMs={100}
      />,
    )

    expect(
      await screen.findByRole('heading', {
        name: /verified incident: azure load balancer failure/i,
      }),
    ).toBeInTheDocument()
    await waitFor(() => expect(incidentLoader).toHaveBeenCalledTimes(2))
    expect(
      screen.queryByRole('heading', { name: /verified incident: database server failure/i }),
    ).not.toBeInTheDocument()
  })

  it('clears previously rendered incident data when a later poll fails closed', async () => {
    const incidentLoader = vi
      .fn()
      .mockResolvedValueOnce(incidentFixture('webServerFailure', '2026-09-04T03:40:03Z'))
      .mockRejectedValue(new Error('untrusted incident asset'))
    render(
      <App
        loader={() => createLiveVerifiedLifecycle()}
        incidentLoader={incidentLoader}
        incidentPollMs={100}
      />,
    )

    expect(
      await screen.findByRole('heading', { name: /verified incident: web server failure/i }),
    ).toBeInTheDocument()
    expect(
      await screen.findByText(/incident feed is unavailable or failed verification/i),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole('heading', { name: /verified incident: web server failure/i }),
    ).not.toBeInTheDocument()
  })
})
