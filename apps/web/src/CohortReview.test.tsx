import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import App from './App'
import { createMockCohortProposalApiClient } from './test/mockCohortClient'
import { createMockContextApiClient, mockAuthSession } from './test/mockClient'

const proposerSession = {
  ...mockAuthSession,
  role: 'proposer' as const,
  userLabel: 'Synthetic human cohort proposer',
}

const renderCohorts = async () => {
  const contextClient = createMockContextApiClient({ session: proposerSession })
  const cohortClient = createMockCohortProposalApiClient({ session: proposerSession })
  const initialContexts = await contextClient.loadAuthorizedWorkloads()
  const rendered = render(
    <App
      client={contextClient}
      cohortClient={cohortClient}
      initialContexts={initialContexts}
    />,
  )
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Cohorts' }))
  await screen.findByRole('heading', { name: /cohort proposal review/i })
  await screen.findByRole('button', { name: /worker.*1,000 members/i })
  return { ...rendered, user, contextClient, cohortClient }
}

describe('cohort proposal review', () => {
  it('shows proposal provenance, confidence, support, conflict detail, and paginates 1,000 members', async () => {
    const { user } = await renderCohorts()

    expect(screen.getByText(/observed snapshot snapshot-wc012-synthetic/i)).toBeInTheDocument()
    expect(screen.getByText(/not allowed by proposal contract/i)).toBeInTheDocument()
    expect(screen.getByText(/declared residual risk/i)).toBeInTheDocument()
    expect(screen.getByText(/inferred proposals.*explicit human review/i)).toBeInTheDocument()
    expect(screen.getByText(/high confidence.*94%/i)).toBeInTheDocument()
    expect(screen.getByText(/maximum matches: 1,000/i)).toBeInTheDocument()

    const memberList = screen.getByRole('list', { name: /filtered cohort members/i })
    expect(within(memberList).getAllByRole('listitem')).toHaveLength(25)
    expect(screen.getByText(/page 1 of 40/i)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /next members/i }))
    expect(screen.getByText(/page 2 of 40/i)).toBeInTheDocument()

    await user.clear(screen.getByRole('searchbox', { name: /filter members/i }))
    await user.type(
      screen.getByRole('searchbox', { name: /filter members/i }),
      'virtualmachines/1000',
    )
    expect(within(memberList).getAllByRole('listitem')).toHaveLength(1)
    expect(screen.getByText(/1 of 1,000/i)).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /web.*medium.*12 members/i }))
    expect(screen.getByText(/synthetic environment tag dissent/i)).toBeInTheDocument()
    expect(screen.getAllByText(/cross environment/i).length).toBeGreaterThan(0)
    expect(screen.getByRole('list', { name: /rejected candidates/i })).toHaveTextContent(
      /cross-environment-rejected/i,
    )
    expect(screen.getAllByText(/snapshot digest/i).length).toBeGreaterThan(0)
  })

  it('writes a high-confidence bounded proposal only after confirmation and never publishes', async () => {
    const { user, contextClient } = await renderCohorts()
    const update = vi.spyOn(contextClient, 'updateDraft')
    const validate = vi.spyOn(contextClient, 'validateDraft')
    const approveLifecycle = vi.spyOn(contextClient, 'approveDraft')
    const publish = vi.spyOn(contextClient, 'publishDraft')

    const approve = screen.getByRole('button', { name: /approve bounded cohort to draft/i })
    expect(approve).toBeEnabled()
    await user.click(approve)

    const dialog = screen.getByRole('alertdialog', { name: /confirm approve/i })
    expect(dialog).toHaveTextContent(/exact concurrency and idempotency/i)
    expect(dialog).toHaveTextContent(/never validates, approves, or publishes/i)
    const confirm = within(dialog).getByRole('button', { name: /confirm approve/i })
    const cancel = within(dialog).getByRole('button', { name: /cancel/i })
    expect(confirm).toHaveFocus()
    await user.tab()
    expect(cancel).toHaveFocus()
    await user.tab({ shift: true })
    expect(confirm).toHaveFocus()
    await user.click(confirm)

    await waitFor(() => expect(update).toHaveBeenCalledOnce())
    const request = update.mock.calls[0]![0]
    expect(request).toMatchObject({
      expectedRevision: 1,
      expectedManifestVersion: '1.0.0',
      expectedDigest: expect.stringMatching(/^sha256:/),
      idempotencyKey: expect.stringMatching(/^cohort-r1-review-proposal-/),
    })
    expect(request.replacementManifest.roles).toHaveLength(4)
    expect(request.replacementManifest.profiles.production!.roles).toEqual([
      expect.objectContaining({
        roleId: 'worker',
        selectors: [expect.objectContaining({ maxMatches: 1000 })],
      }),
    ])
    expect(validate).not.toHaveBeenCalled()
    expect(approveLifecycle).not.toHaveBeenCalled()
    expect(publish).not.toHaveBeenCalled()
  })

  it('blocks medium, conflicting, and cross-environment bulk approval until explicit resolution', async () => {
    const { user } = await renderCohorts()
    await user.click(screen.getByRole('button', { name: /web.*medium.*12 members/i }))

    const approve = screen.getByRole('button', { name: /approve bounded cohort to draft/i })
    expect(approve).toBeDisabled()
    await user.type(
      screen.getByLabelText(/resolution rationale/i),
      'Resolve the synthetic environment dissent for this exact snapshot.',
    )
    expect(approve).toBeDisabled()
    await user.click(screen.getByRole('checkbox', { name: /explicitly resolved/i }))
    expect(approve).toBeEnabled()
  })

  it('gets split and merge selectors from the proposal API rather than fabricating them in the client', async () => {
    const { user, cohortClient } = await renderCohorts()
    const preview = vi.spyOn(cohortClient, 'previewReview')
    await user.click(screen.getByRole('button', { name: /web.*medium.*12 members/i }))
    await user.type(
      screen.getByLabelText(/resolution rationale/i),
      'Split the synthetic cohort using a reviewed bounded selector partition.',
    )
    await user.click(screen.getByRole('checkbox', { name: /explicitly resolved/i }))
    await user.click(screen.getByRole('button', { name: /preview split/i }))
    await user.click(
      within(screen.getByRole('alertdialog', { name: /confirm split/i }))
        .getByRole('button', { name: /confirm split/i }),
    )

    expect(await screen.findByRole('heading', { name: /split result.*api preview only/i }))
      .toBeInTheDocument()
    expect(preview).toHaveBeenCalledWith(expect.objectContaining({
      action: 'split',
      proposalIds: ['proposal-2222222222222222'],
      sourceDraft: expect.objectContaining({ revision: 1 }),
    }))
    expect(screen.getByText(/has not changed wc-007 state/i)).toBeInTheDocument()

    const webMergeChoices = screen.getAllByRole('checkbox', {
      name: /include web proposal in merge/i,
    })
    await user.click(webMergeChoices[0]!)
    await user.click(webMergeChoices[1]!)
    await user.click(screen.getByRole('button', { name: /preview merge of selected/i }))
    await user.click(
      within(screen.getByRole('alertdialog', { name: /confirm merge/i }))
        .getByRole('button', { name: /confirm merge/i }),
    )

    expect(await screen.findByRole('heading', { name: /merge result.*api preview only/i }))
      .toBeInTheDocument()
    expect(preview).toHaveBeenLastCalledWith(expect.objectContaining({
      action: 'merge',
      proposalIds: [
        'proposal-2222222222222222',
        'proposal-3333333333333333',
      ],
      sourceRoles: [
        expect.objectContaining({ roleId: 'web' }),
      ],
    }))
  })

  it('makes rejection confirmation explicit without fabricating persisted authority', async () => {
    const { user, contextClient } = await renderCohorts()
    const update = vi.spyOn(contextClient, 'updateDraft')

    await user.click(screen.getByRole('button', { name: /reject proposal in this review/i }))
    const dialog = screen.getByRole('alertdialog', { name: /confirm reject/i })
    expect(dialog).toHaveTextContent(/session-only and writes no authority/i)
    await user.click(within(dialog).getByRole('button', { name: /confirm reject/i }))

    expect(screen.getByText(/browser review session only/i)).toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
    expect(screen.getByText(/session decision/i).parentElement).toHaveTextContent(/rejected/i)
  })

  it('supports keyboard focus, responsive summaries, and WCAG automated checks', async () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    window.dispatchEvent(new Event('resize'))
    const contextClient = createMockContextApiClient({ session: proposerSession })
    const cohortClient = createMockCohortProposalApiClient({ session: proposerSession })
    const initialContexts = await contextClient.loadAuthorizedWorkloads()
    const { container } = render(
      <App
        client={contextClient}
        cohortClient={cohortClient}
        initialContexts={initialContexts}
      />,
    )
    const user = userEvent.setup()
    const cohorts = screen.getByRole('button', { name: 'Cohorts' })
    cohorts.focus()
    await user.keyboard('{Enter}')
    const heading = await screen.findByRole('heading', { name: /cohort proposal review/i })
    await waitFor(() => expect(heading).toHaveFocus())
    await screen.findByRole('button', { name: /worker.*1,000 members/i })

    expect(screen.getByRole('list', { name: /filtered cohort members/i })).toBeInTheDocument()
    expect((await axe(container)).violations).toHaveLength(0)
  })
})
