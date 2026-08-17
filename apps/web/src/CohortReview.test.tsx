import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import App from './App'
import type { CohortProposalBatch } from './cohortTypes'
import {
  createMockCohortProposalApiClient,
  syntheticCohortBatch,
} from './test/mockCohortClient'
import {
  createMockCohortDecisionApiClient,
  createMockCohortDecisionStore,
  type MockCohortDecisionStore,
} from './test/mockCohortDecisionClient'
import { createMockContextApiClient, mockAuthSession } from './test/mockClient'

const proposerSession = {
  ...mockAuthSession,
  role: 'proposer' as const,
  userLabel: 'Synthetic human cohort proposer',
}

const renderCohorts = async (
  batch?: CohortProposalBatch,
  decisionStore: MockCohortDecisionStore = createMockCohortDecisionStore(),
) => {
  const contextClient = createMockContextApiClient({ session: proposerSession })
  const cohortClient = createMockCohortProposalApiClient({ session: proposerSession, batch })
  const decisionClient = createMockCohortDecisionApiClient({
    session: proposerSession,
    store: decisionStore,
  })
  const initialContexts = await contextClient.loadAuthorizedWorkloads()
  const rendered = render(
    <App
      client={contextClient}
      cohortClient={cohortClient}
      decisionClient={decisionClient}
      initialContexts={initialContexts}
    />,
  )
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Cohorts' }))
  await screen.findByRole('heading', { name: /cohort proposal review/i })
  await screen.findByRole('button', { name: /worker.*1,000 members/i })
  await screen.findByText(/loaded 3 proposals and their durable decision state/i)
  return { ...rendered, user, contextClient, cohortClient, decisionClient, decisionStore }
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

  it('submits a durable atomic decision only after confirmation and never writes WC-007 directly', async () => {
    const { user, contextClient, decisionClient } = await renderCohorts()
    const update = vi.spyOn(contextClient, 'updateDraft')
    const decide = vi.spyOn(decisionClient, 'submitDecision')
    const validate = vi.spyOn(contextClient, 'validateDraft')
    const approveLifecycle = vi.spyOn(contextClient, 'approveDraft')
    const publish = vi.spyOn(contextClient, 'publishDraft')

    const approve = screen.getByRole('button', { name: /approve bounded cohort to draft/i })
    expect(approve).toBeDisabled()
    await user.type(
      screen.getByLabelText(/resolution rationale/i),
      'Approve the exact synthetic high-confidence cohort.',
    )
    expect(approve).toBeEnabled()
    await user.click(approve)

    const dialog = screen.getByRole('alertdialog', { name: /confirm approve/i })
    expect(dialog).toHaveTextContent(/durable decision.*atomic selector-only draft apply/i)
    expect(dialog).toHaveTextContent(/never validates, approves, or publishes/i)
    const confirm = within(dialog).getByRole('button', { name: /confirm approve/i })
    const cancel = within(dialog).getByRole('button', { name: /cancel/i })
    expect(confirm).toHaveFocus()
    await user.tab()
    expect(cancel).toHaveFocus()
    await user.tab({ shift: true })
    expect(confirm).toHaveFocus()
    await user.click(confirm)

    await waitFor(() => expect(decide).toHaveBeenCalledOnce())
    const request = decide.mock.calls[0]![0]
    expect(request).toMatchObject({
      action: 'approve',
      sourceDraft: expect.objectContaining({ revision: 1 }),
      proposalIds: ['proposal-1111111111111111'],
      rationale: 'Approve the exact synthetic high-confidence cohort.',
      candidate: expect.objectContaining({
        candidateId: 'review-proposal-1111111111111111',
        publicationAllowed: false,
      }),
    })
    expect(update).not.toHaveBeenCalled()
    expect(validate).not.toHaveBeenCalled()
    expect(approveLifecycle).not.toHaveBeenCalled()
    expect(publish).not.toHaveBeenCalled()
    expect(screen.getByText(/decision-wc012-0001/i)).toBeInTheDocument()
  })

  it('keeps a full 2,000-character rationale in the decision request and out of WC-007', async () => {
    const { user, contextClient, decisionClient, decisionStore } = await renderCohorts()
    const decide = vi.spyOn(decisionClient, 'submitDecision')
    const update = vi.spyOn(contextClient, 'updateDraft')
    const rationale = 'R'.repeat(2000)

    fireEvent.change(screen.getByLabelText(/resolution rationale/i), {
      target: { value: rationale },
    })
    await user.click(screen.getByRole('button', { name: /approve bounded cohort to draft/i }))
    await user.click(
      within(screen.getByRole('alertdialog', { name: /confirm approve/i }))
        .getByRole('button', { name: /confirm approve/i }),
    )

    await waitFor(() => expect(decide).toHaveBeenCalledOnce())
    expect(decide.mock.calls[0]![0].rationale).toBe(rationale)
    expect(decisionStore.records[0]?.rationale).toBe(rationale)
    expect(update).not.toHaveBeenCalled()
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

  it.each(['low', 'conflicting'] as const)(
    'allows a resolved %s proposal without a selector to request a split preview',
    async (band) => {
      const batch = structuredClone(syntheticCohortBatch)
      const proposal = batch.proposals[1]!
      proposal.confidenceBand = band
      proposal.confidence = 0.4
      proposal.disposition = 'humanResolution'
      proposal.bulkReviewEligible = false
      proposal.selectorPreview = null
      const { user, cohortClient } = await renderCohorts(batch)
      const preview = vi.spyOn(cohortClient, 'previewReview')
      await user.click(screen.getByRole('button', { name: /web.*12 members/i }))

      expect(screen.getByText(/no bounded selector preview was provided/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /approve bounded cohort to draft/i }))
        .toBeDisabled()
      const split = screen.getByRole('button', { name: /preview split/i })
      expect(split).toBeDisabled()
      await user.type(
        screen.getByLabelText(/resolution rationale/i),
        `Resolve the synthetic ${band} proposal before requesting a split preview.`,
      )
      await user.click(screen.getByRole('checkbox', { name: /explicitly resolved/i }))

      expect(split).toBeEnabled()
      expect(screen.getByRole('button', { name: /approve bounded cohort to draft/i }))
        .toBeDisabled()
      await user.click(split)
      await user.click(
        within(screen.getByRole('alertdialog', { name: /confirm split/i }))
          .getByRole('button', { name: /confirm split/i }),
      )
      expect(await screen.findByRole('heading', { name: /split result.*api preview only/i }))
        .toBeInTheDocument()
      expect(preview).toHaveBeenCalledWith(expect.objectContaining({
        action: 'split',
        proposalIds: [proposal.proposalId],
      }))
    },
  )

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

  it('persists rejection, clears cached previews, and gates approve, split, merge, and apply after reload', async () => {
    const decisionStore = createMockCohortDecisionStore()
    const first = await renderCohorts(undefined, decisionStore)
    const { user, contextClient } = first
    const update = vi.spyOn(contextClient, 'updateDraft')

    await user.click(screen.getByRole('button', { name: /web.*medium.*12 members/i }))
    await user.type(
      screen.getByLabelText(/resolution rationale/i),
      'Reject the exact synthetic proposal after reviewing its cached split preview.',
    )
    await user.click(screen.getByRole('checkbox', { name: /explicitly resolved/i }))
    await user.click(screen.getByRole('button', { name: /preview split/i }))
    await user.click(
      within(screen.getByRole('alertdialog', { name: /confirm split/i }))
        .getByRole('button', { name: /confirm split/i }),
    )
    expect(await screen.findByRole('heading', { name: /split result.*api preview only/i }))
      .toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /^reject proposal$/i }))
    const dialog = screen.getByRole('alertdialog', { name: /confirm reject/i })
    expect(dialog).toHaveTextContent(/persists a durable rejection.*permanently blocks/i)
    await user.click(within(dialog).getByRole('button', { name: /confirm reject/i }))

    expect(await screen.findByText(/durable rejection decision-wc012-0001 recorded/i))
      .toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
    expect(screen.queryByRole('heading', { name: /split result.*api preview only/i }))
      .not.toBeInTheDocument()
    expect(screen.getByText('Durable decision', { selector: 'dt' }).parentElement)
      .toHaveTextContent(/rejected/i)
    expect(screen.getByRole('button', { name: /approve bounded cohort to draft/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /^reject proposal$/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /preview split/i })).toBeDisabled()
    expect(screen.getAllByRole('checkbox', { name: /include web proposal in merge/i })[0])
      .toBeDisabled()

    first.unmount()
    const reloaded = await renderCohorts(undefined, decisionStore)
    await reloaded.user.click(screen.getByRole('button', { name: /web.*medium.*12 members/i }))

    expect(screen.getByText('Durable decision', { selector: 'dt' }).parentElement)
      .toHaveTextContent(/rejected/i)
    expect(screen.getByText('decision-wc012-0001')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /approve bounded cohort to draft/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /preview split/i })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /apply preview as draft selector proposal/i }))
      .not.toBeInTheDocument()
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
