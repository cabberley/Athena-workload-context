import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { axe } from 'jest-axe'
import App from './App'
import { SupersessionRecoveryRequiredError } from './client'
import { createMockCohortProposalApiClient } from './test/mockCohortClient'
import { createMockContextApiClient, mockAuthSession } from './test/mockClient'
import type { ContextApiClientPort, DraftRecord } from './types'

const renderStudio = async (
  client = createMockContextApiClient(),
  cohortClient = createMockCohortProposalApiClient({ session: client.auth }),
) => {
  const initialContexts = await client.loadAuthorizedWorkloads()
  return {
    client,
    ...render(
      <App
        client={client}
        cohortClient={cohortClient}
        initialContexts={initialContexts}
      />,
    ),
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

    const versions = screen.getByRole('button', { name: 'Versions' })
    versions.focus()
    await user.keyboard('{Enter}')
    await waitFor(() =>
      expect(
        screen.getByRole('heading', { name: /exact version comparison and rollback/i }),
      ).toHaveFocus(),
    )
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
    expect(approve).toBeDisabled()
    await user.click(screen.getByRole('button', { name: /record review approval/i }))
    await waitFor(() => expect(screen.getByText(/review review-/i)).toBeInTheDocument())
    expect(approve).toBeEnabled()
    await user.click(approve)
    await waitFor(() => expect(screen.getByText(/server approval approval-/i)).toBeInTheDocument())

    const publish = screen.getByRole('button', { name: /publish reviewed candidate/i })
    expect(publish).toBeEnabled()
    await user.click(publish)
    await waitFor(() => expect(screen.getByText(/published (?:initial )?version .*wl-athena/i)).toBeInTheDocument())
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

  it('records rejected fields and required corrections before returning to edit', async () => {
    const user = userEvent.setup()
    await renderStudio()
    await user.click(screen.getByRole('button', { name: /validate draft/i }))
    await user.click(await screen.findByRole('button', { name: /submit for review/i }))
    await user.click(
      screen.getByRole('checkbox', {
        name: /reviewed this exact candidate digest/i,
      }),
    )
    await user.type(
      screen.getByLabelText(/rejected json pointer fields/i),
      '/profiles/production/controls/0/runbookRef',
    )
    await user.type(
      screen.getByLabelText(/required corrections/i),
      'Add the approved production runbook reference.',
    )
    await user.click(screen.getByRole('button', { name: /request corrections/i }))

    expect(await screen.findByText(/draft returned to editing/i))
      .toBeInTheDocument()
    expect(screen.getByRole('button', { name: /save structured edits/i }))
      .toBeEnabled()
  })

  it('blocks lifecycle success and offers exact recovery after partial supersession failure', async () => {
    const baseClient = createMockContextApiClient({ publishedOnly: true })
    let current = await baseClient.createSuccessorDraft(
      mockAuthSession.authorizedWorkloadIds[0]!,
      'Create synthetic successor.',
    )
    current = await baseClient.validateDraft({
      workloadId: current.manifestId,
      draftId: current.draftId,
      expectedRevision: current.revision,
      expectedManifestVersion: current.manifest.manifestVersion,
      expectedDigest: current.manifestDigest,
      reason: 'Validate synthetic successor.',
    })
    current = await baseClient.submitForReview({
      workloadId: current.manifestId,
      draftId: current.draftId,
      expectedRevision: current.revision,
      expectedManifestVersion: current.manifest.manifestVersion,
      expectedDigest: current.manifestDigest,
      reason: 'Submit synthetic successor.',
    })
    current = await baseClient.reviewDraft({
      workloadId: current.manifestId,
      draftId: current.draftId,
      expectedRevision: current.revision,
      expectedManifestVersion: current.manifest.manifestVersion,
      expectedDigest: current.manifestDigest,
      decision: 'approved',
      comments: 'Review the exact synthetic successor.',
      rejectedFields: [],
      requiredCorrections: [],
      reason: 'Record synthetic review.',
    })
    current = await baseClient.approveDraft({
      workloadId: current.manifestId,
      draftId: current.draftId,
      expectedRevision: current.revision,
      expectedManifestVersion: current.manifest.manifestVersion,
      expectedDigest: current.manifestDigest,
      operationalContextReceiptId: 'operational-approval-successor',
      reason: 'Approve synthetic successor.',
    })
    const client = {
      ...baseClient,
      publishDraft: async (request: Parameters<typeof baseClient.publishDraft>[0]) => {
        const published = await baseClient.publishDraft(request)
        throw new SupersessionRecoveryRequiredError(
          {
            workloadId: published.manifestId,
            predecessorVersion: published.previousVersion!,
            predecessorRevision: 5,
            predecessorDigest: canonicalDigest,
            successorVersion: published.manifestVersion,
            successorDigest: published.manifestDigest,
            reason: 'Complete synthetic supersession.',
            idempotencyKey: 'supersede-recovery-test',
          },
          published,
          new Error('Synthetic supersede failure.'),
        )
      },
    }
    const canonicalDigest = current.previousVersion
      ? (await baseClient.loadWorkloadContext(current.manifestId)).published!.manifestDigest
      : current.manifestDigest
    const user = userEvent.setup()
    await renderStudio(client)

    await user.click(screen.getByRole('checkbox', { name: /reviewed this exact candidate digest/i }))
    await user.click(screen.getByRole('button', { name: /publish reviewed candidate/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/publication recovery required/i)
    expect(screen.getByText(/all other lifecycle actions are blocked/i)).toBeInTheDocument()
    expect(screen.queryByText(/published version .*superseded predecessor/i)).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /retry exact supersession/i }))
    await waitFor(() => expect(screen.getByText(/recovered publication/i)).toBeInTheDocument())
  })

  it('provides visible mobile cell labels and programmatic cell labels', async () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 699 })
    window.dispatchEvent(new Event('resize'))
    const { container } = await renderStudio()

    expect(container.querySelectorAll('.mobile-cell-label')).toHaveLength(12)
    expect(screen.getAllByRole('cell', { name: /residual risk:/i })).toHaveLength(3)
  })

  it('renders declared, observed, inferred, exception-ready topology and contextual findings', async () => {
    await renderStudio()

    expect(screen.getByText('observed')).toBeInTheDocument()
    expect(screen.getByText('inferred')).toBeInTheDocument()
    expect(screen.getByText(/synthetic dependency inferred/i)).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /contextual findings and evidence/i }))
      .toBeInTheDocument()
    expect(screen.getByText(/humanReviewRequired:/i)).toBeInTheDocument()
    expect(screen.getByText(/recovery evidence remains incomplete/i)).toBeInTheDocument()
  })

  it('applies a complete structured manifest edit before saving the draft', async () => {
    const user = userEvent.setup()
    await renderStudio()
    await user.click(screen.getByRole('button', { name: 'Manifest' }))
    await user.click(screen.getByText(/full canonical manifest sections/i))

    const editor = screen.getByLabelText(/canonical manifest json/i)
    const payload = JSON.parse((editor as HTMLTextAreaElement).value) as {
      workload: { displayName: string }
    }
    payload.workload.displayName = 'Synthetic full-manifest edit'
    fireEvent.change(editor, { target: { value: JSON.stringify(payload, null, 2) } })
    await user.click(screen.getByRole('button', { name: /apply structured json/i }))

    expect(screen.getByText(/full manifest structure accepted locally/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/workload display name/i)).toHaveValue(
      'Synthetic full-manifest edit',
    )
    await user.click(screen.getByRole('button', { name: /save structured edits/i }))
    await waitFor(() => expect(screen.getByText(/saved at revision 2/i)).toBeInTheDocument())
  })

  it('rebinds the editor after a lifecycle mutation', async () => {
    const user = userEvent.setup()
    await renderStudio(createMockContextApiClient({ publishedOnly: true }))

    await user.click(
      screen.getByRole('button', { name: /create successor draft/i }),
    )
    await waitFor(() =>
      expect(screen.getByText(/successor draft .* created at 1\.0\.1/i))
        .toBeInTheDocument()
    )
    expect(screen.getByText(/manifest version: 1\.0\.1/i))
      .toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Manifest' }))
    await user.click(screen.getByRole('button', { name: /save structured edits/i }))
    await waitFor(() =>
      expect(screen.getByText(/saved at revision 2/i)).toBeInTheDocument()
    )
  })

  it('compares exact versions and creates rollback only as a new draft', async () => {
    const base = createMockContextApiClient({ publishedOnly: true })
    const initial = (await base.loadAuthorizedWorkloads())[0]!
    const rollbackDraft: DraftRecord = {
      draftId: 'draft-synthetic-rollback',
      manifestId: initial.workloadId,
      state: 'draft',
      revision: 1,
      manifest: {
        ...structuredClone(initial.manifest),
        manifestVersion: '1.0.1',
      },
      manifestDigest: initial.manifest.compatibility.artifactDigest,
      previousVersion: initial.manifestVersion,
      createdBy: { actorId: mockAuthSession.actorId, kind: 'human' },
      createdAt: '2026-08-17T00:10:00.000Z',
      updatedBy: { actorId: mockAuthSession.actorId, kind: 'human' },
      updatedAt: '2026-08-17T00:10:00.000Z',
      reason: 'Synthetic rollback-by-new-version.',
      validation: null,
      review: null,
      publicationCandidate: null,
      reviewDecisions: [],
      approval: null,
    }
    const versionedContext = {
      ...initial,
      publishedVersions: [
        {
          manifestVersion: '0.9.0',
          manifestDigest: `sha256:${'1'.repeat(64)}`,
          publishedAt: '2026-08-16T00:00:00.000Z',
          publishedBy: 'human-publisher',
          supersededBy: initial.manifestVersion,
          active: false,
        },
        ...initial.publishedVersions,
      ],
    }
    const client: ContextApiClientPort = {
      ...base,
      loadAuthorizedWorkloads: async () => [versionedContext],
      loadWorkloadContext: async () => versionedContext,
      comparePublishedVersions: vi.fn(async () => ({
        manifestId: initial.workloadId,
        fromVersion: '0.9.0',
        toVersion: initial.manifestVersion,
        fromDigest: `sha256:${'1'.repeat(64)}`,
        toDigest: initial.manifest.compatibility.artifactDigest,
        equivalent: false,
        changedPaths: ['/manifestVersion', '/profiles/production/controls/0'],
      })),
      createRollbackDraft: vi.fn(async () => rollbackDraft),
    }
    const user = userEvent.setup()
    await renderStudio(client)
    await user.click(screen.getByRole('button', { name: 'Versions' }))

    await user.click(screen.getByRole('button', { name: /compare exact versions/i }))
    expect(await screen.findByText('/profiles/production/controls/0')).toBeInTheDocument()
    await user.click(
      screen.getByRole('button', { name: /create rollback draft from source/i }),
    )
    await waitFor(() => expect(client.createRollbackDraft).toHaveBeenCalledWith(
      initial.workloadId,
      '0.9.0',
      'Create rollback-by-new-version draft from 0.9.0.',
    ))
    expect(await screen.findByText(/rollback draft draft-synthetic-rollback created/i))
      .toBeInTheDocument()
  })

  it('clears expired operational evidence when exact refresh fails', async () => {
    vi.useFakeTimers()
    const base = createMockContextApiClient()
    const context = (await base.loadAuthorizedWorkloads())[0]!
    const expiresAt = new Date(Date.now() + 1000).toISOString()
    const enriched = {
      ...context,
      operationalContextRequired: true,
      operationalContext: {
        schemaVersion: 'athena.contextStudio.operationalContext.v1' as const,
        workloadId: context.workloadId,
        manifestVersion: context.manifestVersion,
        profileId: context.profileId,
        draftId: context.draft!.draftId,
        draftRevision: context.draft!.revision,
        manifestDigest: context.draft!.manifestDigest,
        profileDigest: `sha256:${'3'.repeat(64)}`,
        receiptId: 'operational-expiring-receipt',
        receipt: {
          ...context.operationalContext!.receipt,
          receiptId: 'operational-expiring-receipt',
          snapshotId: 'snapshot-expiring',
          expiresAt,
        },
        snapshotId: 'snapshot-expiring',
        collectedAt: new Date(Date.now() - 1000).toISOString(),
        expiresAt,
        evidenceSource: 'Synthetic expiring evidence',
        confidence: 0.9,
        evidenceInventory: [{
          evidenceRef: 'evidence-expiring',
          evidenceDigest: `sha256:${'4'.repeat(64)}`,
        }],
        evidenceInventoryDigest: `sha256:${'5'.repeat(64)}`,
        contentDigest: `sha256:${'7'.repeat(64)}`,
        bindingDigest: `sha256:${'6'.repeat(64)}`,
        relationships: [],
        findings: context.findings,
      },
      evidenceSource: 'Synthetic expiring evidence',
      confidence: 0.9,
    }
    const client: ContextApiClientPort = {
      ...base,
      loadAuthorizedWorkloads: async () => [enriched],
      loadWorkloadContext: vi.fn(async () => {
        throw new Error('synthetic refresh failure')
      }),
    }

    await renderStudio(client)
    expect(screen.getByText(/humanReviewRequired:/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Manifest' }))
    const displayName = screen.getByLabelText(/workload display name/i)
    fireEvent.change(displayName, {
      target: { value: 'Unsaved operator edit' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Overview' }))

    await act(async () => {
      vi.advanceTimersByTime(1001)
      await Promise.resolve()
    })

    expect(screen.queryByText(/humanReviewRequired:/i)).not.toBeInTheDocument()
    expect(screen.getByText(/operational context expired and could not be refreshed/i))
      .toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Manifest' }))
    expect(screen.getByLabelText(/workload display name/i)).toHaveValue(
      'Unsaved operator edit',
    )
    vi.useRealTimers()
  })

  it('preserves unsaved edits when expired operational evidence refreshes', async () => {
    vi.useFakeTimers()
    const base = createMockContextApiClient()
    const context = (await base.loadAuthorizedWorkloads())[0]!
    const expiresAt = new Date(Date.now() + 1000).toISOString()
    const expiring = {
      ...context,
      operationalContext: {
        ...context.operationalContext!,
        expiresAt,
      },
    }
    const refreshed = {
      ...context,
      evidenceSource: 'Refreshed operational evidence',
      operationalContext: {
        ...context.operationalContext!,
        receiptId: 'operational-refreshed',
        receipt: {
          ...context.operationalContext!.receipt,
          receiptId: 'operational-refreshed',
          snapshotId: 'snapshot-refreshed',
          expiresAt: '2100-01-01T00:00:00.000Z',
        },
        snapshotId: 'snapshot-refreshed',
        expiresAt: '2100-01-01T00:00:00.000Z',
        evidenceSource: 'Refreshed operational evidence',
      },
    }
    const client: ContextApiClientPort = {
      ...base,
      loadAuthorizedWorkloads: async () => [expiring],
      loadWorkloadContext: vi.fn(async () => refreshed),
    }

    await renderStudio(client)
    fireEvent.click(screen.getByRole('button', { name: 'Manifest' }))
    const displayName = screen.getByLabelText(/workload display name/i)
    fireEvent.change(displayName, {
      target: { value: 'Unsaved operator edit' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Overview' }))

    await act(async () => {
      vi.advanceTimersByTime(1001)
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(screen.getByText(/evidence source: refreshed operational evidence/i))
      .toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Manifest' }))
    expect(screen.getByLabelText(/workload display name/i)).toHaveValue(
      'Unsaved operator edit',
    )
    vi.useRealTimers()
  })

  it('ignores an A-to-B-to-A stale operational refresh', async () => {
    vi.useFakeTimers()
    const base = createMockContextApiClient()
    const primary = (await base.loadAuthorizedWorkloads())[0]!
    const expiresAt = new Date(Date.now() + 1000).toISOString()
    const expiringPrimary = {
      ...primary,
      operationalContext: {
        ...primary.operationalContext!,
        expiresAt,
      },
    }
    const secondaryManifest = structuredClone(primary.manifest)
    secondaryManifest.manifestId = 'wl-secondary'
    secondaryManifest.workload.displayName = 'Secondary workload'
    const secondary = {
      ...primary,
      workloadId: 'wl-secondary',
      manifest: secondaryManifest,
      catalogueItem: {
        ...primary.catalogueItem,
        id: 'wl-secondary',
        name: 'Secondary workload',
      },
      draft: {
        ...primary.draft!,
        draftId: 'draft-secondary',
        manifestId: 'wl-secondary',
        manifest: secondaryManifest,
      },
      operationalContext: {
        ...primary.operationalContext!,
        workloadId: 'wl-secondary',
        draftId: 'draft-secondary',
        receiptId: 'operational-secondary',
        receipt: {
          ...primary.operationalContext!.receipt,
          receiptId: 'operational-secondary',
          manifestId: 'wl-secondary',
          draftId: 'draft-secondary',
          snapshotId: 'snapshot-secondary',
        },
        snapshotId: 'snapshot-secondary',
      },
    }
    let resolveStale!: (context: typeof expiringPrimary) => void
    const staleRefresh = new Promise<typeof expiringPrimary>((resolve) => {
      resolveStale = resolve
    })
    const client: ContextApiClientPort = {
      ...base,
      loadAuthorizedWorkloads: async () => [expiringPrimary, secondary],
      loadWorkloadContext: vi.fn(async (workloadId) => {
        if (workloadId === primary.workloadId) return staleRefresh
        return secondary
      }),
    }

    await renderStudio(client)
    await act(async () => {
      vi.advanceTimersByTime(1001)
      await Promise.resolve()
    })
    fireEvent.click(
      screen.getByRole('button', { name: /secondary workload/i }),
    )
    await act(async () => Promise.resolve())
    fireEvent.click(
      screen.getByRole('button', {
        name: new RegExp(primary.manifest.workload.displayName, 'i'),
      }),
    )
    await act(async () => Promise.resolve())

    await act(async () => {
      resolveStale({
        ...expiringPrimary,
        evidenceSource: 'STALE ABA RESPONSE',
        operationalContext: {
          ...expiringPrimary.operationalContext!,
          expiresAt: '2100-01-01T00:00:00.000Z',
        },
      })
      await Promise.resolve()
    })

    expect(screen.queryByText(/STALE ABA RESPONSE/i)).not.toBeInTheDocument()
    expect(screen.getByText(/operational context is unavailable/i))
      .toBeInTheDocument()
    vi.useRealTimers()
  })

  it('blocks stale edits when automatic refresh observes a newer revision', async () => {
    vi.useFakeTimers()
    const base = createMockContextApiClient()
    const context = (await base.loadAuthorizedWorkloads())[0]!
    const expiring = {
      ...context,
      operationalContext: {
        ...context.operationalContext!,
        expiresAt: new Date(Date.now() + 1000).toISOString(),
      },
    }
    const serverManifest = structuredClone(context.manifest)
    serverManifest.workload.displayName = 'Server revision B'
    const drifted = {
      ...context,
      manifest: serverManifest,
      draft: {
        ...context.draft!,
        revision: context.draft!.revision + 1,
        manifest: serverManifest,
      },
      operationalContext: {
        ...context.operationalContext!,
        draftRevision: context.draft!.revision + 1,
        expiresAt: '2100-01-01T00:00:00.000Z',
        receipt: {
          ...context.operationalContext!.receipt,
          draftRevision: context.draft!.revision + 1,
          expiresAt: '2100-01-01T00:00:00.000Z',
        },
      },
    }
    const client: ContextApiClientPort = {
      ...base,
      loadAuthorizedWorkloads: async () => [expiring],
      loadWorkloadContext: vi.fn(async () => drifted),
    }

    await renderStudio(client)
    fireEvent.click(screen.getByRole('button', { name: 'Manifest' }))
    fireEvent.change(screen.getByLabelText(/workload display name/i), {
      target: { value: 'Unsaved revision A edit' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Overview' }))
    await act(async () => {
      vi.advanceTimersByTime(1001)
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(
      screen.getByRole('heading', {
        name: /concurrent lifecycle change detected/i,
      }),
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Manifest' }))
    expect(screen.getByLabelText(/workload display name/i)).toHaveValue(
      'Unsaved revision A edit',
    )
    expect(screen.getByRole('button', { name: /save structured edits/i }))
      .toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Cohorts' }))
    expect(
      screen.queryByRole('heading', { name: /cohort proposal review/i }),
    ).not.toBeInTheDocument()
    fireEvent.click(
      screen.getByRole('button', { name: /reload authoritative lifecycle/i }),
    )
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })
    fireEvent.click(screen.getByRole('button', { name: 'Manifest' }))
    expect(screen.getByLabelText(/workload display name/i)).toHaveValue(
      'Server revision B',
    )
    vi.useRealTimers()
  })

  it('passes automated accessibility checks', async () => {
    const { container } = await renderStudio()
    expect((await axe(container)).violations).toHaveLength(0)
  })
})
