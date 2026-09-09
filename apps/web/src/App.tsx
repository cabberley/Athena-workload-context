import { useCallback, useEffect, useRef, useState } from 'react'
import CohortReview from './CohortReview'
import {
  parseCanonicalManifest,
  SupersessionRecoveryRequiredError,
} from './client'
import type { CohortDecisionApiPort, CohortProposalApiPort } from './cohortTypes'
import type {
  AppRoute,
  CanonicalWorkloadManifest,
  ConcurrencyRequest,
  ContextApiClientPort,
  ExactVersionComparison,
  SupersessionRecovery,
  WorkloadContext,
} from './types'
import './App.css'

const cloneManifest = (manifest: CanonicalWorkloadManifest): CanonicalWorkloadManifest =>
  structuredClone(manifest)

const displayEnvironment = (value: string): string =>
  value === 'disasterRecovery' ? 'Disaster Recovery' : `${value.charAt(0).toUpperCase()}${value.slice(1)}`

const errorMessage = (error: unknown, fallback: string): string =>
  error instanceof Error ? error.message : fallback

const boundedLines = (value: string): string[] =>
  value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0)

const concurrencyRequest = (context: WorkloadContext, reason: string): ConcurrencyRequest => {
  if (!context.draft) throw new Error('The active draft is unavailable.')
  return {
    workloadId: context.workloadId,
    draftId: context.draft.draftId,
    expectedRevision: context.draft.revision,
    expectedManifestVersion: context.draft.manifest.manifestVersion,
    expectedDigest: context.draft.manifestDigest,
    reason,
  }
}

const withoutOperationalContext = (
  context: WorkloadContext,
): WorkloadContext => ({
  ...context,
  evidenceSource: 'Operational context is unavailable for the exact lifecycle binding.',
  confidence: null,
  relationships: context.relationships.filter(
    (relationship) =>
      relationship.kind === 'declared' || relationship.kind === 'exception',
  ),
  findings: [],
  provenance: context.provenance.filter(
    (item) => !item.id.startsWith('operational-'),
  ),
  validationMessages: [
    ...context.validationMessages.filter(
      (message) => !message.startsWith('Operational context expired'),
    ),
    'Operational context expired; approval and publication remain blocked until refresh.',
  ],
  operationalContext: null,
})

const workloadAuthorityKey = (context: WorkloadContext): string => [
  context.workloadId,
  context.profileId,
  context.draft?.draftId ?? '',
  context.draft?.revision ?? 0,
  context.draft?.manifestDigest ?? '',
  context.published?.manifestVersion ?? '',
  context.published?.manifestDigest ?? '',
].join('|')

interface FullManifestEditorProps {
  manifest: CanonicalWorkloadManifest
  disabled: boolean
  onApply: (manifest: CanonicalWorkloadManifest) => void
}

function FullManifestEditor({
  manifest,
  disabled,
  onApply,
}: FullManifestEditorProps) {
  const [value, setValue] = useState(() => JSON.stringify(manifest, null, 2))
  const [message, setMessage] = useState(
    'Edit the complete canonical manifest without changing its identity or candidate version.',
  )

  useEffect(() => {
    setValue(JSON.stringify(manifest, null, 2))
  }, [manifest])

  const apply = (): void => {
    try {
      const parsed = parseCanonicalManifest(JSON.parse(value))
      if (
        parsed.manifestId !== manifest.manifestId ||
        parsed.manifestVersion !== manifest.manifestVersion
      ) {
        throw new Error('Manifest identity and candidate version are immutable in this editor.')
      }
      onApply(parsed)
      setMessage('Full manifest structure accepted locally; server validation remains required.')
    } catch (error) {
      setMessage(errorMessage(error, 'Manifest JSON is invalid.'))
    }
  }

  return (
    <details className="full-manifest-editor">
      <summary>Full canonical manifest sections</summary>
      <p>
        This bounded editor preserves the complete roles, relationships, constraints, controls,
        objectives, ownership, unknowns, and exception structures. Publication metadata remains
        server-governed.
      </p>
      <label htmlFor="full-manifest-json">
        Canonical manifest JSON
        <textarea
          id="full-manifest-json"
          rows={20}
          value={value}
          onChange={(event) => setValue(event.target.value)}
          disabled={disabled}
          spellCheck={false}
        />
      </label>
      <button type="button" className="secondary-action" onClick={apply} disabled={disabled}>
        Apply structured JSON
      </button>
      <small role="status">{message}</small>
    </details>
  )
}

interface AppProps {
  client: ContextApiClientPort
  cohortClient: CohortProposalApiPort
  decisionClient?: CohortDecisionApiPort
  initialContexts: WorkloadContext[]
}

function App({ client, cohortClient, decisionClient, initialContexts }: AppProps) {
  const initial = initialContexts[0]!
  const [route, setRoute] = useState<AppRoute>('overview')
  const [contexts, setContexts] = useState(() => new Map(initialContexts.map((context) => [context.workloadId, context])))
  const [selectedWorkloadId, setSelectedWorkloadId] = useState(initial.workloadId)
  const [workloadContext, setWorkloadContext] = useState(initial)
  const [draftForm, setDraftForm] = useState(() => cloneManifest(initial.manifest))
  const [selectedProfileId, setSelectedProfileId] = useState(initial.profileId)
  const initialActiveVersion = initial.publishedVersions.find((version) => version.active)
  const initialEarlierVersion = initial.publishedVersions.find((version) => !version.active)
  const [comparisonFromVersion, setComparisonFromVersion] = useState(
    initialEarlierVersion?.manifestVersion ?? initial.publishedVersions[0]?.manifestVersion ?? '',
  )
  const [comparisonToVersion, setComparisonToVersion] = useState(
    initialActiveVersion?.manifestVersion ?? initial.publishedVersions.at(-1)?.manifestVersion ?? '',
  )
  const [versionComparison, setVersionComparison] =
    useState<ExactVersionComparison | null>(null)
  const [reviewedDigest, setReviewedDigest] = useState<string | null>(null)
  const [reviewComments, setReviewComments] = useState(
    'Reviewed the exact canonical publication candidate.',
  )
  const [rejectedFields, setRejectedFields] = useState('')
  const [requiredCorrections, setRequiredCorrections] = useState('')
  const [supersessionRecovery, setSupersessionRecovery] = useState<SupersessionRecovery | null>(
    initial.pendingSupersessionRecovery,
  )
  const [authorityDrift, setAuthorityDrift] = useState(false)
  const [statusMessage, setStatusMessage] = useState('Authenticated workload context loaded from scoped WC-007 routes.')
  const [busy, setBusy] = useState(false)
  const routeHeadingRef = useRef<HTMLHeadingElement>(null)
  const workloadAuthorityRef = useRef(workloadAuthorityKey(initial))
  const workloadRequestGenerationRef = useRef(0)
  workloadAuthorityRef.current = workloadAuthorityKey(workloadContext)

  useEffect(() => {
    routeHeadingRef.current?.focus()
  }, [route])

  const applyContext = useCallback((next: WorkloadContext): void => {
    setContexts((current) => new Map(current).set(next.workloadId, next))
    setSelectedWorkloadId(next.workloadId)
    setWorkloadContext(next)
    setDraftForm(cloneManifest(next.manifest))
    setSelectedProfileId(next.profileId)
    const activeVersion = next.publishedVersions.find((version) => version.active)
    const earlierVersion = next.publishedVersions.find((version) => !version.active)
    setComparisonFromVersion(
      earlierVersion?.manifestVersion ?? next.publishedVersions[0]?.manifestVersion ?? '',
    )
    setComparisonToVersion(
      activeVersion?.manifestVersion ?? next.publishedVersions.at(-1)?.manifestVersion ?? '',
    )
    setVersionComparison(null)
    setSupersessionRecovery(next.pendingSupersessionRecovery)
    setAuthorityDrift(false)
    setReviewedDigest((current) =>
      current === next.draft?.manifestDigest ? current : null
    )
  }, [])

  const applyExternalContext = useCallback((next: WorkloadContext): void => {
    workloadRequestGenerationRef.current += 1
    applyContext(next)
  }, [applyContext])

  const applyOperationalRefresh = useCallback(
    (next: WorkloadContext): void => {
      setContexts((current) => new Map(current).set(next.workloadId, next))
      setWorkloadContext(next)
      setReviewedDigest((current) =>
        current === next.draft?.manifestDigest ? current : null
      )
    },
    [],
  )

  const refreshCurrentWorkload = useCallback(async (): Promise<WorkloadContext> => {
    const requestGeneration = ++workloadRequestGenerationRef.current
    const requestAuthority = workloadAuthorityRef.current
    const requestWorkloadId = selectedWorkloadId
    const next = await client.loadWorkloadContext(selectedWorkloadId)
    if (
      workloadRequestGenerationRef.current === requestGeneration &&
      workloadAuthorityRef.current === requestAuthority &&
      next.workloadId === requestWorkloadId
    ) {
      applyContext(next)
    }
    return next
  }, [applyContext, client, selectedWorkloadId])

  useEffect(() => {
    const expiresAt = workloadContext.operationalContext?.expiresAt
    if (!expiresAt) return
    const delay = Date.parse(expiresAt) - Date.now()
    const expireAndRefresh = (): void => {
      const requestGeneration = ++workloadRequestGenerationRef.current
      const requestAuthority = workloadAuthorityRef.current
      const requestWorkloadId = selectedWorkloadId
      const expired = withoutOperationalContext(workloadContext)
      setContexts((current) =>
        new Map(current).set(expired.workloadId, expired)
      )
      setWorkloadContext(expired)
      setReviewedDigest((current) =>
        current === expired.draft?.manifestDigest ? current : null
      )
      setStatusMessage(
        'Operational context expired; approval and publication are blocked pending refresh.',
      )
      void client.loadWorkloadContext(selectedWorkloadId)
        .then((next) => {
          if (
            workloadRequestGenerationRef.current === requestGeneration &&
            workloadAuthorityRef.current === requestAuthority &&
            next.workloadId === requestWorkloadId
          ) {
            if (workloadAuthorityKey(next) === requestAuthority) {
              applyOperationalRefresh(next)
            } else {
              setAuthorityDrift(true)
              setStatusMessage(
                'The authoritative lifecycle changed during operational refresh. Unsaved edits are preserved but all mutations are blocked until explicit reload.',
              )
            }
          }
        })
        .catch(() => {
          if (workloadRequestGenerationRef.current === requestGeneration) {
            setStatusMessage(
              'Operational context expired and could not be refreshed for the exact lifecycle binding.',
            )
          }
        })
    }
    if (delay <= 0) {
      expireAndRefresh()
      return
    }
    const timer = window.setTimeout(expireAndRefresh, Math.min(delay, 2_147_483_647))
    return () => window.clearTimeout(timer)
  }, [
    applyOperationalRefresh,
    client,
    selectedWorkloadId,
    workloadContext,
    workloadContext.operationalContext?.expiresAt,
  ])

  const handleSelectWorkload = async (workloadId: string): Promise<void> => {
    if (authorityDrift) {
      setStatusMessage(
        'Reload the authoritative lifecycle before changing workload context.',
      )
      return
    }
    const requestGeneration = ++workloadRequestGenerationRef.current
    setBusy(true)
    try {
      const cached = contexts.get(workloadId)
      if (
        cached &&
        (
          cached.operationalContext === null ||
          Date.parse(cached.operationalContext.expiresAt) > Date.now()
        )
      ) {
        if (workloadRequestGenerationRef.current !== requestGeneration) return
        applyContext(cached)
        setStatusMessage(`Selected authorized workload ${cached.manifest.workload.displayName}.`)
      } else {
        const next = await client.loadWorkloadContext(workloadId)
        if (workloadRequestGenerationRef.current !== requestGeneration) return
        applyContext(next)
        setStatusMessage(`Loaded authorized workload ${next.manifest.workload.displayName}.`)
      }
    } catch (error) {
      setStatusMessage(errorMessage(error, `Unable to load workload ${workloadId}.`))
    } finally {
      setBusy(false)
    }
  }

  const saveDraft = async (): Promise<void> => {
    if (!workloadContext.draft || workloadContext.draft.state !== 'draft') {
      setStatusMessage('Only a WC-007 draft in draft state can be edited.')
      return
    }
    setBusy(true)
    try {
      const updated = await client.updateDraft({
        ...concurrencyRequest(workloadContext, 'Save structured canonical manifest edits for explicit review.'),
        replacementManifest: draftForm,
      })
      setReviewedDigest(null)
      await refreshCurrentWorkload()
      setStatusMessage(`Draft ${updated.draftId} saved at revision ${updated.revision}.`)
    } catch (error) {
      setStatusMessage(errorMessage(error, 'Unable to save the draft.'))
    } finally {
      setBusy(false)
    }
  }

  const createSuccessorDraft = async (): Promise<void> => {
    setBusy(true)
    try {
      const created = await client.createSuccessorDraft(
        selectedWorkloadId,
        'Create a unique successor from the current unsuperseded published version.',
      )
      setReviewedDigest(null)
      await refreshCurrentWorkload()
      setStatusMessage(
        `Successor draft ${created.draftId} created at ${created.manifest.manifestVersion}; previous version ${created.previousVersion}.`,
      )
    } catch (error) {
      setStatusMessage(errorMessage(error, 'Unable to create a successor draft.'))
    } finally {
      setBusy(false)
    }
  }

  const comparePublishedVersions = async (): Promise<void> => {
    if (!comparisonFromVersion || !comparisonToVersion) {
      setStatusMessage('Select two exact published versions to compare.')
      return
    }
    setBusy(true)
    try {
      const comparison = await client.comparePublishedVersions(
        selectedWorkloadId,
        comparisonFromVersion,
        comparisonToVersion,
      )
      setVersionComparison(comparison)
      setStatusMessage(
        comparison.equivalent
          ? `Versions ${comparison.fromVersion} and ${comparison.toVersion} are equivalent.`
          : `Compared exact versions ${comparison.fromVersion} and ${comparison.toVersion}.`,
      )
    } catch (error) {
      setVersionComparison(null)
      setStatusMessage(errorMessage(error, 'Unable to compare exact published versions.'))
    } finally {
      setBusy(false)
    }
  }

  const createRollbackDraft = async (): Promise<void> => {
    if (!comparisonFromVersion) {
      setStatusMessage('Select an older exact version as the rollback source.')
      return
    }
    setBusy(true)
    try {
      const created = await client.createRollbackDraft(
        selectedWorkloadId,
        comparisonFromVersion,
        `Create rollback-by-new-version draft from ${comparisonFromVersion}.`,
      )
      await refreshCurrentWorkload()
      setRoute('manifest')
      setStatusMessage(
        `Rollback draft ${created.draftId} created as new version ${created.manifest.manifestVersion}; no published version was mutated.`,
      )
    } catch (error) {
      setStatusMessage(errorMessage(error, 'Unable to create rollback-by-new-version draft.'))
    } finally {
      setBusy(false)
    }
  }

  const validateDraft = async (): Promise<void> => {
    setBusy(true)
    try {
      const validated = await client.validateDraft(
        concurrencyRequest(workloadContext, 'Validate the exact canonical candidate digest.'),
      )
      await refreshCurrentWorkload()
      setStatusMessage(`WC-007 validated draft ${validated.draftId}.`)
    } catch (error) {
      setStatusMessage(errorMessage(error, 'Validation failed closed.'))
    } finally {
      setBusy(false)
    }
  }

  const submitForReview = async (): Promise<void> => {
    setBusy(true)
    try {
      const submitted = await client.submitForReview(
        concurrencyRequest(workloadContext, 'Submit the validated candidate for explicit human review.'),
      )
      setReviewedDigest(null)
      await refreshCurrentWorkload()
      setStatusMessage(`Draft ${submitted.draftId} is awaiting explicit human review.`)
    } catch (error) {
      setStatusMessage(errorMessage(error, 'Review submission failed closed.'))
    } finally {
      setBusy(false)
    }
  }

  const recordReview = async (
    decision: 'approved' | 'changes_requested',
  ): Promise<void> => {
    const draft = workloadContext.draft
    if (
      !draft ||
      reviewedDigest !== draft.manifestDigest ||
      client.auth.kind !== 'human'
    ) {
      setStatusMessage(
        'A human must explicitly review this exact candidate digest.',
      )
      return
    }
    setBusy(true)
    try {
      const reviewed = await client.reviewDraft({
        ...concurrencyRequest(
          workloadContext,
          decision === 'approved'
            ? 'Record authoritative review approval.'
            : 'Record authoritative requested corrections.',
        ),
        decision,
        comments: reviewComments,
        rejectedFields:
          decision === 'approved' ? [] : boundedLines(rejectedFields),
        requiredCorrections:
          decision === 'approved'
            ? []
            : boundedLines(requiredCorrections),
      })
      if (decision === 'changes_requested') {
        setReviewedDigest(null)
      }
      await refreshCurrentWorkload()
      setStatusMessage(
        decision === 'approved'
          ? `Review ${reviewed.reviewDecisions.at(-1)?.decisionId ?? 'decision'} authorizes approval review.`
          : 'Required corrections were recorded and the draft returned to editing.',
      )
    } catch (error) {
      setStatusMessage(
        errorMessage(error, 'Authoritative review failed closed.'),
      )
    } finally {
      setBusy(false)
    }
  }

  const approveDraft = async (): Promise<void> => {
    const draft = workloadContext.draft
    const operationalReceiptId =
      workloadContext.operationalContext?.receiptId
    if (
      !draft ||
      !operationalReceiptId ||
      reviewedDigest !== draft.manifestDigest ||
      client.auth.kind !== 'human'
    ) {
      setStatusMessage('A human must explicitly review this exact candidate digest before approval.')
      return
    }

    setBusy(true)
    try {
      const approved = await client.approveDraft(
        {
          ...concurrencyRequest(workloadContext, 'Human reviewed and approved the exact candidate digest.'),
          operationalContextReceiptId: operationalReceiptId,
        },
      )
      await refreshCurrentWorkload()
      setReviewedDigest(approved.manifestDigest)
      setStatusMessage(`Server approval ${approved.approval?.decisionId ?? 'record'} is ready for publication review.`)
    } catch (error) {
      setStatusMessage(errorMessage(error, 'Approval failed closed.'))
    } finally {
      setBusy(false)
    }
  }

  const publishDraft = async (): Promise<void> => {
    const draft = workloadContext.draft
    const operationalReceiptId =
      workloadContext.operationalContext?.receiptId
    if (
      !draft?.approval ||
      !operationalReceiptId ||
      reviewedDigest !== draft.manifestDigest ||
      client.auth.kind !== 'human'
    ) {
      setStatusMessage('Publication requires an explicit human review of the exact server-approved candidate.')
      return
    }
    setBusy(true)
    try {
      const published = await client.publishDraft({
        ...concurrencyRequest(workloadContext, 'Publish the explicitly reviewed, server-approved candidate.'),
        approvalId: draft.approval.decisionId,
        operationalContextReceiptId: operationalReceiptId,
      })
      setReviewedDigest(null)
      setSupersessionRecovery(null)
      await refreshCurrentWorkload()
      setStatusMessage(
        published.previousVersion
          ? `Published version ${published.manifestVersion} and superseded predecessor ${published.previousVersion} for ${published.manifestId}.`
          : `Published initial version ${published.manifestVersion} for ${published.manifestId}.`,
      )
    } catch (error) {
      if (error instanceof SupersessionRecoveryRequiredError) {
        setSupersessionRecovery(error.recovery)
        setStatusMessage(error.message)
      } else {
        setStatusMessage(errorMessage(error, 'Publication failed closed.'))
      }
    } finally {
      setBusy(false)
    }
  }

  const recoverSupersession = async (): Promise<void> => {
    if (!supersessionRecovery) return
    setBusy(true)
    try {
      await client.completeSupersession(supersessionRecovery)
      const recovered = supersessionRecovery
      setSupersessionRecovery(null)
      setReviewedDigest(null)
      await refreshCurrentWorkload()
      setStatusMessage(
        `Recovered publication: ${recovered.predecessorVersion} is superseded by ${recovered.successorVersion}.`,
      )
    } catch (error) {
      setStatusMessage(
        `Supersession recovery remains blocked. ${errorMessage(error, 'The exact recovery command failed.')}`,
      )
    } finally {
      setBusy(false)
    }
  }

  const reloadAfterAuthorityDrift = async (): Promise<void> => {
    setBusy(true)
    try {
      await refreshCurrentWorkload()
      setStatusMessage(
        'Reloaded the current authoritative lifecycle after concurrent change.',
      )
    } catch (error) {
      setStatusMessage(
        errorMessage(
          error,
          'The authoritative lifecycle could not be reloaded.',
        ),
      )
    } finally {
      setBusy(false)
    }
  }

  const currentDraft = workloadContext.draft
  const currentReview = currentDraft?.reviewDecisions.at(-1)
  const selectedProfile = draftForm.profiles[selectedProfileId]
  const reviewConfirmed = Boolean(currentDraft && reviewedDigest === currentDraft.manifestDigest)
  const isHuman = client.auth.kind === 'human'
  const lifecycleBlocked =
    supersessionRecovery !== null || authorityDrift
  const canEdit = !lifecycleBlocked && currentDraft?.state === 'draft'
  const canCreateSuccessor = !lifecycleBlocked && !currentDraft && Boolean(workloadContext.published)
  const canValidate = !lifecycleBlocked && currentDraft?.state === 'draft'
  const canSubmit = !lifecycleBlocked && currentDraft?.state === 'validated'
  const canReview =
    !lifecycleBlocked &&
    currentDraft?.state === 'in_review' &&
    reviewConfirmed &&
    isHuman
  const canRequestCorrections =
    canReview && boundedLines(requiredCorrections).length > 0
  const operationalContextReady =
    workloadContext.operationalContext !== null &&
    Date.parse(workloadContext.operationalContext.expiresAt) > Date.now()
  const canApprove =
    !lifecycleBlocked &&
    currentDraft?.state === 'in_review' &&
    currentReview?.decision === 'approved' &&
    currentReview.reviewedRevision === currentDraft.revision &&
    currentReview.manifestDigest === currentDraft.manifestDigest &&
    reviewConfirmed &&
    isHuman &&
    operationalContextReady
  const canPublish =
    !lifecycleBlocked &&
    currentDraft?.state === 'approved' &&
    Boolean(currentDraft.approval) &&
    reviewConfirmed &&
    isHuman &&
    operationalContextReady
  const catalogue = [...contexts.values()].map((context) => context.catalogueItem)
  const activePublishedVersion = workloadContext.publishedVersions.find(
    (version) => version.active,
  )
  const canRollback =
    !lifecycleBlocked &&
    !currentDraft &&
    comparisonFromVersion.length > 0 &&
    activePublishedVersion !== undefined &&
    comparisonFromVersion !== activePublishedVersion.manifestVersion
  const reviewGaps = [
    ...workloadContext.validationMessages,
    ...(workloadContext.catalogueItem.owner ? [] : ['Workload owner is not declared.']),
    ...(workloadContext.catalogueItem.criticality ? [] : ['Workload criticality is not declared.']),
    ...(workloadContext.confidence === null
      ? ['No runtime confidence value is available from the lifecycle route.']
      : []),
    ...workloadContext.controls
      .filter((control) => control.runbookRef === null)
      .map((control) => `Control ${control.id} has no declared runbook.`),
  ]
  const provenanceSource = currentDraft
    ? `Draft ${currentDraft.draftId} revision ${currentDraft.revision}`
    : workloadContext.published
      ? `Published version ${workloadContext.published.manifestVersion}`
      : 'No authoritative lifecycle record'

  const setDisplayName = (displayName: string): void => {
    setDraftForm((current) => ({
      ...current,
      workload: { ...current.workload, displayName },
    }))
    setReviewedDigest(null)
  }

  const setResidualRisk = (riskId: string, statement: string): void => {
    setDraftForm((current) => {
      const profile = current.profiles[selectedProfileId]
      if (!profile) return current
      return {
        ...current,
        profiles: {
          ...current.profiles,
          [selectedProfileId]: {
            ...profile,
            riskAcceptances: profile.riskAcceptances.map((risk) =>
              risk.riskAcceptanceId === riskId ? { ...risk, residualRiskStatement: statement } : risk,
            ),
          },
        },
      }
    })
    setReviewedDigest(null)
  }

  const navigate = (nextRoute: AppRoute): void => {
    setRoute(nextRoute)
  }

  return (
    <div className="studio-shell">
      <header className="topbar" aria-label="Studio header">
        <div>
          <p className="eyebrow">Authenticated, workload-scoped session</p>
          <h1>Athena Context Studio</h1>
        </div>
        <div className="topbar-meta" aria-label="Session and manifest metadata">
          <span className={`pill state-${currentDraft?.state ?? workloadContext.approvalState}`}>
            Approval: {(currentDraft?.state ?? workloadContext.approvalState).replace('_', ' ')}
          </span>
          <span>Authenticated as {workloadContext.auth.userLabel}</span>
          <span>Role: {workloadContext.auth.role}</span>
          <span>Environment: {displayEnvironment(workloadContext.environment)}</span>
          <span>Manifest version: {workloadContext.manifestVersion}</span>
          <span>Evidence source: {workloadContext.evidenceSource}</span>
          <span>Confidence: {workloadContext.confidence === null ? 'Not provided' : `${Math.round(workloadContext.confidence * 100)}%`}</span>
        </div>
      </header>

      <nav className="primary-nav" aria-label="Primary navigation">
        {(['overview', 'cohorts', 'catalogue', 'manifest', 'versions', 'controls'] as AppRoute[]).map((item) => (
          <button
            key={item}
            type="button"
            className={route === item ? 'nav-button is-selected' : 'nav-button'}
            onClick={() => navigate(item)}
            aria-current={route === item ? 'page' : undefined}
          >
            {item[0].toUpperCase() + item.slice(1)}
          </button>
        ))}
      </nav>

      <main className="studio-layout">
        <aside className="panel catalogue-panel" aria-label="Authorized workload catalogue">
          <div className="panel-heading">
            <h2>Authorized workloads</h2>
            <span className="meta-pill">{catalogue.length} scoped</span>
          </div>
          <ul className="catalogue-list">
            {catalogue.map((workload) => (
              <li key={workload.id}>
                <button
                  type="button"
                  className={workload.id === selectedWorkloadId ? 'catalogue-button is-selected' : 'catalogue-button'}
                  onClick={() => void handleSelectWorkload(workload.id)}
                  aria-pressed={workload.id === selectedWorkloadId}
                  disabled={busy || authorityDrift}
                >
                  <span className="catalogue-name">{workload.name}</span>
                  <span className="catalogue-owner">Owner: {workload.owner ?? 'Not declared'}</span>
                  <span className="catalogue-meta">Lifecycle: {workload.status.replace('_', ' ')}</span>
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <div className="content-stack">
          {route === 'overview' && (
            <>
              <section className="panel overview-panel" aria-labelledby="overview-heading">
                <div className="panel-heading">
                  <h2 id="overview-heading" tabIndex={-1} ref={routeHeadingRef}>Context overview</h2>
                </div>
                <div className="status-grid">
                  <div className="stat-card">
                    <span className="stat-label">Environment</span>
                    <strong>{displayEnvironment(workloadContext.environment)}</strong>
                  </div>
                  <div className="stat-card">
                    <span className="stat-label">Manifest version</span>
                    <strong>{workloadContext.manifestVersion}</strong>
                  </div>
                  <div className="stat-card">
                    <span className="stat-label">Approval state</span>
                    <strong>{workloadContext.approvalState.replace('_', ' ')}</strong>
                  </div>
                  <div className="stat-card">
                    <span className="stat-label">Confidence</span>
                    <strong>{workloadContext.confidence === null ? 'Not provided by WC-007' : `${workloadContext.confidence}`}</strong>
                  </div>
                </div>
              </section>

              <section className="panel comparison-panel" aria-labelledby="comparison-heading">
                <div className="panel-heading">
                  <h2 id="comparison-heading">Declared Production / Development / Training comparison</h2>
                </div>
                <div role="table" aria-label="Production, Development and Training comparison" className="comparison-table">
                  <div className="table-head" role="row">
                    <span role="columnheader">Environment</span>
                    <span role="columnheader">Declared topology</span>
                    <span role="columnheader">Declared policy</span>
                    <span role="columnheader">Residual risk</span>
                  </div>
                  {workloadContext.comparison.map((row) => (
                    <div className="table-row" role="row" key={row.environment}>
                      <div role="cell" className="table-cell" aria-label={`Environment: ${displayEnvironment(row.environment)}`}>
                        <span className="mobile-cell-label" aria-hidden="true">Environment</span>
                        {displayEnvironment(row.environment)}
                      </div>
                      <div role="cell" className="table-cell" aria-label={`Declared topology: ${row.topology}`}>
                        <span className="mobile-cell-label" aria-hidden="true">Declared topology</span>
                        {row.topology}
                      </div>
                      <div role="cell" className="table-cell" aria-label={`Declared policy: ${row.policy}`}>
                        <span className="mobile-cell-label" aria-hidden="true">Declared policy</span>
                        {row.policy}
                      </div>
                      <div role="cell" className="table-cell" aria-label={`Residual risk: ${row.residualRisk}`}>
                        <span className="mobile-cell-label" aria-hidden="true">Residual risk</span>
                        {row.residualRisk}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="panel editor-panel" aria-labelledby="relationship-heading">
                <div className="panel-heading">
                  <h2 id="relationship-heading">Declared, observed, inferred and exception relationships</h2>
                </div>
                <p className="source-note">Only relationship classes present in the canonical server response are shown; Context Studio does not infer missing relationships.</p>
                <ul className="relationship-list">
                  {workloadContext.relationships.map((relationship) => (
                    <li key={`${relationship.profileId ?? 'root'}-${relationship.id}`} className={`relationship-item kind-${relationship.kind}`}>
                      <span className="relationship-kind">{relationship.kind}</span>
                      <strong>{relationship.id}</strong>
                      {relationship.kind === 'exception' ? (
                        <>
                          <p>
                            Exception target: {relationship.targetType} {relationship.targetRef}
                          </p>
                          <p>Rationale: {relationship.rationale}</p>
                          <small>
                            Risk acceptance: {relationship.riskAcceptanceRef} • Scope:{' '}
                            {relationship.governanceScope.clausePath} • Expires: {relationship.expiresAt} • Owner:{' '}
                            {relationship.ownerRef}
                          </small>
                        </>
                      ) : relationship.kind === 'declared' ? (
                        <>
                          <p>{relationship.source} {relationship.relationshipType} {relationship.target}</p>
                          <small>
                            Profile: {relationship.profileId ?? 'manifest'} • Owner: {relationship.ownerRef} • Clause:{' '}
                            {relationship.clause}
                          </small>
                        </>
                      ) : relationship.kind === 'observed' ? (
                        <>
                          <p>{relationship.source} observed communicating with {relationship.target}</p>
                          <small>
                            Profile: {relationship.profileId ?? 'runtime'} • Observed:{' '}
                            {relationship.observedAt} • Confidence:{' '}
                            {Math.round(relationship.confidence * 100)}% • Evidence:{' '}
                            {relationship.evidenceRefs.join(', ')}
                          </small>
                        </>
                      ) : (
                        <>
                          <p>{relationship.source} may depend on {relationship.target}</p>
                          <p>{relationship.hypothesis}</p>
                          <small>
                            Profile: {relationship.profileId ?? 'runtime'} • Confidence:{' '}
                            {Math.round(relationship.confidence * 100)}% • Evidence:{' '}
                            {relationship.evidenceRefs.join(', ')}
                          </small>
                        </>
                      )}
                    </li>
                  ))}
                </ul>
              </section>

              <section className="panel evidence-panel" aria-labelledby="finding-heading">
                <div className="panel-heading">
                  <h2 id="finding-heading">Contextual findings and evidence</h2>
                </div>
                {workloadContext.findings.length === 0 ? (
                  <p role="alert">
                    No evaluated findings were supplied for this exact manifest version. The
                    absence is treated as an evidence gap, not a passing health state.
                  </p>
                ) : (
                  <ul className="stack-list">
                    {workloadContext.findings.map((finding) => (
                      <li key={finding.id} className="stack-item">
                        <span className="stack-name">{finding.verdict}: {finding.summary}</span>
                        <span className="stack-meta">
                          Manifest {finding.manifestVersion} • Profile {finding.profileId} • Clause{' '}
                          {finding.clause} • Confidence{' '}
                          {finding.confidence === null
                            ? 'not provided'
                            : `${Math.round(finding.confidence * 100)}%`}
                        </span>
                        <p>Evidence: {finding.evidenceRefs.join(', ') || 'Missing'}</p>
                        <p>
                          Residual risk: {finding.residualRisk ?? 'Not declared'} • Control:{' '}
                          {finding.controlState ?? 'Unknown'}
                        </p>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </>
          )}

          {route === 'catalogue' && (
            <section className="panel catalogue-overview" aria-labelledby="catalogue-heading">
              <div className="panel-heading">
                <h2 id="catalogue-heading" tabIndex={-1} ref={routeHeadingRef}>Workload catalogue</h2>
              </div>
              <dl className="summary-list">
                <div><dt>Selected workload</dt><dd>{workloadContext.manifest.workload.displayName}</dd></div>
                <div><dt>Authorized workload ID</dt><dd>{workloadContext.workloadId}</dd></div>
                <div><dt>Criticality</dt><dd>{workloadContext.catalogueItem.criticality ?? 'Not provided by WC-007'}</dd></div>
                <div><dt>Zone count</dt><dd>{workloadContext.catalogueItem.zoneCount ?? 'Not provided by WC-007'}</dd></div>
              </dl>
            </section>
          )}

          {route === 'cohorts' && authorityDrift && (
            <section className="panel recovery-state" role="alert">
              <h2>Concurrent lifecycle change detected</h2>
              <p>
                Cohort decisions and all lifecycle mutations are blocked until
                the authoritative lifecycle is reloaded.
              </p>
              <button
                type="button"
                className="primary-action"
                onClick={() => void reloadAfterAuthorityDrift()}
                disabled={busy}
              >
                Reload authoritative lifecycle
              </button>
            </section>
          )}

          {route === 'cohorts' && !authorityDrift && (
            <CohortReview
              context={workloadContext}
              contextClient={client}
              cohortClient={cohortClient}
              decisionClient={decisionClient}
              onContextChange={applyExternalContext}
              headingRef={routeHeadingRef}
            />
          )}

          {route === 'manifest' && (
            <section className="panel editor-panel" aria-labelledby="manifest-heading">
              <div className="panel-heading">
                <h2 id="manifest-heading" tabIndex={-1} ref={routeHeadingRef}>Structured manifest editor</h2>
                <button type="button" className="small-button" onClick={() => void refreshCurrentWorkload()} disabled={busy}>
                  Reload scoped context
                </button>
              </div>
              <p className="source-note">All unedited canonical sections are retained. Digests are recomputed with RFC 8785 canonical JSON and Web Crypto before a request is sent.</p>
              <form className="manifest-form" aria-label="Structured manifest editor">
                <div className="editor-grid">
                  <label htmlFor="workload-name">
                    Workload display name
                    <input
                      id="workload-name"
                      value={draftForm.workload.displayName}
                      onChange={(event) => setDisplayName(event.target.value)}
                      disabled={!canEdit || busy}
                    />
                  </label>
                  <label htmlFor="manifest-version">
                    Manifest version
                    <input id="manifest-version" value={draftForm.manifestVersion} readOnly />
                  </label>
                  <label htmlFor="profile">
                    Environment profile
                    <select id="profile" value={selectedProfileId} onChange={(event) => setSelectedProfileId(event.target.value)}>
                      {Object.values(draftForm.profiles).map((profile) => (
                        <option key={profile.profileId} value={profile.profileId}>{displayEnvironment(profile.profileType)}</option>
                      ))}
                    </select>
                  </label>
                  <label htmlFor="authority">
                    Declared authority reference
                    <input id="authority" value={draftForm.ownership[0]?.authorityRef ?? 'Not declared'} readOnly />
                  </label>
                </div>
                <fieldset>
                  <legend>Declared residual risk — {selectedProfile ? displayEnvironment(selectedProfile.profileType) : selectedProfileId}</legend>
                  {selectedProfile?.riskAcceptances.map((risk) => (
                    <label key={risk.riskAcceptanceId} htmlFor={`risk-${risk.riskAcceptanceId}`}>
                      {risk.riskAcceptanceId}
                      <textarea
                        id={`risk-${risk.riskAcceptanceId}`}
                        value={risk.residualRiskStatement}
                        onChange={(event) => setResidualRisk(risk.riskAcceptanceId, event.target.value)}
                        disabled={!canEdit || busy}
                      />
                    </label>
                  ))}
                  {!selectedProfile?.riskAcceptances.length && <p>No residual-risk acceptance is declared for this profile.</p>}
                </fieldset>
                <FullManifestEditor
                  manifest={draftForm}
                  disabled={!canEdit || busy}
                  onApply={(manifest) => {
                    setDraftForm(cloneManifest(manifest))
                    setReviewedDigest(null)
                  }}
                />
              </form>
            </section>
          )}

          {route === 'versions' && (
            <section className="panel comparison-panel" aria-labelledby="versions-heading">
              <div className="panel-heading">
                <h2 id="versions-heading" tabIndex={-1} ref={routeHeadingRef}>
                  Exact version comparison and rollback
                </h2>
              </div>
              <p className="source-note">
                Published versions are immutable. Rollback always creates a new draft whose
                predecessor is the current active version.
              </p>
              <div className="editor-grid">
                <label htmlFor="comparison-from-version">
                  Source version
                  <select
                    id="comparison-from-version"
                    value={comparisonFromVersion}
                    onChange={(event) => {
                      setComparisonFromVersion(event.target.value)
                      setVersionComparison(null)
                    }}
                  >
                    {workloadContext.publishedVersions.map((version) => (
                      <option key={version.manifestVersion} value={version.manifestVersion}>
                        {version.manifestVersion}{version.active ? ' (active)' : ''}
                      </option>
                    ))}
                  </select>
                </label>
                <label htmlFor="comparison-to-version">
                  Target version
                  <select
                    id="comparison-to-version"
                    value={comparisonToVersion}
                    onChange={(event) => {
                      setComparisonToVersion(event.target.value)
                      setVersionComparison(null)
                    }}
                  >
                    {workloadContext.publishedVersions.map((version) => (
                      <option key={version.manifestVersion} value={version.manifestVersion}>
                        {version.manifestVersion}{version.active ? ' (active)' : ''}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="action-stack">
                <button
                  type="button"
                  className="secondary-action"
                  onClick={() => void comparePublishedVersions()}
                  disabled={
                    busy ||
                    !comparisonFromVersion ||
                    !comparisonToVersion ||
                    comparisonFromVersion === comparisonToVersion
                  }
                >
                  Compare exact versions
                </button>
                <button
                  type="button"
                  className="primary-action"
                  onClick={() => void createRollbackDraft()}
                  disabled={busy || !canRollback}
                >
                  Create rollback draft from source
                </button>
              </div>
              <ul className="stack-list" aria-label="Published version history">
                {workloadContext.publishedVersions.map((version) => (
                  <li key={version.manifestVersion} className="stack-item">
                    <span className="stack-name">
                      {version.manifestVersion} {version.active ? 'active' : 'superseded'}
                    </span>
                    <span className="stack-meta">
                      {version.manifestDigest} • Published by {version.publishedBy} at{' '}
                      {version.publishedAt}
                    </span>
                    <p>
                      {version.supersededBy
                        ? `Superseded by ${version.supersededBy}.`
                        : 'No supersession record.'}
                    </p>
                  </li>
                ))}
              </ul>
              {versionComparison && (
                <div className="approval-record" aria-live="polite">
                  <h3>
                    {versionComparison.fromVersion} → {versionComparison.toVersion}
                  </h3>
                  <p>
                    {versionComparison.equivalent
                      ? 'No canonical changes.'
                      : `${versionComparison.changedPaths.length} canonical path changes.`}
                  </p>
                  <ul>
                    {versionComparison.changedPaths.map((path) => (
                      <li key={path}>{path}</li>
                    ))}
                  </ul>
                </div>
              )}
            </section>
          )}

          {route === 'controls' && (
            <section className="panel evidence-panel" aria-labelledby="controls-heading">
              <div className="panel-heading">
                <h2 id="controls-heading" tabIndex={-1} ref={routeHeadingRef}>Controls and lifecycle provenance</h2>
              </div>
              <div className="two-column-grid">
                <div>
                  <h3>Declared controls</h3>
                  <ul className="stack-list">
                    {workloadContext.controls.map((control) => (
                      <li key={`${control.id}-${control.profiles.join('-')}`} className="stack-item">
                        <span className="stack-name">{control.id}</span>
                        <span className="stack-meta">Owner: {control.ownerRef} • Health: {control.health}</span>
                        <p>Runbook: {control.runbookRef ?? 'Not declared'}</p>
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h3>Declared residual risk</h3>
                  <ul className="stack-list">
                    {workloadContext.riskAcceptances.map((risk) => (
                      <li key={`${risk.id}-${risk.profiles.join('-')}`} className="stack-item">
                        <span className="stack-name">{risk.id}</span>
                        <span className="stack-meta">Owner: {risk.ownedBy} • Status: {risk.status}</span>
                        <p>{risk.residualRiskStatement}</p>
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="span-two">
                  <h3>Lifecycle provenance</h3>
                  <ul className="provenance-list">
                    {workloadContext.provenance.map((item) => (
                      <li key={item.id}>
                        <span className="provenance-source">{item.source}</span>
                        <p>{item.summary}</p>
                        <small>{item.clause} • Manifest {item.manifestVersion} • Confidence {item.confidence ?? 'not provided'}</small>
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h3>Explicit unknowns and review gaps</h3>
                  {reviewGaps.length === 0 ? (
                    <p>No unresolved declaration gaps were detected in this view.</p>
                  ) : (
                    <ul className="stack-list">
                      {reviewGaps.map((gap) => (
                        <li key={gap} className="stack-item">{gap}</li>
                      ))}
                    </ul>
                  )}
                </div>
                <div>
                  <h3>Field provenance</h3>
                  <dl className="summary-list">
                    <div>
                      <dt>/workload</dt>
                      <dd>{provenanceSource}</dd>
                    </div>
                    <div>
                      <dt>/profiles/{selectedProfileId}</dt>
                      <dd>
                        {provenanceSource}; owner{' '}
                        {selectedProfile?.ownership[0]?.ownerRef ??
                          workloadContext.catalogueItem.owner ??
                          'not declared'}
                      </dd>
                    </div>
                    <div>
                      <dt>/relationships</dt>
                      <dd>
                        Declared and exception relationships come from {provenanceSource};
                        observed and inferred relationships require separately cited evidence.
                      </dd>
                    </div>
                  </dl>
                </div>
              </div>
            </section>
          )}
        </div>

        {route === 'cohorts' && (
          <aside className="panel review-panel" aria-label="Cohort review guardrails">
            <div className="panel-kicker">Draft-only boundary</div>
            <h2>Cohort review guardrails</h2>
            <p>
              Cohort proposals are inferred from observed evidence. They never become declared
              authority until a human explicitly writes bounded selectors to a WC-007 draft.
            </p>
            <dl className="summary-list">
              <div><dt>Actor</dt><dd>{client.auth.userLabel}</dd></div>
              <div><dt>Role</dt><dd>{client.auth.role}</dd></div>
              <div><dt>Environment</dt><dd>{displayEnvironment(workloadContext.environment)}</dd></div>
              <div><dt>Manifest</dt><dd>{workloadContext.manifestVersion}</dd></div>
              <div><dt>Approval</dt><dd>{currentDraft?.state ?? workloadContext.approvalState}</dd></div>
            </dl>
            <p className="source-note">
              This flow can update a draft with exact revision, digest, and idempotency. It cannot
              validate, approve, or publish a manifest.
            </p>
          </aside>
        )}

        {route !== 'cohorts' && (
        <aside className="panel review-panel" aria-label="Draft review and publication">
          <div className="panel-kicker">Lifecycle state</div>
          <h2>Explicit human review</h2>
          <p>Agent proposals remain non-authoritative drafts. WC-007 server approval and an explicit review of the exact digest are both required before publication.</p>

          {supersessionRecovery && (
            <div className="recovery-state" role="alert">
              <h3>Publication recovery required</h3>
              <p>
                Successor {supersessionRecovery.successorVersion} is published, but predecessor{' '}
                {supersessionRecovery.predecessorVersion} has not been confirmed superseded. All other lifecycle
                actions are blocked.
              </p>
              <button
                type="button"
                className="primary-action"
                onClick={() => void recoverSupersession()}
                disabled={busy}
              >
                Retry exact supersession
              </button>
            </div>
          )}

          {authorityDrift && (
            <div className="recovery-state" role="alert">
              <h3>Concurrent lifecycle change detected</h3>
              <p>
                Unsaved edits remain in the editor, but cannot be saved against
                a newer authoritative revision. Reload before continuing.
              </p>
              <button
                type="button"
                className="primary-action"
                onClick={() => void reloadAfterAuthorityDrift()}
                disabled={busy}
              >
                Reload authoritative lifecycle
              </button>
            </div>
          )}

          <label className="review-confirmation">
            <input
              type="checkbox"
              checked={reviewConfirmed}
              onChange={(event) => setReviewedDigest(event.target.checked ? currentDraft?.manifestDigest ?? null : null)}
              disabled={
                lifecycleBlocked ||
                !isHuman ||
                !currentDraft ||
                !['in_review', 'approved'].includes(currentDraft.state) ||
                busy
              }
            />
            I reviewed this exact candidate digest for publication.
          </label>

          <label htmlFor="review-comments">
            Review comments
            <textarea
              id="review-comments"
              value={reviewComments}
              onChange={(event) => setReviewComments(event.target.value)}
              disabled={busy || !currentDraft || currentDraft.state !== 'in_review'}
            />
          </label>
          <label htmlFor="rejected-fields">
            Rejected JSON pointer fields, one per line
            <textarea
              id="rejected-fields"
              value={rejectedFields}
              onChange={(event) => setRejectedFields(event.target.value)}
              disabled={busy || !currentDraft || currentDraft.state !== 'in_review'}
            />
          </label>
          <label htmlFor="required-corrections">
            Required corrections, one per line
            <textarea
              id="required-corrections"
              value={requiredCorrections}
              onChange={(event) => setRequiredCorrections(event.target.value)}
              disabled={busy || !currentDraft || currentDraft.state !== 'in_review'}
            />
          </label>

          <div className="action-stack">
            <button type="button" className="primary-action" onClick={() => void saveDraft()} disabled={busy || !canEdit}>Save structured edits</button>
            <button type="button" className="secondary-action" onClick={() => void createSuccessorDraft()} disabled={busy || !canCreateSuccessor}>Create successor draft</button>
            <button type="button" className="secondary-action" onClick={() => void validateDraft()} disabled={busy || !canValidate}>Validate draft</button>
            <button type="button" className="secondary-action" onClick={() => void submitForReview()} disabled={busy || !canSubmit}>Submit for review</button>
            <button type="button" className="secondary-action" onClick={() => void recordReview('approved')} disabled={busy || !canReview}>Record review approval</button>
            <button type="button" className="secondary-action" onClick={() => void recordReview('changes_requested')} disabled={busy || !canRequestCorrections}>Request corrections</button>
            <button type="button" className="secondary-action" onClick={() => void approveDraft()} disabled={busy || !canApprove}>Approve reviewed candidate</button>
            <button type="button" className="primary-action" onClick={() => void publishDraft()} disabled={busy || !canPublish}>Publish reviewed candidate</button>
          </div>

          <div className="status-message" aria-live="polite">{statusMessage}</div>
          <div className="approval-record">
            <h3>Review record</h3>
            <p>{currentReview?.decisionId ?? 'Awaiting authoritative reviewer decision.'}</p>
            <small>
              {currentReview
                ? `${currentReview.decision} • ${currentReview.comments}`
                : 'Browser confirmation alone is not review authority.'}
            </small>
            <h3>Approval record</h3>
            <p>{currentDraft?.approval?.decisionId ?? 'Awaiting WC-007 approval decision.'}</p>
            <small>
              {currentDraft?.approval
                ? `${currentDraft.approval.manifestVersion} • ${currentDraft.approval.manifestDigest}`
                : 'No publication authority is inferred by the browser.'}
            </small>
          </div>
        </aside>
        )}
      </main>
    </div>
  )
}

export default App
