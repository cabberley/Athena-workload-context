import { useState } from 'react'
import { createContextApiClient } from './client'
import type { AppRoute, ManifestDraft, WorkloadContext } from './types'
import './App.css'

const apiClient = createContextApiClient()

const cloneManifest = (context: WorkloadContext): ManifestDraft => ({
  ...context.manifest,
  requiredRelationships: [...context.manifest.requiredRelationships],
  optionalRelationships: [...context.manifest.optionalRelationships],
  controls: context.manifest.controls.map((control) => ({ ...control })),
  riskAcceptances: context.manifest.riskAcceptances.map((acceptance) => ({ ...acceptance })),
})

function App() {
  const [route, setRoute] = useState<AppRoute>('overview')
  const [selectedWorkloadId, setSelectedWorkloadId] = useState('atlas-api')
  const [workloadContext, setWorkloadContext] = useState<WorkloadContext>(() =>
    apiClient.loadWorkloadSync('atlas-api'),
  )
  const [draftForm, setDraftForm] = useState<ManifestDraft>(() =>
    cloneManifest(apiClient.loadWorkloadSync('atlas-api')),
  )
  const [statusMessage, setStatusMessage] = useState('Ready to create or reload a draft.')
  const [busy, setBusy] = useState(false)

  const applyContext = (nextContext: WorkloadContext) => {
    setSelectedWorkloadId(nextContext.workloadId)
    setWorkloadContext(nextContext)
    setDraftForm(cloneManifest(nextContext))
  }

  const handleSelectWorkload = async (nextWorkloadId: string) => {
    setBusy(true)
    try {
      const nextContext = await apiClient.loadWorkloadContext(nextWorkloadId)
      applyContext(nextContext)
      setStatusMessage(`Loaded ${nextContext.manifest.workloadName} context.`)
    } catch (error) {
      setStatusMessage(
        error instanceof Error ? error.message : `Unable to load workload ${nextWorkloadId}.`,
      )
    } finally {
      setBusy(false)
    }
  }

  const refreshCurrentWorkload = async (nextWorkloadId = selectedWorkloadId) => {
    const nextContext = await apiClient.reloadWorkload(nextWorkloadId)
    applyContext(nextContext)
    return nextContext
  }

  const updateField = <K extends keyof ManifestDraft>(field: K, value: ManifestDraft[K]) => {
    setDraftForm((current) => ({ ...current, [field]: value }))
  }

  const updateRelationshipList = (
    field: 'requiredRelationships' | 'optionalRelationships',
    value: string,
  ) => {
    setDraftForm((current) => ({
      ...current,
      [field]: value
        .split(/\r?\n/)
        .map((item) => item.trim())
        .filter(Boolean),
    }))
  }

  const saveDraft = async () => {
    setBusy(true)
    try {
      const currentDraft = workloadContext.draft
      if (!currentDraft) {
        const created = await apiClient.createDraft(
          selectedWorkloadId,
          draftForm,
          'Create draft from the structured editor.',
        )
        await refreshCurrentWorkload()
        setStatusMessage(`Draft ${created.draftId} created. Revision ${created.revision}.`)
        return
      }

      const updated = await apiClient.updateDraft({
        draftId: currentDraft.draftId,
        expectedRevision: currentDraft.revision,
        expectedManifestVersion: currentDraft.manifest.manifestVersion,
        expectedDigest: currentDraft.manifestDigest,
        replacementManifest: draftForm,
        reason: 'Save manifest changes with optimistic concurrency checks.',
      })
      await refreshCurrentWorkload()
      setStatusMessage(`Draft ${updated.draftId} saved. Revision ${updated.revision}.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Unable to save the draft.')
    } finally {
      setBusy(false)
    }
  }

  const validateDraft = async () => {
    setBusy(true)
    try {
      const currentDraft = workloadContext.draft
      if (!currentDraft) {
        throw new Error('Create a draft before validation.')
      }
      const validated = await apiClient.validateDraft({
        draftId: currentDraft.draftId,
        expectedRevision: currentDraft.revision,
        expectedManifestVersion: currentDraft.manifest.manifestVersion,
        expectedDigest: currentDraft.manifestDigest,
        reason: 'Validate the structured manifest.',
      })
      await refreshCurrentWorkload()
      setStatusMessage(`Validation checks passed for ${validated.draftId}.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Validation failed.')
    } finally {
      setBusy(false)
    }
  }

  const submitForReview = async () => {
    setBusy(true)
    try {
      const currentDraft = workloadContext.draft
      if (!currentDraft) {
        throw new Error('Create a draft before submission.')
      }
      const submitted = await apiClient.submitForReview({
        draftId: currentDraft.draftId,
        expectedRevision: currentDraft.revision,
        expectedManifestVersion: currentDraft.manifest.manifestVersion,
        expectedDigest: currentDraft.manifestDigest,
        reason: 'Submit ready-for-review draft.',
      })
      await refreshCurrentWorkload()
      setStatusMessage(`Review submission accepted. Draft is in review for ${submitted.draftId}.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Submission failed.')
    } finally {
      setBusy(false)
    }
  }

  const approveDraft = async () => {
    setBusy(true)
    try {
      const currentDraft = workloadContext.draft
      if (!currentDraft) {
        throw new Error('Create a draft before approval.')
      }
      const approved = await apiClient.approveDraft({
        draftId: currentDraft.draftId,
        expectedRevision: currentDraft.revision,
        expectedManifestVersion: currentDraft.manifest.manifestVersion,
        expectedDigest: currentDraft.manifestDigest,
        reason: 'Human approval granted by the server-authorized role.',
      })
      await refreshCurrentWorkload()
      setStatusMessage(`Approval record ${approved.approval?.decisionId ?? 'created'} is ready for publication.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Approval failed.')
    } finally {
      setBusy(false)
    }
  }

  const publishDraft = async () => {
    setBusy(true)
    try {
      const currentDraft = workloadContext.draft
      if (!currentDraft) {
        throw new Error('Create a draft before publication.')
      }
      if (!currentDraft.approval) {
        throw new Error('Publication requires a server-derived approval record.')
      }
      const published = await apiClient.publishDraft({
        draftId: currentDraft.draftId,
        expectedRevision: currentDraft.revision,
        expectedManifestVersion: currentDraft.manifest.manifestVersion,
        expectedDigest: currentDraft.manifestDigest,
        approvalId: currentDraft.approval.decisionId,
        reason: 'Publish the approved manifest version.',
        workloadId: selectedWorkloadId,
        manifestId: currentDraft.manifestId,
      })
      await refreshCurrentWorkload()
      setStatusMessage(`Manifest ${published.manifestVersion} is live for ${published.manifestId}.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Publication failed.')
    } finally {
      setBusy(false)
    }
  }

  const currentDraft = workloadContext.draft
  const publishDisabled =
    busy ||
    !currentDraft ||
    currentDraft.state !== 'approved' ||
    !currentDraft.approval ||
    currentDraft.manifestId !== selectedWorkloadId

  const validateDisabled = busy || !currentDraft || currentDraft.state !== 'draft'
  const submitDisabled = busy || !currentDraft || currentDraft.state !== 'validated'
  const approveDisabled = busy || !currentDraft || currentDraft.state !== 'in_review'

  return (
    <div className="studio-shell">
      <header className="topbar" aria-label="Studio header">
        <div>
          <p className="eyebrow">Authenticated shell</p>
          <h1>Athena Context Studio</h1>
        </div>

        <div className="topbar-meta" aria-label="Session metadata">
          <span className={`pill state-${currentDraft?.state ?? workloadContext.approvalState}`}>
            {currentDraft?.state?.toUpperCase() ?? workloadContext.approvalState.toUpperCase()}
          </span>
          <span>Authenticated as {workloadContext.auth.userLabel}</span>
          <span>Role: {workloadContext.auth.role}</span>
          <span>Port: {workloadContext.auth.port}</span>
          <span>Environment: {workloadContext.environment}</span>
          <span>Manifest {workloadContext.manifest.manifestVersion}</span>
        </div>
      </header>

      <nav className="primary-nav" aria-label="Primary navigation">
        {(['overview', 'catalogue', 'manifest', 'controls'] as AppRoute[]).map((item) => (
          <button
            key={item}
            type="button"
            className={route === item ? 'nav-button is-selected' : 'nav-button'}
            onClick={() => setRoute(item)}
            aria-current={route === item ? 'page' : undefined}
          >
            {item[0].toUpperCase() + item.slice(1)}
          </button>
        ))}
      </nav>

      <main className="studio-layout">
        <aside className="panel catalogue-panel" aria-label="Workload catalogue">
          <div className="panel-heading">
            <h2>Workload catalogue</h2>
            <span className="meta-pill">{workloadContext.workloadCatalogue.length} workloads</span>
          </div>

          <ul className="catalogue-list">
            {workloadContext.workloadCatalogue.map((workload) => (
              <li key={workload.id}>
                <button
                  type="button"
                  className={
                    workload.id === selectedWorkloadId
                      ? 'catalogue-button is-selected'
                      : 'catalogue-button'
                  }
                  onClick={() => void handleSelectWorkload(workload.id)}
                  aria-pressed={workload.id === selectedWorkloadId}
                >
                  <span className="catalogue-name">{workload.name}</span>
                  <span className="catalogue-owner">{workload.owner}</span>
                  <span className="catalogue-meta">
                    {workload.criticality} • {workload.zoneCount} zones
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <div className="content-stack">
          {route === 'overview' && (
            <>
              <section className="panel overview-panel" aria-label="Context overview">
                <div className="status-grid">
                  <div className="stat-card">
                    <span className="stat-label">Evidence source</span>
                    <strong>{workloadContext.evidenceSource}</strong>
                  </div>
                  <div className="stat-card">
                    <span className="stat-label">Confidence</span>
                    <strong>{Math.round(workloadContext.confidence * 100)}%</strong>
                  </div>
                  <div className="stat-card">
                    <span className="stat-label">Environment</span>
                    <strong>{workloadContext.environment}</strong>
                  </div>
                  <div className="stat-card">
                    <span className="stat-label">Workload</span>
                    <strong>{workloadContext.manifest.workloadName}</strong>
                  </div>
                </div>
              </section>

              <section className="panel comparison-panel">
                <div className="panel-heading">
                  <h2>Production / Development / Training comparison</h2>
                </div>

                <div
                  role="table"
                  aria-label="Production, Development and Training comparison"
                  className="comparison-table"
                >
                  <div className="table-head" role="row">
                    <span role="columnheader">Environment</span>
                    <span role="columnheader">Topology</span>
                    <span role="columnheader">Policy</span>
                    <span role="columnheader">Residual risk</span>
                  </div>

                  {workloadContext.comparison.map((row) => (
                    <div className="table-row" role="row" key={row.environment}>
                      <span role="cell">{row.environment}</span>
                      <span role="cell">{row.topology}</span>
                      <span role="cell">{row.policy}</span>
                      <span role="cell">{row.residualRisk}</span>
                    </div>
                  ))}
                </div>
              </section>
            </>
          )}

          {route === 'catalogue' && (
            <section className="panel catalogue-overview" aria-label="Catalogue summary">
              <div className="panel-heading">
                <h2>Catalogue summary</h2>
              </div>

              <dl className="summary-list">
                <div>
                  <dt>Selected workload</dt>
                  <dd>{workloadContext.manifest.workloadName}</dd>
                </div>
                <div>
                  <dt>Criticality</dt>
                  <dd>{workloadContext.workloadCatalogue.find((item) => item.id === selectedWorkloadId)?.criticality ?? 'Tier-1'}</dd>
                </div>
                <div>
                  <dt>Zone count</dt>
                  <dd>{workloadContext.workloadCatalogue.find((item) => item.id === selectedWorkloadId)?.zoneCount ?? 2}</dd>
                </div>
              </dl>
            </section>
          )}

          {(route === 'overview' || route === 'manifest') && (
            <section className="panel editor-panel" aria-label="Manifest editor section">
              <div className="panel-heading">
                <h2>Manifest editor</h2>
                <button type="button" className="small-button" onClick={() => void refreshCurrentWorkload()}>
                  Reload context
                </button>
              </div>

              <form className="manifest-form" aria-label="Manifest editor">
                <div className="editor-grid">
                  <label htmlFor="workload-name">
                    Workload name
                    <input
                      id="workload-name"
                      value={draftForm.workloadName}
                      onChange={(event) => updateField('workloadName', event.target.value)}
                    />
                  </label>

                  <label htmlFor="manifest-version">
                    Manifest version
                    <input
                      id="manifest-version"
                      value={draftForm.manifestVersion}
                      onChange={(event) => updateField('manifestVersion', event.target.value)}
                    />
                  </label>

                  <label htmlFor="business-owner">
                    Business owner
                    <input
                      id="business-owner"
                      value={draftForm.businessOwner}
                      onChange={(event) => updateField('businessOwner', event.target.value)}
                    />
                  </label>

                  <label htmlFor="environment">
                    Environment
                    <input
                      id="environment"
                      value={draftForm.environment}
                      onChange={(event) => updateField('environment', event.target.value as ManifestDraft['environment'])}
                    />
                  </label>

                  <label htmlFor="runbook" className="row-span-2">
                    Runbook
                    <input
                      id="runbook"
                      value={draftForm.runbook}
                      onChange={(event) => updateField('runbook', event.target.value)}
                    />
                  </label>
                </div>

                <div className="editor-grid">
                  <fieldset>
                    <legend>Required relationships</legend>
                    <textarea
                      aria-label="Required relationships"
                      value={draftForm.requiredRelationships.join('\n')}
                      onChange={(event) => updateRelationshipList('requiredRelationships', event.target.value)}
                    />
                  </fieldset>

                  <fieldset>
                    <legend>Optional relationships</legend>
                    <textarea
                      aria-label="Optional relationships"
                      value={draftForm.optionalRelationships.join('\n')}
                      onChange={(event) => updateRelationshipList('optionalRelationships', event.target.value)}
                    />
                  </fieldset>
                </div>
              </form>
            </section>
          )}

          {route === 'controls' && (
            <section className="panel evidence-panel" aria-label="Controls and provenance section">
              <div className="panel-heading">
                <h2>Controls and provenance</h2>
              </div>

              <div className="two-column-grid">
                <div>
                  <h3>Controls</h3>
                  <ul className="stack-list">
                    {workloadContext.controls.map((control) => (
                      <li key={control.id} className="stack-item">
                        <span className="stack-name">{control.name}</span>
                        <span className="stack-meta">{control.owner}</span>
                        <p>{control.description}</p>
                      </li>
                    ))}
                  </ul>
                </div>

                <div>
                  <h3>Risk acceptances</h3>
                  <ul className="stack-list">
                    {workloadContext.riskAcceptances.map((item) => (
                      <li key={item.id} className="stack-item">
                        <span className="stack-name">{item.owner}</span>
                        <span className="stack-meta">{item.accepted ? 'Accepted' : 'Pending'}</span>
                        <p>{item.description}</p>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="span-two">
                  <h3>Provenance</h3>
                  <ul className="provenance-list">
                    {workloadContext.provenance.map((item) => (
                      <li key={item.id}>
                        <span className="provenance-source">{item.source}</span>
                        <p>{item.summary}</p>
                        <small>
                          {item.clause} • {item.manifestVersion}
                        </small>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>
          )}

          {route !== 'manifest' && route !== 'controls' && (
            <section className="panel editor-panel" aria-label="Context review panel">
              <div className="panel-heading">
                <h2>Declared vs observed</h2>
              </div>

              <ul className="relationship-list">
                {workloadContext.relationships.map((relationship) => (
                  <li
                    key={relationship.title}
                    className={`relationship-item kind-${relationship.kind}`}
                  >
                    <span className="relationship-kind">{relationship.kind}</span>
                    <strong>{relationship.title}</strong>
                    <p>{relationship.detail}</p>
                    <small>{relationship.clause}</small>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>

        <aside className="panel review-panel" aria-label="Draft review panel">
          <div className="panel-kicker">Lifecycle state</div>
          <h2>Draft review</h2>
          <p>Agent proposals remain drafts until the server-derived approval record exists.</p>

          <div className="action-stack">
            <button type="button" className="primary-action" onClick={() => void saveDraft()} disabled={busy}>
              Save draft
            </button>
            <button type="button" className="secondary-action" onClick={() => void validateDraft()} disabled={validateDisabled}>
              Validate draft
            </button>
            <button type="button" className="secondary-action" onClick={() => void submitForReview()} disabled={submitDisabled}>
              Submit for review
            </button>
            <button type="button" className="secondary-action" onClick={() => void approveDraft()} disabled={approveDisabled}>
              Approve draft
            </button>
            <button type="button" className="primary-action" onClick={() => void publishDraft()} disabled={publishDisabled}>
              Publish
            </button>
          </div>

          <div className="status-message" aria-live="polite">
            {statusMessage}
          </div>

          <div className="approval-record">
            <h3>Approval record</h3>
            <p>{currentDraft?.approval ? currentDraft.approval.decisionId : 'Awaiting server approval decision.'}</p>
            <small>
              {currentDraft?.approval
                ? `${currentDraft.approval.manifestVersion} • ${currentDraft.approval.manifestDigest}`
                : 'Requires approval before publication.'}
            </small>
          </div>

          <div className="declared-panel">
            <h3>Relationship context</h3>
            <ul className="relationship-list">
              {workloadContext.relationships.map((relationship) => (
                <li
                  key={relationship.title}
                  className={`relationship-item kind-${relationship.kind}`}
                >
                  <span className="relationship-kind">{relationship.kind}</span>
                  <strong>{relationship.title}</strong>
                  <p>{relationship.detail}</p>
                  <small>{relationship.clause}</small>
                </li>
              ))}
            </ul>
          </div>
        </aside>
      </main>
    </div>
  )
}

export default App
