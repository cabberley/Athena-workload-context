import { useEffect, useMemo, useState } from 'react'
import type { AppRoute, ContextApiClientPort, ManifestDraft, WorkloadContext } from './types'
import './App.css'

const cloneManifest = (context: WorkloadContext): ManifestDraft => ({
  ...context.manifest,
  requiredRelationships: [...context.manifest.requiredRelationships],
  optionalRelationships: [...context.manifest.optionalRelationships],
  controls: context.manifest.controls.map((control) => ({ ...control })),
  riskAcceptances: context.manifest.riskAcceptances.map((acceptance) => ({ ...acceptance })),
})

const bumpVersion = (value: string): string => {
  const match = /^([0-9]+)\.([0-9]+)\.([0-9]+)$/.exec(value.trim())
  if (!match) {
    return value
  }
  const [, major, minor, patch] = match
  return `${Number(major)}.${Number(minor)}.${Number(patch) + 1}`
}

function App({ client }: { client: ContextApiClientPort }) {
  const [route, setRoute] = useState<AppRoute>('overview')
  const [selectedWorkloadId, setSelectedWorkloadId] = useState('atlas-api')
  const [workloadContext, setWorkloadContext] = useState<WorkloadContext | null>(() => {
    try {
      return client.loadWorkloadSync('atlas-api')
    } catch {
      return null
    }
  })
  const [draftForm, setDraftForm] = useState<ManifestDraft | null>(() => {
    try {
      const initial = client.loadWorkloadSync('atlas-api')
      return cloneManifest(initial)
    } catch {
      return null
    }
  })
  const [statusMessage, setStatusMessage] = useState('Ready to create a draft or load the selected workload.')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (workloadContext) {
      setDraftForm(cloneManifest(workloadContext))
    }
  }, [workloadContext])

  const currentDraft = workloadContext?.draft ?? null
  const publishDisabled =
    busy ||
    !currentDraft ||
    currentDraft.state !== 'approved' ||
    !currentDraft.approval ||
    selectedWorkloadId !== currentDraft.manifestId

  const validateDisabled = busy || !currentDraft || currentDraft.state !== 'draft'
  const submitDisabled = busy || !currentDraft || currentDraft.state !== 'validated'
  const approveDisabled = busy || !currentDraft || currentDraft.state !== 'in_review'

  const applyContext = (nextContext: WorkloadContext) => {
    setSelectedWorkloadId(nextContext.workloadId)
    setWorkloadContext(nextContext)
    setDraftForm(cloneManifest(nextContext))
  }

  const refreshCurrentWorkload = async (nextWorkloadId = selectedWorkloadId) => {
    const nextContext = await client.reloadWorkload(nextWorkloadId)
    applyContext(nextContext)
    return nextContext
  }

  const handleSelectWorkload = async (nextWorkloadId: string) => {
    setBusy(true)
    try {
      const nextContext = await client.loadWorkloadContext(nextWorkloadId)
      applyContext(nextContext)
      setStatusMessage(`Loaded ${nextContext.manifest.workloadName} context.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : `Unable to load workload ${nextWorkloadId}.`)
    } finally {
      setBusy(false)
    }
  }

  const updateField = <K extends keyof ManifestDraft>(field: K, value: ManifestDraft[K]) => {
    setDraftForm((current) => {
      if (!current) {
        return current
      }
      return { ...current, [field]: value }
    })
  }

  const updateRelationshipList = (field: 'requiredRelationships' | 'optionalRelationships', value: string) => {
    setDraftForm((current) => {
      if (!current) {
        return current
      }
      return {
        ...current,
        [field]: value
          .split(/\r?\n/)
          .map((item) => item.trim())
          .filter(Boolean),
      }
    })
  }

  const saveDraft = async () => {
    if (!draftForm || !workloadContext) {
      setStatusMessage('No draft content is currently loaded.')
      return
    }
    setBusy(true)
    try {
      if (!currentDraft) {
        const created = await client.createDraft(selectedWorkloadId, draftForm, 'Create draft from the structured manifest editor.')
        await refreshCurrentWorkload(selectedWorkloadId)
        setStatusMessage(`Draft ${created.draftId} created. Revision ${created.revision}.`)
        return
      }

      const updated = await client.updateDraft({
        draftId: currentDraft.draftId,
        expectedRevision: currentDraft.revision,
        expectedManifestVersion: currentDraft.manifest.manifestVersion,
        expectedDigest: currentDraft.manifestDigest,
        replacementManifest: draftForm,
        reason: 'Save the manifest with optimistic concurrency checks.',
      })
      await refreshCurrentWorkload(selectedWorkloadId)
      setStatusMessage(`Draft ${updated.draftId} saved. Revision ${updated.revision}.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Unable to save the draft.')
    } finally {
      setBusy(false)
    }
  }

  const createDraftVersion = async () => {
    if (!workloadContext || !draftForm) {
      setStatusMessage('No manifest context is currently loaded.')
      return
    }
    setBusy(true)
    try {
      const source = workloadContext.published?.manifest ?? workloadContext.manifest
      const nextVersion = bumpVersion(source.manifestVersion)
      const nextManifest: ManifestDraft = {
        ...source,
        manifestVersion: nextVersion,
        manifestDigest: source.manifestDigest ?? source.compatibility?.artifactDigest,
      }
      const created = await client.createDraft(selectedWorkloadId, nextManifest, 'Create a new draft version from the active published manifest.')
      await refreshCurrentWorkload(selectedWorkloadId)
      setStatusMessage(`Draft version ${created.draftId} created. Revision ${created.revision}.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Unable to create a new draft version.')
    } finally {
      setBusy(false)
    }
  }

  const validateDraft = async () => {
    if (!currentDraft) {
      setStatusMessage('Create a draft before validation.')
      return
    }
    setBusy(true)
    try {
      const validated = await client.validateDraft({
        draftId: currentDraft.draftId,
        expectedRevision: currentDraft.revision,
        expectedManifestVersion: currentDraft.manifest.manifestVersion,
        expectedDigest: currentDraft.manifestDigest,
        reason: 'Validate the structured manifest and confirm the digest matches the current draft.',
      })
      await refreshCurrentWorkload(selectedWorkloadId)
      setStatusMessage(`Validation checks passed for ${validated.draftId}.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Validation failed.')
    } finally {
      setBusy(false)
    }
  }

  const submitForReview = async () => {
    if (!currentDraft) {
      setStatusMessage('Create a draft before review submission.')
      return
    }
    setBusy(true)
    try {
      const submitted = await client.submitForReview({
        draftId: currentDraft.draftId,
        expectedRevision: currentDraft.revision,
        expectedManifestVersion: currentDraft.manifest.manifestVersion,
        expectedDigest: currentDraft.manifestDigest,
        reason: 'Submit the validated draft for human review.',
      })
      await refreshCurrentWorkload(selectedWorkloadId)
      setStatusMessage(`Review submission accepted. Draft ${submitted.draftId} is in review.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Submission failed.')
    } finally {
      setBusy(false)
    }
  }

  const approveDraft = async () => {
    if (!currentDraft) {
      setStatusMessage('Create a draft before approval.')
      return
    }
    setBusy(true)
    try {
      const approved = await client.approveDraft({
        draftId: currentDraft.draftId,
        expectedRevision: currentDraft.revision,
        expectedManifestVersion: currentDraft.manifest.manifestVersion,
        expectedDigest: currentDraft.manifestDigest,
        reason: 'Approve the draft for publication using the server-authoritative approval decision.',
      })
      await refreshCurrentWorkload(selectedWorkloadId)
      setStatusMessage(`Approval record ${approved.approval?.decisionId ?? 'created'} is ready for publication.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Approval failed.')
    } finally {
      setBusy(false)
    }
  }

  const publishDraft = async () => {
    if (!currentDraft) {
      setStatusMessage('Create a draft before publication.')
      return
    }
    if (!currentDraft.approval) {
      setStatusMessage('Publication requires a server-derived approval record.')
      return
    }
    setBusy(true)
    try {
      const published = await client.publishDraft({
        draftId: currentDraft.draftId,
        expectedRevision: currentDraft.revision,
        expectedManifestVersion: currentDraft.manifest.manifestVersion,
        expectedDigest: currentDraft.manifestDigest,
        approvalId: currentDraft.approval.decisionId,
        reason: 'Publish the approved manifest version to the authoritative registry.',
        workloadId: selectedWorkloadId,
        manifestId: currentDraft.manifestId,
      })
      await refreshCurrentWorkload(selectedWorkloadId)
      setStatusMessage(`Published version ${published.manifestVersion} for ${published.manifestId}.`)
    } catch (error) {
      setStatusMessage(error instanceof Error ? error.message : 'Publication failed.')
    } finally {
      setBusy(false)
    }
  }

  const comparisonRows = useMemo(() => workloadContext?.comparison ?? [], [workloadContext])

  if (!workloadContext || !draftForm) {
    return (
      <div className="loading-state" aria-live="polite">
        Loading Athena Context Studio…
      </div>
    )
  }

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
                  className={workload.id === selectedWorkloadId ? 'catalogue-button is-selected' : 'catalogue-button'}
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

              <section className="panel comparison-panel" aria-label="Production and environment comparison">
                <div className="panel-heading">
                  <h2>Production / Development / Training comparison</h2>
                </div>

                <div role="table" aria-label="Production, Development and Training comparison" className="comparison-table">
                  <div className="table-head" role="row">
                    <span role="columnheader">Environment</span>
                    <span role="columnheader">Topology</span>
                    <span role="columnheader">Policy</span>
                    <span role="columnheader">Residual risk</span>
                  </div>

                  {comparisonRows.map((row) => (
                    <div className="table-row" role="row" key={row.environment}>
                      <span role="cell" data-label="Environment">{row.environment}</span>
                      <span role="cell" data-label="Topology">{row.topology}</span>
                      <span role="cell" data-label="Policy">{row.policy}</span>
                      <span role="cell" data-label="Residual risk">{row.residualRisk}</span>
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
                      value={draftForm.requiredRelationships.join('\\n')}
                      onChange={(event) => updateRelationshipList('requiredRelationships', event.target.value)}
                    />
                  </fieldset>

                  <fieldset>
                    <legend>Optional relationships</legend>
                    <textarea
                      aria-label="Optional relationships"
                      value={draftForm.optionalRelationships.join('\\n')}
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
                  <li key={relationship.title} className={`relationship-item kind-${relationship.kind}`}>
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
          <p>Agent proposals remain drafts until the authenticated server approval record exists.</p>

          <div className="action-stack">
            <button type="button" className="primary-action" onClick={() => void saveDraft()} disabled={busy || !draftForm}>
              Save draft
            </button>
            <button type="button" className="secondary-action" onClick={() => void createDraftVersion()} disabled={busy || !workloadContext}>
              Create new version draft
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
                <li key={relationship.title} className={`relationship-item kind-${relationship.kind}`}>
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
