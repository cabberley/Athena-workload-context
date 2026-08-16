import { useMemo, useState } from 'react'
import { createContextApiClient } from './client'
import { contextStudioFixture } from './data/fixtures'
import type { ApprovalState, ContextStudioSnapshot } from './types'
import './App.css'

const apiClient = createContextApiClient()

function App() {
  const [snapshot] = useState<ContextStudioSnapshot>(contextStudioFixture)
  const [selectedWorkloadId, setSelectedWorkloadId] = useState(
    contextStudioFixture.workloadCatalogue[0]?.id ?? 'atlas-api',
  )
  const [humanAuthorityApproved, setHumanAuthorityApproved] = useState(false)
  const [approvalState, setApprovalState] = useState<ApprovalState>(contextStudioFixture.approvalState)
  const [statusMessage, setStatusMessage] = useState('Draft is ready for human validation.')

  const activeWorkload = useMemo(
    () =>
      snapshot.workloadCatalogue.find((entry) => entry.id === selectedWorkloadId) ??
      snapshot.workloadCatalogue[0],
    [selectedWorkloadId, snapshot],
  )

  const handleApprovalStateChange = (nextState: ApprovalState) => {
    if (nextState === 'published' && !humanAuthorityApproved) {
      setStatusMessage('Publication requires explicit human authority approval.')
      return
    }

    setApprovalState(nextState)
    setStatusMessage(
      nextState === 'published' ? 'Authority-approved proposal is ready for publication.' : 'Draft is ready for human validation.',
    )
  }

  const handlePublish = async () => {
    if (!activeWorkload) {
      return
    }

    const response = await apiClient.publishProposal({
      workloadId: activeWorkload.id,
      environment: snapshot.environment,
      humanAuthorityApproved,
    })

    setStatusMessage(response.reason)

    if (response.allowed) {
      setApprovalState(response.state)
    } else {
      setApprovalState('draft')
    }
  }

  if (!activeWorkload) {
    return <div className="loading-state">Loading Context Studio…</div>
  }

  const publishDisabled = approvalState === 'published' || !humanAuthorityApproved

  return (
    <div className="studio-shell">
      <header className="topbar" aria-label="Studio header">
        <div>
          <p className="eyebrow">Authenticated shell</p>
          <h1>Athena Context Studio</h1>
        </div>

        <div className="topbar-meta" aria-label="Session metadata">
          <span className={`pill state-${approvalState}`}>{approvalState.toUpperCase()}</span>
          <span>Authenticated</span>
          <span>Port: {snapshot.auth.port}</span>
          <span>Environment: {snapshot.environment}</span>
          <span>Manifest v{snapshot.manifestVersion}</span>
        </div>
      </header>

      <nav className="primary-nav" aria-label="Primary">
        <button type="button" className="nav-button is-selected">
          Overview
        </button>
        <button type="button" className="nav-button">
          Catalogue
        </button>
        <button type="button" className="nav-button">
          Manifest
        </button>
        <button type="button" className="nav-button">
          Controls
        </button>
      </nav>

      <main className="studio-layout">
        <aside className="panel catalogue-panel" aria-label="Workload catalogue">
          <div className="panel-heading">
            <h2>Workload catalogue</h2>
            <span className="meta-pill">{snapshot.workloadCatalogue.length} workloads</span>
          </div>

          <ul className="catalogue-list">
            {snapshot.workloadCatalogue.map((workload) => (
              <li key={workload.id}>
                <button
                  type="button"
                  className={
                    workload.id === selectedWorkloadId
                      ? 'catalogue-button is-selected'
                      : 'catalogue-button'
                  }
                  onClick={() => setSelectedWorkloadId(workload.id)}
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
          <section className="panel overview-panel" aria-label="Context overview">
            <div className="status-grid">
              <div className="stat-card">
                <span className="stat-label">Evidence source</span>
                <strong>{snapshot.evidenceSource}</strong>
              </div>
              <div className="stat-card">
                <span className="stat-label">Confidence</span>
                <strong>{Math.round(snapshot.confidence * 100)}%</strong>
              </div>
              <div className="stat-card">
                <span className="stat-label">Environment</span>
                <strong>{snapshot.environment}</strong>
              </div>
              <div className="stat-card">
                <span className="stat-label">Workload</span>
                <strong>{activeWorkload.name}</strong>
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

              {snapshot.comparison.map((row) => (
                <div className="table-row" role="row" key={row.environment}>
                  <span role="cell">{row.environment}</span>
                  <span role="cell">{row.topology}</span>
                  <span role="cell">{row.policy}</span>
                  <span role="cell">{row.residualRisk}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="panel editor-panel">
            <div className="panel-heading">
              <h2>Manifest editor</h2>
            </div>

            <form aria-label="Manifest editor" className="manifest-form">
              <div className="editor-grid">
                <label htmlFor="workload-name">
                  Workload name
                  <input id="workload-name" value={snapshot.manifest.workloadName} readOnly />
                </label>

                <label htmlFor="manifest-version">
                  Manifest version
                  <input id="manifest-version" value={snapshot.manifestVersion} readOnly />
                </label>

                <label htmlFor="business-owner">
                  Business owner
                  <input id="business-owner" value={snapshot.manifest.businessOwner} readOnly />
                </label>

                <label htmlFor="approval-state">
                  Approval state
                  <select
                    id="approval-state"
                    value={approvalState}
                    onChange={(event) =>
                      handleApprovalStateChange(event.target.value as ApprovalState)
                    }
                  >
                    <option value="draft">Draft</option>
                    <option value="validation">Validation</option>
                    <option value="approved">Approved</option>
                    <option value="published">Published</option>
                  </select>
                </label>
              </div>

              <div className="editor-grid">
                <fieldset>
                  <legend>Required relationships</legend>
                  <ul className="stack-list">
                    {snapshot.manifest.requiredRelationships.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </fieldset>

                <fieldset>
                  <legend>Optional relationships</legend>
                  <ul className="stack-list">
                    {snapshot.manifest.optionalRelationships.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </fieldset>
              </div>
            </form>
          </section>

          <section className="panel evidence-panel">
            <div className="panel-heading">
              <h2>Controls and provenance</h2>
            </div>

            <div className="two-column-grid">
              <div>
                <h3>Controls</h3>
                <ul className="stack-list">
                  {snapshot.controls.map((control) => (
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
                  {snapshot.riskAcceptances.map((item) => (
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
                  {snapshot.provenance.map((item) => (
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
        </div>

        <aside className="panel review-panel" aria-label="Proposal review">
          <div className={`approval-badge state-${approvalState}`}>{approvalState.toUpperCase()}</div>
          <h2>Draft review</h2>
          <p>Agent proposals are drafts until a human authority approves them.</p>

          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={humanAuthorityApproved}
              onChange={(event) => setHumanAuthorityApproved(event.target.checked)}
            />
            <span>Human authority approved</span>
          </label>

          <button
            type="button"
            className="primary-action"
            onClick={handlePublish}
            disabled={publishDisabled}
          >
            Publish proposal
          </button>

          <div className="status-message" aria-live="polite">
            {statusMessage}
          </div>

          <div className="declared-panel">
            <h3>Declared vs observed</h3>
            <ul className="relationship-list">
              {snapshot.relationships.map((relationship) => (
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
