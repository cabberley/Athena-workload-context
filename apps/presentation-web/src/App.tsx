import { useEffect, useRef, useState, type KeyboardEvent } from 'react'
import {
  LIFECYCLE_PHASES,
  type LifecyclePhase,
  type PresentationPayload,
} from './contracts'
import { loadVerifiedLifecycle } from './runtime'
import {
  loadVerifiedIncidents,
  type VerifiedIncident,
  type VerifiedIncidentFeed,
} from './incidents'
import {
  guidanceTemplateLabel,
  loadVerifiedOperatorGuidanceFeed,
  type GuidanceRunbookLink,
  type GuidanceStep,
  type VerifiedOperatorGuidance,
  type VerifiedOperatorGuidanceFeed,
} from './guidance'
import type { BlastRadius, ImpactLevel } from './derivations'
import type { VerifiedLifecycle } from './verification'
import './App.css'

export interface AppProps {
  loader?: () => Promise<VerifiedLifecycle>
  incidentLoader?: () => Promise<VerifiedIncidentFeed>
  guidanceLoader?: (
    incidentFeed: VerifiedIncidentFeed,
  ) => Promise<VerifiedOperatorGuidanceFeed>
  incidentPollMs?: number
}

const PHASE_LABELS: Record<LifecyclePhase, string> = {
  baseline: 'Baseline',
  faulted: 'Fault contained',
  recovered: 'Recovery verified',
}

const BLAST_RADIUS_LABELS: Record<BlastRadius, string> = {
  'none-active': 'None active',
  'contained-web-tier': 'Contained to web tier',
  resolved: 'Resolved',
}

function App({
  loader = loadVerifiedLifecycle,
  incidentLoader = loadVerifiedIncidents,
  guidanceLoader = loadVerifiedOperatorGuidanceFeed,
  incidentPollMs = 8_000,
}: AppProps) {
  const [lifecycle, setLifecycle] = useState<VerifiedLifecycle | null>(null)
  const [failed, setFailed] = useState(false)
  const [selectedPhase, setSelectedPhase] = useState<LifecyclePhase>('baseline')
  const phaseHeadingRef = useRef<HTMLHeadingElement>(null)
  const [incidentFeed, setIncidentFeed] = useState<VerifiedIncidentFeed | null>(null)
  const [incidentUnavailable, setIncidentUnavailable] = useState(false)
  const [guidanceFeed, setGuidanceFeed] =
    useState<VerifiedOperatorGuidanceFeed | null>(null)
  const [guidanceUnavailable, setGuidanceUnavailable] = useState(false)

  useEffect(() => {
    let current = true
    void loader()
      .then((verified) => {
        if (current) setLifecycle(verified)
      })
      .catch(() => {
        if (current) setFailed(true)
      })
    return () => {
      current = false
    }
  }, [loader])

  useEffect(() => {
    let current = true
    let timer: ReturnType<typeof globalThis.setTimeout> | undefined
    let latestPublishedAt = 0
    let latestGuidancePublishedAt = 0
    let latestGuidanceBindings: Record<string, string> = {}
    const refresh = async (): Promise<void> => {
      try {
        const verified = await incidentLoader()
        let verifiedGuidance: VerifiedOperatorGuidanceFeed | null = null
        let guidanceFailed = false
        if (guidanceLoader && verified.incidents.length > 0) {
          try {
            verifiedGuidance = await guidanceLoader(verified)
          } catch {
            guidanceFailed = true
          }
        }
        if (!current) return
        const publishedAt = Date.parse(verified.publishedAt)
        if (publishedAt >= latestPublishedAt) {
          latestPublishedAt = publishedAt
          setIncidentFeed(verified)
          setIncidentUnavailable(false)
          if (verifiedGuidance) {
            const guidancePublishedAt = Date.parse(verifiedGuidance.publishedAt)
            const nextBindings = Object.fromEntries(
              Object.values(verifiedGuidance.guidanceByIncidentId).map((guidance) => [
                guidance.incidentId,
                guidance.stateResultDigest,
              ]),
            )
            const sameOccurrenceBindings =
              Object.keys(nextBindings).length ===
                Object.keys(latestGuidanceBindings).length &&
              Object.entries(nextBindings).every(
                ([incidentId, digest]) =>
                  latestGuidanceBindings[incidentId] === digest,
              )
            if (
              guidancePublishedAt >= latestGuidancePublishedAt ||
              !sameOccurrenceBindings
            ) {
              latestGuidancePublishedAt = guidancePublishedAt
              latestGuidanceBindings = nextBindings
              setGuidanceFeed(verifiedGuidance)
              setGuidanceUnavailable(false)
            }
          } else if (guidanceFailed) {
            setGuidanceFeed(null)
            setGuidanceUnavailable(true)
          } else if (verified.incidents.length === 0) {
            setGuidanceFeed(null)
            setGuidanceUnavailable(false)
          }
        }
      } catch {
        if (current) {
          setIncidentFeed(null)
          setIncidentUnavailable(true)
          setGuidanceFeed(null)
          setGuidanceUnavailable(false)
        }
      } finally {
        if (current) timer = globalThis.setTimeout(() => void refresh(), incidentPollMs)
      }
    }
    void refresh()
    return () => {
      current = false
      if (timer !== undefined) globalThis.clearTimeout(timer)
    }
  }, [guidanceLoader, incidentLoader, incidentPollMs])

  useEffect(() => {
    if (lifecycle) phaseHeadingRef.current?.focus()
  }, [lifecycle, selectedPhase])

  if (failed) {
    return (
      <main className="state-shell" aria-labelledby="failure-title">
        <section className="state-panel">
          <p className="eyebrow">Athena presentation</p>
          <h1 id="failure-title">Lifecycle data was withheld</h1>
          <p role="alert">
            A reviewed asset failed authenticity, integrity, schema, or lifecycle consistency
            verification. No partial lifecycle data was rendered.
          </p>
          <p>Ask the demo operator to republish the complete reviewed static asset set.</p>
        </section>
      </main>
    )
  }

  if (!lifecycle) {
    return (
      <main className="state-shell" aria-labelledby="loading-title">
        <section className="state-panel">
          <p className="eyebrow">Athena presentation</p>
          <h1 id="loading-title">Verifying reviewed lifecycle assets</h1>
          <p role="status" aria-live="polite">
            Lifecycle data remains hidden until every phase and detached signature is verified.
          </p>
        </section>
      </main>
    )
  }

  const selected = lifecycle.phases[selectedPhase]
  const payload = selected.payload
  const livePublication =
    lifecycle.publication.kind === 'live' ? lifecycle.publication : null

  const selectFromKeyboard = (
    event: KeyboardEvent<HTMLButtonElement>,
    phase: LifecyclePhase,
  ): void => {
    const index = LIFECYCLE_PHASES.indexOf(phase)
    let nextIndex: number | null = null
    if (event.key === 'ArrowRight') nextIndex = (index + 1) % LIFECYCLE_PHASES.length
    if (event.key === 'ArrowLeft') {
      nextIndex = (index - 1 + LIFECYCLE_PHASES.length) % LIFECYCLE_PHASES.length
    }
    if (event.key === 'Home') nextIndex = 0
    if (event.key === 'End') nextIndex = LIFECYCLE_PHASES.length - 1
    if (nextIndex !== null) {
      event.preventDefault()
      setSelectedPhase(LIFECYCLE_PHASES[nextIndex]!)
    }
  }

  return (
    <div className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Athena operational context</p>
          <h1>Verified web-node lifecycle</h1>
          <p className="hero-summary">
            {livePublication
              ? 'A presentation-only view of one verified live workload evaluation.'
              : 'A standalone, presentation-only view of one signed synthetic fixture.'}
          </p>
        </div>
        <div
          className="synthetic-badge"
          aria-label={
            livePublication ? 'Live workload evaluation' : 'Synthetic demo data'
          }
        >
          <span aria-hidden="true">◇</span>
          {livePublication ? 'Live workload evaluation' : 'Synthetic fixture'}
        </div>
      </header>

      <main>
        <IncidentPanel
          incidents={incidentFeed?.incidents ?? null}
          unavailable={incidentUnavailable}
          guidanceByIncidentId={guidanceFeed?.guidanceByIncidentId ?? {}}
          guidanceUnavailable={guidanceUnavailable}
        />
        <section className="trust-strip" aria-labelledby="trust-heading">
          <div>
            <p className="status-kicker">Trust status</p>
            <h2 id="trust-heading">
              <span className="status-mark" aria-hidden="true">
                ✓
              </span>{' '}
              Verified locally
            </h2>
          </div>
          <p role="status" aria-live="polite">
            All three payloads passed strict contract, digest, lifecycle, key fingerprint, and
            detached {lifecycle.trust.algorithm} verification.
          </p>
          <dl className="trust-details">
            {livePublication ? (
              <>
                <div>
                  <dt>Target resource group</dt>
                  <dd>
                    <code>{livePublication.targetResourceGroup}</code>
                  </dd>
                </div>
                <div>
                  <dt>Run ID</dt>
                  <dd>
                    <code>{livePublication.runId}</code>
                  </dd>
                </div>
                <div>
                  <dt>Last evaluated</dt>
                  <dd>
                    <time dateTime={livePublication.evaluatedAt}>
                      {livePublication.evaluatedAt}
                    </time>
                  </dd>
                </div>
                <div>
                  <dt>Published</dt>
                  <dd>
                    <time dateTime={livePublication.publishedAt}>
                      {livePublication.publishedAt}
                    </time>
                  </dd>
                </div>
              </>
            ) : (
              <div>
                <dt>Publication mode</dt>
                <dd>Reviewed deterministic static fixture</dd>
              </div>
            )}
            <div>
              <dt>Reviewed key</dt>
              <dd>
                <code>{lifecycle.trust.keyId}</code>
              </dd>
            </div>
            <div>
              <dt>SPKI fingerprint</dt>
              <dd>
                <code>{lifecycle.trust.keyFingerprint}</code>
              </dd>
            </div>
          </dl>
        </section>

        <nav className="phase-navigation" aria-label="Verified lifecycle phases">
          <ol>
            {LIFECYCLE_PHASES.map((phase, index) => (
              <li key={phase}>
                <button
                  type="button"
                  className={phase === selectedPhase ? 'phase-button active' : 'phase-button'}
                  aria-current={phase === selectedPhase ? 'step' : undefined}
                  onClick={() => setSelectedPhase(phase)}
                  onKeyDown={(event) => selectFromKeyboard(event, phase)}
                >
                  <span className="phase-number" aria-hidden="true">
                    {index + 1}
                  </span>
                  <span>
                    <strong>{PHASE_LABELS[phase]}</strong>
                    <small>{phase}</small>
                  </span>
                </button>
              </li>
            ))}
          </ol>
        </nav>

        <article className="phase-content" aria-labelledby="phase-heading">
          <header className="phase-header">
            <div>
              <p className="eyebrow">{payload.phase} phase</p>
              <h2 id="phase-heading" ref={phaseHeadingRef} tabIndex={-1}>
                {phaseHeadline(payload)}
              </h2>
              <p>{payload.findings[0]!.summary}</p>
            </div>
            <Verdict payload={payload} />
          </header>

          <div className="card-grid">
            <section className="metric-card" aria-labelledby="blast-radius-heading">
              <p className="card-label">
                {livePublication
                  ? 'Derived from signed control/evidence-plane results'
                  : 'Derived only from signed synthetic node state'}
              </p>
              <h3 id="blast-radius-heading">Blast radius</h3>
              <p className={`metric-value tone-${selected.blastRadius}`}>
                {BLAST_RADIUS_LABELS[selected.blastRadius]}
              </p>
              <p>{blastRadiusExplanation(selected.blastRadius)}</p>
            </section>

            <section className="metric-card" aria-labelledby="impact-heading">
              <p className="card-label">
                {livePublication
                  ? 'Bounded mapping of signed control/evidence-plane results'
                  : 'Deterministic signed-fixture field mapping'}
              </p>
              <h3 id="impact-heading">Impact level</h3>
              <ImpactDetails impact={selected.impact} />
            </section>

            <section className="metric-card evidence-card" aria-labelledby="evidence-heading">
              <p className="card-label">Signed web-tier evidence</p>
              <h3 id="evidence-heading">Affected and running nodes</h3>
              <dl className="evidence-metrics">
                <div>
                  <dt>Running</dt>
                  <dd>
                    {payload.runtimeState.webTier.runningNodes} of{' '}
                    {payload.runtimeState.webTier.expectedNodes}
                  </dd>
                </div>
                <div>
                  <dt>Faulted</dt>
                  <dd>{payload.runtimeState.webTier.faultedNodes}</dd>
                </div>
              </dl>
              <p>
                <strong>Affected node:</strong>{' '}
                <code>{payload.faultRun?.targetVmName ?? 'none signed'}</code>
              </p>
              <p>
                <strong>Signed evidence references:</strong>{' '}
                {payload.findings.reduce(
                  (total, finding) => total + finding.evidenceRefs.length,
                  0,
                )}
              </p>
            </section>

            <section className="metric-card" aria-labelledby="athena-heading">
              <p className="card-label">Signed Athena judgment</p>
              <h3 id="athena-heading">Verdict and risk</h3>
              <dl className="stacked-details">
                <div>
                  <dt>Verdict</dt>
                  <dd>{payload.findings[0]!.verdict}</dd>
                </div>
                <div>
                  <dt>Risk level</dt>
                  <dd>{payload.argus.riskLevel}</dd>
                </div>
                <div>
                  <dt>Predicted issue</dt>
                  <dd>{payload.argus.predictedIssue}</dd>
                </div>
              </dl>
            </section>
          </div>

          <section className="explanation" aria-labelledby="explanation-heading">
            <p className="eyebrow">Traceable reasoning</p>
            <h3 id="explanation-heading">How Athena determined this</h3>
            <ol>
              <li>
                <strong>Snapshot binding:</strong> the signed payload binds the synthetic snapshot
                identifier to its artifact and semantic digests.
              </li>
              <li>
                <strong>Policy judgment:</strong> the presentation result digest binds the exact
                exported phase finding, evidence references, verdict, and reviewed guidance from
                Athena's verified evaluation.
              </li>
              <li>
                <strong>Local authenticity:</strong> Web Crypto verified the detached RS256
                signature against the reviewed same-origin public key and pinned SPKI fingerprint.
              </li>
              <li>
                <strong>Bounded derivation:</strong> blast radius and impact use only signed phase,
                service state, node counts, fault/reset state, verdict, and risk level.
              </li>
              {livePublication ? (
                <li>
                  <strong>Live scope binding:</strong> the published target resource group is
                  case-folded and hashed in the browser, then matched to the signed synthetic
                  workload resource-group binding for all three phases.
                </li>
              ) : null}
            </ol>
            <p className="boundary-note">
              {livePublication
                ? 'Impact and blast radius describe only the signed control/evidence-plane results. No broader database, worker, load balancer, geographic, or customer impact is inferred.'
                : 'No database, worker, load balancer, geographic, or customer impact is inferred because those fields are absent from the signed synthetic presentation contract.'}
            </p>
          </section>

          <section className="provenance" aria-labelledby="provenance-heading">
            <h3 id="provenance-heading">Signed provenance</h3>
            <dl>
              <div>
                <dt>Snapshot artifact digest</dt>
                <dd>
                  <code>{payload.athena.artifactDigest}</code>
                </dd>
              </div>
              <div>
                <dt>Snapshot semantic digest</dt>
                <dd>
                  <code>{payload.athena.semanticDigest}</code>
                </dd>
              </div>
              <div>
                <dt>Presentation result digest</dt>
                <dd>
                  <code>{payload.athena.resultDigest}</code>
                </dd>
              </div>
              <div>
                <dt>Recommended human action</dt>
                <dd>{payload.argus.recommendedAction}</dd>
              </div>
            </dl>
          </section>
        </article>
      </main>

      <footer>
        {livePublication
          ? 'Presentation-only browser boundary. The browser makes same-origin reads only; a private managed-identity sidecar reads the allowlisted Blob assets.'
          : 'Presentation-only browser boundary. No Azure, Blob, ARM, MCP, or workload calls are made.'}
      </footer>
    </div>
  )
}

function IncidentPanel({
  incidents,
  unavailable,
  guidanceByIncidentId,
  guidanceUnavailable,
}: {
  incidents: VerifiedIncident[] | null
  unavailable: boolean
  guidanceByIncidentId: Readonly<Record<string, VerifiedOperatorGuidance>>
  guidanceUnavailable: boolean
}) {
  if (!incidents || incidents.length === 0) {
    return (
      <section className="incident-panel" aria-labelledby="incident-heading">
        <p className="status-kicker">Dynamic operational status</p>
        <h2 id="incident-heading">No verified active incident</h2>
        <p role="status">
          {unavailable
            ? 'The incident feed is unavailable or failed verification; no incident data was rendered.'
            : 'Athena is polling the signed incident feed every few seconds.'}
        </p>
      </section>
    )
  }
  return (
    <section className="incident-panel" aria-labelledby="incident-heading">
      <p className="status-kicker">Dynamic operational status</p>
      <h2 id="incident-heading">
        {incidents.length === 1
          ? '1 verified active incident'
          : `${incidents.length} verified active incidents`}
      </h2>
      {incidents.map(({ state }) => (
        <article
          key={state.incidentId}
          className={`incident-entry incident-${state.lifecycle}`}
          aria-labelledby={`incident-${state.incidentId}`}
        >
          <h3 id={`incident-${state.incidentId}`}>
            Verified incident: {scenarioLabel(state.scenario)}
          </h3>
          <p role="status" aria-live="polite">
            {state.findings[0]!.summary}
          </p>
          <dl className="incident-details">
            <div>
              <dt>Status</dt>
              <dd>{state.lifecycle}</dd>
            </div>
            <div>
              <dt>Availability</dt>
              <dd>{state.availability}</dd>
            </div>
            <div>
              <dt>Blast radius</dt>
              <dd>{state.blastRadius}</dd>
            </div>
            <div>
              <dt>Operator attention</dt>
              <dd>{state.operatorAttention}</dd>
            </div>
            <div>
              <dt>Notification</dt>
              <dd>{state.notificationStatus}</dd>
            </div>
            <div>
              <dt>Last update</dt>
              <dd>
                <time dateTime={state.updatedAt}>{state.updatedAt}</time>
              </dd>
            </div>
          </dl>
          <h4>How Athena determined the impact</h4>
          <ol>
            {state.reasoning.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ol>
          <p className="no-remediation">
            Athena does not remediate automatically. Recovery requires a separately governed
            operator action.
          </p>
          {guidanceByIncidentId[state.incidentId] ? (
            <OperatorGuidancePanel
              guidance={guidanceByIncidentId[state.incidentId]!}
            />
          ) : guidanceUnavailable ? (
            <section className="guidance-unavailable" aria-label="Operator guidance unavailable">
              <h4>Operator guidance unavailable</h4>
              <p role="status">
                The incident remains independently verified through the v1 feed, but its v2
                enrichment was unavailable or failed verification. No unverified guidance was
                rendered.
              </p>
            </section>
          ) : null}
        </article>
      ))}
    </section>
  )
}

const OperatorGuidancePanel = ({
  guidance: verified,
}: {
  guidance: VerifiedOperatorGuidance
}) => {
  const guidance = verified.guidance
  const topHypothesis = guidance.hypotheses[0]!
  return (
    <section
      className="operator-guidance"
      aria-labelledby={`guidance-${verified.incidentId}`}
    >
      <p className="status-kicker">Verified v2 enrichment</p>
      <h4 id={`guidance-${verified.incidentId}`}>Incident-specific operator guidance</h4>
      <p>
        This bounded guidance is evidence-linked and confidence-sensitive. It does not authorize
        execution or automatic remediation.
      </p>
      <dl className="incident-details guidance-summary">
        <div>
          <dt>Affected role</dt>
          <dd>{guidance.affectedRoleImpact.roleRef}</dd>
        </div>
        <div>
          <dt>Declared profile</dt>
          <dd>{guidance.affectedRoleImpact.profileId}</dd>
        </div>
        <div>
          <dt>Impact</dt>
          <dd>
            {humanizeCode(guidance.affectedRoleImpact.impactCode)} (
            {guidance.affectedRoleImpact.impactSeverity})
          </dd>
        </div>
        <div>
          <dt>Top confidence</dt>
          <dd>{topHypothesis.confidence}</dd>
        </div>
        <div>
          <dt>Generated</dt>
          <dd>
            <time dateTime={guidance.generatedAt}>{guidance.generatedAt}</time>
          </dd>
        </div>
        <div>
          <dt>Execution authorization</dt>
          <dd>Required separately</dd>
        </div>
      </dl>

      <h5>Evidence timeline</h5>
      <ol className="guidance-list">
        {guidance.timeline.map((entry) => (
          <li key={entry.entryId}>
            <strong>{humanizeCode(entry.timelineKind)}</strong>: {humanizeCode(entry.summaryCode)}
            <br />
            <time dateTime={entry.observedStart}>{entry.observedStart}</time>
            {entry.observedEnd !== entry.observedStart ? (
              <>
                {' '}
                to <time dateTime={entry.observedEnd}>{entry.observedEnd}</time>
              </>
            ) : null}
            <EvidenceList values={entry.evidenceIds} />
          </li>
        ))}
      </ol>

      <h5>Ranked hypotheses</h5>
      <ol className="guidance-list">
        {guidance.hypotheses.map((hypothesis) => (
          <li key={hypothesis.hypothesisId}>
            <strong>
              {humanizeCode(hypothesis.category)} — {hypothesis.confidence}
            </strong>
            <p>
              {hypothesis.supportingEvidenceCount} supporting evidence item
              {hypothesis.supportingEvidenceCount === 1 ? '' : 's'}.
            </p>
            <EvidenceList values={hypothesis.supportingEvidenceIds} />
            <CodeList label="Contradictions" values={hypothesis.contradictionCodes} />
            <CodeList label="Missing evidence" values={hypothesis.missingEvidenceCodes} />
          </li>
        ))}
      </ol>

      <GuidanceSteps heading="Confirmation checks" steps={guidance.confirmationChecks} />
      <GuidanceSteps heading="Investigation checks" steps={guidance.investigationSteps} />
      <GuidanceSteps heading="Safe manual options" steps={guidance.safeManualOptions} />
      <GuidanceSteps
        heading="Rollback considerations"
        steps={guidance.rollbackConsiderations}
      />
      <GuidanceSteps heading="Recovery validation" steps={guidance.recoveryValidation} />
      <GuidanceSteps heading="Escalation" steps={guidance.escalation} />
      <RunbookLinks links={guidance.runbookLinks} />
      <CodeList label="Guidance-wide missing evidence" values={guidance.missingEvidence} />
      <CodeList label="Withheld because" values={guidance.legality.withheldReasons} />

      <p className="guidance-boundary">
        Athena never executes these steps. Manual and rollback options appear only when the signed
        guidance legality permits them, and every execution still requires separate operator
        authorization.
      </p>
    </section>
  )
}

const GuidanceSteps = ({
  heading,
  steps,
}: {
  heading: string
  steps: GuidanceStep[]
}) => {
  if (steps.length === 0) return null
  return (
    <section className="guidance-group" aria-label={heading}>
      <h5>{heading}</h5>
      <ol className="guidance-list">
        {steps.map((step) => (
          <li key={step.stepId}>
            <strong>{guidanceTemplateLabel(step.templateCode)}</strong>
            <span className="guidance-mode">
              {step.readOnly ? 'Read-only check' : 'Operator-authorized option'}
            </span>
            {step.parameters.length > 0 ? (
              <dl className="guidance-parameters">
                {step.parameters.map((parameter) => (
                  <div key={parameter.parameterKind}>
                    <dt>{humanizeCode(parameter.parameterKind)}</dt>
                    <dd>
                      <code>{parameter.value}</code>
                    </dd>
                  </div>
                ))}
              </dl>
            ) : null}
            <EvidenceList values={step.evidenceIds} />
            {step.provenanceClauseRef ? (
              <p>
                Approved clause: <code>{step.provenanceClauseRef}</code>
              </p>
            ) : null}
          </li>
        ))}
      </ol>
    </section>
  )
}

const RunbookLinks = ({ links }: { links: GuidanceRunbookLink[] }) => {
  if (links.length === 0) return null
  return (
    <section className="guidance-group" aria-label="Approved runbook references">
      <h5>Approved runbook references</h5>
      <ul className="guidance-list">
        {links.map((link) => (
          <li key={link.linkId}>
            {link.reference.referenceKind === 'https' ? (
              <a href={link.reference.uri} rel="noreferrer">
                Open approved operator runbook
              </a>
            ) : (
              <>
                Approved opaque reference: <code>{link.reference.opaqueRef}</code>
              </>
            )}
            <span className="guidance-mode">Reference only · {link.reference.version}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}

const EvidenceList = ({ values }: { values: string[] }) =>
  values.length > 0 ? (
    <p className="guidance-evidence">
      Evidence: {values.map((value) => <code key={value}>{value}</code>)}
    </p>
  ) : null

const CodeList = ({ label, values }: { label: string; values: string[] }) =>
  values.length > 0 ? (
    <p className="guidance-evidence">
      {label}: {values.map((value) => <code key={value}>{humanizeCode(value)}</code>)}
    </p>
  ) : null

const humanizeCode = (value: string): string =>
  value
    .replaceAll(/[._-]+/g, ' ')
    .replaceAll(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/^./, (character) => character.toUpperCase())

const scenarioLabel = (scenario: VerifiedIncident['state']['scenario']): string => {
  if (scenario === 'singletonDatabaseFailure') return 'database server failure'
  if (scenario === 'webServerFailure') return 'web server failure'
  return 'Azure Load Balancer failure'
}

const Verdict = ({ payload }: { payload: PresentationPayload }) => (
  <div className={`verdict verdict-${payload.findings[0]!.verdict}`}>
    <span aria-hidden="true">{payload.findings[0]!.verdict === 'fail' ? '!' : '✓'}</span>
    <div>
      <small>Athena verdict</small>
      <strong>{payload.findings[0]!.verdict}</strong>
    </div>
  </div>
)

const ImpactDetails = ({ impact }: { impact: ImpactLevel }) => (
  <dl className="impact-list">
    <div>
      <dt>Availability</dt>
      <dd>{impact.availability}</dd>
    </div>
    <div>
      <dt>Redundancy</dt>
      <dd>{impact.redundancy}</dd>
    </div>
    <div>
      <dt>Operator attention</dt>
      <dd>{impact.operatorAttention}</dd>
    </div>
  </dl>
)

const phaseHeadline = (payload: PresentationPayload): string => {
  if (payload.phase === 'baseline') return 'Redundant web tier is healthy'
  if (payload.phase === 'faulted') return 'One web node is faulted; a peer remains running'
  return 'Web-tier redundancy is restored'
}

const blastRadiusExplanation = (blastRadius: BlastRadius): string => {
  if (blastRadius === 'none-active') {
    return 'Baseline contains zero faulted nodes and every signed web node is running.'
  }
  if (blastRadius === 'contained-web-tier') {
    return 'Exactly one signed web node is stopped while at least one signed peer remains running.'
  }
  return 'The signed reset state is running and the recovered phase contains zero faulted nodes.'
}

export default App
