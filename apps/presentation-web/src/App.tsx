import { useEffect, useRef, useState, type KeyboardEvent } from 'react'
import {
  LIFECYCLE_PHASES,
  type LifecyclePhase,
  type PresentationPayload,
} from './contracts'
import { loadVerifiedLifecycle } from './runtime'
import type { BlastRadius, ImpactLevel } from './derivations'
import type { VerifiedLifecycle } from './verification'
import './App.css'

export interface AppProps {
  loader?: () => Promise<VerifiedLifecycle>
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

function App({ loader = loadVerifiedLifecycle }: AppProps) {
  const [lifecycle, setLifecycle] = useState<VerifiedLifecycle | null>(null)
  const [failed, setFailed] = useState(false)
  const [selectedPhase, setSelectedPhase] = useState<LifecyclePhase>('baseline')
  const phaseHeadingRef = useRef<HTMLHeadingElement>(null)

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
            A standalone, presentation-only view of one signed synthetic demonstration.
          </p>
        </div>
        <div className="synthetic-badge" aria-label="Synthetic demo data">
          <span aria-hidden="true">◇</span>
          Synthetic demo data
        </div>
      </header>

      <main>
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
              <p className="card-label">Derived only from signed node state</p>
              <h3 id="blast-radius-heading">Blast radius</h3>
              <p className={`metric-value tone-${selected.blastRadius}`}>
                {BLAST_RADIUS_LABELS[selected.blastRadius]}
              </p>
              <p>{blastRadiusExplanation(selected.blastRadius)}</p>
            </section>

            <section className="metric-card" aria-labelledby="impact-heading">
              <p className="card-label">Deterministic signed-field mapping</p>
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
            </ol>
            <p className="boundary-note">
              No database, worker, load balancer, geographic, or customer impact is inferred
              because those fields are absent from the signed presentation contract.
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
        Presentation-only browser boundary. No Azure, Blob, ARM, MCP, or workload calls are made.
      </footer>
    </div>
  )
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
