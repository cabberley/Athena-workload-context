import { useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import {
  applyCohortCandidateToDraft,
  cohortDraftIdempotencyKey,
  proposalReviewCandidate,
} from './cohortDraft'
import type {
  CohortDecisionState,
  CohortProposal,
  CohortProposalApiPort,
  CohortProposalBatch,
  CohortReviewCandidate,
} from './cohortTypes'
import type {
  CanonicalManifestSelector,
  ContextApiClientPort,
  WorkloadContext,
} from './types'

const MEMBER_PAGE_SIZE = 25
const REJECTED_PAGE_SIZE = 20

const displayEnvironment = (value: string): string =>
  value === 'disasterRecovery'
    ? 'Disaster Recovery'
    : `${value.charAt(0).toUpperCase()}${value.slice(1)}`

const displayToken = (value: string): string =>
  value.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/^./, (letter) => letter.toUpperCase())

const errorMessage = (error: unknown, fallback: string): string =>
  error instanceof Error ? error.message : fallback

const selectorSummary = (selector: CanonicalManifestSelector): string => {
  switch (selector.selectorType) {
    case 'resourceIdList':
      return `${selector.resourceIds.length} explicit bounded resource IDs`
    case 'tagPredicate':
      return selector.predicates.map((item) => `${item.key} = ${item.value}`).join(' and ')
    case 'namePredicate':
      return [
        selector.prefix ? `prefix ${selector.prefix}` : null,
        selector.suffix ? `suffix ${selector.suffix}` : null,
      ].filter(Boolean).join(', ')
    case 'resourceType':
      return `${selector.resourceType}; ${selector.locations.length || 'all'} location filters; ` +
        `${selector.resourceGroups.length || 'all'} resource-group filters`
    case 'vmScaleSet':
      return `${selector.scaleSetResourceId}; ${selector.instanceIds.length || 'all'} instance filters`
    case 'loadBalancerBackend':
      return `${selector.loadBalancerResourceId}; backend ${selector.backendPoolName}`
    case 'subnet':
      return selector.subnetResourceId
    case 'image':
      return `${selector.publisher}/${selector.offer}/${selector.sku}/${selector.version ?? 'any version'}`
    case 'provenance':
      return `${selector.collectorToolName} ${selector.collectorToolVersion}; identity evidence ${selector.identityEvidenceRef}`
    case 'compositeAll':
      return `All of ${selector.children.map((child) => child.selectorId).join(', ')}`
    case 'compositeAny':
      return `Any of ${selector.children.map((child) => child.selectorId).join(', ')}`
  }
}

const draftBinding = (context: WorkloadContext) => {
  if (!context.draft) return null
  return {
    draftId: context.draft.draftId,
    revision: context.draft.revision,
    manifestDigest: context.draft.manifestDigest,
  }
}

const relevantBatchConflicts = (
  proposal: CohortProposal,
  batch: CohortProposalBatch,
) => batch.conflicts.filter(
  (conflict) =>
    conflict.roleRefs.length === 0 ||
    conflict.roleRefs.some((roleRef) => roleRef === proposal.role.roleId),
)

const needsResolution = (
  proposal: CohortProposal,
  batch: CohortProposalBatch,
): boolean =>
  proposal.confidenceBand !== 'high' ||
  proposal.dissent.length > 0 ||
  proposal.conflicts.length > 0 ||
  proposal.rejectedCandidates.some((candidate) => candidate.reasons.includes('crossEnvironment')) ||
  relevantBatchConflicts(proposal, batch).length > 0

type Confirmation =
  | { action: 'approve' | 'reject' | 'split'; proposalIds: string[] }
  | { action: 'merge'; proposalIds: string[] }
  | { action: 'apply'; proposalIds: string[]; candidate: CohortReviewCandidate }

interface CohortReviewProps {
  context: WorkloadContext
  contextClient: ContextApiClientPort
  cohortClient: CohortProposalApiPort
  onContextChange: (context: WorkloadContext) => void
  headingRef: RefObject<HTMLHeadingElement>
}

export default function CohortReview({
  context,
  contextClient,
  cohortClient,
  onContextChange,
  headingRef,
}: CohortReviewProps) {
  const [batch, setBatch] = useState<CohortProposalBatch | null>(null)
  const [selectedProposalId, setSelectedProposalId] = useState<string | null>(null)
  const [loadState, setLoadState] = useState<'loading' | 'ready' | 'error' | 'unavailable'>('loading')
  const [statusMessage, setStatusMessage] = useState('Loading exact draft-bound cohort proposals.')
  const [memberFilter, setMemberFilter] = useState('')
  const [memberPage, setMemberPage] = useState(0)
  const [rejectedPage, setRejectedPage] = useState(0)
  const [resolution, setResolution] = useState('')
  const [resolutionAcknowledged, setResolutionAcknowledged] = useState(false)
  const [mergeSelection, setMergeSelection] = useState<Set<string>>(new Set())
  const [decisions, setDecisions] = useState<Map<string, CohortDecisionState>>(new Map())
  const [candidate, setCandidate] = useState<CohortReviewCandidate | null>(null)
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const [busy, setBusy] = useState(false)
  const confirmationButtonRef = useRef<HTMLButtonElement>(null)
  const confirmationDialogRef = useRef<HTMLDivElement>(null)
  const confirmationReturnFocusRef = useRef<HTMLElement | null>(null)

  const activeManifest = context.draft?.manifest ?? context.manifest
  const profile = Object.values(activeManifest.profiles).find(
    (item) => item.profileType === context.environment,
  )
  const binding = useMemo(() => draftBinding(context), [context])

  useEffect(() => {
    if (!confirmation) return
    confirmationButtonRef.current?.focus()
  }, [confirmation])

  useEffect(() => {
    if (loadState === 'ready') headingRef.current?.focus()
  }, [headingRef, loadState])

  useEffect(() => {
    let active = true
    setBatch(null)
    setCandidate(null)
    setSelectedProposalId(null)
    setMergeSelection(new Set())
    if (!profile || !binding || context.draft?.state !== 'draft') {
      setLoadState('unavailable')
      setStatusMessage(
        'Cohort review requires an active WC-007 draft in draft state. No proposal authority was inferred.',
      )
      return () => {
        active = false
      }
    }
    if (
      contextClient.auth.actorId !== cohortClient.auth.actorId ||
      !cohortClient.auth.authorizedWorkloadIds.includes(context.workloadId)
    ) {
      setLoadState('error')
      setStatusMessage('Context and cohort API identities or workload scopes do not match.')
      return () => {
        active = false
      }
    }
    setLoadState('loading')
    setStatusMessage('Loading exact draft-bound cohort proposals.')
    void cohortClient.loadProposalBatch({
      workloadId: context.workloadId,
      manifestVersion: context.draft.manifest.manifestVersion,
      profileId: profile.profileId,
      sourceDraft: binding,
    }).then((loaded) => {
      if (!active) return
      setBatch(loaded)
      setSelectedProposalId(loaded.proposals[0]?.proposalId ?? null)
      setLoadState('ready')
      setStatusMessage(
        loaded.proposals.length
          ? `Loaded ${loaded.proposals.length} non-authoritative proposals for explicit human review.`
          : 'The cohort API returned no proposals for this exact draft and profile.',
      )
    }).catch((error: unknown) => {
      if (!active) return
      setLoadState('error')
      setStatusMessage(errorMessage(error, 'Unable to load cohort proposals.'))
    })
    return () => {
      active = false
    }
  }, [
    cohortClient,
    binding,
    context.workloadId,
    context.draft,
    context.environment,
    contextClient.auth.actorId,
    profile,
  ])

  const selected = batch?.proposals.find(
    (proposal) => proposal.proposalId === selectedProposalId,
  ) ?? null
  const filteredMembers = useMemo(() => {
    if (!selected) return []
    const query = memberFilter.trim().toLowerCase()
    return query
      ? selected.members.filter((member) => member.toLowerCase().includes(query))
      : selected.members
  }, [memberFilter, selected])
  const memberPageCount = Math.max(1, Math.ceil(filteredMembers.length / MEMBER_PAGE_SIZE))
  const visibleMembers = filteredMembers.slice(
    memberPage * MEMBER_PAGE_SIZE,
    (memberPage + 1) * MEMBER_PAGE_SIZE,
  )
  const rejectedPageCount = Math.max(
    1,
    Math.ceil((selected?.rejectedCandidates.length ?? 0) / REJECTED_PAGE_SIZE),
  )
  const visibleRejected = selected?.rejectedCandidates.slice(
    rejectedPage * REJECTED_PAGE_SIZE,
    (rejectedPage + 1) * REJECTED_PAGE_SIZE,
  ) ?? []
  const isHuman = contextClient.auth.kind === 'human' && cohortClient.auth.kind === 'human'
  const canWriteDraft = isHuman && contextClient.auth.role === 'proposer'
  const selectedNeedsResolution = Boolean(selected && batch && needsResolution(selected, batch))
  const resolutionReady =
    resolution.trim().length >= 12 &&
    resolution.trim().length <= 2000 &&
    resolutionAcknowledged
  const selectedDecision = selected ? decisions.get(selected.proposalId) ?? 'pending' : 'pending'

  const selectProposal = (proposalId: string): void => {
    setSelectedProposalId(proposalId)
    setMemberFilter('')
    setMemberPage(0)
    setRejectedPage(0)
    setResolution('')
    setResolutionAcknowledged(false)
    setCandidate(null)
  }

  const updateMergeSelection = (proposalId: string, checked: boolean): void => {
    setMergeSelection((current) => {
      const next = new Set(current)
      if (checked) next.add(proposalId)
      else next.delete(proposalId)
      return next
    })
  }

  const openConfirmation = (
    action: Confirmation['action'],
    proposalIds: string[],
    reviewCandidate?: CohortReviewCandidate,
  ): void => {
    confirmationReturnFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null
    if (action === 'apply' && reviewCandidate) {
      setConfirmation({ action, proposalIds, candidate: reviewCandidate })
    } else if (action !== 'apply') {
      setConfirmation({ action, proposalIds } as Confirmation)
    }
  }

  const closeConfirmation = (): void => {
    setConfirmation(null)
    queueMicrotask(() => confirmationReturnFocusRef.current?.focus())
  }

  const previewTransformation = async (
    action: 'split' | 'merge',
    proposalIds: string[],
  ): Promise<void> => {
    if (!batch || !binding || !profile || !resolutionReady) {
      setStatusMessage('Split and merge require an acknowledged resolution rationale.')
      return
    }
    setBusy(true)
    try {
      const preview = await cohortClient.previewReview({
        action,
        workloadId: context.workloadId,
        manifestVersion: activeManifest.manifestVersion,
        profileId: profile.profileId,
        sourceDraft: binding,
        proposalIds,
        sourceRoles: [
          ...new Map(
            batch.proposals
              .filter((proposal) => proposalIds.includes(proposal.proposalId))
              .map((proposal) => [proposal.role.roleId, proposal.role]),
          ).values(),
        ],
        sourceMembers: batch.proposals
          .filter((proposal) => proposalIds.includes(proposal.proposalId))
          .flatMap((proposal) => proposal.members),
        proposalSetDigest: batch.proposalSetDigest,
        snapshotArtifactDigest: batch.snapshot.artifactDigest,
        resolution: resolution.trim(),
      })
      setCandidate(preview)
      setStatusMessage(
        `${displayToken(action)} preview loaded from the cohort API. It has not changed WC-007 state.`,
      )
    } catch (error) {
      setCandidate(null)
      setStatusMessage(errorMessage(error, `Unable to preview the ${action}.`))
    } finally {
      setBusy(false)
    }
  }

  const applyCandidate = async (reviewCandidate: CohortReviewCandidate): Promise<void> => {
    if (!canWriteDraft || !context.draft || !batch) {
      setStatusMessage('A human proposer with WC-007 update permission is required to write a draft.')
      return
    }
    setBusy(true)
    try {
      const replacementManifest = applyCohortCandidateToDraft(
        context,
        reviewCandidate,
        batch,
        new Date(),
      )
      await contextClient.updateDraft({
        workloadId: context.workloadId,
        draftId: context.draft.draftId,
        expectedRevision: context.draft.revision,
        expectedManifestVersion: context.draft.manifest.manifestVersion,
        expectedDigest: context.draft.manifestDigest,
        replacementManifest,
        reason: (
          `Human ${reviewCandidate.action} review wrote bounded selector proposal(s) from ` +
          `${reviewCandidate.sourceProposalIds.join(', ')}; snapshot ` +
          `${reviewCandidate.snapshot.artifactDigest}. Draft only; publication was not requested. ` +
          reviewCandidate.resolution
        ).slice(0, 2000),
        idempotencyKey: cohortDraftIdempotencyKey(
          reviewCandidate,
          context.draft.revision,
        ),
      })
      const refreshed = await contextClient.loadWorkloadContext(context.workloadId)
      onContextChange(refreshed)
      setDecisions((current) => {
        const next = new Map(current)
        reviewCandidate.sourceProposalIds.forEach((proposalId) => next.set(proposalId, 'drafted'))
        return next
      })
      setCandidate(null)
      setStatusMessage(
        `Bounded ${reviewCandidate.action} selector proposal saved to WC-007 draft revision ` +
        `${refreshed.draft?.revision ?? 'unknown'}. Nothing was validated, approved, or published.`,
      )
    } catch (error) {
      setStatusMessage(errorMessage(error, 'The draft selector update failed closed.'))
    } finally {
      setBusy(false)
    }
  }

  const confirmAction = async (): Promise<void> => {
    const pending = confirmation
    if (!pending || !batch) return
    closeConfirmation()
    if (pending.action === 'reject') {
      setDecisions((current) => {
        const next = new Map(current)
        pending.proposalIds.forEach((proposalId) => next.set(proposalId, 'rejected'))
        return next
      })
      setStatusMessage(
        'Proposal rejected for this browser review session only. No authoritative or draft state was written.',
      )
      return
    }
    if (pending.action === 'split' || pending.action === 'merge') {
      await previewTransformation(pending.action, pending.proposalIds)
      return
    }
    if (pending.action === 'apply') {
      await applyCandidate(pending.candidate)
      return
    }
    const proposal = batch.proposals.find(
      (item) => item.proposalId === pending.proposalIds[0],
    )
    if (!proposal) {
      setStatusMessage('The selected proposal is no longer in the exact loaded batch.')
      return
    }
    try {
      await applyCandidate(
        proposalReviewCandidate(proposal, batch, resolution.trim()),
      )
    } catch (error) {
      setStatusMessage(errorMessage(error, 'The proposal could not be bounded for the draft.'))
    }
  }

  const mergeCandidates = batch?.proposals.filter(
    (proposal) => mergeSelection.has(proposal.proposalId),
  ) ?? []
  const mergeRoleCount = new Set(mergeCandidates.map((proposal) => proposal.role.roleId)).size
  const canMerge =
    isHuman &&
    mergeCandidates.length >= 2 &&
    mergeRoleCount === 1 &&
    resolutionReady

  if (loadState === 'loading') {
    return <section className="panel cohort-panel" aria-live="polite">{statusMessage}</section>
  }

  if (loadState === 'error' || loadState === 'unavailable' || !batch) {
    return (
      <section className="panel cohort-panel" aria-labelledby="cohort-heading">
        <h2 id="cohort-heading">Cohort proposal review</h2>
        <div className="review-notice" role={loadState === 'error' ? 'alert' : 'status'}>
          <strong>{loadState === 'error' ? 'Proposal API unavailable' : 'Draft required'}</strong>
          <p>{statusMessage}</p>
        </div>
      </section>
    )
  }

  return (
    <section className="panel cohort-panel" aria-labelledby="cohort-heading">
      <div className="panel-heading">
        <div>
          <p className="panel-kicker">Inferred proposals — explicit human review required</p>
          <h2 id="cohort-heading" tabIndex={-1} ref={headingRef}>Cohort proposal review</h2>
        </div>
        <span className="meta-pill">Draft only</span>
      </div>

      <dl className="cohort-metadata">
        <div><dt>Environment</dt><dd>{displayEnvironment(batch.scope.profileType)}</dd></div>
        <div><dt>Manifest version</dt><dd>{batch.scope.manifestVersion}</dd></div>
        <div><dt>Approval state</dt><dd>{context.draft?.state ?? context.approvalState}</dd></div>
        <div>
          <dt>Declared residual risk</dt>
          <dd>
            {profile?.riskAcceptances.length
              ? `${profile.riskAcceptances.length} declared · ${profile.riskAcceptances[0]!.residualRiskStatement}`
              : 'Not declared for this environment'}
          </dd>
        </div>
        <div><dt>Evidence source</dt><dd>Observed snapshot {batch.snapshot.snapshotId}</dd></div>
        <div><dt>Snapshot digest</dt><dd className="digest-value">{batch.snapshot.artifactDigest}</dd></div>
        <div><dt>Proposal set digest</dt><dd className="digest-value">{batch.proposalSetDigest}</dd></div>
        <div><dt>Draft binding</dt><dd>{batch.sourceDraft.draftId} · revision {batch.sourceDraft.revision}</dd></div>
        <div><dt>Publication</dt><dd>Not allowed by proposal contract</dd></div>
      </dl>

      <p className="relationship-legend">
        <strong>Observed:</strong> bounded evidence summaries. <strong>Inferred:</strong> cohort membership.
        {' '}<strong>Declared:</strong> selector changes only after a confirmed WC-007 draft update.
        {' '}<strong>Exception:</strong> conflicts require an explicit resolution.
      </p>

      <div className="cohort-workspace">
        <div>
          <h3>Proposals</h3>
          <ul className="proposal-list">
            {batch.proposals.map((proposal) => {
              const decision = decisions.get(proposal.proposalId) ?? 'pending'
              return (
                <li key={proposal.proposalId}>
                  <button
                    type="button"
                    className={proposal.proposalId === selectedProposalId
                      ? 'proposal-button is-selected'
                      : 'proposal-button'}
                    onClick={() => selectProposal(proposal.proposalId)}
                    aria-pressed={proposal.proposalId === selectedProposalId}
                  >
                    <span>
                      <strong>{proposal.role.roleId}</strong>
                      <span className={`confidence-badge confidence-${proposal.confidenceBand}`}>
                        {proposal.confidenceBand} · {Math.round(proposal.confidence * 100)}%
                      </span>
                    </span>
                    <span>{proposal.members.length.toLocaleString()} members · {displayToken(decision)}</span>
                  </button>
                  <label className="merge-choice">
                    <input
                      type="checkbox"
                      checked={mergeSelection.has(proposal.proposalId)}
                      onChange={(event) =>
                        updateMergeSelection(proposal.proposalId, event.target.checked)}
                      disabled={!isHuman || busy}
                    />
                    Include {proposal.role.roleId} proposal in merge
                  </label>
                </li>
              )
            })}
          </ul>
          <button
            type="button"
            className="secondary-action merge-action"
            disabled={!canMerge || busy}
            onClick={() => openConfirmation(
              'merge',
              batch.proposals
                .filter((proposal) => mergeSelection.has(proposal.proposalId))
                .map((proposal) => proposal.proposalId),
            )}
          >
            Preview merge of selected proposals
          </button>
          {mergeCandidates.length >= 2 && mergeRoleCount !== 1 && (
            <p className="field-help" role="status">Merge requires proposals for the same declared role.</p>
          )}
        </div>

        {selected && (
          <div className="proposal-detail">
            <div className="proposal-title">
              <div>
                <p className="relationship-kind">Inferred relationship</p>
                <h3>{selected.role.roleId}</h3>
              </div>
              <span className={`confidence-badge confidence-${selected.confidenceBand}`}>
                {displayToken(selected.confidenceBand)} confidence · {Math.round(selected.confidence * 100)}%
              </span>
            </div>
            <dl className="proposal-summary">
              <div><dt>Member count</dt><dd>{selected.members.length.toLocaleString()}</dd></div>
              <div><dt>Review band</dt><dd>{displayToken(selected.disposition)}</dd></div>
              <div><dt>Dissent</dt><dd>{selected.dissent.length.toLocaleString()}</dd></div>
              <div><dt>Conflicts</dt><dd>{selected.conflicts.length + relevantBatchConflicts(selected, batch).length}</dd></div>
              <div><dt>Rejected candidates</dt><dd>{selected.rejectedCandidates.length.toLocaleString()}</dd></div>
              <div><dt>Session decision</dt><dd>{displayToken(selectedDecision)}</dd></div>
            </dl>

            <div className="selector-preview">
              <h4>Bounded selector preview</h4>
              {selected.selectorPreview ? (
                <>
                  <p>
                    <strong>{displayToken(selected.selectorPreview.selector.selectorType)}</strong>
                    {' '}— {selectorSummary(selected.selectorPreview.selector)}
                  </p>
                  <p>
                    Maximum matches: {selected.selectorPreview.maxMatches.toLocaleString()} ·
                    Result digest: <span className="digest-value">
                      {selected.selectorPreview.selectorResultDigest}
                    </span>
                  </p>
                </>
              ) : (
                <p role="alert">
                  No bounded selector preview was provided. Direct draft approval is blocked;
                  a human may request a server-generated split preview after explicit resolution.
                </p>
              )}
            </div>

            <div className="evidence-grid">
              <div>
                <h4>Observed support evidence</h4>
                {selected.supportingEvidence.length ? (
                  <ul className="compact-list">
                    {selected.supportingEvidence.map((evidence, index) => (
                      <li key={`${evidence.signalType}-${index}`}>
                        <strong>{displayToken(evidence.signalType)}</strong>
                        <span>{evidence.signalValue}</span>
                        <small>
                          {evidence.memberCount.toLocaleString()} members ·
                          {' '}{evidence.evidenceRefCount.toLocaleString()} bounded references
                        </small>
                      </li>
                    ))}
                  </ul>
                ) : <p>No support evidence summary was provided.</p>}
              </div>
              <div>
                <h4>Dissent</h4>
                {selected.dissent.length ? (
                  <ul className="compact-list">
                    {selected.dissent.slice(0, REJECTED_PAGE_SIZE).map((item) => (
                      <li key={`${item.resourceId}-${item.signalType}`}>
                        <strong>{displayToken(item.signalType)}</strong>
                        <span className="resource-id">{item.resourceId}</span>
                        <span>{item.reason}</span>
                        <small>Expected {item.expectedValue}; observed {item.observedValue ?? 'not provided'}</small>
                      </li>
                    ))}
                  </ul>
                ) : <p>No dissent was declared by the proposal API.</p>}
              </div>
            </div>

            <div>
              <h4>Conflicts and exceptions requiring resolution</h4>
              {[...selected.conflicts, ...relevantBatchConflicts(selected, batch)].length ? (
                <ul className="conflict-list">
                  {[...selected.conflicts, ...relevantBatchConflicts(selected, batch)].map(
                    (conflict, index) => (
                      <li key={`${conflict.code}-${index}`}>
                        <strong>{displayToken(conflict.code)}</strong>
                        <span>{conflict.detail}</span>
                        <small>
                          {conflict.resourceIds.length.toLocaleString()} bounded resource references ·
                          {' '}{conflict.roleRefs.length.toLocaleString()} role references
                        </small>
                      </li>
                    ),
                  )}
                </ul>
              ) : <p>No conflicts were declared by the proposal API.</p>}
            </div>

            <div className="member-browser">
              <div className="member-browser-heading">
                <h4>Members</h4>
                <span>{filteredMembers.length.toLocaleString()} of {selected.members.length.toLocaleString()}</span>
              </div>
              <label htmlFor="member-filter">
                Filter members
                <input
                  id="member-filter"
                  type="search"
                  value={memberFilter}
                  onChange={(event) => {
                    setMemberFilter(event.target.value)
                    setMemberPage(0)
                  }}
                  placeholder="Filter by bounded resource ID"
                />
              </label>
              <ul className="resource-page" aria-label="Filtered cohort members">
                {visibleMembers.map((member) => <li key={member} className="resource-id">{member}</li>)}
              </ul>
              {!visibleMembers.length && <p>No members match this filter.</p>}
              <div className="pagination" aria-label="Member pages">
                <button
                  type="button"
                  className="small-button"
                  disabled={memberPage === 0}
                  onClick={() => setMemberPage((page) => Math.max(0, page - 1))}
                >
                  Previous members
                </button>
                <span>Page {Math.min(memberPage + 1, memberPageCount)} of {memberPageCount}</span>
                <button
                  type="button"
                  className="small-button"
                  disabled={memberPage + 1 >= memberPageCount}
                  onClick={() => setMemberPage((page) => page + 1)}
                >
                  Next members
                </button>
              </div>
            </div>

            <div className="member-browser">
              <div className="member-browser-heading">
                <h4>Rejected candidates</h4>
                <span>{selected.rejectedCandidates.length.toLocaleString()}</span>
              </div>
              {visibleRejected.length ? (
                <ul className="resource-page" aria-label="Rejected candidates">
                  {visibleRejected.map((item) => (
                    <li key={item.resourceId}>
                      <span className="resource-id">{item.resourceId}</span>
                      <small>{item.reasons.map(displayToken).join(', ')}</small>
                    </li>
                  ))}
                </ul>
              ) : <p>No rejected candidates were declared.</p>}
              {selected.rejectedCandidates.length > REJECTED_PAGE_SIZE && (
                <div className="pagination" aria-label="Rejected candidate pages">
                  <button
                    type="button"
                    className="small-button"
                    disabled={rejectedPage === 0}
                    onClick={() => setRejectedPage((page) => Math.max(0, page - 1))}
                  >
                    Previous rejected
                  </button>
                  <span>Page {rejectedPage + 1} of {rejectedPageCount}</span>
                  <button
                    type="button"
                    className="small-button"
                    disabled={rejectedPage + 1 >= rejectedPageCount}
                    onClick={() => setRejectedPage((page) => page + 1)}
                  >
                    Next rejected
                  </button>
                </div>
              )}
            </div>

            <fieldset className="resolution-fieldset">
              <legend>Explicit resolution</legend>
              <label htmlFor="cohort-resolution">
                Resolution rationale
                <textarea
                  id="cohort-resolution"
                  value={resolution}
                  maxLength={2000}
                  onChange={(event) => setResolution(event.target.value)}
                  disabled={!isHuman || busy}
                  aria-describedby="cohort-resolution-help"
                />
              </label>
              <p id="cohort-resolution-help" className="field-help">
                Required for medium, low, conflicting, cross-environment, split, or merge review.
              </p>
              <label className="review-confirmation">
                <input
                  type="checkbox"
                  checked={resolutionAcknowledged}
                  onChange={(event) => setResolutionAcknowledged(event.target.checked)}
                  disabled={!isHuman || busy}
                />
                I explicitly resolved the listed dissent, conflicts, and environment boundary for
                this exact snapshot and proposal digest.
              </label>
            </fieldset>

            <div className="cohort-actions">
              <button
                type="button"
                className="primary-action"
                disabled={
                  busy ||
                  !canWriteDraft ||
                  !selected.selectorPreview ||
                  selectedDecision !== 'pending' ||
                  (selectedNeedsResolution && !resolutionReady)
                }
                onClick={() => openConfirmation('approve', [selected.proposalId])}
              >
                Approve bounded cohort to draft
              </button>
              <button
                type="button"
                className="secondary-action"
                disabled={!isHuman || busy || selectedDecision !== 'pending'}
                onClick={() => openConfirmation('reject', [selected.proposalId])}
              >
                Reject proposal in this review
              </button>
              <button
                type="button"
                className="secondary-action"
                disabled={!isHuman || busy || !resolutionReady}
                onClick={() => openConfirmation('split', [selected.proposalId])}
              >
                Preview split
              </button>
            </div>
            {!canWriteDraft && (
              <p className="field-help" role="status">
                Draft approval requires a human session with the WC-007 proposer role. Current role:
                {' '}{contextClient.auth.role}.
              </p>
            )}

            {candidate && (
              <div className="candidate-preview" aria-labelledby="candidate-preview-heading">
                <h4 id="candidate-preview-heading">
                  {displayToken(candidate.action)} result — API preview only
                </h4>
                <p>
                  {candidate.roleUpdates.length} role update(s), bound to snapshot
                  {' '}<span className="digest-value">{candidate.snapshot.artifactDigest}</span>.
                </p>
                <ul className="compact-list">
                  {candidate.roleUpdates.map((update) => (
                    <li key={update.role.roleId}>
                      <strong>{update.role.roleId}</strong>
                      <span>{update.memberCount.toLocaleString()} summarized members</span>
                      {update.selectorPreviews.map((preview) => (
                        <small key={preview.selector.selectorId}>
                          {preview.selector.selectorId}: {selectorSummary(preview.selector)}
                          {' '}· max {preview.maxMatches.toLocaleString()}
                        </small>
                      ))}
                    </li>
                  ))}
                </ul>
                <button
                  type="button"
                  className="primary-action"
                  disabled={!canWriteDraft || busy}
                  onClick={() => openConfirmation(
                    'apply',
                    candidate.sourceProposalIds,
                    candidate,
                  )}
                >
                  Apply preview as draft selector proposal
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="status-message" aria-live="polite">{statusMessage}</div>

      {confirmation && (
        <div
          className="confirmation-backdrop"
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="cohort-confirmation-heading"
          aria-describedby="cohort-confirmation-description"
          onKeyDown={(event) => {
            if (event.key === 'Escape') closeConfirmation()
            if (event.key === 'Tab') {
              const controls = confirmationDialogRef.current?.querySelectorAll<HTMLButtonElement>(
                'button:not(:disabled)',
              )
              if (!controls?.length) return
              const first = controls[0]!
              const last = controls[controls.length - 1]!
              if (event.shiftKey && document.activeElement === first) {
                event.preventDefault()
                last.focus()
              } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault()
                first.focus()
              }
            }
          }}
        >
          <div className="confirmation-dialog" ref={confirmationDialogRef}>
            <h3 id="cohort-confirmation-heading">
              Confirm {displayToken(confirmation.action)}
            </h3>
            <p id="cohort-confirmation-description">
              Confirm this action for {confirmation.proposalIds.length} exact proposal(s) in
              {' '}{displayEnvironment(batch.scope.profileType)}, manifest {batch.scope.manifestVersion},
              snapshot <span className="digest-value">{batch.snapshot.artifactDigest}</span>.
              {confirmation.action === 'reject'
                ? ' Rejection is session-only and writes no authority.'
                : confirmation.action === 'split' || confirmation.action === 'merge'
                  ? ' This requests a non-authoritative selector preview and does not change the manifest.'
                  : ' This writes only bounded selectors to the current WC-007 draft with exact concurrency and idempotency. It never validates, approves, or publishes.'}
            </p>
            <div className="confirmation-actions">
              <button
                type="button"
                className="secondary-action"
                onClick={closeConfirmation}
              >
                Cancel
              </button>
              <button
                ref={confirmationButtonRef}
                type="button"
                className="primary-action"
                onClick={() => void confirmAction()}
              >
                Confirm {displayToken(confirmation.action)}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
