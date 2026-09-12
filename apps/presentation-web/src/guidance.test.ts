import { canonicalizeJson, sha256Digest, type JsonValue } from './canonical'
import { parseIncidentGuidance } from './guidance'

const digest = (character: string): string => `sha256:${character.repeat(64)}`

const digestBound = async (
  payload: Record<string, JsonValue>,
  idKey: string,
  digestKey: string,
  prefix: string,
): Promise<Record<string, JsonValue>> => {
  const valueDigest = await sha256Digest(canonicalizeJson(payload))
  return {
    ...payload,
    [idKey]: `${prefix}${valueDigest.slice(7, 39)}`,
    [digestKey]: valueDigest,
  }
}

const buildGuidance = async (
  overrides: Record<string, JsonValue> = {},
): Promise<Record<string, JsonValue>> => {
  const sourceBinding = await digestBound({
    incidentSubjectId: `incident-subject-${'2'.repeat(32)}`,
    incidentSubjectDigest: digest('2'),
    incidentId: 'inc-123456789abc',
    incidentRevision: 1,
    incidentStateDigest: digest('3'),
    incidentBoundRequestId: `incident-bound-request-${'4'.repeat(32)}`,
    incidentBoundRequestDigest: digest('4'),
    correlationReportId: `report-${'5'.repeat(32)}`,
    correlationReportDigest: digest('5'),
    correlationRequestDigest: digest('6'),
    transitionDigest: digest('7'),
    ruleCatalogDigest: digest('8'),
    inputInventoryDigest: digest('9'),
    guidanceAuthorityId: `guidance-authority-${'a'.repeat(32)}`,
    guidanceAuthorityDigest: digest('a'),
    guidanceBindingId: `guidance-binding-${'b'.repeat(32)}`,
    guidanceBindingDigest: digest('b'),
    selectionKind: 'noRunbook',
    noRunbookReason: 'confidenceTooLow',
  }, 'sourceId', 'sourceDigest', 'guidance-source-')
  const readOnlyStep = async (
    actionKind: string,
    templateCode: string,
  ): Promise<Record<string, JsonValue>> => digestBound({
    actionKind,
    templateCode,
    parameters: [],
    evidenceIds: [`obs-${'d'.repeat(32)}`],
    readOnly: true,
    requiresAuthorization: false,
  }, 'stepId', 'stepDigest', 'guidance-step-')
  const timeline = await digestBound({
    timelineKind: 'healthTransition',
    observedStart: '2026-09-04T03:40:00Z',
    observedEnd: '2026-09-04T03:40:03Z',
    summaryCode: 'synthetic.web-node-degraded',
    evidenceIds: [`obs-${'d'.repeat(32)}`],
  }, 'entryId', 'entryDigest', 'guidance-timeline-')
  const payload: Record<string, JsonValue> = {
    schemaVersion: 'athena.wc027IncidentGuidance.v1',
    algorithmId: 'athena.wc027.incident-guidance.v1',
    generatedAt: '2026-09-04T03:41:00Z',
    sourceBinding,
    affectedRoleImpact: {
      roleRef: 'web',
      profileId: 'Production',
      impactSeverity: 'limited',
      impactCode: 'roleDegraded',
    },
    timeline: [timeline],
    hypotheses: [
      {
        rank: 1,
        hypothesisId: `hyp-${'f'.repeat(32)}`,
        hypothesisDigest: digest('f'),
        category: 'guestServiceFailure',
        confidence: 'Medium',
        supportingEvidenceIds: [`obs-${'d'.repeat(32)}`],
        supportingEvidenceCount: 1,
        supportingEvidenceDigest: digest('1'),
        contradictionCodes: [],
        missingEvidenceCodes: ['endpointHealth'],
      },
    ],
    confirmationChecks: [
      await readOnlyStep('confirmationCheck', 'confirmBackendHealth'),
    ],
    investigationSteps: [
      await readOnlyStep('investigationCheck', 'inspectGuestHealth'),
    ],
    safeManualOptions: [],
    rollbackConsiderations: [],
    recoveryValidation: [
      await readOnlyStep('recoveryValidation', 'validateRecoverySignals'),
    ],
    escalation: [
      await readOnlyStep('escalation', 'escalateHumanReview'),
    ],
    runbookLinks: [],
    missingEvidence: ['endpointHealth'],
    legality: {
      confidence: 'Medium',
      selectionKind: 'noRunbook',
      manualActionsAuthorized: false,
      rollbackAuthorized: false,
      runbookReferenceAuthorized: false,
      executionAuthorizationRequired: true,
      withheldReasons: ['confidenceTooLow', 'missingEvidence'],
    },
    noAutoRemediation: true,
    ...overrides,
  }
  const guidanceDigest = await sha256Digest(canonicalizeJson(payload))
  return {
    ...payload,
    guidanceId: `incident-guidance-${guidanceDigest.slice(7, 39)}`,
    guidanceDigest,
  }
}

const rebindGuidance = async (
  guidance: Record<string, JsonValue>,
): Promise<Record<string, JsonValue>> => {
  const payload = structuredClone(guidance)
  delete payload.guidanceId
  delete payload.guidanceDigest
  const guidanceDigest = await sha256Digest(canonicalizeJson(payload))
  return {
    ...payload,
    guidanceId: `incident-guidance-${guidanceDigest.slice(7, 39)}`,
    guidanceDigest,
  }
}

describe('WC-027 guidance presentation contract', () => {
  it('accepts bounded lower-confidence read-only guidance', async () => {
    const guidance = await parseIncidentGuidance(await buildGuidance())

    expect(guidance.legality.confidence).toBe('Medium')
    expect(guidance.safeManualOptions).toHaveLength(0)
    expect(guidance.runbookLinks).toHaveLength(0)
    expect(guidance.noAutoRemediation).toBe(true)
  })

  it('rejects manual resolution content below Confirmed confidence', async () => {
    const manual = await digestBound({
      actionKind: 'manualResolutionOption',
      templateCode: 'reviewApprovedManualOption',
      parameters: [],
      evidenceIds: [],
      provenanceClauseRef: '/profiles/Production/controls/web',
      optionId: `guidance-option-${'7'.repeat(32)}`,
      readOnly: false,
      requiresAuthorization: true,
    }, 'stepId', 'stepDigest', 'guidance-step-')
    const guidance = await buildGuidance({ safeManualOptions: [manual] })

    await expect(parseIncidentGuidance(guidance)).rejects.toThrow(
      /option binding|confidence-sensitive legality/i,
    )
  })

  it('rejects unbounded step collections and unknown fields', async () => {
    const guidance = await buildGuidance()
    guidance.confirmationChecks = Array.from(
      { length: 65 },
      (_, index) => {
        const suffix = index.toString(16).padStart(32, '0')
        return {
          stepId: `guidance-step-${suffix}`,
          actionKind: 'confirmationCheck',
          templateCode: 'confirmBackendHealth',
          parameters: [],
          evidenceIds: [],
          readOnly: true,
          requiresAuthorization: false,
          stepDigest: digest('8'),
        } satisfies Record<string, JsonValue>
      },
    )
    delete guidance.guidanceId
    delete guidance.guidanceDigest
    const guidanceDigest = await sha256Digest(canonicalizeJson(guidance))
    guidance.guidanceId = `incident-guidance-${guidanceDigest.slice(7, 39)}`
    guidance.guidanceDigest = guidanceDigest

    await expect(parseIncidentGuidance(guidance)).rejects.toThrow(/collection exceeds/i)

    const unknown = await buildGuidance({ unexpected: true })
    await expect(parseIncidentGuidance(unknown)).rejects.toThrow(/unexpected fields/i)
  })

  it('rejects malformed nested hypothesis digests and omission pairs', async () => {
    const malformedDigest = await buildGuidance()
    const malformedHypothesis = (
      malformedDigest.hypotheses as Record<string, JsonValue>[]
    )[0]!
    malformedHypothesis.hypothesisDigest = 'not-a-digest'
    await expect(
      parseIncidentGuidance(await rebindGuidance(malformedDigest)),
    ).rejects.toThrow(/hypothesis is invalid/i)

    const incompleteOmission = await buildGuidance()
    const omittedHypothesis = (
      incompleteOmission.hypotheses as Record<string, JsonValue>[]
    )[0]!
    omittedHypothesis.omittedCandidateCount = 2
    await expect(
      parseIncidentGuidance(await rebindGuidance(incompleteOmission)),
    ).rejects.toThrow(/hypothesis is invalid/i)
  })
})
