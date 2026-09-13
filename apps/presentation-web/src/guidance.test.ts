import { canonicalizeJson, sha256Digest, type JsonValue } from './canonical'
import type { Sha256Digest } from './contracts'
import {
  assertGuidanceMatchesVerifiedOccurrence,
  loadVerifiedOperatorGuidanceFeed,
  parseIncidentGuidance,
  type ParsedEnrichmentManifest,
  type ParsedPublishedReportStatement,
} from './guidance'
import type { VerifiedIncident } from './incidents'

const digest = (character: string): Sha256Digest =>
  `sha256:${character.repeat(64)}`

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
  it('continues to the signed v2 feed when the verified v1 active set is empty', async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockRejectedValue(new Error('synthetic feed unavailable'))

    await expect(
      loadVerifiedOperatorGuidanceFeed(
        {
          incidents: [],
          publishedAt: '2026-09-04T03:40:03Z',
          keyFingerprint: digest('0'),
          sourceIndexDigest: digest('1'),
        },
        {
          origin: 'https://presentation.example.invalid',
          fetchImpl,
          anchors: {
            keyId: 'synthetic-feed-key',
            fingerprint: digest('2'),
            reportKeyId: 'synthetic-report-key',
            reportFingerprint: digest('3'),
            enrichmentKeyId: 'synthetic-enrichment-key',
            enrichmentFingerprint: digest('4'),
            guidanceKeyId: 'synthetic-guidance-key',
            guidanceFingerprint: digest('5'),
          },
        },
      ),
    ).rejects.toThrow(/could not be loaded/i)
    expect(fetchImpl).toHaveBeenCalledWith(
      'https://presentation.example.invalid/incidents/feed-v2.json',
      expect.anything(),
    )
  })

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

  it('rejects cross-contract occurrence binding drift before verification', async () => {
    const guidance = await parseIncidentGuidance(await buildGuidance())
    const stateDigest = digest('3')
    const statePrefix = `incidents/inc-123456789abc/versions/${'3'.repeat(64)}`
    const stateReference = {
      name: `${statePrefix}/state.json`,
      version: 'state-version',
      contentDigest: digest('c'),
    } as const
    const stateAttestationReference = {
      name: `${statePrefix}/attestation.json`,
      version: 'attestation-version',
      contentDigest: digest('d'),
    } as const
    const reportReference = {
      name: `${statePrefix}/correlation-reports/report-${'5'.repeat(32)}/report.json`,
      version: 'report-version',
      contentDigest: digest('e'),
    } as const
    const reportAttestationReference = {
      name: `${statePrefix}/correlation-reports/report-${'5'.repeat(32)}/attestation.json`,
      version: 'report-attestation-version',
      contentDigest: digest('f'),
    } as const
    const manifest: ParsedEnrichmentManifest = {
      enrichmentId: `incident-enrichment-${'8'.repeat(32)}`,
      incidentId: 'inc-123456789abc',
      incidentTransitionId: `wc016-${'1'.repeat(64)}`,
      incidentRevision: 1,
      incidentStateResultDigest: stateDigest,
      incidentStateReference: stateReference,
      incidentStateAttestationReference: stateAttestationReference,
      incidentSubjectId: `incident-subject-${'2'.repeat(32)}`,
      incidentSubjectDigest: digest('2'),
      incidentBoundRequestId: `incident-bound-request-${'4'.repeat(32)}`,
      incidentBoundRequestDigest: digest('4'),
      correlationReportAsset: {
        incidentTransitionId: `wc016-${'1'.repeat(64)}`,
        incidentRevision: 1,
        incidentStateResultDigest: stateDigest,
        incidentSubjectId: `incident-subject-${'2'.repeat(32)}`,
        incidentSubjectDigest: digest('2'),
        incidentBoundRequestId: `incident-bound-request-${'4'.repeat(32)}`,
        incidentBoundRequestDigest: digest('4'),
        reportId: `report-${'5'.repeat(32)}`,
        reportDigest: digest('5'),
        reportContentDigest: digest('e'),
        authorityProofDigest: digest('0'),
        correlationRequestDigest: digest('6'),
        correlationTransitionDigest: digest('7'),
        publicationStatementId: `report-publication-${'a'.repeat(32)}`,
        publicationStatementDigest: digest('a'),
        reportReference,
        attestationReference: reportAttestationReference,
      },
      guidanceAsset: {
        guidanceId: guidance.guidanceId,
        guidanceDigest: guidance.guidanceDigest,
        guidanceReference: {
          name: `${statePrefix}/guidance/${guidance.guidanceId}/guidance.json`,
          version: 'guidance-version',
          contentDigest: digest('8'),
        },
        attestationReference: {
          name: `${statePrefix}/guidance/${guidance.guidanceId}/attestation.json`,
          version: 'guidance-attestation-version',
          contentDigest: digest('9'),
        },
      },
      manifestDigest: digest('b'),
    }
    const statement: ParsedPublishedReportStatement = {
      statementId: `report-publication-${'a'.repeat(32)}`,
      incidentId: manifest.incidentId,
      incidentTransitionId: manifest.incidentTransitionId,
      incidentRevision: manifest.incidentRevision,
      incidentStateResultDigest: manifest.incidentStateResultDigest,
      incidentStateReference: stateReference,
      incidentStateAttestationReference: stateAttestationReference,
      incidentSubjectId: manifest.incidentSubjectId,
      incidentSubjectDigest: manifest.incidentSubjectDigest,
      incidentBoundRequestId: manifest.incidentBoundRequestId,
      incidentBoundRequestDigest: manifest.incidentBoundRequestDigest,
      correlationRequestDigest:
        manifest.correlationReportAsset.correlationRequestDigest,
      correlationTransitionDigest:
        manifest.correlationReportAsset.correlationTransitionDigest,
      reportId: manifest.correlationReportAsset.reportId,
      reportDigest: manifest.correlationReportAsset.reportDigest,
      reportContentDigest: manifest.correlationReportAsset.reportContentDigest,
      authorityProofDigest:
        manifest.correlationReportAsset.authorityProofDigest,
      statementDigest: digest('a'),
    }
    const incident: VerifiedIncident = {
      publishedAt: '2026-09-04T03:40:04Z',
      keyFingerprint: digest('0'),
      state: {
        schemaVersion: 'athena.incidentState.v1',
        incidentId: manifest.incidentId,
        transitionId: manifest.incidentTransitionId,
        scenario: 'webServerFailure',
        lifecycle: 'resolved',
        workloadRole: 'web',
        detectedAt: '2026-09-04T03:40:00Z',
        updatedAt: '2026-09-04T03:40:03Z',
        targetBinding: digest('1'),
        availability: 'normal',
        blastRadius: 'none',
        operatorAttention: 'normal',
        findings: [{
          clauseId: 'synthetic-operational-health',
          verdict: 'resolved',
          summary: 'The synthetic incident recovered.',
          evidenceRefs: [],
        }],
        reasoning: ['The signed recovery state was observed.'],
        notificationStatus: 'notRequired',
        resultDigest: stateDigest,
        noAutoRemediation: true,
      },
      occurrence: {
        statePath: stateReference.name,
        stateVersion: stateReference.version,
        stateSha256: stateReference.contentDigest,
        attestationPath: stateAttestationReference.name,
        attestationVersion: stateAttestationReference.version,
        attestationSha256: stateAttestationReference.contentDigest,
        pointerPath: `${statePrefix}/pointer.json`,
        pointerVersion: 'pointer-version',
        pointerSha256: digest('a'),
        pointerAttestationPath: `${statePrefix}/pointer-attestation.json`,
        pointerAttestationVersion: 'pointer-attestation-version',
        pointerAttestationSha256: digest('b'),
      },
    }

    expect(() =>
      assertGuidanceMatchesVerifiedOccurrence(
        guidance,
        manifest,
        statement,
        incident,
      ),
    ).not.toThrow()

    const mutations = [
      (value: ParsedPublishedReportStatement) => {
        value.incidentRevision = 2
      },
      (value: ParsedPublishedReportStatement) => {
        value.incidentSubjectId = `incident-subject-${'9'.repeat(32)}`
      },
      (value: ParsedPublishedReportStatement) => {
        value.incidentSubjectDigest = digest('9')
      },
      (value: ParsedPublishedReportStatement) => {
        value.incidentBoundRequestId =
          `incident-bound-request-${'9'.repeat(32)}`
      },
      (value: ParsedPublishedReportStatement) => {
        value.incidentBoundRequestDigest = digest('9')
      },
      (value: ParsedPublishedReportStatement) => {
        value.correlationRequestDigest = digest('9')
      },
      (value: ParsedPublishedReportStatement) => {
        value.correlationTransitionDigest = digest('9')
      },
    ]
    for (const mutate of mutations) {
      const changed = structuredClone(statement)
      mutate(changed)
      expect(() =>
        assertGuidanceMatchesVerifiedOccurrence(
          guidance,
          manifest,
          changed,
          incident,
        ),
      ).toThrow(/independently verified occurrence/i)
    }

    for (const referenceName of [
      'incidentStateReference',
      'incidentStateAttestationReference',
    ] as const) {
      const changedManifest = structuredClone(manifest)
      changedManifest[referenceName].version = 'different-version'
      expect(() =>
        assertGuidanceMatchesVerifiedOccurrence(
          guidance,
          changedManifest,
          statement,
          incident,
        ),
      ).toThrow(/independently verified occurrence/i)
    }
  })
})
