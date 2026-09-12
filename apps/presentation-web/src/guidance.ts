import { canonicalizeJson, sha256Digest, type JsonValue } from './canonical'
import { type Sha256Digest } from './contracts'
import type { VerifiedIncident, VerifiedIncidentFeed } from './incidents'
import {
  fetchBoundedJsonAsset,
  resolveSameOriginAssetUrl,
  type BoundedJsonAsset,
  type LoadPresentationOptions,
} from './runtime'
import {
  VerificationError,
  computePublicKeyFingerprint,
} from './verification'

const MAX_FEED_BYTES = 128 * 1024
const MAX_POINTER_BYTES = 16 * 1024
const MAX_MANIFEST_BYTES = 64 * 1024
const MAX_GUIDANCE_BYTES = 64 * 1024
const MAX_ATTESTATION_BYTES = 16 * 1024
const MAX_FEED_AGE_MS = 15 * 60_000
const MAX_CLOCK_SKEW_MS = 60_000

const DIGEST = /^sha256:[a-f0-9]{64}$/
const INCIDENT_ID = /^inc-[a-f0-9]{12}$/
const GUIDANCE_ID = /^incident-guidance-[a-f0-9]{32}$/
const ENRICHMENT_ID = /^incident-enrichment-[a-f0-9]{32}$/
const OPTION_ID = /^guidance-option-[a-f0-9]{32}$/
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}$/
const ROOT_CAUSE_CATEGORIES = [
  'networkSecurityChange',
  'routingChange',
  'guestResourcePressure',
  'guestServiceFailure',
  'platformHealth',
  'backendHealth',
  'deploymentChange',
  'dependencyFailure',
  'unknown',
] as const
const CONTRADICTION_CODES = [
  'changeFailed',
  'changeAfterDegradation',
  'completeAllowedFlow',
  'completeHealthyConnectionMonitor',
  'recoveryBeforeCorrection',
  'competingCause',
] as const
const MISSING_EVIDENCE_CODES = [
  'effectiveRuleAttribution',
  'deniedFlow',
  'connectionMonitorResult',
  'endpointHealth',
  'affectedPath',
  'completeObservationWindow',
  'recoveryObservation',
  'changeDetails',
  'omittedCandidates',
] as const
const NO_RUNBOOK_REASONS = [
  'noMatchingControl',
  'legacyManualFailoverRunbookInsufficient',
  'controlNotEffective',
  'reviewExpired',
  'unsupportedRunbookReference',
  'unresolvedOwner',
  'unresolvedGovernanceScope',
  'confidenceTooLow',
] as const
const WITHHELD_REASONS = [
  'confidenceTooLow',
  'noRunbook',
  'competingCause',
  'missingEvidence',
  'authorityUnavailable',
] as const

export type GuidanceConfidence =
  | 'Unknown'
  | 'Low'
  | 'Medium'
  | 'High'
  | 'Confirmed'

export type GuidanceActionKind =
  | 'investigationCheck'
  | 'confirmationCheck'
  | 'manualResolutionOption'
  | 'rollbackConsideration'
  | 'recoveryValidation'
  | 'escalation'

export type GuidanceTemplateCode =
  | 'confirmEffectiveRule'
  | 'confirmBackendHealth'
  | 'inspectGuestHealth'
  | 'inspectNetworkPath'
  | 'inspectRecentChange'
  | 'reviewApprovedManualOption'
  | 'reviewRollbackAuthority'
  | 'validateRecoverySignals'
  | 'escalateHumanReview'

export interface VersionPinnedReference {
  name: string
  version: string
  contentDigest: Sha256Digest
}

export interface GuidanceHypothesis {
  rank: number
  hypothesisId: string
  category: string
  confidence: GuidanceConfidence
  supportingEvidenceIds: string[]
  supportingEvidenceCount: number
  contradictionCodes: string[]
  missingEvidenceCodes: string[]
}

export interface GuidanceStep {
  stepId: string
  actionKind: GuidanceActionKind
  templateCode: GuidanceTemplateCode
  parameters: Array<{
    parameterKind: 'resourceId' | 'pathId' | 'evidenceId' | 'optionId' | 'roleRef'
    value: string
  }>
  evidenceIds: string[]
  provenanceClauseRef?: string
  optionId?: string
  readOnly: boolean
  requiresAuthorization: boolean
}

export interface GuidanceRunbookLink {
  linkId: string
  optionId: string
  reference:
    | {
        referenceKind: 'https'
        uri: string
        version: string
        contentDigest: Sha256Digest
      }
    | {
        referenceKind: 'opaque'
        opaqueRef: string
        version: string
        contentDigest: Sha256Digest
      }
}

export interface IncidentGuidance {
  schemaVersion: 'athena.wc027IncidentGuidance.v1'
  guidanceId: string
  generatedAt: string
  sourceBinding: {
    incidentSubjectId: string
    incidentSubjectDigest: Sha256Digest
    incidentId: string
    incidentRevision: number
    incidentStateDigest: Sha256Digest
    incidentBoundRequestId: string
    incidentBoundRequestDigest: Sha256Digest
    correlationReportId: string
    correlationReportDigest: Sha256Digest
    correlationRequestDigest: Sha256Digest
    transitionDigest: Sha256Digest
    selectionKind: 'selectedRunbook' | 'noRunbook'
    selectedOptionId?: string
    noRunbookReason?: string
  }
  affectedRoleImpact: {
    roleRef: string
    profileId: string
    impactSeverity: 'none' | 'limited' | 'significant' | 'critical' | 'unknown'
    impactCode:
      | 'roleRecovered'
      | 'roleDegraded'
      | 'dataTierUnavailable'
      | 'ingressUnavailable'
      | 'unknownImpact'
  }
  timeline: Array<{
    entryId: string
    timelineKind:
      | 'healthTransition'
      | 'guestSignal'
      | 'networkEvidence'
      | 'platformHealth'
      | 'resourceChange'
      | 'recovery'
    observedStart: string
    observedEnd: string
    summaryCode: string
    evidenceIds: [string]
  }>
  hypotheses: GuidanceHypothesis[]
  confirmationChecks: GuidanceStep[]
  investigationSteps: GuidanceStep[]
  safeManualOptions: GuidanceStep[]
  rollbackConsiderations: GuidanceStep[]
  recoveryValidation: GuidanceStep[]
  escalation: GuidanceStep[]
  runbookLinks: GuidanceRunbookLink[]
  missingEvidence: string[]
  legality: {
    confidence: GuidanceConfidence
    selectionKind: 'selectedRunbook' | 'noRunbook'
    manualActionsAuthorized: boolean
    rollbackAuthorized: boolean
    runbookReferenceAuthorized: boolean
    executionAuthorizationRequired: true
    withheldReasons: string[]
  }
  noAutoRemediation: true
  guidanceDigest: Sha256Digest
}

export interface VerifiedOperatorGuidance {
  status: 'verified'
  incidentId: string
  lifecycle: 'active' | 'resolved'
  stateResultDigest: Sha256Digest
  feedPublishedAt: string
  enrichmentId: string
  guidance: IncidentGuidance
}

export interface VerifiedOperatorGuidanceFeed {
  publishedAt: string
  guidanceByIncidentId: Readonly<Record<string, VerifiedOperatorGuidance>>
}

export interface GuidanceTrustAnchor {
  keyId: string
  fingerprint: Sha256Digest
  publicKey: unknown
}

export interface GuidanceTrustAnchors {
  feed: GuidanceTrustAnchor
  enrichment: GuidanceTrustAnchor
  guidance: GuidanceTrustAnchor
}

export interface IncidentGuidanceBundle {
  feedIndex: BoundedJsonAsset
  feedIndexAttestation: BoundedJsonAsset
  feedPointer: BoundedJsonAsset
  feedPointerAttestation: BoundedJsonAsset
  enrichmentManifest: BoundedJsonAsset
  enrichmentAttestation: BoundedJsonAsset
  guidance: BoundedJsonAsset
  guidanceAttestation: BoundedJsonAsset
}

export interface GuidanceLoadOptions extends LoadPresentationOptions {
  feedIndexUrl?: URL
  anchors?: Omit<GuidanceTrustAnchors['feed'], 'publicKey'> & {
    enrichmentKeyId: string
    enrichmentFingerprint: Sha256Digest
    guidanceKeyId: string
    guidanceFingerprint: Sha256Digest
  }
}

interface ParsedAttestation {
  signatureAlgorithm: 'RS256'
  keyVaultKeyId: string
  detachedSignature: string
  signedPreimageDigest?: Sha256Digest
}

export const loadVerifiedOperatorGuidanceFeed = async (
  incidentFeed: VerifiedIncidentFeed,
  options: GuidanceLoadOptions = {},
): Promise<VerifiedOperatorGuidanceFeed> => {
  if (incidentFeed.incidents.length === 0) {
    return { publishedAt: incidentFeed.publishedAt, guidanceByIncidentId: {} }
  }
  if (!incidentFeed.sourceIndexDigest) {
    throw new VerificationError('Verified v1 index provenance is unavailable.')
  }
  const configured = options.anchors ?? trustAnchorsFromEnvironment()
  const fetchImpl = options.fetchImpl ?? globalThis.fetch
  const cryptoProvider = options.cryptoProvider ?? globalThis.crypto
  const origin = options.origin ?? globalThis.location.origin
  const timeoutMs = options.timeoutMs ?? 5_000
  const applicationRoot = new URL('/', `${origin}/`)
  const indexUrl =
    options.feedIndexUrl ??
    resolveSameOriginAssetUrl('./incidents/feed-v2.json', applicationRoot, origin)
  if (
    indexUrl.origin !== origin ||
    indexUrl.search !== '' ||
    indexUrl.hash !== ''
  ) {
    throw new VerificationError('Incident feed v2 must use the application origin.')
  }
  const feedIndex = await fetchBoundedJsonAsset(
    indexUrl,
    MAX_FEED_BYTES,
    fetchImpl,
    timeoutMs,
  )
  const index = parseFeedIndex(await requireCanonicalAsset(
    feedIndex,
    MAX_FEED_BYTES,
    'incident feed v2 index',
  ))
  const feedIndexAttestation = await fetchBoundedJsonAsset(
    resolveSameOriginAssetUrl(index.indexAttestationPath, applicationRoot, origin),
    MAX_ATTESTATION_BYTES,
    fetchImpl,
    timeoutMs,
  )
  const keyAssets = await Promise.all(
    [
      './trust/wc027-feed-public-key.jwk.json',
      './trust/wc027-enrichment-public-key.jwk.json',
      './trust/wc027-guidance-public-key.jwk.json',
    ].map((path) =>
      fetchBoundedJsonAsset(
        resolveSameOriginAssetUrl(path, applicationRoot, origin),
        16 * 1024,
        fetchImpl,
        timeoutMs,
      ),
    ),
  )
  const feedKey = keyAssets[0]!
  const enrichmentKey = keyAssets[1]!
  const guidanceKey = keyAssets[2]!
  const anchors: GuidanceTrustAnchors = {
    feed: {
      keyId: configured.keyId,
      fingerprint: configured.fingerprint,
      publicKey: feedKey.value,
    },
    enrichment: {
      keyId: configured.enrichmentKeyId,
      fingerprint: configured.enrichmentFingerprint,
      publicKey: enrichmentKey.value,
    },
    guidance: {
      keyId: configured.guidanceKeyId,
      fingerprint: configured.guidanceFingerprint,
      publicKey: guidanceKey.value,
    },
  }
  const verifiedEntries = await Promise.all(
    incidentFeed.incidents.map(async (incident) => {
      const entry = index.active.find(
        (candidate) => candidate.incidentId === incident.state.incidentId,
      )
      if (!entry) {
        throw new VerificationError(
          'Verified v2 enrichment is unavailable for an active v1 incident.',
        )
      }
      const [feedPointer, feedPointerAttestation] = await Promise.all([
        fetchVersionedReference(
          entry.feedPointerReference,
          MAX_POINTER_BYTES,
          applicationRoot,
          origin,
          fetchImpl,
          timeoutMs,
        ),
        fetchVersionedReference(
          entry.feedPointerAttestationReference,
          MAX_ATTESTATION_BYTES,
          applicationRoot,
          origin,
          fetchImpl,
          timeoutMs,
        ),
      ])
      const pointer = await parseFeedPointer(
        await requireCanonicalAsset(
          feedPointer,
          MAX_POINTER_BYTES,
          'incident feed v2 pointer',
        ),
        cryptoProvider,
      )
      const [enrichmentManifest, enrichmentAttestation] = await Promise.all([
        fetchVersionedReference(
          pointer.enrichmentAsset.manifestReference,
          MAX_MANIFEST_BYTES,
          applicationRoot,
          origin,
          fetchImpl,
          timeoutMs,
        ),
        fetchVersionedReference(
          pointer.enrichmentAsset.attestationReference,
          MAX_ATTESTATION_BYTES,
          applicationRoot,
          origin,
          fetchImpl,
          timeoutMs,
        ),
      ])
      const manifest = await parseEnrichmentManifest(
        await requireCanonicalAsset(
          enrichmentManifest,
          MAX_MANIFEST_BYTES,
          'incident enrichment manifest',
        ),
        cryptoProvider,
      )
      const [guidance, guidanceAttestation] = await Promise.all([
        fetchVersionedReference(
          manifest.guidanceAsset.guidanceReference,
          MAX_GUIDANCE_BYTES,
          applicationRoot,
          origin,
          fetchImpl,
          timeoutMs,
        ),
        fetchVersionedReference(
          manifest.guidanceAsset.attestationReference,
          MAX_ATTESTATION_BYTES,
          applicationRoot,
          origin,
          fetchImpl,
          timeoutMs,
        ),
      ])
      return verifyIncidentGuidanceBundle(
        {
          feedIndex,
          feedIndexAttestation,
          feedPointer,
          feedPointerAttestation,
          enrichmentManifest,
          enrichmentAttestation,
          guidance,
          guidanceAttestation,
        },
        incidentFeed,
        incident,
        anchors,
        cryptoProvider,
      )
    }),
  )
  return {
    publishedAt: index.publishedAt,
    guidanceByIncidentId: Object.fromEntries(
      verifiedEntries.map((guidance) => [guidance.incidentId, guidance]),
    ),
  }
}

export const verifyIncidentGuidanceBundle = async (
  bundle: IncidentGuidanceBundle,
  incidentFeed: VerifiedIncidentFeed,
  incident: VerifiedIncident,
  anchors: GuidanceTrustAnchors,
  cryptoProvider: Crypto = globalThis.crypto,
  nowMs = Date.now(),
): Promise<VerifiedOperatorGuidance> => {
  if (!incidentFeed.sourceIndexDigest || !incident.occurrence) {
    throw new VerificationError(
      'Verified v1 occurrence metadata is required before guidance can be trusted.',
    )
  }
  const indexRecord = await requireCanonicalAsset(
    bundle.feedIndex,
    MAX_FEED_BYTES,
    'incident feed v2 index',
  )
  const index = parseFeedIndex(indexRecord)
  const indexAttestation = parseAttestation(
    bundle.feedIndexAttestation,
    MAX_ATTESTATION_BYTES,
    'athena.wc027IncidentFeedIndexAttestation.v2',
    ['schemaVersion', 'indexDigest', 'signatureAlgorithm', 'keyVaultKeyId', 'detachedSignature'],
  )
  if (
    index.sourceActiveIndexDigest !== incidentFeed.sourceIndexDigest ||
    Date.parse(index.publishedAt) < Date.parse(incidentFeed.publishedAt) ||
    nowMs - Date.parse(index.publishedAt) > MAX_FEED_AGE_MS ||
    Date.parse(index.publishedAt) - nowMs > MAX_CLOCK_SKEW_MS ||
    index.keyId !== anchors.feed.keyId ||
    index.keyFingerprint !== anchors.feed.fingerprint ||
    indexAttestation.digest !== await sha256Digest(bundle.feedIndex.bytes, cryptoProvider)
  ) {
    throw new VerificationError('Incident feed v2 is not bound to the verified v1 index.')
  }
  await verifySignature(
    bundle.feedIndex.bytes,
    indexAttestation.attestation,
    anchors.feed,
    cryptoProvider,
  )
  const entry = index.active.find((candidate) => candidate.incidentId === incident.state.incidentId)
  if (
    !entry ||
    entry.lifecycle !== 'active' ||
    entry.stateResultDigest !== incident.state.resultDigest ||
    entry.updatedAt !== incident.state.updatedAt
  ) {
    throw new VerificationError('Incident feed v2 does not bind the verified v1 occurrence.')
  }

  const pointerRecord = await requireCanonicalAsset(
    bundle.feedPointer,
    MAX_POINTER_BYTES,
    'incident feed v2 pointer',
  )
  const pointer = await parseFeedPointer(pointerRecord, cryptoProvider)
  const pointerAttestation = parseAttestation(
    bundle.feedPointerAttestation,
    MAX_ATTESTATION_BYTES,
    'athena.wc027IncidentEnrichmentFeedPointerAttestation.v2',
    [
      'schemaVersion',
      'pointerId',
      'pointerDigest',
      'signatureAlgorithm',
      'keyVaultKeyId',
      'signedPreimageDigest',
      'detachedSignature',
    ],
  )
  const pointerBytesDigest = await sha256Digest(bundle.feedPointer.bytes, cryptoProvider)
  if (
    entry.feedPointerReference.contentDigest !== pointerBytesDigest ||
    entry.feedPointerAttestationReference.contentDigest !==
      await sha256Digest(bundle.feedPointerAttestation.bytes, cryptoProvider) ||
    pointerAttestation.id !== pointer.pointerId ||
    pointerAttestation.digest !== pointer.pointerDigest ||
    pointerAttestation.attestation.signedPreimageDigest !== pointerBytesDigest ||
    pointer.incidentId !== entry.incidentId ||
    pointer.lifecycle !== entry.lifecycle ||
    pointer.stateResultDigest !== entry.stateResultDigest ||
    pointer.stateUpdatedAt !== entry.updatedAt ||
    entry.feedPointerReference.name !==
      pointer.enrichmentAsset.manifestReference.name.replace(
        /[/]manifest[.]json$/,
        '/feed-pointer.json',
      ) ||
    entry.feedPointerAttestationReference.name !==
      pointer.enrichmentAsset.manifestReference.name.replace(
        /[/]manifest[.]json$/,
        '/feed-pointer-attestation.json',
      )
  ) {
    throw new VerificationError('Incident feed v2 pointer does not match its signed index entry.')
  }
  await verifySignature(
    bundle.feedPointer.bytes,
    pointerAttestation.attestation,
    anchors.feed,
    cryptoProvider,
  )
  requireOccurrenceBinding(pointer, incident)

  const manifestRecord = await requireCanonicalAsset(
    bundle.enrichmentManifest,
    MAX_MANIFEST_BYTES,
    'incident enrichment manifest',
  )
  const manifest = await parseEnrichmentManifest(manifestRecord, cryptoProvider)
  const enrichmentAttestation = parseAttestation(
    bundle.enrichmentAttestation,
    MAX_ATTESTATION_BYTES,
    'athena.wc027IncidentEnrichmentAttestation.v1',
    [
      'schemaVersion',
      'enrichmentId',
      'manifestDigest',
      'signatureAlgorithm',
      'keyVaultKeyId',
      'signedPreimageDigest',
      'detachedSignature',
    ],
  )
  const manifestBytesDigest = await sha256Digest(
    bundle.enrichmentManifest.bytes,
    cryptoProvider,
  )
  if (
    pointer.enrichmentAsset.manifestReference.contentDigest !== manifestBytesDigest ||
    pointer.enrichmentAsset.attestationReference.contentDigest !==
      await sha256Digest(bundle.enrichmentAttestation.bytes, cryptoProvider) ||
    enrichmentAttestation.id !== manifest.enrichmentId ||
    enrichmentAttestation.digest !== manifest.manifestDigest ||
    enrichmentAttestation.attestation.signedPreimageDigest !== manifestBytesDigest ||
    manifest.enrichmentId !== pointer.enrichmentAsset.enrichmentId ||
    manifest.manifestDigest !== pointer.enrichmentAsset.manifestDigest ||
    manifest.incidentId !== pointer.incidentId ||
    manifest.incidentStateResultDigest !== pointer.stateResultDigest
  ) {
    throw new VerificationError('Incident enrichment does not match the verified feed pointer.')
  }
  await verifySignature(
    bundle.enrichmentManifest.bytes,
    enrichmentAttestation.attestation,
    anchors.enrichment,
    cryptoProvider,
  )

  const guidanceRecord = await requireCanonicalAsset(
    bundle.guidance,
    MAX_GUIDANCE_BYTES,
    'incident guidance',
  )
  const guidance = await parseIncidentGuidance(guidanceRecord, cryptoProvider)
  const guidanceAttestation = parseAttestation(
    bundle.guidanceAttestation,
    MAX_ATTESTATION_BYTES,
    'athena.wc027IncidentGuidanceAttestation.v1',
    [
      'schemaVersion',
      'guidanceId',
      'guidanceDigest',
      'signatureAlgorithm',
      'keyVaultKeyId',
      'signedPreimageDigest',
      'detachedSignature',
    ],
  )
  const guidanceBytesDigest = await sha256Digest(bundle.guidance.bytes, cryptoProvider)
  if (
    manifest.guidanceAsset.guidanceReference.contentDigest !== guidanceBytesDigest ||
    manifest.guidanceAsset.attestationReference.contentDigest !==
      await sha256Digest(bundle.guidanceAttestation.bytes, cryptoProvider) ||
    guidanceAttestation.id !== guidance.guidanceId ||
    guidanceAttestation.digest !== guidance.guidanceDigest ||
    guidanceAttestation.attestation.signedPreimageDigest !== guidanceBytesDigest ||
    manifest.guidanceAsset.guidanceId !== guidance.guidanceId ||
    manifest.guidanceAsset.guidanceDigest !== guidance.guidanceDigest ||
    guidance.sourceBinding.incidentId !== manifest.incidentId ||
    guidance.sourceBinding.incidentRevision !== manifest.incidentRevision ||
    guidance.sourceBinding.incidentStateDigest !== manifest.incidentStateResultDigest ||
    guidance.sourceBinding.incidentSubjectId !== manifest.incidentSubjectId ||
    guidance.sourceBinding.incidentSubjectDigest !== manifest.incidentSubjectDigest ||
    guidance.sourceBinding.incidentBoundRequestId !== manifest.incidentBoundRequestId ||
    guidance.sourceBinding.incidentBoundRequestDigest !==
      manifest.incidentBoundRequestDigest ||
    guidance.sourceBinding.correlationReportId !== manifest.correlationReportAsset.reportId ||
    guidance.sourceBinding.correlationReportDigest !==
      manifest.correlationReportAsset.reportDigest ||
    guidance.sourceBinding.correlationRequestDigest !==
      manifest.correlationReportAsset.correlationRequestDigest ||
    guidance.sourceBinding.transitionDigest !==
      manifest.correlationReportAsset.correlationTransitionDigest ||
    manifest.incidentStateReference.name !== pointer.sourceStateReference.name ||
    manifest.incidentStateReference.version !== pointer.sourceStateReference.version ||
    manifest.incidentStateReference.contentDigest !==
      pointer.sourceStateReference.contentDigest ||
    manifest.incidentStateAttestationReference.name !==
      pointer.sourceStateAttestationReference.name ||
    manifest.incidentStateAttestationReference.version !==
      pointer.sourceStateAttestationReference.version ||
    manifest.incidentStateAttestationReference.contentDigest !==
      pointer.sourceStateAttestationReference.contentDigest
  ) {
    throw new VerificationError('Incident guidance does not match its verified enrichment.')
  }
  await verifySignature(
    bundle.guidance.bytes,
    guidanceAttestation.attestation,
    anchors.guidance,
    cryptoProvider,
  )
  return {
    status: 'verified',
    incidentId: pointer.incidentId,
    lifecycle: pointer.lifecycle,
    stateResultDigest: pointer.stateResultDigest,
    feedPublishedAt: index.publishedAt,
    enrichmentId: manifest.enrichmentId,
    guidance,
  }
}

const requireOccurrenceBinding = (
  pointer: ParsedFeedPointer,
  incident: VerifiedIncident,
): void => {
  const occurrence = incident.occurrence
  if (
    !occurrence ||
    pointer.sourceStateReference.name !== occurrence.statePath ||
    pointer.sourceStateReference.contentDigest !== occurrence.stateSha256 ||
    pointer.sourceStateAttestationReference.name !== occurrence.attestationPath ||
    pointer.sourceStateAttestationReference.contentDigest !== occurrence.attestationSha256 ||
    pointer.sourcePointerReference.name !== occurrence.pointerPath ||
    pointer.sourcePointerReference.contentDigest !== occurrence.pointerSha256 ||
    pointer.sourcePointerAttestationReference.name !== occurrence.pointerAttestationPath ||
    pointer.sourcePointerAttestationReference.contentDigest !==
      occurrence.pointerAttestationSha256
  ) {
    throw new VerificationError('Incident guidance is not bound to the verified v1 occurrence.')
  }
}

interface ParsedFeedEntry {
  incidentId: string
  lifecycle: 'active' | 'resolved'
  stateResultDigest: Sha256Digest
  updatedAt: string
  feedPointerReference: VersionPinnedReference
  feedPointerAttestationReference: VersionPinnedReference
}

interface ParsedFeedPointer {
  pointerId: string
  incidentId: string
  lifecycle: 'active' | 'resolved'
  stateResultDigest: Sha256Digest
  stateUpdatedAt: string
  occurrenceDigest: Sha256Digest
  sourceStateReference: VersionPinnedReference
  sourceStateAttestationReference: VersionPinnedReference
  sourcePointerReference: VersionPinnedReference
  sourcePointerAttestationReference: VersionPinnedReference
  enrichmentAsset: ParsedEnrichmentReference
  publishedAt: string
  pointerDigest: Sha256Digest
}

interface ParsedEnrichmentReference {
  referenceId: string
  incidentId: string
  incidentStateResultDigest: Sha256Digest
  enrichmentId: string
  manifestDigest: Sha256Digest
  manifestReference: VersionPinnedReference
  attestationReference: VersionPinnedReference
}

interface ParsedEnrichmentManifest {
  enrichmentId: string
  incidentId: string
  incidentRevision: number
  incidentStateResultDigest: Sha256Digest
  incidentStateReference: VersionPinnedReference
  incidentStateAttestationReference: VersionPinnedReference
  incidentSubjectId: string
  incidentSubjectDigest: Sha256Digest
  incidentBoundRequestId: string
  incidentBoundRequestDigest: Sha256Digest
  correlationReportAsset: {
    reportId: string
    reportDigest: Sha256Digest
    correlationRequestDigest: Sha256Digest
    correlationTransitionDigest: Sha256Digest
  }
  guidanceAsset: {
    guidanceId: string
    guidanceDigest: Sha256Digest
    guidanceReference: VersionPinnedReference
    attestationReference: VersionPinnedReference
  }
  manifestDigest: Sha256Digest
}

const parseFeedIndex = (
  record: Record<string, JsonValue>,
): {
  active: ParsedFeedEntry[]
  sourceActiveIndexDigest: Sha256Digest
  indexAttestationPath: string
  keyId: string
  keyFingerprint: Sha256Digest
  publishedAt: string
} => {
  requireExactKeys(record, [
    'schemaVersion',
    'active',
    'recentlyResolved',
    'resolvedRetentionStart',
    'resolvedHistoryTruncated',
    'resolvedHistoryTotalCount',
    'sourceActiveIndexDigest',
    'indexAttestationPath',
    'keyId',
    'keyFingerprint',
    'publishedAt',
  ], ['omittedResolvedCount'])
  if (
    record.schemaVersion !== 'athena.wc027IncidentFeedIndex.v2' ||
    !Array.isArray(record.active) ||
    record.active.length > 64 ||
    !Array.isArray(record.recentlyResolved) ||
    record.recentlyResolved.length > 64 ||
    !isDigest(record.sourceActiveIndexDigest) ||
    typeof record.keyId !== 'string' ||
    !isDigest(record.keyFingerprint) ||
    typeof record.indexAttestationPath !== 'string' ||
    !/^\.[/]incidents[/]feed-v2-index-attestations[/][a-f0-9]{64}[.]json$/.test(
      record.indexAttestationPath,
    ) ||
    !isTimestamp(record.publishedAt)
  ) {
    throw new VerificationError('Incident feed v2 index schema is invalid.')
  }
  const active = record.active.map(parseFeedEntry)
  const resolved = record.recentlyResolved.map(parseFeedEntry)
  const activeIds = active.map((entry) => entry.incidentId)
  if (
    active.some((entry) => entry.lifecycle !== 'active') ||
    activeIds.join('\0') !== [...activeIds].sort().join('\0') ||
    new Set(activeIds).size !== activeIds.length ||
    resolved.some((entry) => entry.lifecycle !== 'resolved') ||
    new Set(resolved.map((entry) => entry.incidentId)).size !== resolved.length ||
    resolved.some((entry) => activeIds.includes(entry.incidentId))
  ) {
    throw new VerificationError('Incident feed v2 active entries are not deterministic.')
  }
  return {
    active,
    sourceActiveIndexDigest: record.sourceActiveIndexDigest,
    indexAttestationPath: record.indexAttestationPath,
    keyId: record.keyId,
    keyFingerprint: record.keyFingerprint,
    publishedAt: record.publishedAt,
  }
}

const parseFeedEntry = (value: unknown): ParsedFeedEntry => {
  const record = requireRecord(value)
  requireExactKeys(record, [
    'incidentId',
    'lifecycle',
    'stateResultDigest',
    'updatedAt',
    'feedPointerReference',
    'feedPointerAttestationReference',
  ])
  if (
    typeof record.incidentId !== 'string' ||
    !INCIDENT_ID.test(record.incidentId) ||
    (record.lifecycle !== 'active' && record.lifecycle !== 'resolved') ||
    !isDigest(record.stateResultDigest) ||
    !isTimestamp(record.updatedAt)
  ) {
    throw new VerificationError('Incident feed v2 entry schema is invalid.')
  }
  return {
    incidentId: record.incidentId,
    lifecycle: record.lifecycle,
    stateResultDigest: record.stateResultDigest,
    updatedAt: record.updatedAt,
    feedPointerReference: parseReference(record.feedPointerReference),
    feedPointerAttestationReference: parseReference(
      record.feedPointerAttestationReference,
    ),
  }
}

const parseFeedPointer = async (
  record: Record<string, JsonValue>,
  cryptoProvider: Crypto,
): Promise<ParsedFeedPointer> => {
  requireExactKeys(record, [
    'schemaVersion',
    'pointerId',
    'incidentId',
    'lifecycle',
    'stateResultDigest',
    'stateUpdatedAt',
    'occurrenceDigest',
    'sourceStateReference',
    'sourceStateAttestationReference',
    'sourcePointerReference',
    'sourcePointerAttestationReference',
    'enrichmentAsset',
    'publishedAt',
    'noAutoRemediation',
    'pointerDigest',
  ])
  if (
    record.schemaVersion !== 'athena.wc027IncidentEnrichmentFeedPointer.v2' ||
    typeof record.pointerId !== 'string' ||
    !/^incident-feed-v2-pointer-[a-f0-9]{32}$/.test(record.pointerId) ||
    typeof record.incidentId !== 'string' ||
    !INCIDENT_ID.test(record.incidentId) ||
    (record.lifecycle !== 'active' && record.lifecycle !== 'resolved') ||
    !isDigest(record.stateResultDigest) ||
    !isTimestamp(record.stateUpdatedAt) ||
    !isDigest(record.occurrenceDigest) ||
    !isTimestamp(record.publishedAt) ||
    record.noAutoRemediation !== true ||
    !isDigest(record.pointerDigest)
  ) {
    throw new VerificationError('Incident feed v2 pointer schema is invalid.')
  }
  await requireDigestBoundId(
    record,
    ['pointerId', 'pointerDigest'],
    record.pointerDigest,
    'incident-feed-v2-pointer-',
    record.pointerId,
    cryptoProvider,
  )
  const sourceStateReference = parseReference(record.sourceStateReference)
  const sourceStateAttestationReference = parseReference(
    record.sourceStateAttestationReference,
  )
  const sourcePointerReference = parseReference(record.sourcePointerReference)
  const sourcePointerAttestationReference = parseReference(
    record.sourcePointerAttestationReference,
  )
  const enrichmentAsset = await parseEnrichmentReference(
    requireRecord(record.enrichmentAsset),
    cryptoProvider,
  )
  const prefix = `incidents/${record.incidentId}/versions/${record.stateResultDigest.slice(
    'sha256:'.length,
  )}`
  if (
    sourceStateReference.name !== `${prefix}/state.json` ||
    sourceStateAttestationReference.name !== `${prefix}/attestation.json` ||
    sourcePointerReference.name !== `${prefix}/pointer.json` ||
    sourcePointerAttestationReference.name !== `${prefix}/pointer-attestation.json` ||
    enrichmentAsset.incidentId !== record.incidentId ||
    enrichmentAsset.incidentStateResultDigest !== record.stateResultDigest ||
    Date.parse(record.publishedAt) < Date.parse(record.stateUpdatedAt)
  ) {
    throw new VerificationError('Incident feed v2 pointer occurrence binding is invalid.')
  }
  return {
    pointerId: record.pointerId,
    incidentId: record.incidentId,
    lifecycle: record.lifecycle,
    stateResultDigest: record.stateResultDigest,
    stateUpdatedAt: record.stateUpdatedAt,
    occurrenceDigest: record.occurrenceDigest,
    sourceStateReference,
    sourceStateAttestationReference,
    sourcePointerReference,
    sourcePointerAttestationReference,
    enrichmentAsset,
    publishedAt: record.publishedAt,
    pointerDigest: record.pointerDigest,
  }
}

const parseEnrichmentReference = async (
  record: Record<string, JsonValue>,
  cryptoProvider: Crypto,
): Promise<ParsedEnrichmentReference> => {
  requireExactKeys(record, [
    'schemaVersion',
    'referenceId',
    'incidentId',
    'incidentStateResultDigest',
    'enrichmentId',
    'manifestDigest',
    'manifestReference',
    'attestationReference',
    'referenceDigest',
  ])
  if (
    record.schemaVersion !== 'athena.wc027IncidentEnrichmentAssetReference.v1' ||
    typeof record.referenceId !== 'string' ||
    !/^enrichment-asset-[a-f0-9]{32}$/.test(record.referenceId) ||
    typeof record.incidentId !== 'string' ||
    !INCIDENT_ID.test(record.incidentId) ||
    !isDigest(record.incidentStateResultDigest) ||
    typeof record.enrichmentId !== 'string' ||
    !ENRICHMENT_ID.test(record.enrichmentId) ||
    !isDigest(record.manifestDigest) ||
    !isDigest(record.referenceDigest)
  ) {
    throw new VerificationError('Incident enrichment reference schema is invalid.')
  }
  await requireDigestBoundId(
    record,
    ['referenceId', 'referenceDigest'],
    record.referenceDigest,
    'enrichment-asset-',
    record.referenceId,
    cryptoProvider,
  )
  const manifestReference = parseReference(record.manifestReference)
  const attestationReference = parseReference(record.attestationReference)
  const prefix = `incidents/${record.incidentId}/versions/${record.incidentStateResultDigest.slice(
    'sha256:'.length,
  )}/enrichments/${record.enrichmentId}`
  if (
    manifestReference.name !== `${prefix}/manifest.json` ||
    attestationReference.name !== `${prefix}/attestation.json`
  ) {
    throw new VerificationError('Incident enrichment reference paths are invalid.')
  }
  return {
    referenceId: record.referenceId,
    incidentId: record.incidentId,
    incidentStateResultDigest: record.incidentStateResultDigest,
    enrichmentId: record.enrichmentId,
    manifestDigest: record.manifestDigest,
    manifestReference,
    attestationReference,
  }
}

const parseEnrichmentManifest = async (
  record: Record<string, JsonValue>,
  cryptoProvider: Crypto,
): Promise<ParsedEnrichmentManifest> => {
  requireExactKeys(record, [
    'schemaVersion',
    'enrichmentId',
    'incidentId',
    'incidentTransitionId',
    'incidentRevision',
    'incidentStateResultDigest',
    'incidentStateReference',
    'incidentStateAttestationReference',
    'incidentSubjectId',
    'incidentSubjectDigest',
    'incidentBoundRequestId',
    'incidentBoundRequestDigest',
    'correlationReportAsset',
    'guidanceAsset',
    'noAutoRemediation',
    'manifestDigest',
  ])
  if (
    record.schemaVersion !== 'athena.wc027IncidentEnrichmentManifest.v1' ||
    typeof record.enrichmentId !== 'string' ||
    !ENRICHMENT_ID.test(record.enrichmentId) ||
    typeof record.incidentId !== 'string' ||
    !INCIDENT_ID.test(record.incidentId) ||
    typeof record.incidentTransitionId !== 'string' ||
    !/^wc016-[a-f0-9]{64}$/.test(record.incidentTransitionId) ||
    typeof record.incidentRevision !== 'number' ||
    !Number.isInteger(record.incidentRevision) ||
    record.incidentRevision < 1 ||
    !isDigest(record.incidentStateResultDigest) ||
    typeof record.incidentSubjectId !== 'string' ||
    !/^incident-subject-[a-f0-9]{32}$/.test(record.incidentSubjectId) ||
    !isDigest(record.incidentSubjectDigest) ||
    typeof record.incidentBoundRequestId !== 'string' ||
    !/^incident-bound-request-[a-f0-9]{32}$/.test(record.incidentBoundRequestId) ||
    !isDigest(record.incidentBoundRequestDigest) ||
    record.noAutoRemediation !== true ||
    !isDigest(record.manifestDigest)
  ) {
    throw new VerificationError('Incident enrichment manifest schema is invalid.')
  }
  await requireDigestBoundId(
    record,
    ['enrichmentId', 'manifestDigest'],
    record.manifestDigest,
    'incident-enrichment-',
    record.enrichmentId,
    cryptoProvider,
  )
  const report = await parseCorrelationReportAsset(record.correlationReportAsset)
  const guidance = await parseGuidanceAsset(record.guidanceAsset)
  const stateReference = parseReference(record.incidentStateReference)
  const stateAttestationReference = parseReference(
    record.incidentStateAttestationReference,
  )
  const statePrefix = `incidents/${record.incidentId}/versions/${record.incidentStateResultDigest.slice(
    'sha256:'.length,
  )}`
  if (
    stateReference.name !== `${statePrefix}/state.json` ||
    stateAttestationReference.name !== `${statePrefix}/attestation.json` ||
    report.incidentId !== record.incidentId ||
    report.incidentTransitionId !== record.incidentTransitionId ||
    report.incidentRevision !== record.incidentRevision ||
    report.incidentStateResultDigest !== record.incidentStateResultDigest ||
    report.incidentSubjectId !== record.incidentSubjectId ||
    report.incidentSubjectDigest !== record.incidentSubjectDigest ||
    report.incidentBoundRequestId !== record.incidentBoundRequestId ||
    report.incidentBoundRequestDigest !== record.incidentBoundRequestDigest ||
    guidance.incidentId !== record.incidentId ||
    guidance.incidentStateDigest !== record.incidentStateResultDigest
  ) {
    throw new VerificationError('Incident enrichment asset bindings are invalid.')
  }
  return {
    enrichmentId: record.enrichmentId,
    incidentId: record.incidentId,
    incidentRevision: record.incidentRevision as number,
    incidentStateResultDigest: record.incidentStateResultDigest,
    incidentStateReference: stateReference,
    incidentStateAttestationReference: stateAttestationReference,
    incidentSubjectId: record.incidentSubjectId as string,
    incidentSubjectDigest: record.incidentSubjectDigest as Sha256Digest,
    incidentBoundRequestId: record.incidentBoundRequestId as string,
    incidentBoundRequestDigest: record.incidentBoundRequestDigest as Sha256Digest,
    correlationReportAsset: {
      reportId: report.reportId,
      reportDigest: report.reportDigest,
      correlationRequestDigest: report.correlationRequestDigest,
      correlationTransitionDigest: report.correlationTransitionDigest,
    },
    guidanceAsset: {
      guidanceId: guidance.guidanceId,
      guidanceDigest: guidance.guidanceDigest,
      guidanceReference: parseReference(guidance.guidanceReference),
      attestationReference: parseReference(guidance.attestationReference),
    },
    manifestDigest: record.manifestDigest,
  }

  async function parseCorrelationReportAsset(
    value: unknown,
  ): Promise<{
    incidentId: string
    incidentTransitionId: string
    incidentRevision: number
    incidentStateResultDigest: Sha256Digest
    incidentSubjectId: string
    incidentSubjectDigest: Sha256Digest
    incidentBoundRequestId: string
    incidentBoundRequestDigest: Sha256Digest
    reportId: string
    reportDigest: Sha256Digest
    correlationRequestDigest: Sha256Digest
    correlationTransitionDigest: Sha256Digest
  }> {
    const record = requireRecord(value)
    requireExactKeys(record, [
      'schemaVersion',
      'referenceId',
      'incidentId',
      'incidentTransitionId',
      'incidentRevision',
      'incidentStateResultDigest',
      'incidentSubjectId',
      'incidentSubjectDigest',
      'incidentBoundRequestId',
      'incidentBoundRequestDigest',
      'correlationRequestDigest',
      'correlationTransitionDigest',
      'reportId',
      'reportDigest',
      'reportContentDigest',
      'authorityProofDigest',
      'publicationStatementId',
      'publicationStatementDigest',
      'reportReference',
      'attestationReference',
      'referenceDigest',
    ])
    if (
      record.schemaVersion !==
        'athena.wc027PublishedCorrelationReportAssetReference.v1' ||
      typeof record.incidentId !== 'string' ||
      !INCIDENT_ID.test(record.incidentId) ||
      typeof record.incidentTransitionId !== 'string' ||
      !/^wc016-[a-f0-9]{64}$/.test(record.incidentTransitionId) ||
      typeof record.incidentRevision !== 'number' ||
      !Number.isInteger(record.incidentRevision) ||
      record.incidentRevision < 1 ||
      !isDigest(record.incidentStateResultDigest) ||
      typeof record.incidentSubjectId !== 'string' ||
      !/^incident-subject-[a-f0-9]{32}$/.test(record.incidentSubjectId) ||
      !isDigest(record.incidentSubjectDigest) ||
      typeof record.incidentBoundRequestId !== 'string' ||
      !/^incident-bound-request-[a-f0-9]{32}$/.test(record.incidentBoundRequestId) ||
      !isDigest(record.incidentBoundRequestDigest) ||
      !isDigest(record.correlationRequestDigest) ||
      !isDigest(record.correlationTransitionDigest) ||
      typeof record.reportId !== 'string' ||
      !/^report-[a-f0-9]{32}$/.test(record.reportId) ||
      !isDigest(record.reportDigest) ||
      !isDigest(record.reportContentDigest)
    ) {
      throw new VerificationError('Published correlation report reference is invalid.')
    }
    if (
      typeof record.referenceId !== 'string' ||
      !/^report-asset-[a-f0-9]{32}$/.test(record.referenceId) ||
      !isDigest(record.referenceDigest)
    ) {
      throw new VerificationError('Published correlation report digest is invalid.')
    }
    await requireDigestBoundId(
      record,
      ['referenceId', 'referenceDigest'],
      record.referenceDigest,
      'report-asset-',
      record.referenceId,
      cryptoProvider,
    )
    const reportReference = parseReference(record.reportReference)
    const attestationReference = parseReference(record.attestationReference)
    const prefix = `incidents/${record.incidentId}/versions/${record.incidentStateResultDigest.slice(
      'sha256:'.length,
    )}/correlation-reports/${record.reportId}`
    if (
      reportReference.name !== `${prefix}/report.json` ||
      reportReference.contentDigest !== record.reportContentDigest ||
      attestationReference.name !== `${prefix}/attestation.json`
    ) {
      throw new VerificationError('Published correlation report paths are invalid.')
    }
    return {
      incidentId: record.incidentId,
      incidentTransitionId: record.incidentTransitionId,
      incidentRevision: record.incidentRevision,
      incidentStateResultDigest: record.incidentStateResultDigest,
      incidentSubjectId: record.incidentSubjectId,
      incidentSubjectDigest: record.incidentSubjectDigest,
      incidentBoundRequestId: record.incidentBoundRequestId,
      incidentBoundRequestDigest: record.incidentBoundRequestDigest,
      reportId: record.reportId,
      reportDigest: record.reportDigest,
      correlationRequestDigest: record.correlationRequestDigest,
      correlationTransitionDigest: record.correlationTransitionDigest,
    }
  }

  async function parseGuidanceAsset(
    value: unknown,
  ): Promise<{
    incidentId: string
    incidentStateDigest: Sha256Digest
    guidanceId: string
    guidanceDigest: Sha256Digest
    guidanceReference: VersionPinnedReference
    attestationReference: VersionPinnedReference
  }> {
    const record = requireRecord(value)
    requireExactKeys(record, [
      'schemaVersion',
      'referenceId',
      'incidentId',
      'incidentStateDigest',
      'guidanceId',
      'guidanceDigest',
      'guidanceReference',
      'attestationReference',
      'referenceDigest',
    ])
    if (
      record.schemaVersion !== 'athena.wc027IncidentGuidanceAssetReference.v1' ||
      typeof record.incidentId !== 'string' ||
      !INCIDENT_ID.test(record.incidentId) ||
      !isDigest(record.incidentStateDigest) ||
      typeof record.guidanceId !== 'string' ||
      !GUIDANCE_ID.test(record.guidanceId) ||
      !isDigest(record.guidanceDigest) ||
      typeof record.referenceId !== 'string' ||
      !/^guidance-asset-[a-f0-9]{32}$/.test(record.referenceId) ||
      !isDigest(record.referenceDigest)
    ) {
      throw new VerificationError('Incident guidance asset reference is invalid.')
    }
    await requireDigestBoundId(
      record,
      ['referenceId', 'referenceDigest'],
      record.referenceDigest,
      'guidance-asset-',
      record.referenceId,
      cryptoProvider,
    )
    const guidanceReference = parseReference(record.guidanceReference)
    const attestationReference = parseReference(record.attestationReference)
    const prefix = `incidents/${record.incidentId}/versions/${record.incidentStateDigest.slice(
      'sha256:'.length,
    )}/guidance/${record.guidanceId}`
    if (
      guidanceReference.name !== `${prefix}/guidance.json` ||
      attestationReference.name !== `${prefix}/attestation.json`
    ) {
      throw new VerificationError('Incident guidance asset paths are invalid.')
    }
    return {
      incidentId: record.incidentId,
      incidentStateDigest: record.incidentStateDigest,
      guidanceId: record.guidanceId,
      guidanceDigest: record.guidanceDigest,
      guidanceReference,
      attestationReference,
    }
  }
}

export const parseIncidentGuidance = async (
  record: Record<string, JsonValue>,
  cryptoProvider: Crypto = globalThis.crypto,
): Promise<IncidentGuidance> => {
  requireExactKeys(record, [
    'schemaVersion',
    'guidanceId',
    'algorithmId',
    'generatedAt',
    'sourceBinding',
    'affectedRoleImpact',
    'timeline',
    'hypotheses',
    'confirmationChecks',
    'investigationSteps',
    'safeManualOptions',
    'rollbackConsiderations',
    'recoveryValidation',
    'escalation',
    'runbookLinks',
    'missingEvidence',
    'legality',
    'noAutoRemediation',
    'guidanceDigest',
  ])
  if (
    record.schemaVersion !== 'athena.wc027IncidentGuidance.v1' ||
    record.algorithmId !== 'athena.wc027.incident-guidance.v1' ||
    typeof record.guidanceId !== 'string' ||
    !GUIDANCE_ID.test(record.guidanceId) ||
    !isTimestamp(record.generatedAt) ||
    record.noAutoRemediation !== true ||
    !isDigest(record.guidanceDigest)
  ) {
    throw new VerificationError('Incident guidance schema is invalid.')
  }
  await requireDigestBoundId(
    record,
    ['guidanceId', 'guidanceDigest'],
    record.guidanceDigest,
    'incident-guidance-',
    record.guidanceId,
    cryptoProvider,
  )
  const source = parseSourceBinding(record.sourceBinding)
  const impact = parseAffectedRoleImpact(record.affectedRoleImpact)
  const timeline = parseBoundedArray(record.timeline, 1, 128, parseTimeline)
  const hypotheses = parseBoundedArray(record.hypotheses, 1, 64, parseHypothesis)
  const confirmationChecks = parseSteps(record.confirmationChecks, 64, 'confirmationCheck')
  const investigationSteps = parseSteps(record.investigationSteps, 64, 'investigationCheck')
  const safeManualOptions = parseSteps(record.safeManualOptions, 32, 'manualResolutionOption')
  const rollbackConsiderations = parseSteps(
    record.rollbackConsiderations,
    32,
    'rollbackConsideration',
  )
  const recoveryValidation = parseSteps(record.recoveryValidation, 32, 'recoveryValidation')
  const escalation = parseSteps(record.escalation, 32, 'escalation')
  const runbookLinks = parseBoundedArray(record.runbookLinks, 0, 16, parseRunbookLink)
  const legality = parseLegality(record.legality)
  const missingEvidence = parseStringArray(record.missingEvidence, 64)
  if (
    missingEvidence.some(
      (code) =>
        !MISSING_EVIDENCE_CODES.includes(
          code as (typeof MISSING_EVIDENCE_CODES)[number],
        ),
    )
  ) {
    throw new VerificationError('Incident guidance missing-evidence code is invalid.')
  }
  await validateNestedGuidanceDigests(record, cryptoProvider)
  const timelineKeys = timeline.map(
    (entry) => `${entry.observedStart}\0${entry.entryId}`,
  )
  const hypothesisIds = hypotheses.map((item) => item.hypothesisId)
  const runbookIds = runbookLinks.map((item) => item.linkId)
  if (
    hypotheses.some((item, index) => item.rank !== index + 1) ||
    new Set(hypothesisIds).size !== hypothesisIds.length ||
    timelineKeys.join('\0') !== [...timelineKeys].sort().join('\0') ||
    new Set(timeline.map((entry) => entry.entryId)).size !== timeline.length ||
    runbookIds.join('\0') !== [...runbookIds].sort().join('\0') ||
    new Set(runbookIds).size !== runbookIds.length ||
    legality.confidence !== hypotheses[0]!.confidence ||
    legality.selectionKind !== source.selectionKind
  ) {
    throw new VerificationError('Incident guidance confidence binding is invalid.')
  }

  async function validateNestedGuidanceDigests(
    guidance: Record<string, JsonValue>,
    cryptoProvider: Crypto,
  ): Promise<void> {
    const source = requireRecord(guidance.sourceBinding)
    if (
      typeof source.sourceId !== 'string' ||
      !/^guidance-source-[a-f0-9]{32}$/.test(source.sourceId) ||
      !isDigest(source.sourceDigest)
    ) {
      throw new VerificationError('Incident guidance source digest is invalid.')
    }
    await requireDigestBoundId(
      source,
      ['sourceId', 'sourceDigest'],
      source.sourceDigest,
      'guidance-source-',
      source.sourceId,
      cryptoProvider,
    )
    const collections: Array<{
      value: JsonValue | undefined
      id: string
      digest: string
      prefix: string
    }> = [
      {
        value: guidance.timeline,
        id: 'entryId',
        digest: 'entryDigest',
        prefix: 'guidance-timeline-',
      },
      ...[
        'confirmationChecks',
        'investigationSteps',
        'safeManualOptions',
        'rollbackConsiderations',
        'recoveryValidation',
        'escalation',
      ].map((key) => ({
        value: guidance[key],
        id: 'stepId',
        digest: 'stepDigest',
        prefix: 'guidance-step-',
      })),
      {
        value: guidance.runbookLinks,
        id: 'linkId',
        digest: 'linkDigest',
        prefix: 'guidance-link-',
      },
    ]
    for (const collection of collections) {
      if (!Array.isArray(collection.value)) {
        throw new VerificationError('Incident guidance collection is invalid.')
      }
      for (const item of collection.value) {
        const record = requireRecord(item)
        const id = record[collection.id]
        const digest = record[collection.digest]
        if (typeof id !== 'string' || !isDigest(digest)) {
          throw new VerificationError('Incident guidance nested digest is invalid.')
        }
        await requireDigestBoundId(
          record,
          [collection.id, collection.digest],
          digest,
          collection.prefix,
          id,
          cryptoProvider,
        )
      }
    }
  }
  const selectedOptionId = source.selectedOptionId
  const allSteps = [
    ...confirmationChecks,
    ...investigationSteps,
    ...safeManualOptions,
    ...rollbackConsiderations,
    ...recoveryValidation,
    ...escalation,
  ]
  if (
    [...safeManualOptions, ...rollbackConsiderations].some(
      (step) => step.optionId !== selectedOptionId,
    ) ||
    runbookLinks.some((link) => link.optionId !== selectedOptionId) ||
    allSteps.some((step) =>
      step.parameters.some(
        (parameter) =>
          parameter.parameterKind === 'optionId' &&
          parameter.value !== selectedOptionId,
      ),
    )
  ) {
    throw new VerificationError('Incident guidance option binding is invalid.')
  }
  const lowerConfidence = ['Unknown', 'Low', 'Medium'].includes(hypotheses[0]!.confidence)
  if (
    (lowerConfidence &&
      (safeManualOptions.length > 0 ||
        rollbackConsiderations.length > 0 ||
        runbookLinks.length > 0 ||
        confirmationChecks.length === 0 ||
        investigationSteps.length === 0)) ||
    (hypotheses[0]!.confidence === 'High' &&
      (safeManualOptions.length > 0 || rollbackConsiderations.length > 0)) ||
    (source.selectionKind === 'noRunbook' &&
      (safeManualOptions.length > 0 ||
        rollbackConsiderations.length > 0 ||
        runbookLinks.length > 0 ||
        escalation.length === 0)) ||
    (safeManualOptions.length > 0 && !legality.manualActionsAuthorized) ||
    (rollbackConsiderations.length > 0 && !legality.rollbackAuthorized) ||
    (runbookLinks.length > 0 && !legality.runbookReferenceAuthorized)
  ) {
    throw new VerificationError('Incident guidance exceeds its confidence-sensitive legality.')
  }
  return {
    schemaVersion: record.schemaVersion,
    guidanceId: record.guidanceId,
    generatedAt: record.generatedAt,
    sourceBinding: source,
    affectedRoleImpact: impact,
    timeline,
    hypotheses,
    confirmationChecks,
    investigationSteps,
    safeManualOptions,
    rollbackConsiderations,
    recoveryValidation,
    escalation,
    runbookLinks,
    missingEvidence,
    legality,
    noAutoRemediation: true,
    guidanceDigest: record.guidanceDigest,
  }
}

const parseSourceBinding = (value: unknown): IncidentGuidance['sourceBinding'] => {
  const record = requireRecord(value)
  requireExactKeys(record, [
    'sourceId',
    'incidentSubjectId',
    'incidentSubjectDigest',
    'incidentId',
    'incidentRevision',
    'incidentStateDigest',
    'incidentBoundRequestId',
    'incidentBoundRequestDigest',
    'correlationReportId',
    'correlationReportDigest',
    'correlationRequestDigest',
    'transitionDigest',
    'ruleCatalogDigest',
    'inputInventoryDigest',
    'guidanceAuthorityId',
    'guidanceAuthorityDigest',
    'guidanceBindingId',
    'guidanceBindingDigest',
    'selectionKind',
    'sourceDigest',
  ], ['selectedOptionId', 'noRunbookReason'])
  if (
    typeof record.sourceId !== 'string' ||
    !/^guidance-source-[a-f0-9]{32}$/.test(record.sourceId) ||
    typeof record.incidentSubjectId !== 'string' ||
    !/^incident-subject-[a-f0-9]{32}$/.test(record.incidentSubjectId) ||
    !isDigest(record.incidentSubjectDigest) ||
    typeof record.incidentId !== 'string' ||
    !INCIDENT_ID.test(record.incidentId) ||
    typeof record.incidentRevision !== 'number' ||
    !Number.isInteger(record.incidentRevision) ||
    record.incidentRevision < 1 ||
    !isDigest(record.incidentStateDigest) ||
    typeof record.incidentBoundRequestId !== 'string' ||
    !/^incident-bound-request-[a-f0-9]{32}$/.test(record.incidentBoundRequestId) ||
    !isDigest(record.incidentBoundRequestDigest) ||
    typeof record.correlationReportId !== 'string' ||
    !/^report-[a-f0-9]{32}$/.test(record.correlationReportId) ||
    !isDigest(record.correlationReportDigest) ||
    !isDigest(record.correlationRequestDigest) ||
    !isDigest(record.transitionDigest) ||
    !isDigest(record.ruleCatalogDigest) ||
    !isDigest(record.inputInventoryDigest) ||
    typeof record.guidanceAuthorityId !== 'string' ||
    !/^guidance-authority-[a-f0-9]{32}$/.test(record.guidanceAuthorityId) ||
    !isDigest(record.guidanceAuthorityDigest) ||
    typeof record.guidanceBindingId !== 'string' ||
    !/^guidance-binding-[a-f0-9]{32}$/.test(record.guidanceBindingId) ||
    !isDigest(record.guidanceBindingDigest) ||
    !isDigest(record.sourceDigest) ||
    (record.selectionKind !== 'selectedRunbook' && record.selectionKind !== 'noRunbook')
  ) {
    throw new VerificationError('Incident guidance source binding is invalid.')
  }
  const selectedOptionId =
    typeof record.selectedOptionId === 'string' ? record.selectedOptionId : undefined
  const noRunbookReason =
    typeof record.noRunbookReason === 'string' ? record.noRunbookReason : undefined
  if (
    (record.selectionKind === 'selectedRunbook' &&
      (!selectedOptionId || !OPTION_ID.test(selectedOptionId) || noRunbookReason)) ||
    (record.selectionKind === 'noRunbook' &&
      (selectedOptionId ||
        !noRunbookReason ||
        !NO_RUNBOOK_REASONS.includes(
          noRunbookReason as (typeof NO_RUNBOOK_REASONS)[number],
        )))
  ) {
    throw new VerificationError('Incident guidance selection binding is invalid.')
  }
  return {
    incidentSubjectId: record.incidentSubjectId,
    incidentSubjectDigest: record.incidentSubjectDigest,
    incidentId: record.incidentId,
    incidentRevision: record.incidentRevision,
    incidentStateDigest: record.incidentStateDigest,
    incidentBoundRequestId: record.incidentBoundRequestId,
    incidentBoundRequestDigest: record.incidentBoundRequestDigest,
    correlationReportId: record.correlationReportId,
    correlationReportDigest: record.correlationReportDigest,
    correlationRequestDigest: record.correlationRequestDigest,
    transitionDigest: record.transitionDigest,
    selectionKind: record.selectionKind,
    selectedOptionId,
    noRunbookReason,
  }
}

const parseAffectedRoleImpact = (
  value: unknown,
): IncidentGuidance['affectedRoleImpact'] => {
  const record = requireRecord(value)
  requireExactKeys(record, ['roleRef', 'profileId', 'impactSeverity', 'impactCode'])
  const severities = ['none', 'limited', 'significant', 'critical', 'unknown']
  const codes = [
    'roleRecovered',
    'roleDegraded',
    'dataTierUnavailable',
    'ingressUnavailable',
    'unknownImpact',
  ]
  if (
    typeof record.roleRef !== 'string' ||
    !IDENTIFIER.test(record.roleRef) ||
    typeof record.profileId !== 'string' ||
    record.profileId.length > 128 ||
    typeof record.impactSeverity !== 'string' ||
    !severities.includes(record.impactSeverity) ||
    typeof record.impactCode !== 'string' ||
    !codes.includes(record.impactCode)
  ) {
    throw new VerificationError('Incident guidance impact is invalid.')
  }
  return record as unknown as IncidentGuidance['affectedRoleImpact']
}

const parseTimeline = (value: unknown): IncidentGuidance['timeline'][number] => {
  const record = requireRecord(value)
  requireExactKeys(record, [
    'entryId',
    'timelineKind',
    'observedStart',
    'observedEnd',
    'summaryCode',
    'evidenceIds',
    'entryDigest',
  ])
  const kinds = [
    'healthTransition',
    'guestSignal',
    'networkEvidence',
    'platformHealth',
    'resourceChange',
    'recovery',
  ]
  const evidence = parseStringArray(record.evidenceIds, 1)
  if (
    evidence.length !== 1 ||
    typeof record.entryId !== 'string' ||
    !/^guidance-timeline-[a-f0-9]{32}$/.test(record.entryId) ||
    typeof record.timelineKind !== 'string' ||
    !kinds.includes(record.timelineKind) ||
    !isTimestamp(record.observedStart) ||
    !isTimestamp(record.observedEnd) ||
    Date.parse(record.observedStart) > Date.parse(record.observedEnd) ||
    typeof record.summaryCode !== 'string' ||
    !IDENTIFIER.test(record.summaryCode)
  ) {
    throw new VerificationError('Incident guidance timeline entry is invalid.')
  }
  return {
    entryId: record.entryId,
    timelineKind: record.timelineKind as IncidentGuidance['timeline'][number]['timelineKind'],
    observedStart: record.observedStart,
    observedEnd: record.observedEnd,
    summaryCode: record.summaryCode,
    evidenceIds: [evidence[0]!],
  }
}

const parseHypothesis = (value: unknown): GuidanceHypothesis => {
  const record = requireRecord(value)
  requireExactKeys(record, [
    'rank',
    'hypothesisId',
    'hypothesisDigest',
    'category',
    'confidence',
    'supportingEvidenceIds',
    'supportingEvidenceCount',
    'supportingEvidenceDigest',
    'contradictionCodes',
    'missingEvidenceCodes',
  ], ['causeResourceDigest', 'affectedPathId', 'omittedCandidateCount', 'omittedCandidateDigest'])
  if (
    !Number.isInteger(record.rank) ||
    typeof record.rank !== 'number' ||
    record.rank < 1 ||
    record.rank > 64 ||
    typeof record.hypothesisId !== 'string' ||
    !/^hyp-[a-f0-9]{32}$/.test(record.hypothesisId) ||
    !isDigest(record.hypothesisDigest) ||
    typeof record.category !== 'string' ||
    !ROOT_CAUSE_CATEGORIES.includes(
      record.category as (typeof ROOT_CAUSE_CATEGORIES)[number],
    ) ||
    !isConfidence(record.confidence) ||
    !Number.isInteger(record.supportingEvidenceCount) ||
    typeof record.supportingEvidenceCount !== 'number' ||
    record.supportingEvidenceCount < 0 ||
    record.supportingEvidenceCount > 128 ||
    !isDigest(record.supportingEvidenceDigest) ||
    (record.causeResourceDigest !== undefined &&
      !isDigest(record.causeResourceDigest)) ||
    (record.affectedPathId !== undefined &&
      (typeof record.affectedPathId !== 'string' ||
        record.affectedPathId.length < 1 ||
        record.affectedPathId.length > 128)) ||
    (record.omittedCandidateCount !== undefined &&
      (typeof record.omittedCandidateCount !== 'number' ||
        !Number.isInteger(record.omittedCandidateCount) ||
        record.omittedCandidateCount < 1 ||
        record.omittedCandidateCount > 4096)) ||
    (record.omittedCandidateDigest !== undefined &&
      !isDigest(record.omittedCandidateDigest)) ||
    ((record.omittedCandidateCount === undefined) !==
      (record.omittedCandidateDigest === undefined))
  ) {
    throw new VerificationError('Incident guidance hypothesis is invalid.')
  }
  const supportingEvidenceIds = parseStringArray(record.supportingEvidenceIds, 4)
  if (record.supportingEvidenceCount < supportingEvidenceIds.length) {
    throw new VerificationError('Incident guidance evidence count is invalid.')
  }
  const contradictionCodes = parseStringArray(record.contradictionCodes, 64)
  const missingEvidenceCodes = parseStringArray(record.missingEvidenceCodes, 64)
  if (
    contradictionCodes.some(
      (code) =>
        !CONTRADICTION_CODES.includes(
          code as (typeof CONTRADICTION_CODES)[number],
        ),
    ) ||
    missingEvidenceCodes.some(
      (code) =>
        !MISSING_EVIDENCE_CODES.includes(
          code as (typeof MISSING_EVIDENCE_CODES)[number],
        ),
    )
  ) {
    throw new VerificationError('Incident guidance evidence code is invalid.')
  }
  return {
    rank: record.rank,
    hypothesisId: record.hypothesisId,
    category: record.category,
    confidence: record.confidence,
    supportingEvidenceIds,
    supportingEvidenceCount: record.supportingEvidenceCount,
    contradictionCodes,
    missingEvidenceCodes,
  }
}

const parseSteps = (
  value: unknown,
  maximum: number,
  action: GuidanceActionKind,
): GuidanceStep[] => {
  const steps = parseBoundedArray(value, 0, maximum, parseStep)
  const ids = steps.map((step) => step.stepId)
  if (
    steps.some((step) => step.actionKind !== action) ||
    ids.join('\0') !== [...ids].sort().join('\0') ||
    new Set(ids).size !== ids.length
  ) {
    throw new VerificationError('Incident guidance step is in the wrong collection.')
  }
  return steps
}

const parseStep = (value: unknown): GuidanceStep => {
  const record = requireRecord(value)
  requireExactKeys(record, [
    'stepId',
    'actionKind',
    'templateCode',
    'parameters',
    'evidenceIds',
    'readOnly',
    'requiresAuthorization',
    'stepDigest',
  ], ['provenanceClauseRef', 'optionId'])
  const actions: GuidanceActionKind[] = [
    'investigationCheck',
    'confirmationCheck',
    'manualResolutionOption',
    'rollbackConsideration',
    'recoveryValidation',
    'escalation',
  ]
  const templates: GuidanceTemplateCode[] = [
    'confirmEffectiveRule',
    'confirmBackendHealth',
    'inspectGuestHealth',
    'inspectNetworkPath',
    'inspectRecentChange',
    'reviewApprovedManualOption',
    'reviewRollbackAuthority',
    'validateRecoverySignals',
    'escalateHumanReview',
  ]
  if (
    typeof record.stepId !== 'string' ||
    !/^guidance-step-[a-f0-9]{32}$/.test(record.stepId) ||
    typeof record.actionKind !== 'string' ||
    !actions.includes(record.actionKind as GuidanceActionKind) ||
    typeof record.templateCode !== 'string' ||
    !templates.includes(record.templateCode as GuidanceTemplateCode) ||
    typeof record.readOnly !== 'boolean' ||
    typeof record.requiresAuthorization !== 'boolean'
  ) {
    throw new VerificationError('Incident guidance step is invalid.')
  }
  const actionKind = record.actionKind as GuidanceActionKind
  const templateCode = record.templateCode as GuidanceTemplateCode
  const expectedAction: Record<GuidanceTemplateCode, GuidanceActionKind> = {
    confirmEffectiveRule: 'confirmationCheck',
    confirmBackendHealth: 'confirmationCheck',
    inspectGuestHealth: 'investigationCheck',
    inspectNetworkPath: 'investigationCheck',
    inspectRecentChange: 'investigationCheck',
    reviewApprovedManualOption: 'manualResolutionOption',
    reviewRollbackAuthority: 'rollbackConsideration',
    validateRecoverySignals: 'recoveryValidation',
    escalateHumanReview: 'escalation',
  }
  if (expectedAction[templateCode] !== actionKind) {
    throw new VerificationError('Incident guidance template does not match its action.')
  }
  const prescriptive =
    actionKind === 'manualResolutionOption' || actionKind === 'rollbackConsideration'
  const optionId = typeof record.optionId === 'string' ? record.optionId : undefined
  const provenanceClauseRef =
    typeof record.provenanceClauseRef === 'string'
      ? record.provenanceClauseRef
      : undefined
  if (
    (prescriptive &&
      (record.readOnly ||
        !record.requiresAuthorization ||
        !optionId ||
        !OPTION_ID.test(optionId) ||
        !provenanceClauseRef)) ||
    (!prescriptive &&
      (!record.readOnly ||
        record.requiresAuthorization ||
        optionId !== undefined ||
        provenanceClauseRef !== undefined))
  ) {
    throw new VerificationError('Incident guidance step authorization flags are invalid.')
  }
  const parameters = parseBoundedArray(record.parameters, 0, 16, parseParameter)
  const allowedKinds: Record<
    GuidanceTemplateCode,
    Set<GuidanceStep['parameters'][number]['parameterKind']>
  > = {
    confirmEffectiveRule: new Set(['resourceId', 'pathId', 'evidenceId']),
    confirmBackendHealth: new Set(['resourceId', 'pathId', 'evidenceId']),
    inspectGuestHealth: new Set(['resourceId', 'evidenceId', 'roleRef']),
    inspectNetworkPath: new Set(['resourceId', 'pathId', 'evidenceId', 'roleRef']),
    inspectRecentChange: new Set(['resourceId', 'evidenceId']),
    reviewApprovedManualOption: new Set(['optionId', 'roleRef', 'pathId']),
    reviewRollbackAuthority: new Set(['optionId', 'roleRef']),
    validateRecoverySignals: new Set(['resourceId', 'pathId', 'evidenceId']),
    escalateHumanReview: new Set(['roleRef', 'evidenceId']),
  }
  const parameterKeys = parameters.map(
    (parameter) => `${parameter.parameterKind}\0${parameter.value}`,
  )
  if (
    parameters.some((parameter) => !allowedKinds[templateCode].has(parameter.parameterKind)) ||
    new Set(parameters.map((parameter) => parameter.parameterKind)).size !==
      parameters.length ||
    parameterKeys.join('\0') !== [...parameterKeys].sort().join('\0')
  ) {
    throw new VerificationError('Incident guidance template parameters are invalid.')
  }
  return {
    stepId: record.stepId,
    actionKind,
    templateCode,
    parameters,
    evidenceIds: parseStringArray(record.evidenceIds, 32),
    provenanceClauseRef,
    optionId,
    readOnly: record.readOnly,
    requiresAuthorization: record.requiresAuthorization,
  }
}

const parseParameter = (value: unknown): GuidanceStep['parameters'][number] => {
  const record = requireRecord(value)
  requireExactKeys(record, ['parameterKind', 'value'])
  const kinds = ['resourceId', 'pathId', 'evidenceId', 'optionId', 'roleRef']
  if (
    typeof record.parameterKind !== 'string' ||
    !kinds.includes(record.parameterKind) ||
    typeof record.value !== 'string' ||
    record.value.length < 1 ||
    record.value.length > 512
  ) {
    throw new VerificationError('Incident guidance template parameter is invalid.')
  }
  const patterns: Record<string, RegExp> = {
    resourceId:
      /^\/subscriptions\/[a-f0-9-]{36}\/resourcegroups\/[a-z0-9_().-]{1,90}\/providers\/[a-z0-9.]+(?:\/[a-z0-9.()_-]+\/[a-z0-9.()_-]+)+$/,
    pathId: /^path-[a-f0-9]{32}$/,
    evidenceId: /^(?:obs-[a-f0-9]{32}|coverage-[a-f0-9]{32}|chg-[a-f0-9]{12})$/,
    optionId: OPTION_ID,
    roleRef: IDENTIFIER,
  }
  if (!patterns[record.parameterKind]!.test(record.value)) {
    throw new VerificationError('Incident guidance template parameter is invalid.')
  }
  return record as unknown as GuidanceStep['parameters'][number]
}

const parseRunbookLink = (value: unknown): GuidanceRunbookLink => {
  const record = requireRecord(value)
  requireExactKeys(record, [
    'linkId',
    'optionId',
    'optionDigest',
    'runbookReference',
    'labelCode',
    'referenceOnly',
    'linkDigest',
  ])
  if (
    typeof record.linkId !== 'string' ||
    !/^guidance-link-[a-f0-9]{32}$/.test(record.linkId) ||
    typeof record.optionId !== 'string' ||
    !OPTION_ID.test(record.optionId) ||
    record.labelCode !== 'approvedOperatorRunbook' ||
    record.referenceOnly !== true
  ) {
    throw new VerificationError('Incident guidance runbook link is invalid.')
  }
  const reference = requireRecord(record.runbookReference)
  requireExactKeys(
    reference,
    reference.referenceKind === 'https'
      ? ['referenceKind', 'uri', 'version', 'contentDigest']
      : ['referenceKind', 'opaqueRef', 'version', 'contentDigest'],
  )
  if (
    reference.referenceKind === 'https' &&
    typeof reference.uri === 'string' &&
    isSafeHttps(reference.uri) &&
    typeof reference.version === 'string' &&
    isDigest(reference.contentDigest)
  ) {
    return {
      linkId: record.linkId,
      optionId: record.optionId,
      reference: {
        referenceKind: 'https',
        uri: reference.uri,
        version: reference.version,
        contentDigest: reference.contentDigest,
      },
    }
  }
  if (
    reference.referenceKind === 'opaque' &&
    typeof reference.opaqueRef === 'string' &&
    /^(?:urn:[A-Za-z0-9][A-Za-z0-9:._-]{1,508}|synthetic:\/\/[A-Za-z0-9][A-Za-z0-9./_-]{1,498})$/.test(
      reference.opaqueRef,
    ) &&
    typeof reference.version === 'string' &&
    isDigest(reference.contentDigest)
  ) {
    return {
      linkId: record.linkId,
      optionId: record.optionId,
      reference: {
        referenceKind: 'opaque',
        opaqueRef: reference.opaqueRef,
        version: reference.version,
        contentDigest: reference.contentDigest,
      },
    }
  }
  throw new VerificationError('Incident guidance runbook reference is invalid.')
}

const parseLegality = (value: unknown): IncidentGuidance['legality'] => {
  const record = requireRecord(value)
  requireExactKeys(record, [
    'confidence',
    'selectionKind',
    'manualActionsAuthorized',
    'rollbackAuthorized',
    'runbookReferenceAuthorized',
    'executionAuthorizationRequired',
    'withheldReasons',
  ])
  if (
    !isConfidence(record.confidence) ||
    (record.selectionKind !== 'selectedRunbook' && record.selectionKind !== 'noRunbook') ||
    typeof record.manualActionsAuthorized !== 'boolean' ||
    typeof record.rollbackAuthorized !== 'boolean' ||
    typeof record.runbookReferenceAuthorized !== 'boolean' ||
    record.executionAuthorizationRequired !== true
  ) {
    throw new VerificationError('Incident guidance legality is invalid.')
  }
  if (
    (record.selectionKind === 'noRunbook' &&
      (record.manualActionsAuthorized ||
        record.rollbackAuthorized ||
        record.runbookReferenceAuthorized)) ||
    ((record.manualActionsAuthorized || record.rollbackAuthorized) &&
      record.confidence !== 'Confirmed') ||
    (record.runbookReferenceAuthorized &&
      !['High', 'Confirmed'].includes(record.confidence))
  ) {
    throw new VerificationError('Incident guidance legality exceeds confidence.')
  }
  const withheldReasons = parseStringArray(record.withheldReasons, 16)
  if (
    withheldReasons.some(
      (reason) =>
        !WITHHELD_REASONS.includes(
          reason as (typeof WITHHELD_REASONS)[number],
        ),
    )
  ) {
    throw new VerificationError('Incident guidance withheld reason is invalid.')
  }
  return {
    confidence: record.confidence,
    selectionKind: record.selectionKind,
    manualActionsAuthorized: record.manualActionsAuthorized,
    rollbackAuthorized: record.rollbackAuthorized,
    runbookReferenceAuthorized: record.runbookReferenceAuthorized,
    executionAuthorizationRequired: true,
    withheldReasons,
  }
}

const parseReference = (value: unknown): VersionPinnedReference => {
  const record = requireRecord(value)
  requireExactKeys(record, ['name', 'version', 'contentDigest'])
  if (
    typeof record.name !== 'string' ||
    record.name.length > 512 ||
    record.name.startsWith('/') ||
    record.name.includes('\\') ||
    record.name.includes('%') ||
    record.name.split('/').some((part) => ['', '.', '..'].includes(part)) ||
    typeof record.version !== 'string' ||
    !VERSION.test(record.version) ||
    !isDigest(record.contentDigest)
  ) {
    throw new VerificationError('Version-pinned incident asset reference is invalid.')
  }
  return {
    name: record.name,
    version: record.version,
    contentDigest: record.contentDigest,
  }
}

const parseAttestation = (
  asset: BoundedJsonAsset,
  maximumBytes: number,
  schemaVersion: string,
  keys: string[],
): { id?: string; digest: Sha256Digest; attestation: ParsedAttestation } => {
  if (asset.bytes.byteLength < 1 || asset.bytes.byteLength > maximumBytes) {
    throw new VerificationError('Incident guidance attestation exceeds its byte bound.')
  }
  const record = requireRecord(asset.value)
  requireExactKeys(record, keys)
  const canonical = new TextEncoder().encode(`${canonicalizeJson(record)}\n`)
  if (!equalBytes(asset.bytes, canonical)) {
    throw new VerificationError('Incident guidance attestation is not canonical JSON.')
  }
  const digest =
    record.indexDigest ?? record.pointerDigest ?? record.manifestDigest ?? record.guidanceDigest
  const id = record.pointerId ?? record.enrichmentId ?? record.guidanceId
  if (
    record.schemaVersion !== schemaVersion ||
    !isDigest(digest) ||
    record.signatureAlgorithm !== 'RS256' ||
    typeof record.keyVaultKeyId !== 'string' ||
    typeof record.detachedSignature !== 'string' ||
    !/^[A-Za-z0-9_-]+$/.test(record.detachedSignature) ||
    (record.signedPreimageDigest !== undefined &&
      !isDigest(record.signedPreimageDigest))
  ) {
    throw new VerificationError('Incident guidance attestation schema is invalid.')
  }
  return {
    id: typeof id === 'string' ? id : undefined,
    digest,
    attestation: {
      signatureAlgorithm: 'RS256',
      keyVaultKeyId: record.keyVaultKeyId,
      detachedSignature: record.detachedSignature,
      signedPreimageDigest: isDigest(record.signedPreimageDigest)
        ? record.signedPreimageDigest
        : undefined,
    },
  }
}

const verifySignature = async (
  payload: Uint8Array,
  attestation: ParsedAttestation,
  anchor: GuidanceTrustAnchor,
  cryptoProvider: Crypto,
): Promise<void> => {
  const publicKey = parseWc027PublicKey(anchor.publicKey)
  if (
    anchor.keyId !== publicKey.keyId ||
    anchor.fingerprint !== publicKey.fingerprint ||
    attestation.keyVaultKeyId !== anchor.keyId
  ) {
    throw new VerificationError('Incident guidance trust anchor binding is invalid.')
  }

  function parseWc027PublicKey(
    value: unknown,
  ): {
    keyId: string
    fingerprint: Sha256Digest
    jwk: JsonWebKey
  } {
    const record = requireRecord(value)
    requireExactKeys(record, ['schemaVersion', 'keyId', 'fingerprint', 'jwk'])
    const jwk = requireRecord(record.jwk)
    requireExactKeys(jwk, ['kty', 'n', 'e', 'alg', 'key_ops', 'ext'])
    if (
      record.schemaVersion !== 'athena.presentationWeb.publicKey.v1' ||
      typeof record.keyId !== 'string' ||
      record.keyId.length < 1 ||
      record.keyId.length > 512 ||
      [...record.keyId].some((character) => character < '\x21' || character > '\x7e') ||
      !isDigest(record.fingerprint) ||
      jwk.kty !== 'RSA' ||
      typeof jwk.n !== 'string' ||
      !/^[A-Za-z0-9_-]+$/.test(jwk.n) ||
      typeof jwk.e !== 'string' ||
      !/^[A-Za-z0-9_-]+$/.test(jwk.e) ||
      jwk.alg !== 'RS256' ||
      !Array.isArray(jwk.key_ops) ||
      jwk.key_ops.length !== 1 ||
      jwk.key_ops[0] !== 'verify' ||
      jwk.ext !== true
    ) {
      throw new VerificationError('WC-027 verification key contract is invalid.')
    }
    return {
      keyId: record.keyId,
      fingerprint: record.fingerprint,
      jwk: {
        kty: 'RSA',
        n: jwk.n,
        e: jwk.e,
        alg: 'RS256',
        key_ops: ['verify'],
        ext: true,
      },
    }
  }
  const imported = await cryptoProvider.subtle.importKey(
    'jwk',
    publicKey.jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify'],
  )
  if (
    (await computePublicKeyFingerprint(imported, cryptoProvider)) !==
    anchor.fingerprint
  ) {
    throw new VerificationError('Incident guidance trust anchor fingerprint is invalid.')
  }
  const signature = decodeBase64Url(attestation.detachedSignature)
  const algorithm = imported.algorithm as RsaHashedKeyAlgorithm
  if (
    signature.byteLength !== algorithm.modulusLength / 8 ||
    !(await cryptoProvider.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      imported,
      signature,
      payload,
    ))
  ) {
    throw new VerificationError('Incident guidance signature is invalid.')
  }
}

const requireCanonicalAsset = async (
  asset: BoundedJsonAsset,
  maximumBytes: number,
  label: string,
): Promise<Record<string, JsonValue>> => {
  if (asset.bytes.byteLength < 1 || asset.bytes.byteLength > maximumBytes) {
    throw new VerificationError(`The ${label} exceeds its byte bound.`)
  }
  const record = requireRecord(asset.value)
  const canonical = new TextEncoder().encode(`${canonicalizeJson(record)}\n`)
  if (!equalBytes(asset.bytes, canonical)) {
    throw new VerificationError(`The ${label} is not canonical JSON.`)
  }
  return record
}

const requireDigestBoundId = async (
  record: Record<string, JsonValue>,
  excluded: string[],
  claimedDigest: Sha256Digest,
  prefix: string,
  claimedId: string,
  cryptoProvider: Crypto,
): Promise<void> => {
  const value = structuredClone(record)
  for (const key of excluded) delete value[key]
  const expected = await sha256Digest(canonicalizeJson(value), cryptoProvider)
  if (
    claimedDigest !== expected ||
    claimedId !== `${prefix}${expected.slice('sha256:'.length, 'sha256:'.length + 32)}`
  ) {
    throw new VerificationError('Incident guidance digest-bound identifier is invalid.')
  }
}

const requireRecord = (value: unknown): Record<string, JsonValue> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VerificationError('Incident guidance contract requires an object.')
  }
  return value as Record<string, JsonValue>
}

const requireExactKeys = (
  record: Record<string, JsonValue>,
  required: string[],
  optional: string[] = [],
): void => {
  const actual = Object.keys(record)
  if (
    required.some((key) => !Object.hasOwn(record, key)) ||
    actual.some((key) => !required.includes(key) && !optional.includes(key))
  ) {
    throw new VerificationError('Incident guidance contract contains unexpected fields.')
  }
}

const parseBoundedArray = <T>(
  value: unknown,
  minimum: number,
  maximum: number,
  parser: (item: unknown) => T,
): T[] => {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    throw new VerificationError('Incident guidance collection exceeds its bound.')
  }
  return value.map(parser)
}

const parseStringArray = (value: unknown, maximum: number): string[] => {
  if (
    !Array.isArray(value) ||
    value.length > maximum ||
    value.some(
      (item) => typeof item !== 'string' || item.length < 1 || item.length > 512,
    )
  ) {
    throw new VerificationError('Incident guidance string collection is invalid.')
  }
  const strings = value as string[]
  if (
    strings.join('\0') !== [...strings].sort().join('\0') ||
    new Set(strings).size !== strings.length
  ) {
    throw new VerificationError('Incident guidance values are not deterministic.')
  }
  return strings
}

const isDigest = (value: unknown): value is Sha256Digest =>
  typeof value === 'string' && DIGEST.test(value)

const isTimestamp = (value: unknown): value is string =>
  typeof value === 'string' && !Number.isNaN(Date.parse(value))

const isConfidence = (value: unknown): value is GuidanceConfidence =>
  typeof value === 'string' &&
  ['Unknown', 'Low', 'Medium', 'High', 'Confirmed'].includes(value)

const isSafeHttps = (value: string): boolean => {
  try {
    const url = new URL(value)
    return (
      url.protocol === 'https:' &&
      url.username === '' &&
      url.password === '' &&
      url.search === '' &&
      url.hash === ''
    )
  } catch {
    return false
  }
}

const equalBytes = (left: Uint8Array, right: Uint8Array): boolean =>
  left.byteLength === right.byteLength &&
  left.every((value, index) => value === right[index])

const fetchVersionedReference = (
  reference: VersionPinnedReference,
  maximumBytes: number,
  applicationRoot: URL,
  origin: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<BoundedJsonAsset> => {
  const url = resolveSameOriginAssetUrl(
    `./${reference.name}`,
    applicationRoot,
    origin,
  )
  return fetchBoundedJsonAsset(url, maximumBytes, fetchImpl, timeoutMs)
}

const trustAnchorsFromEnvironment = (): NonNullable<GuidanceLoadOptions['anchors']> => {
  const environment = import.meta.env as Record<string, string | undefined>
  const values = {
    keyId: environment.VITE_WC027_FEED_KEY_ID,
    fingerprint: environment.VITE_WC027_FEED_KEY_FINGERPRINT,
    enrichmentKeyId: environment.VITE_WC027_ENRICHMENT_KEY_ID,
    enrichmentFingerprint: environment.VITE_WC027_ENRICHMENT_KEY_FINGERPRINT,
    guidanceKeyId: environment.VITE_WC027_GUIDANCE_KEY_ID,
    guidanceFingerprint: environment.VITE_WC027_GUIDANCE_KEY_FINGERPRINT,
  }
  if (
    !values.keyId ||
    !isDigest(values.fingerprint) ||
    !values.enrichmentKeyId ||
    !isDigest(values.enrichmentFingerprint) ||
    !values.guidanceKeyId ||
    !isDigest(values.guidanceFingerprint)
  ) {
    throw new VerificationError(
      'WC-027 browser trust anchors are not configured; guidance remains unavailable.',
    )
  }
  return {
    keyId: values.keyId,
    fingerprint: values.fingerprint,
    enrichmentKeyId: values.enrichmentKeyId,
    enrichmentFingerprint: values.enrichmentFingerprint,
    guidanceKeyId: values.guidanceKeyId,
    guidanceFingerprint: values.guidanceFingerprint,
  }
}

const decodeBase64Url = (value: string): Uint8Array => {
  if (value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new VerificationError('Incident guidance signature is not valid base64url.')
  }
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/')
  const decoded = globalThis.atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='))
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0))
}

export const guidanceTemplateLabel = (code: GuidanceTemplateCode): string =>
  ({
    confirmEffectiveRule: 'Confirm the effective rule and current evidence',
    confirmBackendHealth: 'Confirm backend health and path evidence',
    inspectGuestHealth: 'Inspect guest health using the cited evidence',
    inspectNetworkPath: 'Inspect the governed network path',
    inspectRecentChange: 'Inspect the cited recent change',
    reviewApprovedManualOption: 'Review the approved manual resolution option',
    reviewRollbackAuthority: 'Review rollback authority and prerequisites',
    validateRecoverySignals: 'Validate recovery using the cited signals',
    escalateHumanReview: 'Escalate for human review',
  })[code]
