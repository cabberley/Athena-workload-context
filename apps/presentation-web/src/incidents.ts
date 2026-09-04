import { canonicalizeJson, sha256Digest, type JsonValue } from './canonical'
import {
  parsePresentationPublicKey,
  type PresentationPublicKey,
  type Sha256Digest,
} from './contracts'
import {
  PINNED_LIVE_PRESENTATION_KEY_FINGERPRINT,
  PINNED_PRESENTATION_KEY_ID,
  VerificationError,
  computePublicKeyFingerprint,
} from './verification'
import {
  fetchBoundedJsonAsset,
  requireContentDigest,
  resolveSameOriginAssetUrl,
  type LoadPresentationOptions,
} from './runtime'

const MAX_INCIDENT_POINTER_BYTES = 16 * 1024
const MAX_INCIDENT_STATE_BYTES = 64 * 1024
const MAX_INCIDENT_ATTESTATION_BYTES = 24 * 1024

export type IncidentScenario =
  | 'singletonDatabaseFailure'
  | 'webServerFailure'
  | 'loadBalancerFailure'
export type IncidentLifecycle =
  | 'detected'
  | 'queued'
  | 'reassessing'
  | 'active'
  | 'recoveryObserved'
  | 'resolved'
  | 'failedClosed'

export interface IncidentState {
  schemaVersion: 'athena.incidentState.v1'
  incidentId: string
  scenario: IncidentScenario
  lifecycle: IncidentLifecycle
  workloadRole: 'database-primary' | 'web' | 'load-balancer'
  detectedAt: string
  updatedAt: string
  targetBinding: Sha256Digest
  availability: 'normal' | 'warning' | 'critical' | 'unknown'
  blastRadius:
    | 'none'
    | 'web-tier'
    | 'ingress-edge'
    | 'data-tier'
    | 'whole-workload'
    | 'unknown'
  operatorAttention: 'normal' | 'required' | 'urgent'
  findings: Array<{
    clauseId: string
    verdict: 'pass' | 'fail' | 'resolved' | 'review'
    summary: string
    evidenceRefs: string[]
  }>
  reasoning: string[]
  notificationStatus: 'notRequired' | 'pending' | 'sent' | 'failed'
  resultDigest: Sha256Digest
  noAutoRemediation: true
}

interface IncidentAttestation {
  schemaVersion: 'athena.incidentStateAttestation.v1'
  resultDigest: Sha256Digest
  signatureAlgorithm: 'RS256'
  keyVaultKeyId: string
  detachedSignature: string
}

interface IncidentPointer {
  schemaVersion: 'athena.incidentFeed.v1'
  statePath: string
  stateSha256: Sha256Digest
  attestationPath: string
  attestationSha256: Sha256Digest
  pointerAttestationPath: string
  keyId: string
  keyFingerprint: Sha256Digest
  publishedAt: string
}

interface IncidentPointerAttestation {
  schemaVersion: 'athena.incidentFeedAttestation.v1'
  pointerDigest: Sha256Digest
  signatureAlgorithm: 'RS256'
  keyVaultKeyId: string
  detachedSignature: string
}

export interface VerifiedIncident {
  state: IncidentState
  publishedAt: string
  keyFingerprint: Sha256Digest
}

export const loadVerifiedIncident = async (
  options: LoadPresentationOptions = {},
): Promise<VerifiedIncident> => {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch
  const cryptoProvider = options.cryptoProvider ?? globalThis.crypto
  const pointerUrl =
    options.manifestUrl ?? new URL('./incidents/current.json', document.baseURI)
  const origin = options.origin ?? globalThis.location.origin
  const timeoutMs = options.timeoutMs ?? 5_000
  const pointerAsset = await fetchBoundedJsonAsset(
    pointerUrl,
    MAX_INCIDENT_POINTER_BYTES,
    fetchImpl,
    timeoutMs,
  )
  const pointer = parseIncidentPointer(pointerAsset.value)
  const applicationRoot = new URL('/', `${origin}/`)
  const pointerAttestationUrl = resolveSameOriginAssetUrl(
    pointer.pointerAttestationPath,
    applicationRoot,
    origin,
  )
  const keyUrl = resolveSameOriginAssetUrl(
    './trust/live-presentation-public-key.jwk.json',
    applicationRoot,
    origin,
  )
  const [pointerAttestationAsset, keyAsset] = await Promise.all([
    fetchBoundedJsonAsset(
      pointerAttestationUrl,
      MAX_INCIDENT_ATTESTATION_BYTES,
      fetchImpl,
      timeoutMs,
    ),
    fetchBoundedJsonAsset(keyUrl, MAX_INCIDENT_POINTER_BYTES, fetchImpl, timeoutMs),
  ])
  const pointerAttestation = parseIncidentPointerAttestation(
    pointerAttestationAsset.value,
  )
  const key = parsePresentationPublicKey(keyAsset.value)
  await verifyIncidentPointer(
    pointerAsset.bytes,
    pointer,
    pointerAttestation,
    key,
    cryptoProvider,
  )
  const stateUrl = resolveSameOriginAssetUrl(
    pointer.statePath,
    applicationRoot,
    origin,
  )
  const attestationUrl = resolveSameOriginAssetUrl(
    pointer.attestationPath,
    applicationRoot,
    origin,
  )
  const [stateAsset, attestationAsset] = await Promise.all([
    fetchBoundedJsonAsset(stateUrl, MAX_INCIDENT_STATE_BYTES, fetchImpl, timeoutMs),
    fetchBoundedJsonAsset(
      attestationUrl,
      MAX_INCIDENT_ATTESTATION_BYTES,
      fetchImpl,
      timeoutMs,
    ),
  ])
  await Promise.all([
    requireContentDigest(
      stateAsset.bytes,
      pointer.stateSha256,
      cryptoProvider,
      'incident state',
    ),
    requireContentDigest(
      attestationAsset.bytes,
      pointer.attestationSha256,
      cryptoProvider,
      'incident attestation',
    ),
  ])
  const state = parseIncidentState(stateAsset.value)
  const attestation = parseIncidentAttestation(attestationAsset.value)
  await verifyIncident(pointer, state, attestation, key, cryptoProvider)
  const ageMs = Date.now() - Date.parse(state.updatedAt)
  if (ageMs < -60_000 || ageMs > 15 * 60_000) {
    throw new VerificationError('Incident state is outside its freshness window.')
  }
  return { state, publishedAt: pointer.publishedAt, keyFingerprint: key.fingerprint }
}

const verifyIncidentPointer = async (
  pointerBytes: Uint8Array,
  pointer: IncidentPointer,
  attestation: IncidentPointerAttestation,
  key: PresentationPublicKey,
  cryptoProvider: Crypto,
): Promise<void> => {
  if (
    pointer.keyId !== PINNED_PRESENTATION_KEY_ID ||
    key.keyId !== PINNED_PRESENTATION_KEY_ID ||
    pointer.keyFingerprint !== PINNED_LIVE_PRESENTATION_KEY_FINGERPRINT ||
    key.fingerprint !== PINNED_LIVE_PRESENTATION_KEY_FINGERPRINT ||
    attestation.keyVaultKeyId !== PINNED_PRESENTATION_KEY_ID
  ) {
    throw new VerificationError('Incident pointer trust binding is invalid.')
  }
  await requireContentDigest(
    pointerBytes,
    attestation.pointerDigest,
    cryptoProvider,
    'incident pointer',
  )
  const imported = await cryptoProvider.subtle.importKey(
    'jwk',
    key.jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify'],
  )
  if ((await computePublicKeyFingerprint(imported, cryptoProvider)) !== key.fingerprint) {
    throw new VerificationError('Incident pointer key fingerprint is invalid.')
  }
  const signature = decodeBase64Url(attestation.detachedSignature)
  const algorithm = imported.algorithm as RsaHashedKeyAlgorithm
  if (
    signature.byteLength !== algorithm.modulusLength / 8 ||
    !(await cryptoProvider.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      imported,
      signature,
      pointerBytes,
    ))
  ) {
    throw new VerificationError('Incident pointer signature is invalid.')
  }
}

export const verifyIncident = async (
  pointer: IncidentPointer,
  state: IncidentState,
  attestation: IncidentAttestation,
  key: PresentationPublicKey,
  cryptoProvider: Crypto = globalThis.crypto,
): Promise<void> => {
  if (
    pointer.keyId !== PINNED_PRESENTATION_KEY_ID ||
    key.keyId !== PINNED_PRESENTATION_KEY_ID ||
    pointer.keyFingerprint !== PINNED_LIVE_PRESENTATION_KEY_FINGERPRINT ||
    key.fingerprint !== PINNED_LIVE_PRESENTATION_KEY_FINGERPRINT ||
    attestation.keyVaultKeyId !== PINNED_PRESENTATION_KEY_ID ||
    attestation.resultDigest !== state.resultDigest ||
    !pointer.statePath.startsWith(`./incidents/${state.incidentId}/`) ||
    !pointer.attestationPath.startsWith(`./incidents/${state.incidentId}/`) ||
    Date.parse(pointer.publishedAt) < Date.parse(state.updatedAt) ||
    Date.parse(pointer.publishedAt) - Date.parse(state.updatedAt) > 60_000
  ) {
    throw new VerificationError('Incident trust binding is invalid.')
  }
  const imported = await cryptoProvider.subtle.importKey(
    'jwk',
    key.jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify'],
  )
  if ((await computePublicKeyFingerprint(imported, cryptoProvider)) !== key.fingerprint) {
    throw new VerificationError('Incident key fingerprint is invalid.')
  }
  const preimage = incidentCanonicalPreimage(state)
  if ((await sha256Digest(preimage, cryptoProvider)) !== state.resultDigest) {
    throw new VerificationError('Incident result digest is invalid.')
  }
  const signature = decodeBase64Url(attestation.detachedSignature)
  const algorithm = imported.algorithm as RsaHashedKeyAlgorithm
  if (signature.byteLength !== algorithm.modulusLength / 8) {
    throw new VerificationError('Incident signature has an invalid RSA size.')
  }
  const valid = await cryptoProvider.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    imported,
    signature,
    preimage,
  )
  if (!valid) throw new VerificationError('Incident signature is invalid.')
}

const incidentCanonicalPreimage = (state: IncidentState): Uint8Array => {
  const value = structuredClone(state) as unknown as Record<string, JsonValue>
  delete value.resultDigest
  return new TextEncoder().encode(canonicalizeJson(value))
}

const parseIncidentPointer = (value: unknown): IncidentPointer => {
  const record = exactRecord(value, [
    'schemaVersion',
    'statePath',
    'stateSha256',
    'attestationPath',
    'attestationSha256',
    'pointerAttestationPath',
    'keyId',
    'keyFingerprint',
    'publishedAt',
  ])
  if (
    record.schemaVersion !== 'athena.incidentFeed.v1' ||
    !isAssetPath(record.statePath) ||
    !isAssetPath(record.attestationPath) ||
    !isDigest(record.stateSha256) ||
    !isDigest(record.attestationSha256) ||
    !isAssetPath(record.pointerAttestationPath) ||
    typeof record.keyId !== 'string' ||
    !isDigest(record.keyFingerprint) ||
    !isTimestamp(record.publishedAt)
  ) {
    throw new VerificationError('Incident pointer contract is invalid.')
  }
  return record as unknown as IncidentPointer
}

const parseIncidentState = (value: unknown): IncidentState => {
  const record = exactRecord(value, [
    'schemaVersion',
    'incidentId',
    'scenario',
    'lifecycle',
    'workloadRole',
    'detectedAt',
    'updatedAt',
    'targetBinding',
    'availability',
    'blastRadius',
    'operatorAttention',
    'findings',
    'reasoning',
    'notificationStatus',
    'resultDigest',
    'noAutoRemediation',
  ])
  if (
    record.schemaVersion !== 'athena.incidentState.v1' ||
    typeof record.incidentId !== 'string' ||
    !['singletonDatabaseFailure', 'webServerFailure', 'loadBalancerFailure'].includes(
      String(record.scenario),
    ) ||
    ![
      'detected',
      'queued',
      'reassessing',
      'active',
      'recoveryObserved',
      'resolved',
      'failedClosed',
    ].includes(String(record.lifecycle)) ||
    !['database-primary', 'web', 'load-balancer'].includes(
      String(record.workloadRole),
    ) ||
    !isTimestamp(record.detectedAt) ||
    !isTimestamp(record.updatedAt) ||
    !isDigest(record.targetBinding) ||
    !isDigest(record.resultDigest) ||
    record.noAutoRemediation !== true ||
    !Array.isArray(record.findings) ||
    record.findings.length < 1 ||
    !Array.isArray(record.reasoning) ||
    record.reasoning.length < 1 ||
    record.reasoning.length > 16 ||
    record.reasoning.some(
      (item) => typeof item !== 'string' || item.length < 1 || item.length > 512,
    ) ||
    !Array.isArray(record.findings) ||
    record.findings.length > 32 ||
    record.findings.some((finding) => !isIncidentFinding(finding)) ||
    !['normal', 'warning', 'critical', 'unknown'].includes(
      String(record.availability),
    ) ||
    ![
      'none',
      'web-tier',
      'ingress-edge',
      'data-tier',
      'whole-workload',
      'unknown',
    ].includes(String(record.blastRadius)) ||
    !['normal', 'required', 'urgent'].includes(String(record.operatorAttention)) ||
    !['notRequired', 'pending', 'sent', 'failed'].includes(
      String(record.notificationStatus),
    ) ||
    !/^inc-[a-f0-9]{12}$/.test(record.incidentId) ||
    Date.parse(record.updatedAt) < Date.parse(record.detectedAt)
  ) {
    throw new VerificationError('Incident state contract is invalid.')
  }
  return record as unknown as IncidentState
}

const parseIncidentAttestation = (value: unknown): IncidentAttestation => {
  const record = exactRecord(value, [
    'schemaVersion',
    'resultDigest',
    'signatureAlgorithm',
    'keyVaultKeyId',
    'detachedSignature',
  ])
  if (
    record.schemaVersion !== 'athena.incidentStateAttestation.v1' ||
    !isDigest(record.resultDigest) ||
    record.signatureAlgorithm !== 'RS256' ||
    typeof record.keyVaultKeyId !== 'string' ||
    typeof record.detachedSignature !== 'string' ||
    !/^[A-Za-z0-9_-]+$/.test(record.detachedSignature)
  ) {
    throw new VerificationError('Incident attestation contract is invalid.')
  }
  return record as unknown as IncidentAttestation
}

const parseIncidentPointerAttestation = (
  value: unknown,
): IncidentPointerAttestation => {
  const record = exactRecord(value, [
    'schemaVersion',
    'pointerDigest',
    'signatureAlgorithm',
    'keyVaultKeyId',
    'detachedSignature',
  ])
  if (
    record.schemaVersion !== 'athena.incidentFeedAttestation.v1' ||
    !isDigest(record.pointerDigest) ||
    record.signatureAlgorithm !== 'RS256' ||
    typeof record.keyVaultKeyId !== 'string' ||
    typeof record.detachedSignature !== 'string' ||
    !/^[A-Za-z0-9_-]+$/.test(record.detachedSignature)
  ) {
    throw new VerificationError('Incident pointer attestation contract is invalid.')
  }
  return record as unknown as IncidentPointerAttestation
}

const exactRecord = (value: unknown, keys: string[]): Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new VerificationError('Incident asset must be an object.')
  }
  const record = value as Record<string, unknown>
  if (
    Object.keys(record).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(record, key))
  ) {
    throw new VerificationError('Incident asset contains unexpected fields.')
  }
  return record
}

const isDigest = (value: unknown): value is Sha256Digest =>
  typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value)
const isTimestamp = (value: unknown): value is string =>
  typeof value === 'string' && !Number.isNaN(Date.parse(value))
const isAssetPath = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^\.\/incidents\/[a-z0-9][a-z0-9./-]*\.json$/.test(value) &&
  !value.includes('..')

const isIncidentFinding = (value: unknown): boolean => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  return (
    Object.keys(record).length === 4 &&
    typeof record.clauseId === 'string' &&
    record.clauseId.length >= 1 &&
    record.clauseId.length <= 128 &&
    ['pass', 'fail', 'resolved', 'review'].includes(String(record.verdict)) &&
    typeof record.summary === 'string' &&
    record.summary.length >= 1 &&
    record.summary.length <= 512 &&
    Array.isArray(record.evidenceRefs) &&
    record.evidenceRefs.length >= 1 &&
    record.evidenceRefs.length <= 32 &&
    record.evidenceRefs.every(
      (item) => typeof item === 'string' && item.length >= 1 && item.length <= 512,
    )
  )
}

const decodeBase64Url = (value: string): Uint8Array => {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/')
  const decoded = globalThis.atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='))
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0))
}
