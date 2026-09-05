import { canonicalizeJson, sha256Digest, type JsonValue } from './canonical'
import {
  parsePresentationPublicKey,
  type PresentationPublicKey,
  type Sha256Digest,
} from './contracts'
import {
  PINNED_INCIDENT_KEY_FINGERPRINT,
  PINNED_INCIDENT_KEY_ID,
  VerificationError,
  computePublicKeyFingerprint,
} from './verification'
import {
  fetchBoundedJsonAsset,
  requireContentDigest,
  resolveSameOriginAssetUrl,
  type LoadPresentationOptions,
} from './runtime'

const MAX_INCIDENT_INDEX_BYTES = 64 * 1024
const MAX_INCIDENT_POINTER_BYTES = 16 * 1024
const MAX_INCIDENT_STATE_BYTES = 64 * 1024
const MAX_INCIDENT_ATTESTATION_BYTES = 24 * 1024
const MAX_INCIDENT_FEED_AGE_MS = 15 * 60_000
const MAX_CLOCK_SKEW_MS = 60_000

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

export interface IncidentState {
  schemaVersion: 'athena.incidentState.v1'
  incidentId: string
  transitionId: string
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
  notificationStatus: 'notRequired' | 'pendingDispatch'
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
  incidentId: string
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

interface ActiveIncidentEntry {
  incidentId: string
  scenario: IncidentScenario
  lifecycle: 'active'
  workloadRole: IncidentState['workloadRole']
  pointerPath: string
  pointerSha256: Sha256Digest
  detectedAt: string
  updatedAt: string
}

interface ActiveIncidentIndex {
  schemaVersion: 'athena.activeIncidentIndex.v1'
  incidents: ActiveIncidentEntry[]
  indexAttestationPath: string
  keyId: string
  keyFingerprint: Sha256Digest
  publishedAt: string
}

interface ActiveIncidentIndexAttestation {
  schemaVersion: 'athena.activeIncidentIndexAttestation.v1'
  indexDigest: Sha256Digest
  signatureAlgorithm: 'RS256'
  keyVaultKeyId: string
  detachedSignature: string
}

export interface VerifiedIncident {
  state: IncidentState
  publishedAt: string
  keyFingerprint: Sha256Digest
}

export interface VerifiedIncidentFeed {
  incidents: VerifiedIncident[]
  publishedAt: string
  keyFingerprint: Sha256Digest
}

export const assertIncidentFeedFreshness = (
  publishedAt: string,
  nowMs = Date.now(),
): void => {
  const ageMs = nowMs - Date.parse(publishedAt)
  if (!Number.isFinite(ageMs) || ageMs < -MAX_CLOCK_SKEW_MS || ageMs > MAX_INCIDENT_FEED_AGE_MS) {
    throw new VerificationError('Active incident feed is outside its freshness window.')
  }
}

export const loadVerifiedIncidents = async (
  options: LoadPresentationOptions = {},
): Promise<VerifiedIncidentFeed> => {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch
  const cryptoProvider = options.cryptoProvider ?? globalThis.crypto
  const indexUrl =
    options.manifestUrl ?? new URL('./incidents/active.json', document.baseURI)
  const origin = options.origin ?? globalThis.location.origin
  const timeoutMs = options.timeoutMs ?? 5_000
  const indexAsset = await fetchBoundedJsonAsset(
    indexUrl,
    MAX_INCIDENT_INDEX_BYTES,
    fetchImpl,
    timeoutMs,
  )
  const index = parseActiveIncidentIndex(indexAsset.value)
  const applicationRoot = new URL('/', `${origin}/`)
  const indexAttestationUrl = resolveSameOriginAssetUrl(
    index.indexAttestationPath,
    applicationRoot,
    origin,
  )
  const keyUrl = resolveSameOriginAssetUrl(
    './trust/incident-public-key.jwk.json',
    applicationRoot,
    origin,
  )
  const [indexAttestationAsset, keyAsset] = await Promise.all([
    fetchBoundedJsonAsset(
      indexAttestationUrl,
      MAX_INCIDENT_ATTESTATION_BYTES,
      fetchImpl,
      timeoutMs,
    ),
    fetchBoundedJsonAsset(keyUrl, MAX_INCIDENT_POINTER_BYTES, fetchImpl, timeoutMs),
  ])
  const indexAttestation = parseActiveIncidentIndexAttestation(
    indexAttestationAsset.value,
  )
  const key = parsePresentationPublicKey(keyAsset.value)
  const importedKey = await verifySignedBytes(
    indexAsset.bytes,
    indexAttestation.indexDigest,
    indexAttestation.detachedSignature,
    index.keyId,
    index.keyFingerprint,
    indexAttestation.keyVaultKeyId,
    key,
    cryptoProvider,
    'Active incident index',
  )
  assertIncidentFeedFreshness(index.publishedAt)
  const incidents = await Promise.all(
    index.incidents.map((entry) =>
      loadVerifiedIncidentEntry(
        entry,
        applicationRoot,
        origin,
        fetchImpl,
        timeoutMs,
        key,
        importedKey,
        cryptoProvider,
      ),
    ),
  )
  return {
    incidents,
    publishedAt: index.publishedAt,
    keyFingerprint: key.fingerprint,
  }
}

const loadVerifiedIncidentEntry = async (
  entry: ActiveIncidentEntry,
  applicationRoot: URL,
  origin: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
  key: PresentationPublicKey,
  importedKey: CryptoKey,
  cryptoProvider: Crypto,
): Promise<VerifiedIncident> => {
  const pointerUrl = resolveSameOriginAssetUrl(
    entry.pointerPath,
    applicationRoot,
    origin,
  )
  const pointerAsset = await fetchBoundedJsonAsset(
    pointerUrl,
    MAX_INCIDENT_POINTER_BYTES,
    fetchImpl,
    timeoutMs,
  )
  await requireContentDigest(
    pointerAsset.bytes,
    entry.pointerSha256,
    cryptoProvider,
    'incident pointer',
  )
  const pointer = parseIncidentPointer(pointerAsset.value)
  if (
    entry.pointerPath !==
    `${pointer.statePath.slice(0, -'/state.json'.length)}/pointer.json`
  ) {
    throw new VerificationError('Active incident pointer version binding is invalid.')
  }
  const pointerAttestationUrl = resolveSameOriginAssetUrl(
    pointer.pointerAttestationPath,
    applicationRoot,
    origin,
  )
  const pointerAttestationAsset = await fetchBoundedJsonAsset(
    pointerAttestationUrl,
    MAX_INCIDENT_ATTESTATION_BYTES,
    fetchImpl,
    timeoutMs,
  )
  const pointerAttestation = parseIncidentPointerAttestation(
    pointerAttestationAsset.value,
  )
  await verifySignedBytes(
    pointerAsset.bytes,
    pointerAttestation.pointerDigest,
    pointerAttestation.detachedSignature,
    pointer.keyId,
    pointer.keyFingerprint,
    pointerAttestation.keyVaultKeyId,
    key,
    cryptoProvider,
    'Incident pointer',
    importedKey,
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
  await verifyIncident(pointer, state, attestation, key, cryptoProvider, importedKey)
  if (
    state.incidentId !== entry.incidentId ||
    state.scenario !== entry.scenario ||
    state.lifecycle !== entry.lifecycle ||
    state.workloadRole !== entry.workloadRole ||
    state.detectedAt !== entry.detectedAt ||
    state.updatedAt !== entry.updatedAt
  ) {
    throw new VerificationError('Active incident entry binding is invalid.')
  }
  if (Date.parse(state.updatedAt) - Date.now() > 60_000) {
    throw new VerificationError('Incident state timestamp is in the future.')
  }
  return { state, publishedAt: pointer.publishedAt, keyFingerprint: key.fingerprint }
}

const verifySignedBytes = async (
  payload: Uint8Array,
  digest: Sha256Digest,
  signatureValue: string,
  keyId: string,
  keyFingerprint: Sha256Digest,
  attestationKeyId: string,
  key: PresentationPublicKey,
  cryptoProvider: Crypto,
  label: 'Active incident index' | 'Incident pointer',
  importedKey?: CryptoKey,
): Promise<CryptoKey> => {
  if (
    keyId !== PINNED_INCIDENT_KEY_ID ||
    key.keyId !== PINNED_INCIDENT_KEY_ID ||
    keyFingerprint !== PINNED_INCIDENT_KEY_FINGERPRINT ||
    key.fingerprint !== PINNED_INCIDENT_KEY_FINGERPRINT ||
    attestationKeyId !== PINNED_INCIDENT_KEY_ID
  ) {
    throw new VerificationError(`${label} trust binding is invalid.`)
  }
  const digestLabel =
    label === 'Active incident index' ? 'active incident index' : 'incident pointer'
  await requireContentDigest(payload, digest, cryptoProvider, digestLabel)
  const imported =
    importedKey ??
    (await cryptoProvider.subtle.importKey(
      'jwk',
      key.jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['verify'],
    ))
  if ((await computePublicKeyFingerprint(imported, cryptoProvider)) !== key.fingerprint) {
    throw new VerificationError(`${label} key fingerprint is invalid.`)
  }
  const signature = decodeBase64Url(signatureValue)
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
    throw new VerificationError(`${label} signature is invalid.`)
  }
  return imported
}

export const verifyIncident = async (
  pointer: IncidentPointer,
  state: IncidentState,
  attestation: IncidentAttestation,
  key: PresentationPublicKey,
  cryptoProvider: Crypto = globalThis.crypto,
  importedKey?: CryptoKey,
): Promise<void> => {
  if (
    pointer.incidentId !== state.incidentId ||
    pointer.keyId !== PINNED_INCIDENT_KEY_ID ||
    key.keyId !== PINNED_INCIDENT_KEY_ID ||
    pointer.keyFingerprint !== PINNED_INCIDENT_KEY_FINGERPRINT ||
    key.fingerprint !== PINNED_INCIDENT_KEY_FINGERPRINT ||
    attestation.keyVaultKeyId !== PINNED_INCIDENT_KEY_ID ||
    attestation.resultDigest !== state.resultDigest ||
    !pointer.statePath.startsWith(`./incidents/${state.incidentId}/versions/`) ||
    !pointer.attestationPath.startsWith(
      `./incidents/${state.incidentId}/versions/`,
    ) ||
    Date.parse(pointer.publishedAt) < Date.parse(state.updatedAt)
  ) {
    throw new VerificationError('Incident trust binding is invalid.')
  }
  const imported =
    importedKey ??
    (await cryptoProvider.subtle.importKey(
      'jwk',
      key.jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['verify'],
    ))
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

const parseActiveIncidentIndex = (value: unknown): ActiveIncidentIndex => {
  const record = exactRecord(value, [
    'schemaVersion',
    'incidents',
    'indexAttestationPath',
    'keyId',
    'keyFingerprint',
    'publishedAt',
  ])
  if (
    record.schemaVersion !== 'athena.activeIncidentIndex.v1' ||
    !Array.isArray(record.incidents) ||
    record.incidents.length > 64 ||
    !isIndexAttestationPath(record.indexAttestationPath) ||
    typeof record.keyId !== 'string' ||
    !isDigest(record.keyFingerprint) ||
    !isTimestamp(record.publishedAt)
  ) {
    throw new VerificationError('Active incident index contract is invalid.')
  }
  const incidents = record.incidents.map(parseActiveIncidentEntry)
  const incidentIds = incidents.map((entry) => entry.incidentId)
  if (
    incidentIds.some((value, index) => index > 0 && incidentIds[index - 1]! >= value)
  ) {
    throw new VerificationError('Active incident index ordering is invalid.')
  }
  return { ...record, incidents } as unknown as ActiveIncidentIndex
}

const parseActiveIncidentEntry = (value: unknown): ActiveIncidentEntry => {
  const record = exactRecord(value, [
    'incidentId',
    'scenario',
    'lifecycle',
    'workloadRole',
    'pointerPath',
    'pointerSha256',
    'detectedAt',
    'updatedAt',
  ])
  if (
    typeof record.incidentId !== 'string' ||
    !/^inc-[a-f0-9]{12}$/.test(record.incidentId) ||
    !['singletonDatabaseFailure', 'webServerFailure', 'loadBalancerFailure'].includes(
      String(record.scenario),
    ) ||
    record.lifecycle !== 'active' ||
    !['database-primary', 'web', 'load-balancer'].includes(
      String(record.workloadRole),
    ) ||
    !new RegExp(
      `^\\./incidents/${record.incidentId}/versions/[a-f0-9]{64}/pointer\\.json$`,
    ).test(String(record.pointerPath)) ||
    !isDigest(record.pointerSha256) ||
    !isTimestamp(record.detectedAt) ||
    !isTimestamp(record.updatedAt) ||
    Date.parse(record.updatedAt) < Date.parse(record.detectedAt)
  ) {
    throw new VerificationError('Active incident entry contract is invalid.')
  }
  return record as unknown as ActiveIncidentEntry
}

const parseIncidentPointer = (value: unknown): IncidentPointer => {
  const record = exactRecord(value, [
    'schemaVersion',
    'incidentId',
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
    typeof record.incidentId !== 'string' ||
    !/^inc-[a-f0-9]{12}$/.test(record.incidentId) ||
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
  const pointer = record as unknown as IncidentPointer
  const versionPrefix = `./incidents/${pointer.incidentId}/versions/`
  const stateMatch = pointer.statePath.match(
    new RegExp(
      `^${versionPrefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([a-f0-9]{64})/state\\.json$`,
    ),
  )
  if (
    stateMatch === null ||
    pointer.attestationPath !==
      `${versionPrefix}${stateMatch[1]!}/attestation.json` ||
    pointer.pointerAttestationPath !==
      `${versionPrefix}${stateMatch[1]!}/pointer-attestation.json`
  ) {
    throw new VerificationError('Incident pointer version binding is invalid.')
  }
  return pointer
}

const parseIncidentState = (value: unknown): IncidentState => {
  const record = exactRecord(value, [
    'schemaVersion',
    'incidentId',
    'transitionId',
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
    typeof record.transitionId !== 'string' ||
    !/^wc016-[a-f0-9]{64}$/.test(record.transitionId) ||
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
    record.findings.length > 32 ||
    record.findings.some((finding) => !isIncidentFinding(finding)) ||
    !Array.isArray(record.reasoning) ||
    record.reasoning.length < 1 ||
    record.reasoning.length > 16 ||
    record.reasoning.some(
      (item) => typeof item !== 'string' || item.length < 1 || item.length > 512,
    ) ||
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
    !['notRequired', 'pendingDispatch'].includes(String(record.notificationStatus)) ||
    !/^inc-[a-f0-9]{12}$/.test(record.incidentId) ||
    Date.parse(record.updatedAt) < Date.parse(record.detectedAt) ||
    (record.lifecycle === 'active' && record.availability === 'normal') ||
    (record.lifecycle === 'resolved' && record.availability !== 'normal') ||
    (['active', 'resolved'].includes(String(record.lifecycle)) &&
      record.notificationStatus !== 'pendingDispatch') ||
    (!['active', 'resolved'].includes(String(record.lifecycle)) &&
      record.notificationStatus !== 'notRequired')
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

const parseActiveIncidentIndexAttestation = (
  value: unknown,
): ActiveIncidentIndexAttestation => {
  const record = exactRecord(value, [
    'schemaVersion',
    'indexDigest',
    'signatureAlgorithm',
    'keyVaultKeyId',
    'detachedSignature',
  ])
  if (
    record.schemaVersion !== 'athena.activeIncidentIndexAttestation.v1' ||
    !isDigest(record.indexDigest) ||
    record.signatureAlgorithm !== 'RS256' ||
    typeof record.keyVaultKeyId !== 'string' ||
    typeof record.detachedSignature !== 'string' ||
    !/^[A-Za-z0-9_-]+$/.test(record.detachedSignature)
  ) {
    throw new VerificationError(
      'Active incident index attestation contract is invalid.',
    )
  }
  return record as unknown as ActiveIncidentIndexAttestation
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
  typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value) &&
  !Number.isNaN(Date.parse(value))
const isAssetPath = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^\.\/incidents\/[a-z0-9][a-z0-9./-]*\.json$/.test(value) &&
  !value.includes('..')
const isIndexAttestationPath = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^\.\/incidents\/index-attestations\/[a-f0-9]{64}\.json$/.test(value)

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
