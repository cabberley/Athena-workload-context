export const PRESENTATION_SCHEMA_VERSION = 'athena.argus.presentation.v1' as const
export const ATTESTATION_SCHEMA_VERSION =
  'athena.argus.presentationAttestation.v1' as const
export const RUNTIME_SCHEMA_VERSION = 'athena.presentationWeb.runtime.v1' as const
export const LIVE_RUNTIME_SCHEMA_VERSION = 'athena.presentationWeb.runtime.v2' as const
export const PUBLIC_KEY_SCHEMA_VERSION = 'athena.presentationWeb.publicKey.v1' as const
export const REVIEWED_PUBLIC_KEY_PATH =
  './trust/presentation-public-key.jwk.json' as const
export const REVIEWED_PUBLIC_KEY_ASSET_SHA256 =
  'sha256:0259687206cff5a27bcc32e0456f8a1e13fe10f0db2ef19935bf4a87a437b107' as const
export const REVIEWED_LIVE_PUBLIC_KEY_PATH =
  './trust/live-presentation-public-key.jwk.json' as const
export const REVIEWED_LIVE_PUBLIC_KEY_ASSET_SHA256 =
  'sha256:a8937fd9e7acb7b3010369184aa439284dfd6d0da072ff47360f8034152eb9b9' as const
export const SCENARIO_ID = 'athena-web-node-fault.v1' as const
export const SYNTHETIC_WORKLOAD_NAME = 'Synthetic Athena web workload' as const
export const LIFECYCLE_PHASES = ['baseline', 'faulted', 'recovered'] as const

export type LifecyclePhase = (typeof LIFECYCLE_PHASES)[number]
export type Sha256Digest = `sha256:${string}`
export type ServiceState = 'healthy' | 'degraded-redundancy' | 'recovered'
export type Verdict = 'pass' | 'fail' | 'resolved'
export type RiskLevel = 'normal' | 'warning'

export interface PresentationFaultRun {
  faultRunId: string
  targetVmName: string
  afterPowerState: 'stopped' | 'running'
}

export interface PresentationFinding {
  clauseId: string
  verdict: Verdict
  summary: string
  evidenceRefs: string[]
}

export interface PresentationPayload {
  schemaVersion: typeof PRESENTATION_SCHEMA_VERSION
  scenarioId: typeof SCENARIO_ID
  phase: LifecyclePhase
  workload: {
    name: typeof SYNTHETIC_WORKLOAD_NAME
    manifestId: string
    manifestVersion: string
    profileId: string
    resourceGroup: string
  }
  faultRun?: PresentationFaultRun
  athena: {
    snapshotId: string
    artifactDigest: Sha256Digest
    semanticDigest: Sha256Digest
    resultDigest: Sha256Digest
    signatureAlgorithm: 'RS256'
    keyVaultKeyId: string
  }
  runtimeState: {
    webTier: {
      expectedNodes: number
      runningNodes: number
      faultedNodes: number
      serviceState: ServiceState
    }
  }
  findings: PresentationFinding[]
  argus: {
    riskLevel: RiskLevel
    predictedIssue: string
    recommendedAction: string
  }
}

export interface PresentationAttestation {
  schemaVersion: typeof ATTESTATION_SCHEMA_VERSION
  resultDigest: Sha256Digest
  signatureAlgorithm: 'RS256'
  keyVaultKeyId: string
  detachedSignature: string
}

export interface RuntimePhaseAsset {
  phase: LifecyclePhase
  payloadPath: string
  payloadSha256: Sha256Digest
  attestationPath: string
  attestationSha256: Sha256Digest
}

export interface RuntimeManifestKey {
  path: string
  assetSha256: Sha256Digest
  keyId: string
  fingerprint: Sha256Digest
}

export interface StaticRuntimeManifest {
  schemaVersion: typeof RUNTIME_SCHEMA_VERSION
  classification: 'synthetic-demo-only'
  key: RuntimeManifestKey
  phases: RuntimePhaseAsset[]
}

export interface LiveRuntimeManifest {
  schemaVersion: typeof LIVE_RUNTIME_SCHEMA_VERSION
  classification: 'live-workload-evaluation'
  runId: string
  targetResourceGroup: string
  evaluatedAt: string
  publishedAt: string
  key: RuntimeManifestKey
  phases: RuntimePhaseAsset[]
}

export type RuntimeManifest = StaticRuntimeManifest | LiveRuntimeManifest

export interface PresentationPublicKey {
  schemaVersion: typeof PUBLIC_KEY_SCHEMA_VERSION
  keyId: string
  fingerprint: Sha256Digest
  jwk: JsonWebKey
}

export const PHASE_CONTRACT = {
  baseline: {
    serviceState: 'healthy',
    verdict: 'pass',
    riskLevel: 'normal',
    summary: 'Both synthetic web nodes are represented as running.',
    predictedIssue: 'No synthetic web-node fault detected',
    recommendedAction:
      'Observe the synthetic baseline and confirm both redundant nodes are represented as healthy.',
  },
  faulted: {
    serviceState: 'degraded-redundancy',
    verdict: 'fail',
    riskLevel: 'warning',
    summary: 'One redundant synthetic web node is stopped while its peer remains running.',
    predictedIssue: 'Reduced synthetic web-tier redundancy',
    recommendedAction:
      'Review the synthetic finding and authorize recovery only through the separate demo operator workflow.',
  },
  recovered: {
    serviceState: 'recovered',
    verdict: 'resolved',
    riskLevel: 'normal',
    summary: 'The affected synthetic web node is represented as running after recovery.',
    predictedIssue: 'Synthetic web-tier redundancy restored',
    recommendedAction:
      'Confirm the synthetic node and redundancy indicators are healthy, then close the demo finding.',
  },
} as const satisfies Record<
  LifecyclePhase,
  {
    serviceState: ServiceState
    verdict: Verdict
    riskLevel: RiskLevel
    summary: string
    predictedIssue: string
    recommendedAction: string
  }
>

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/
const SYNTHETIC_ID_PATTERN = /^synthetic-[a-z0-9][a-z0-9-]{0,126}$/
const SYNTHETIC_KEY_PATTERN = /^synthetic-key:\/\/[a-z0-9][a-z0-9._/-]{0,199}$/
const SEMVER_PATTERN =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/
const ASSET_PATH_PATTERN = /^\.\/[a-z0-9][a-z0-9./-]*\.json$/
const LIVE_RUN_ID_PATTERN =
  /^synthetic-run-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const RESOURCE_GROUP_PATTERN = /^[A-Za-z0-9_().-]{1,90}$/
const UTC_TIMESTAMP_PATTERN =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$/
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/
const JWK_COMPONENT_PATTERN = /^[A-Za-z0-9_-]+$/

export class ContractValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ContractValidationError'
  }
}

export const parsePresentationPayload = (
  value: unknown,
  expectedPhase?: LifecyclePhase,
): PresentationPayload => {
  const payload = requireRecord(value, 'presentation payload')
  const phase = readPhase(payload.phase, 'presentation phase')
  const payloadKeys =
    phase === 'baseline'
      ? [
          'schemaVersion',
          'scenarioId',
          'phase',
          'workload',
          'athena',
          'runtimeState',
          'findings',
          'argus',
        ]
      : [
          'schemaVersion',
          'scenarioId',
          'phase',
          'workload',
          'faultRun',
          'athena',
          'runtimeState',
          'findings',
          'argus',
        ]
  assertExactKeys(payload, payloadKeys, 'presentation payload')
  if (expectedPhase !== undefined && phase !== expectedPhase) {
    fail('presentation phase does not match the requested lifecycle phase')
  }

  const workload = parseWorkload(payload.workload)
  const athena = parseAthena(payload.athena)
  const runtimeState = parseRuntimeState(payload.runtimeState, phase)
  const findings = parseFindings(payload.findings, phase)
  const argus = parseArgus(payload.argus, phase)
  const faultRun =
    phase === 'baseline' ? undefined : parseFaultRun(payload.faultRun, phase)

  return {
    schemaVersion: requireLiteral(
      payload.schemaVersion,
      PRESENTATION_SCHEMA_VERSION,
      'presentation schemaVersion',
    ),
    scenarioId: requireLiteral(payload.scenarioId, SCENARIO_ID, 'presentation scenarioId'),
    phase,
    workload,
    ...(faultRun === undefined ? {} : { faultRun }),
    athena,
    runtimeState,
    findings,
    argus,
  }
}

export const parsePresentationAttestation = (
  value: unknown,
): PresentationAttestation => {
  const attestation = requireRecord(value, 'presentation attestation')
  assertExactKeys(
    attestation,
    [
      'schemaVersion',
      'resultDigest',
      'signatureAlgorithm',
      'keyVaultKeyId',
      'detachedSignature',
    ],
    'presentation attestation',
  )
  return {
    schemaVersion: requireLiteral(
      attestation.schemaVersion,
      ATTESTATION_SCHEMA_VERSION,
      'attestation schemaVersion',
    ),
    resultDigest: requireDigest(attestation.resultDigest, 'attestation resultDigest'),
    signatureAlgorithm: requireLiteral(
      attestation.signatureAlgorithm,
      'RS256',
      'attestation signatureAlgorithm',
    ),
    keyVaultKeyId: requireSyntheticKeyId(
      attestation.keyVaultKeyId,
      'attestation keyVaultKeyId',
    ),
    detachedSignature: requirePatternString(
      attestation.detachedSignature,
      BASE64URL_PATTERN,
      16_384,
      'attestation detachedSignature',
    ),
  }
}

export const parseRuntimeManifest = (value: unknown): RuntimeManifest => {
  const manifest = requireRecord(value, 'runtime manifest')
  const schemaVersion = requireString(
    manifest.schemaVersion,
    64,
    'runtime manifest schemaVersion',
  )
  const live = schemaVersion === LIVE_RUNTIME_SCHEMA_VERSION
  if (!live && schemaVersion !== RUNTIME_SCHEMA_VERSION) {
    fail('runtime manifest schemaVersion has an unexpected value')
  }
  assertExactKeys(
    manifest,
    live
      ? [
          'schemaVersion',
          'classification',
          'runId',
          'targetResourceGroup',
          'evaluatedAt',
          'publishedAt',
          'key',
          'phases',
        ]
      : ['schemaVersion', 'classification', 'key', 'phases'],
    'runtime manifest',
  )
  const key = requireRecord(manifest.key, 'runtime manifest key')
  assertExactKeys(
    key,
    ['path', 'assetSha256', 'keyId', 'fingerprint'],
    'runtime manifest key',
  )
  const rawPhases = manifest.phases
  if (!Array.isArray(rawPhases) || rawPhases.length !== LIFECYCLE_PHASES.length) {
    fail('runtime manifest must contain exactly the three lifecycle phases')
  }
  const phases = (rawPhases as unknown[]).map((item, index) => {
    const phaseAsset = requireRecord(item, `runtime manifest phase ${index}`)
    assertExactKeys(
      phaseAsset,
      ['phase', 'payloadPath', 'payloadSha256', 'attestationPath', 'attestationSha256'],
      `runtime manifest phase ${index}`,
    )
    const phase = readPhase(phaseAsset.phase, `runtime manifest phase ${index}`)
    if (phase !== LIFECYCLE_PHASES[index]) {
      fail('runtime manifest phases must use baseline, faulted, recovered order')
    }
    return {
      phase,
      payloadPath: requireAssetPath(
        phaseAsset.payloadPath,
        `runtime manifest ${phase} payloadPath`,
      ),
      payloadSha256: requireDigest(
        phaseAsset.payloadSha256,
        `runtime manifest ${phase} payloadSha256`,
      ),
      attestationPath: requireAssetPath(
        phaseAsset.attestationPath,
        `runtime manifest ${phase} attestationPath`,
      ),
      attestationSha256: requireDigest(
        phaseAsset.attestationSha256,
        `runtime manifest ${phase} attestationSha256`,
      ),
    }
  })
  const assetPaths = phases.flatMap((item) => [item.payloadPath, item.attestationPath])
  const keyPath = requireAssetPath(key.path, 'runtime manifest key path')
  const keyAssetSha256 = requireDigest(
    key.assetSha256,
    'runtime manifest key assetSha256',
  )
  const keyId = requireSyntheticKeyId(key.keyId, 'runtime manifest keyId')
  const keyFingerprint = requireDigest(
    key.fingerprint,
    'runtime manifest key fingerprint',
  )
  if (new Set([...assetPaths, keyPath]).size !== assetPaths.length + 1) {
    fail('runtime manifest asset paths must be unique')
  }

  const common = {
    key: {
      path: keyPath,
      assetSha256: keyAssetSha256,
      keyId,
      fingerprint: keyFingerprint,
    },
    phases,
  }
  if (!live) {
    return {
      schemaVersion: RUNTIME_SCHEMA_VERSION,
      classification: requireLiteral(
        manifest.classification,
        'synthetic-demo-only',
        'runtime manifest classification',
      ),
      ...common,
    }
  }

  const runId = requirePatternString(
    manifest.runId,
    LIVE_RUN_ID_PATTERN,
    76,
    'runtime manifest runId',
  )
  const targetResourceGroup = requirePatternString(
    manifest.targetResourceGroup,
    RESOURCE_GROUP_PATTERN,
    90,
    'runtime manifest targetResourceGroup',
  )
  if (targetResourceGroup.endsWith('.')) {
    fail('runtime manifest targetResourceGroup must not end with a period')
  }
  const publishedAt = requirePatternString(
    manifest.publishedAt,
    UTC_TIMESTAMP_PATTERN,
    32,
    'runtime manifest publishedAt',
  )
  if (!Number.isFinite(Date.parse(publishedAt))) {
    fail('runtime manifest publishedAt is not one valid UTC timestamp')
  }
  const evaluatedAt = requirePatternString(
    manifest.evaluatedAt,
    UTC_TIMESTAMP_PATTERN,
    32,
    'runtime manifest evaluatedAt',
  )
  if (!Number.isFinite(Date.parse(evaluatedAt))) {
    fail('runtime manifest evaluatedAt is not one valid UTC timestamp')
  }
  if (Date.parse(publishedAt) < Date.parse(evaluatedAt)) {
    fail('runtime manifest publishedAt must not precede evaluatedAt')
  }
  if (
    keyPath !== REVIEWED_LIVE_PUBLIC_KEY_PATH ||
    keyAssetSha256 !== REVIEWED_LIVE_PUBLIC_KEY_ASSET_SHA256
  ) {
    fail('runtime manifest live key asset does not match the reviewed live key')
  }
  for (const phase of phases) {
    const prefix = `./live/runs/${runId}/${phase.phase}`
    if (
      phase.payloadPath !== `${prefix}/argus-presentation.json` ||
      phase.attestationPath !== `${prefix}/presentation-attestation.json`
    ) {
      fail('runtime manifest live paths do not match the selected run and phase')
    }
  }
  return {
    schemaVersion: LIVE_RUNTIME_SCHEMA_VERSION,
    classification: requireLiteral(
      manifest.classification,
      'live-workload-evaluation',
      'runtime manifest classification',
    ),
    runId,
    targetResourceGroup,
    evaluatedAt,
    publishedAt,
    ...common,
  }
}

export const parsePresentationPublicKey = (value: unknown): PresentationPublicKey => {
  const asset = requireRecord(value, 'presentation public key')
  assertExactKeys(asset, ['schemaVersion', 'keyId', 'fingerprint', 'jwk'], 'presentation public key')
  const jwk = requireRecord(asset.jwk, 'presentation public key JWK')
  assertExactKeys(jwk, ['kty', 'n', 'e', 'alg', 'key_ops', 'ext'], 'presentation public key JWK')
  if (
    !Array.isArray(jwk.key_ops) ||
    jwk.key_ops.length !== 1 ||
    jwk.key_ops[0] !== 'verify'
  ) {
    fail('presentation public key JWK key_ops must contain only verify')
  }
  if (jwk.ext !== true) {
    fail('presentation public key JWK ext must be true')
  }
  return {
    schemaVersion: requireLiteral(
      asset.schemaVersion,
      PUBLIC_KEY_SCHEMA_VERSION,
      'presentation public key schemaVersion',
    ),
    keyId: requireSyntheticKeyId(asset.keyId, 'presentation public key keyId'),
    fingerprint: requireDigest(asset.fingerprint, 'presentation public key fingerprint'),
    jwk: {
      kty: requireLiteral(jwk.kty, 'RSA', 'presentation public key JWK kty'),
      n: requirePatternString(
        jwk.n,
        JWK_COMPONENT_PATTERN,
        1024,
        'presentation public key JWK modulus',
        342,
      ),
      e: requireLiteral(jwk.e, 'AQAB', 'presentation public key JWK exponent'),
      alg: requireLiteral(jwk.alg, 'RS256', 'presentation public key JWK alg'),
      key_ops: ['verify'],
      ext: true,
    },
  }
}

const parseWorkload = (value: unknown): PresentationPayload['workload'] => {
  const workload = requireRecord(value, 'presentation workload')
  assertExactKeys(
    workload,
    ['name', 'manifestId', 'manifestVersion', 'profileId', 'resourceGroup'],
    'presentation workload',
  )
  return {
    name: requireLiteral(workload.name, SYNTHETIC_WORKLOAD_NAME, 'presentation workload name'),
    manifestId: requireSyntheticId(workload.manifestId, 'presentation workload manifestId'),
    manifestVersion: requirePatternString(
      workload.manifestVersion,
      SEMVER_PATTERN,
      128,
      'presentation workload manifestVersion',
    ),
    profileId: requireSyntheticId(workload.profileId, 'presentation workload profileId'),
    resourceGroup: requireSyntheticId(
      workload.resourceGroup,
      'presentation workload resourceGroup',
    ),
  }
}

const parseFaultRun = (
  value: unknown,
  phase: Exclude<LifecyclePhase, 'baseline'>,
): PresentationFaultRun => {
  const faultRun = requireRecord(value, 'presentation faultRun')
  assertExactKeys(
    faultRun,
    ['faultRunId', 'targetVmName', 'afterPowerState'],
    'presentation faultRun',
  )
  return {
    faultRunId: requireSyntheticId(faultRun.faultRunId, 'presentation faultRun faultRunId'),
    targetVmName: requireSyntheticId(
      faultRun.targetVmName,
      'presentation faultRun targetVmName',
    ),
    afterPowerState: requireLiteral(
      faultRun.afterPowerState,
      phase === 'faulted' ? 'stopped' : 'running',
      'presentation faultRun afterPowerState',
    ),
  }
}

const parseAthena = (value: unknown): PresentationPayload['athena'] => {
  const athena = requireRecord(value, 'presentation Athena metadata')
  assertExactKeys(
    athena,
    [
      'snapshotId',
      'artifactDigest',
      'semanticDigest',
      'resultDigest',
      'signatureAlgorithm',
      'keyVaultKeyId',
    ],
    'presentation Athena metadata',
  )
  return {
    snapshotId: requireSyntheticId(athena.snapshotId, 'presentation Athena snapshotId'),
    artifactDigest: requireDigest(
      athena.artifactDigest,
      'presentation Athena artifactDigest',
    ),
    semanticDigest: requireDigest(
      athena.semanticDigest,
      'presentation Athena semanticDigest',
    ),
    resultDigest: requireDigest(athena.resultDigest, 'presentation Athena resultDigest'),
    signatureAlgorithm: requireLiteral(
      athena.signatureAlgorithm,
      'RS256',
      'presentation Athena signatureAlgorithm',
    ),
    keyVaultKeyId: requireSyntheticKeyId(
      athena.keyVaultKeyId,
      'presentation Athena keyVaultKeyId',
    ),
  }
}

const parseRuntimeState = (
  value: unknown,
  phase: LifecyclePhase,
): PresentationPayload['runtimeState'] => {
  const runtimeState = requireRecord(value, 'presentation runtimeState')
  assertExactKeys(runtimeState, ['webTier'], 'presentation runtimeState')
  const webTier = requireRecord(runtimeState.webTier, 'presentation webTier')
  assertExactKeys(
    webTier,
    ['expectedNodes', 'runningNodes', 'faultedNodes', 'serviceState'],
    'presentation webTier',
  )
  const expectedNodes = requireInteger(webTier.expectedNodes, 2, 100, 'webTier expectedNodes')
  const runningNodes = requireInteger(webTier.runningNodes, 0, 100, 'webTier runningNodes')
  const faultedNodes = requireInteger(webTier.faultedNodes, 0, 100, 'webTier faultedNodes')
  if (expectedNodes !== runningNodes + faultedNodes) {
    fail('webTier expectedNodes must equal runningNodes plus faultedNodes')
  }
  const contract = PHASE_CONTRACT[phase]
  if (
    (phase === 'baseline' &&
      (faultedNodes !== 0 || runningNodes !== expectedNodes)) ||
    (phase === 'faulted' && (faultedNodes !== 1 || runningNodes < 1)) ||
    (phase === 'recovered' &&
      (faultedNodes !== 0 || runningNodes !== expectedNodes))
  ) {
    fail('webTier node counts do not match the presentation phase')
  }
  return {
    webTier: {
      expectedNodes,
      runningNodes,
      faultedNodes,
      serviceState: requireLiteral(
        webTier.serviceState,
        contract.serviceState,
        'webTier serviceState',
      ),
    },
  }
}

const parseFindings = (
  value: unknown,
  phase: LifecyclePhase,
): PresentationFinding[] => {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) {
    fail('presentation findings must contain between one and 100 entries')
  }
  const contract = PHASE_CONTRACT[phase]
  const findings: PresentationFinding[] = (value as unknown[]).map((item, index) => {
    const finding = requireRecord(item, `presentation finding ${index}`)
    assertExactKeys(
      finding,
      ['clauseId', 'verdict', 'summary', 'evidenceRefs'],
      `presentation finding ${index}`,
    )
    const rawEvidenceRefs = finding.evidenceRefs
    if (
      !Array.isArray(rawEvidenceRefs) ||
      rawEvidenceRefs.length < 1 ||
      rawEvidenceRefs.length > 100
    ) {
      fail(`presentation finding ${index} evidenceRefs are outside the allowed bound`)
    }
    const evidenceRefs = (rawEvidenceRefs as unknown[]).map((reference, referenceIndex) =>
      requireSyntheticId(
        reference,
        `presentation finding ${index} evidenceRefs ${referenceIndex}`,
      ),
    )
    if (
      new Set(evidenceRefs).size !== evidenceRefs.length ||
      [...evidenceRefs].sort().some((reference, referenceIndex) => reference !== evidenceRefs[referenceIndex])
    ) {
      fail(`presentation finding ${index} evidenceRefs must be unique and sorted`)
    }
    return {
      clauseId: requireSyntheticId(
        finding.clauseId,
        `presentation finding ${index} clauseId`,
      ),
      verdict: requireLiteral(
        finding.verdict,
        contract.verdict,
        `presentation finding ${index} verdict`,
      ),
      summary: requireLiteral(
        finding.summary,
        contract.summary,
        `presentation finding ${index} summary`,
      ),
      evidenceRefs,
    }
  })
  if (new Set(findings.map((finding) => finding.clauseId)).size !== findings.length) {
    fail('presentation clauseIds must be unique')
  }
  return findings
}

const parseArgus = (
  value: unknown,
  phase: LifecyclePhase,
): PresentationPayload['argus'] => {
  const argus = requireRecord(value, 'presentation ARGUS guidance')
  assertExactKeys(
    argus,
    ['riskLevel', 'predictedIssue', 'recommendedAction'],
    'presentation ARGUS guidance',
  )
  const contract = PHASE_CONTRACT[phase]
  return {
    riskLevel: requireLiteral(
      argus.riskLevel,
      contract.riskLevel,
      'presentation ARGUS riskLevel',
    ),
    predictedIssue: requireLiteral(
      argus.predictedIssue,
      contract.predictedIssue,
      'presentation ARGUS predictedIssue',
    ),
    recommendedAction: requireLiteral(
      argus.recommendedAction,
      contract.recommendedAction,
      'presentation ARGUS recommendedAction',
    ),
  }
}

const readPhase = (value: unknown, context: string): LifecyclePhase => {
  const phase = requireString(value, 16, context)
  if (!LIFECYCLE_PHASES.includes(phase as LifecyclePhase)) {
    fail(`${context} is unsupported`)
  }
  return phase as LifecyclePhase
}

const requireRecord = (value: unknown, context: string): Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    fail(`${context} must be an object`)
  }
  return value as Record<string, unknown>
}

const assertExactKeys = (
  value: Record<string, unknown>,
  expected: readonly string[],
  context: string,
): void => {
  const actualKeys = Object.keys(value).sort()
  const expectedKeys = [...expected].sort()
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    fail(`${context} has missing or unsupported fields`)
  }
}

const requireString = (
  value: unknown,
  maxLength: number,
  context: string,
  minLength = 1,
): string => {
  if (
    typeof value !== 'string' ||
    value.length < minLength ||
    value.length > maxLength ||
    containsUnpairedSurrogate(value)
  ) {
    fail(`${context} is outside the allowed string bound`)
  }
  return value as string
}

const requirePatternString = (
  value: unknown,
  pattern: RegExp,
  maxLength: number,
  context: string,
  minLength = 1,
): string => {
  const text = requireString(value, maxLength, context, minLength)
  if (!pattern.test(text)) {
    fail(`${context} has an invalid format`)
  }
  return text
}

const requireLiteral = <T extends string | number>(
  value: unknown,
  expected: T,
  context: string,
): T => {
  if (value !== expected) {
    fail(`${context} has an unexpected value`)
  }
  return expected
}

const requireInteger = (
  value: unknown,
  minimum: number,
  maximum: number,
  context: string,
): number => {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    fail(`${context} is outside the allowed integer bound`)
  }
  return value as number
}

const requireDigest = (value: unknown, context: string): Sha256Digest =>
  requirePatternString(value, DIGEST_PATTERN, 71, context, 71) as Sha256Digest

const requireSyntheticId = (value: unknown, context: string): string =>
  requirePatternString(value, SYNTHETIC_ID_PATTERN, 137, context)

const requireSyntheticKeyId = (value: unknown, context: string): string =>
  requirePatternString(value, SYNTHETIC_KEY_PATTERN, 216, context)

const requireAssetPath = (value: unknown, context: string): string => {
  const path = requirePatternString(value, ASSET_PATH_PATTERN, 200, context)
  if (path.includes('..') || path.includes('//')) {
    fail(`${context} must be a bounded relative path`)
  }
  return path
}

const containsUnpairedSurrogate = (value: string): boolean => {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true
      index += 1
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true
    }
  }
  return false
}

const fail = (message: string): never => {
  throw new ContractValidationError(message)
}
