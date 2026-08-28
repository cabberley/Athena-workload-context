import { presentationCanonicalPreimage, sha256Digest } from './canonical'
import {
  LIFECYCLE_PHASES,
  parsePresentationAttestation,
  parsePresentationPayload,
  type LifecyclePhase,
  type PresentationAttestation,
  type PresentationPayload,
  type PresentationPublicKey,
  type RuntimeManifest,
  type Sha256Digest,
} from './contracts'
import {
  deriveBlastRadius,
  deriveImpactLevel,
  type BlastRadius,
  type ImpactLevel,
} from './derivations'

export const PINNED_PRESENTATION_KEY_ID =
  'synthetic-key://athena-argus-demo/rs256-v1'
export const PINNED_PRESENTATION_KEY_FINGERPRINT =
  'sha256:9323d86eb7d1fffccc409a89795e04ef71db7c9b011dad9c2f3e3fcf6e81784a'

export interface UnverifiedPhaseAssets {
  payload: unknown
  attestation: unknown
}

export type UnverifiedLifecycleAssets = Record<LifecyclePhase, UnverifiedPhaseAssets>

export interface VerifiedPhase {
  payload: PresentationPayload
  attestation: PresentationAttestation
  blastRadius: BlastRadius
  impact: ImpactLevel
}

export interface VerifiedLifecycle {
  classification: 'synthetic-demo-only'
  trust: {
    status: 'verified'
    algorithm: 'RS256'
    keyId: string
    keyFingerprint: Sha256Digest
    verifiedPhases: 3
  }
  phases: Record<LifecyclePhase, VerifiedPhase>
}

export class VerificationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VerificationError'
  }
}

export const verifyLifecycleAssets = async (
  manifest: RuntimeManifest,
  publicKey: PresentationPublicKey,
  assets: UnverifiedLifecycleAssets,
  cryptoProvider: Crypto = globalThis.crypto,
): Promise<VerifiedLifecycle> => {
  const importedKey = await verifyAndImportPublicKey(
    manifest,
    publicKey,
    cryptoProvider,
  )
  const verifiedEntries = await Promise.all(
    LIFECYCLE_PHASES.map(async (phase) => {
      const phaseAssets = assets[phase]
      const payload = parsePresentationPayload(phaseAssets.payload, phase)
      const attestation = parsePresentationAttestation(phaseAssets.attestation)
      await verifyPhaseSignature(payload, attestation, importedKey, cryptoProvider)
      return [
        phase,
        {
          payload,
          attestation,
          blastRadius: deriveBlastRadius(payload),
          impact: deriveImpactLevel(payload),
        },
      ] as const
    }),
  )
  const phases = Object.fromEntries(verifiedEntries) as Record<LifecyclePhase, VerifiedPhase>
  validateLifecycleConsistency(phases)
  return {
    classification: 'synthetic-demo-only',
    trust: {
      status: 'verified',
      algorithm: 'RS256',
      keyId: publicKey.keyId,
      keyFingerprint: publicKey.fingerprint,
      verifiedPhases: 3,
    },
    phases,
  }
}

export const verifyPhaseSignature = async (
  payload: PresentationPayload,
  attestation: PresentationAttestation,
  publicKey: CryptoKey,
  cryptoProvider: Crypto = globalThis.crypto,
): Promise<void> => {
  if (
    payload.athena.resultDigest !== attestation.resultDigest ||
    payload.athena.signatureAlgorithm !== attestation.signatureAlgorithm ||
    payload.athena.keyVaultKeyId !== attestation.keyVaultKeyId
  ) {
    throw new VerificationError('Presentation attestation metadata does not match its payload.')
  }
  const preimage = presentationCanonicalPreimage(payload)
  const recomputedDigest = await sha256Digest(preimage, cryptoProvider)
  if (recomputedDigest !== payload.athena.resultDigest) {
    throw new VerificationError('Presentation canonical result digest does not match.')
  }
  const signature = decodeBase64Url(attestation.detachedSignature)
  const algorithm = publicKey.algorithm as RsaHashedKeyAlgorithm
  if (algorithm.name !== 'RSASSA-PKCS1-v1_5' || signature.byteLength !== algorithm.modulusLength / 8) {
    throw new VerificationError('Presentation detached signature has an invalid RSA size.')
  }
  const valid = await cryptoProvider.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    signature,
    preimage,
  )
  if (!valid) {
    throw new VerificationError('Presentation detached RS256 signature is invalid.')
  }
}

export const computePublicKeyFingerprint = async (
  key: CryptoKey,
  cryptoProvider: Crypto = globalThis.crypto,
): Promise<Sha256Digest> => {
  const spki = await cryptoProvider.subtle.exportKey('spki', key)
  return sha256Digest(spki, cryptoProvider)
}

const verifyAndImportPublicKey = async (
  manifest: RuntimeManifest,
  publicKey: PresentationPublicKey,
  cryptoProvider: Crypto,
): Promise<CryptoKey> => {
  if (!cryptoProvider?.subtle) {
    throw new VerificationError('Web Crypto is unavailable.')
  }
  if (
    manifest.key.keyId !== PINNED_PRESENTATION_KEY_ID ||
    publicKey.keyId !== PINNED_PRESENTATION_KEY_ID ||
    manifest.key.fingerprint !== PINNED_PRESENTATION_KEY_FINGERPRINT ||
    publicKey.fingerprint !== PINNED_PRESENTATION_KEY_FINGERPRINT
  ) {
    throw new VerificationError('Presentation key identity does not match the reviewed trust anchor.')
  }
  const importedKey = await cryptoProvider.subtle.importKey(
    'jwk',
    publicKey.jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify'],
  )
  const fingerprint = await computePublicKeyFingerprint(importedKey, cryptoProvider)
  if (
    fingerprint !== publicKey.fingerprint ||
    fingerprint !== manifest.key.fingerprint
  ) {
    throw new VerificationError('Presentation public key fingerprint does not match.')
  }
  return importedKey
}

export const validateLifecycleConsistency = (
  phases: Record<LifecyclePhase, VerifiedPhase>,
): void => {
  const baseline = phases.baseline.payload
  const faulted = phases.faulted.payload
  const recovered = phases.recovered.payload
  const workloadBinding = JSON.stringify(baseline.workload)
  if (
    JSON.stringify(faulted.workload) !== workloadBinding ||
    JSON.stringify(recovered.workload) !== workloadBinding
  ) {
    throw new VerificationError('Lifecycle workload binding is inconsistent.')
  }
  if (
    faulted.runtimeState.webTier.expectedNodes !==
      baseline.runtimeState.webTier.expectedNodes ||
    recovered.runtimeState.webTier.expectedNodes !==
      baseline.runtimeState.webTier.expectedNodes
  ) {
    throw new VerificationError('Lifecycle expected web-node count is inconsistent.')
  }
  if (
    faulted.faultRun === undefined ||
    recovered.faultRun === undefined ||
    faulted.faultRun.faultRunId !== recovered.faultRun.faultRunId ||
    faulted.faultRun.targetVmName !== recovered.faultRun.targetVmName ||
    faulted.faultRun.afterPowerState !== 'stopped' ||
    recovered.faultRun.afterPowerState !== 'running'
  ) {
    throw new VerificationError('Lifecycle fault and reset lineage is inconsistent.')
  }
  const baselineClauses = baseline.findings.map((finding) => finding.clauseId).join('\0')
  if (
    faulted.findings.map((finding) => finding.clauseId).join('\0') !== baselineClauses ||
    recovered.findings.map((finding) => finding.clauseId).join('\0') !== baselineClauses
  ) {
    throw new VerificationError('Lifecycle finding clauses are inconsistent.')
  }
  const keyIds = new Set(
    LIFECYCLE_PHASES.map((phase) => phases[phase].payload.athena.keyVaultKeyId),
  )
  if (keyIds.size !== 1 || !keyIds.has(PINNED_PRESENTATION_KEY_ID)) {
    throw new VerificationError('Lifecycle signing-key binding is inconsistent.')
  }
  requireDistinctSignedValues(
    LIFECYCLE_PHASES.map((phase) => phases[phase].payload.athena.snapshotId),
    'snapshot identifiers',
  )
  requireDistinctSignedValues(
    LIFECYCLE_PHASES.map((phase) => phases[phase].payload.athena.resultDigest),
    'presentation result digests',
  )
  requireDistinctSignedValues(
    LIFECYCLE_PHASES.map((phase) => phases[phase].payload.athena.artifactDigest),
    'snapshot artifact digests',
  )
  requireDistinctSignedValues(
    LIFECYCLE_PHASES.map((phase) => phases[phase].payload.athena.semanticDigest),
    'snapshot semantic digests',
  )
}

const requireDistinctSignedValues = (values: string[], label: string): void => {
  if (new Set(values).size !== LIFECYCLE_PHASES.length) {
    throw new VerificationError(`Lifecycle ${label} are not phase-distinct.`)
  }
}

const decodeBase64Url = (value: string): Uint8Array => {
  if (value.length % 4 === 1 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new VerificationError('Presentation detached signature is not valid base64url.')
  }
  try {
    const base64 = value.replaceAll('-', '+').replaceAll('_', '/')
    const decoded = globalThis.atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='))
    const bytes = new Uint8Array(decoded.length)
    for (let index = 0; index < decoded.length; index += 1) {
      bytes[index] = decoded.charCodeAt(index)
    }
    return bytes
  } catch {
    throw new VerificationError('Presentation detached signature is not valid base64url.')
  }
}
