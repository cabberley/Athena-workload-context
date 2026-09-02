import baselineAttestation from '../../public/fixtures/baseline.attestation.json'
import baselinePayload from '../../public/fixtures/baseline.presentation.json'
import faultedAttestation from '../../public/fixtures/faulted.attestation.json'
import faultedPayload from '../../public/fixtures/faulted.presentation.json'
import recoveredAttestation from '../../public/fixtures/recovered.attestation.json'
import recoveredPayload from '../../public/fixtures/recovered.presentation.json'
import runtimeManifest from '../../public/runtime-manifest.json'
import publicKey from '../../public/trust/presentation-public-key.jwk.json'
import livePublicKey from '../../public/trust/live-presentation-public-key.jwk.json'
import {
  parsePresentationPublicKey,
  parseRuntimeManifest,
  type LifecyclePhase,
  type RuntimeManifest,
} from '../contracts'
import {
  verifyLifecycleAssets,
  type UnverifiedLifecycleAssets,
  type VerifiedLifecycle,
} from '../verification'

export const rawRuntimeManifest = runtimeManifest as unknown
export const rawPublicKey = publicKey as unknown
export const rawLivePublicKey = livePublicKey as unknown
export const rawLifecycleAssets: UnverifiedLifecycleAssets = {
  baseline: {
    payload: baselinePayload,
    attestation: baselineAttestation,
  },
  faulted: {
    payload: faultedPayload,
    attestation: faultedAttestation,
  },
  recovered: {
    payload: recoveredPayload,
    attestation: recoveredAttestation,
  },
}

export const cloneLifecycleAssets = (): UnverifiedLifecycleAssets =>
  structuredClone(rawLifecycleAssets)

export const createVerifiedLifecycle = (): Promise<VerifiedLifecycle> =>
  verifyLifecycleAssets(
    parseRuntimeManifest(rawRuntimeManifest),
    parsePresentationPublicKey(rawPublicKey),
    cloneLifecycleAssets(),
  )

export const createLiveRuntimeManifest = (
  targetResourceGroup = 'rg-athena-demo-workload',
): RuntimeManifest => {
  const manifest = structuredClone(rawRuntimeManifest) as Record<string, unknown>
  manifest.schemaVersion = 'athena.presentationWeb.runtime.v2'
  manifest.classification = 'live-workload-evaluation'
  manifest.runId = 'synthetic-run-live-001'
  manifest.targetResourceGroup = targetResourceGroup
  manifest.evaluatedAt = '2026-09-01T23:59:00Z'
  manifest.publishedAt = '2026-09-02T00:00:00Z'
  manifest.key = {
    path: './trust/live-presentation-public-key.jwk.json',
    assetSha256:
      'sha256:a8937fd9e7acb7b3010369184aa439284dfd6d0da072ff47360f8034152eb9b9',
    keyId: 'synthetic-key://athena-argus-demo/rs256-v1',
    fingerprint:
      'sha256:b2e63939232aa747228751288082c7310996c4e00e45b4bf167d269a61d1f515',
  }
  const phases = manifest.phases as Array<Record<string, unknown>>
  for (const phase of phases) {
    const phaseName = phase.phase as LifecyclePhase
    const prefix = `./live/runs/synthetic-run-live-001/${phaseName}`
    phase.payloadPath = `${prefix}/argus-presentation.json`
    phase.attestationPath = `${prefix}/presentation-attestation.json`
  }
  return parseRuntimeManifest(manifest)
}

export const createLiveVerifiedLifecycle = async (): Promise<VerifiedLifecycle> => {
  const verified = await createVerifiedLifecycle()
  return {
    ...verified,
    classification: 'live-workload-evaluation',
    publication: {
      kind: 'live',
      runId: 'synthetic-run-live-001',
      targetResourceGroup: 'rg-athena-demo-workload',
      evaluatedAt: '2026-09-01T23:59:00Z',
      publishedAt: '2026-09-02T00:00:00Z',
    },
  }
}

export const payloadFor = (phase: LifecyclePhase): unknown =>
  cloneLifecycleAssets()[phase].payload
