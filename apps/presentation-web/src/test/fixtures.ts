import baselineAttestation from '../../public/fixtures/baseline.attestation.json'
import baselinePayload from '../../public/fixtures/baseline.presentation.json'
import faultedAttestation from '../../public/fixtures/faulted.attestation.json'
import faultedPayload from '../../public/fixtures/faulted.presentation.json'
import recoveredAttestation from '../../public/fixtures/recovered.attestation.json'
import recoveredPayload from '../../public/fixtures/recovered.presentation.json'
import runtimeManifest from '../../public/runtime-manifest.json'
import publicKey from '../../public/trust/presentation-public-key.jwk.json'
import {
  parsePresentationPublicKey,
  parseRuntimeManifest,
  type LifecyclePhase,
} from '../contracts'
import {
  verifyLifecycleAssets,
  type UnverifiedLifecycleAssets,
  type VerifiedLifecycle,
} from '../verification'

export const rawRuntimeManifest = runtimeManifest as unknown
export const rawPublicKey = publicKey as unknown
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

export const payloadFor = (phase: LifecyclePhase): unknown =>
  cloneLifecycleAssets()[phase].payload
