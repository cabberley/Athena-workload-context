import {
  parsePresentationAttestation,
  parsePresentationPayload,
  parsePresentationPublicKey,
  parseRuntimeManifest,
} from './contracts'
import {
  cloneLifecycleAssets,
  createLiveRuntimeManifest,
  createVerifiedLifecycle,
  rawLifecycleAssets,
  rawPublicKey,
  rawRuntimeManifest,
} from './test/fixtures'
import {
  deriveSyntheticResourceGroupBinding,
  validateLifecycleConsistency,
  VerificationError,
  verifyLifecycleAssets,
  verifyPhaseSignature,
} from './verification'

describe('detached RS256 lifecycle verification', () => {
  it('verifies all authentic contract-shaped synthetic fixtures', async () => {
    const verified = await createVerifiedLifecycle()

    expect(verified.trust).toEqual({
      status: 'verified',
      algorithm: 'RS256',
      keyId: 'synthetic-key://athena-argus-demo/rs256-v1',
      keyFingerprint:
        'sha256:9323d86eb7d1fffccc409a89795e04ef71db7c9b011dad9c2f3e3fcf6e81784a',
      verifiedPhases: 3,
    })
    expect(verified.phases.faulted.blastRadius).toBe('contained-web-tier')
    expect(verified.publication).toEqual({ kind: 'static-fixture' })
  })

  it('verifies live publication metadata and its cryptographic resource-group binding', async () => {
    const verified = await verifyLifecycleAssets(
      createLiveRuntimeManifest(),
      parsePresentationPublicKey(rawPublicKey),
      cloneLifecycleAssets(),
    )

    expect(verified.classification).toBe('live-workload-evaluation')
    expect(verified.publication).toEqual({
      kind: 'live',
      runId: 'synthetic-run-live-001',
      targetResourceGroup: 'rg-athena-demo-workload',
      evaluatedAt: '2026-09-01T23:59:00Z',
      publishedAt: '2026-09-02T00:00:00Z',
    })
    expect(
      await deriveSyntheticResourceGroupBinding('RG-ATHENA-DEMO-WORKLOAD'),
    ).toBe(
      'synthetic-rg-36c4a74ac567d0bba5e5e4d9e940d5f685bfad399f3fc045d69d8a58eca8a0bf',
    )
  })

  it('rejects a live manifest whose target resource group differs from signed workload scope', async () => {
    await expect(
      verifyLifecycleAssets(
        createLiveRuntimeManifest('other-reviewed-rg'),
        parsePresentationPublicKey(rawPublicKey),
        cloneLifecycleAssets(),
      ),
    ).rejects.toThrow(/target resource group/i)
  })

  it('rejects a structurally valid tampered payload digest', async () => {
    const assets = cloneLifecycleAssets()
    const payload = assets.baseline.payload as {
      workload: { manifestVersion: string }
    }
    payload.workload.manifestVersion = '1.0.1'

    await expect(
      verifyLifecycleAssets(
        parseRuntimeManifest(rawRuntimeManifest),
        parsePresentationPublicKey(rawPublicKey),
        assets,
      ),
    ).rejects.toThrow(/canonical result digest/i)
  })

  it('rejects a tampered detached signature', async () => {
    const assets = cloneLifecycleAssets()
    const attestation = assets.recovered.attestation as {
      detachedSignature: string
    }
    attestation.detachedSignature = `${
      attestation.detachedSignature.startsWith('A') ? 'B' : 'A'
    }${attestation.detachedSignature.slice(1)}`

    await expect(
      verifyLifecycleAssets(
        parseRuntimeManifest(rawRuntimeManifest),
        parsePresentationPublicKey(rawPublicKey),
        assets,
      ),
    ).rejects.toThrow(/signature is invalid/i)
  })

  it('rejects the authentic signature when checked with the wrong RSA key', async () => {
    const wrongPair = (await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair
    const payload = parsePresentationPayload(rawLifecycleAssets.faulted.payload, 'faulted')
    const attestation = parsePresentationAttestation(
      rawLifecycleAssets.faulted.attestation,
    )

    await expect(
      verifyPhaseSignature(payload, attestation, wrongPair.publicKey),
    ).rejects.toThrow(/signature is invalid/i)
  })

  it('pins both key ID and SPKI fingerprint', async () => {
    const key = structuredClone(rawPublicKey) as { fingerprint: string }
    key.fingerprint = `sha256:${'0'.repeat(64)}`

    await expect(
      verifyLifecycleAssets(
        parseRuntimeManifest(rawRuntimeManifest),
        parsePresentationPublicKey(key),
        cloneLifecycleAssets(),
      ),
    ).rejects.toThrow(/reviewed trust anchor/i)
  })

  it('rejects baseline-faulted-recovered lineage drift after phase verification', async () => {
    const verified = await createVerifiedLifecycle()
    const inconsistent = structuredClone(verified.phases)
    inconsistent.recovered.payload.faultRun!.faultRunId =
      'synthetic-fault-run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

    expect(() => validateLifecycleConsistency(inconsistent)).toThrow(
      new VerificationError('Lifecycle fault and reset lineage is inconsistent.'),
    )
  })
})
