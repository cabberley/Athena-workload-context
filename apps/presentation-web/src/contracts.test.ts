import {
  ContractValidationError,
  parsePresentationAttestation,
  parsePresentationPayload,
  parsePresentationPublicKey,
  parseRuntimeManifest,
} from './contracts'
import {
  cloneLifecycleAssets,
  rawPublicKey,
  rawRuntimeManifest,
} from './test/fixtures'

describe('frozen presentation contract validation', () => {
  it('accepts the exact baseline, faulted and recovered wire shapes', () => {
    const assets = cloneLifecycleAssets()
    for (const phase of ['baseline', 'faulted', 'recovered'] as const) {
      expect(parsePresentationPayload(assets[phase].payload, phase).phase).toBe(phase)
      expect(parsePresentationAttestation(assets[phase].attestation).schemaVersion).toBe(
        'athena.argus.presentationAttestation.v1',
      )
    }
  })

  it('rejects extra fields, phase drift and unsorted evidence references', () => {
    const extra = cloneLifecycleAssets().baseline.payload as Record<string, unknown>
    extra.tenantId = 'synthetic-not-allowed'
    expect(() => parsePresentationPayload(extra, 'baseline')).toThrow(
      /missing or unsupported fields/i,
    )

    const drift = cloneLifecycleAssets().faulted.payload as { phase: string }
    drift.phase = 'recovered'
    expect(() => parsePresentationPayload(drift, 'faulted')).toThrow(ContractValidationError)

    const unsorted = cloneLifecycleAssets().faulted.payload as {
      findings: { evidenceRefs: string[] }[]
    }
    unsorted.findings[0]!.evidenceRefs.reverse()
    expect(() => parsePresentationPayload(unsorted, 'faulted')).toThrow(/unique and sorted/i)
  })

  it('rejects unsupported counts, guidance and signature alphabets', () => {
    const counts = cloneLifecycleAssets().faulted.payload as {
      runtimeState: { webTier: { faultedNodes: number } }
    }
    counts.runtimeState.webTier.faultedNodes = 2
    expect(() => parsePresentationPayload(counts, 'faulted')).toThrow(/expectedNodes/i)

    const guidance = cloneLifecycleAssets().baseline.payload as {
      argus: { predictedIssue: string }
    }
    guidance.argus.predictedIssue = 'Database outage'
    expect(() => parsePresentationPayload(guidance, 'baseline')).toThrow(/predictedIssue/i)

    const attestation = cloneLifecycleAssets().baseline.attestation as {
      detachedSignature: string
    }
    attestation.detachedSignature = 'AA=='
    expect(() => parsePresentationAttestation(attestation)).toThrow(/invalid format/i)
  })

  it('validates the bounded runtime manifest and reviewed RSA key shape', () => {
    const manifest = parseRuntimeManifest(rawRuntimeManifest)
    const publicKey = parsePresentationPublicKey(rawPublicKey)
    expect(manifest.phases.map((phase) => phase.phase)).toEqual([
      'baseline',
      'faulted',
      'recovered',
    ])
    expect(publicKey.jwk).toMatchObject({
      kty: 'RSA',
      alg: 'RS256',
      e: 'AQAB',
      key_ops: ['verify'],
    })
  })
})
