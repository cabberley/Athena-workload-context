import canonicalFixture from '../../../src/athena_context/data/fixtures/canonical-manifest.json'
import { canonicalizeJson, refreshCanonicalManifestDigests } from './canonical'
import type { CanonicalWorkloadManifest } from './types'

describe('WC-001 browser canonicalization', () => {
  it('matches the Python RFC 8785 artifact and semantic digests', async () => {
    const fixture = canonicalFixture as unknown as CanonicalWorkloadManifest
    const refreshed = await refreshCanonicalManifestDigests(fixture)

    expect(refreshed.compatibility.artifactDigest).toBe(fixture.compatibility.artifactDigest)
    expect(refreshed.compatibility.semanticDigest).toBe(fixture.compatibility.semanticDigest)
  })

  it('normalizes NFC text, timestamps and RFC 8785 key order', () => {
    expect(canonicalizeJson({
      z: 'e\u0301',
      at: '2026-08-17T10:00:00+10:00',
      a: 1,
    })).toBe('{"a":1,"at":"2026-08-17T00:00:00.000Z","z":"é"}')
  })

  it('updates the artifact digest but not semantic digest for presentation-only displayName', async () => {
    const fixture = canonicalFixture as unknown as CanonicalWorkloadManifest
    const edited = structuredClone(fixture)
    edited.workload.displayName = 'Synthetic renamed workload'
    const refreshed = await refreshCanonicalManifestDigests(edited)

    expect(refreshed.compatibility.artifactDigest).toBe(
      'sha256:12ea9340ff046f9fa955a80c78e8b2e98eef8bbe02b3e4397a976f0f80bd3328',
    )
    expect(refreshed.compatibility.semanticDigest).toBe(
      'sha256:4cb99758a49d39da2191ddaa583cd00b43c504d1cf0dad3b636fcda9468e7ec0',
    )
  })

  it('matches Python digests for an exact successor version candidate', async () => {
    const successor = structuredClone(canonicalFixture) as unknown as CanonicalWorkloadManifest
    successor.manifestVersion = '1.0.1'
    const refreshed = await refreshCanonicalManifestDigests(successor)

    expect(refreshed.compatibility.artifactDigest).toBe(
      'sha256:edf5850158d16b39c52f7d5996f16dbbc018e2eeed8f6d519629f74b71b0c56d',
    )
    expect(refreshed.compatibility.semanticDigest).toBe(
      'sha256:de812ae3b2812a6c35592b6e3aa4b9a3a181f0f16e9c448cd12774849eed7f6f',
    )
  })
})
