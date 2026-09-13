import { canonicalizeJson, presentationCanonicalPreimage, sha256Digest } from './canonical'
import { parsePresentationPayload } from './contracts'
import { payloadFor } from './test/fixtures'

describe('RFC 8785 presentation canonicalization', () => {
  it('normalizes Unicode, timestamps and UTF-16 key order deterministically', () => {
    expect(
      canonicalizeJson({
        z: 'e\u0301',
        at: '2026-08-17T10:00:00+10:00',
        a: 1,
      }),
    ).toBe('{"a":1,"at":"2026-08-17T00:00:00.000Z","z":"é"}')
  })

  it('preserves opaque Azure Blob versions while canonicalizing real timestamps', () => {
    expect(
      canonicalizeJson({
        publishedAt: '2026-08-20T23:50:41Z',
        version: '2026-08-20T23:50:41.2983616Z',
      }),
    ).toBe(
      '{"publishedAt":"2026-08-20T23:50:41.000Z","version":"2026-08-20T23:50:41.2983616Z"}',
    )
  })

  it('matches every frozen presentation result digest with resultDigest excluded', async () => {
    for (const phase of ['baseline', 'faulted', 'recovered'] as const) {
      const payload = parsePresentationPayload(payloadFor(phase), phase)
      expect(await sha256Digest(presentationCanonicalPreimage(payload))).toBe(
        payload.athena.resultDigest,
      )
    }
  })

  it('rejects unsafe canonical JSON values', () => {
    expect(() => canonicalizeJson({ value: -0 })).toThrow(/negative zero/i)
    expect(() => canonicalizeJson({ value: '\ud800' })).toThrow(/surrogate/i)
  })
})
