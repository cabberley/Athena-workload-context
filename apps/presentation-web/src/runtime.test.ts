import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  fetchBoundedJsonAsset,
  loadVerifiedLifecycle,
  PresentationLoadError,
  resolveSameOriginAssetUrl,
} from './runtime'
import { createLiveRuntimeManifest } from './test/fixtures'

const assetBytes = new Map<string, Uint8Array>(
  [
    'runtime-manifest.json',
    'trust/presentation-public-key.jwk.json',
    'fixtures/baseline.presentation.json',
    'fixtures/baseline.attestation.json',
    'fixtures/faulted.presentation.json',
    'fixtures/faulted.attestation.json',
    'fixtures/recovered.presentation.json',
    'fixtures/recovered.attestation.json',
  ].map((path) => [path, readFileSync(join(process.cwd(), 'public', path))]),
)

const createAssetFetch = (overrides: Partial<Record<string, Uint8Array>> = {}) =>
  vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    void init
    const url = new URL(String(input))
    const path = url.pathname.replace(/^\//, '')
    const bytes = overrides[path] ?? assetBytes.get(path)
    if (!bytes) return new Response('{}', { status: 404, headers: jsonHeaders })
    return new Response(bytes, { status: 200, headers: jsonHeaders })
  })

const jsonHeaders = { 'Content-Type': 'application/json; charset=utf-8' }

describe('same-origin bounded runtime asset loading', () => {
  it('loads, hashes and verifies the complete reviewed asset set', async () => {
    const fetchMock = createAssetFetch()
    const lifecycle = await loadVerifiedLifecycle({
      fetchImpl: fetchMock as typeof fetch,
      manifestUrl: new URL('https://demo.invalid/runtime-manifest.json'),
      origin: 'https://demo.invalid',
    })

    expect(lifecycle.phases.baseline.payload.phase).toBe('baseline')
    expect(lifecycle.phases.faulted.payload.phase).toBe('faulted')
    expect(lifecycle.phases.recovered.payload.phase).toBe('recovered')
    expect(fetchMock).toHaveBeenCalledTimes(8)
    expect(fetchMock.mock.calls[0]![1]).toMatchObject({
      method: 'GET',
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
    })
  })

  it('loads a live v2 manifest through same-origin run-scoped paths', async () => {
    const manifest = createLiveRuntimeManifest()
    const overrides: Partial<Record<string, Uint8Array>> = {
      'runtime-manifest.json': new TextEncoder().encode(
        `${JSON.stringify(manifest)}\n`,
      ),
    }
    for (const phase of manifest.phases) {
      overrides[phase.payloadPath.replace(/^\.\//, '')] = assetBytes.get(
        `fixtures/${phase.phase}.presentation.json`,
      )
      overrides[phase.attestationPath.replace(/^\.\//, '')] = assetBytes.get(
        `fixtures/${phase.phase}.attestation.json`,
      )
    }
    const lifecycle = await loadVerifiedLifecycle({
      fetchImpl: createAssetFetch(overrides) as typeof fetch,
      manifestUrl: new URL('https://demo.invalid/runtime-manifest.json'),
      origin: 'https://demo.invalid',
    })

    expect(lifecycle.publication).toEqual({
      kind: 'live',
      runId: 'synthetic-run-live-001',
      targetResourceGroup: 'rg-athena-demo-workload',
      evaluatedAt: '2026-09-01T23:59:00Z',
      publishedAt: '2026-09-02T00:00:00Z',
    })
  })

  it('rejects cross-origin and path-traversal asset references', () => {
    const manifestUrl = new URL('https://demo.invalid/runtime-manifest.json')
    expect(() =>
      resolveSameOriginAssetUrl(
        'https://other.invalid/payload.json',
        manifestUrl,
        'https://demo.invalid',
      ),
    ).toThrow(/bounded relative/i)
    expect(() =>
      resolveSameOriginAssetUrl(
        './../payload.json',
        manifestUrl,
        'https://demo.invalid',
      ),
    ).toThrow(/bounded relative/i)
  })

  it('rejects byte-limit, content-type and invalid UTF-8 responses', async () => {
    const url = new URL('https://demo.invalid/asset.json')
    await expect(
      fetchBoundedJsonAsset(
        url,
        4,
        vi.fn(async () => new Response('12345', { headers: jsonHeaders })) as typeof fetch,
      ),
    ).rejects.toMatchObject({ code: 'size' })

    await expect(
      fetchBoundedJsonAsset(
        url,
        100,
        vi.fn(async () =>
          new Response('{}', { headers: { 'Content-Type': 'text/html' } }),
        ) as typeof fetch,
      ),
    ).rejects.toMatchObject({ code: 'content-type' })

    await expect(
      fetchBoundedJsonAsset(
        url,
        100,
        vi.fn(async () =>
          new Response(new Uint8Array([0xff]), { headers: jsonHeaders }),
        ) as typeof fetch,
      ),
    ).rejects.toMatchObject({ code: 'utf8' })
  })

  it('aborts a presentation request that exceeds the configured timeout', async () => {
    const fetchMock = vi.fn(
      (_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted')))
        }),
    )

    await expect(
      fetchBoundedJsonAsset(
        new URL('https://demo.invalid/asset.json'),
        100,
        fetchMock as typeof fetch,
        5,
      ),
    ).rejects.toMatchObject({ code: 'network' })
  })

  it('fails closed when a reviewed file content digest changes', async () => {
    const original = assetBytes.get('fixtures/faulted.presentation.json')!
    const changed = new Uint8Array([...original, 0x20])
    const fetchMock = createAssetFetch({
      'fixtures/faulted.presentation.json': changed,
    })

    await expect(
      loadVerifiedLifecycle({
        fetchImpl: fetchMock as typeof fetch,
        manifestUrl: new URL('https://demo.invalid/runtime-manifest.json'),
        origin: 'https://demo.invalid',
      }),
    ).rejects.toEqual(
      new PresentationLoadError(
        'digest',
        'The faulted payload did not match its reviewed content digest.',
      ),
    )
  })
})
