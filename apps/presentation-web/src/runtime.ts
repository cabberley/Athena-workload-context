import { sha256Digest } from './canonical'
import {
  parsePresentationPublicKey,
  parseRuntimeManifest,
  type LifecyclePhase,
  type Sha256Digest,
} from './contracts'
import {
  verifyLifecycleAssets,
  type UnverifiedLifecycleAssets,
  type VerifiedLifecycle,
} from './verification'

const MAX_RUNTIME_MANIFEST_BYTES = 16 * 1024
const MAX_PUBLIC_KEY_BYTES = 16 * 1024
const MAX_PRESENTATION_BYTES = 128 * 1024
const MAX_ATTESTATION_BYTES = 24 * 1024
const DEFAULT_TIMEOUT_MS = 5_000

export type PresentationLoadErrorCode =
  | 'configuration'
  | 'same-origin'
  | 'network'
  | 'http'
  | 'content-type'
  | 'size'
  | 'utf8'
  | 'json'
  | 'digest'
  | 'verification'

export class PresentationLoadError extends Error {
  constructor(
    readonly code: PresentationLoadErrorCode,
    message: string,
  ) {
    super(message)
    this.name = 'PresentationLoadError'
  }
}

export interface LoadPresentationOptions {
  fetchImpl?: typeof fetch
  manifestUrl?: URL
  origin?: string
  timeoutMs?: number
  cryptoProvider?: Crypto
}

export interface BoundedJsonAsset {
  bytes: Uint8Array
  value: unknown
}

export const loadVerifiedLifecycle = async (
  options: LoadPresentationOptions = {},
): Promise<VerifiedLifecycle> => {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch
  const cryptoProvider = options.cryptoProvider ?? globalThis.crypto
  const manifestUrl =
    options.manifestUrl ?? new URL('./runtime-manifest.json', document.baseURI)
  const origin = options.origin ?? globalThis.location.origin
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  assertSameOriginUrl(manifestUrl, origin)

  const manifestAsset = await fetchBoundedJsonAsset(
    manifestUrl,
    MAX_RUNTIME_MANIFEST_BYTES,
    fetchImpl,
    timeoutMs,
  )
  let manifest
  try {
    manifest = parseRuntimeManifest(manifestAsset.value)
  } catch {
    throw new PresentationLoadError(
      'verification',
      'The reviewed runtime manifest failed closed validation.',
    )
  }

  const keyUrl = resolveSameOriginAssetUrl(manifest.key.path, manifestUrl, origin)
  const keyAsset = await fetchBoundedJsonAsset(
    keyUrl,
    MAX_PUBLIC_KEY_BYTES,
    fetchImpl,
    timeoutMs,
  )
  await requireContentDigest(
    keyAsset.bytes,
    manifest.key.assetSha256,
    cryptoProvider,
    'reviewed public key',
  )

  const phaseEntries = await Promise.all(
    manifest.phases.map(async (phaseAsset) => {
      const payloadUrl = resolveSameOriginAssetUrl(
        phaseAsset.payloadPath,
        manifestUrl,
        origin,
      )
      const attestationUrl = resolveSameOriginAssetUrl(
        phaseAsset.attestationPath,
        manifestUrl,
        origin,
      )
      const [payload, attestation] = await Promise.all([
        fetchBoundedJsonAsset(
          payloadUrl,
          MAX_PRESENTATION_BYTES,
          fetchImpl,
          timeoutMs,
        ),
        fetchBoundedJsonAsset(
          attestationUrl,
          MAX_ATTESTATION_BYTES,
          fetchImpl,
          timeoutMs,
        ),
      ])
      await Promise.all([
        requireContentDigest(
          payload.bytes,
          phaseAsset.payloadSha256,
          cryptoProvider,
          `${phaseAsset.phase} payload`,
        ),
        requireContentDigest(
          attestation.bytes,
          phaseAsset.attestationSha256,
          cryptoProvider,
          `${phaseAsset.phase} attestation`,
        ),
      ])
      return [
        phaseAsset.phase,
        { payload: payload.value, attestation: attestation.value },
      ] as const
    }),
  )

  try {
    const publicKey = parsePresentationPublicKey(keyAsset.value)
    const assets = Object.fromEntries(phaseEntries) as UnverifiedLifecycleAssets
    return await verifyLifecycleAssets(manifest, publicKey, assets, cryptoProvider)
  } catch {
    throw new PresentationLoadError(
      'verification',
      'Athena lifecycle authenticity or consistency verification failed closed.',
    )
  }
}

export const resolveSameOriginAssetUrl = (
  path: string,
  manifestUrl: URL,
  expectedOrigin: string,
): URL => {
  if (
    !path.startsWith('./') ||
    path.includes('..') ||
    path.includes('\\') ||
    path.includes('%') ||
    path.includes('?') ||
    path.includes('#')
  ) {
    throw new PresentationLoadError(
      'same-origin',
      'Runtime assets must use bounded relative same-origin paths.',
    )
  }
  const url = new URL(path, manifestUrl)
  assertSameOriginUrl(url, expectedOrigin)
  return url
}

export const fetchBoundedJsonAsset = async (
  url: URL,
  maximumBytes: number,
  fetchImpl: typeof fetch = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<BoundedJsonAsset> => {
  if (typeof fetchImpl !== 'function' || timeoutMs < 1 || timeoutMs > 30_000) {
    throw new PresentationLoadError(
      'configuration',
      'Presentation runtime configuration is invalid.',
    )
  }
  const controller = new AbortController()
  const timer = globalThis.setTimeout(() => controller.abort(), timeoutMs)
  let response: Response
  try {
    response = await fetchImpl(url.href, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error',
      signal: controller.signal,
    })
  } catch {
    globalThis.clearTimeout(timer)
    throw new PresentationLoadError(
      'network',
      'A reviewed presentation asset could not be loaded.',
    )
  }
  try {
    if (!response.ok || response.redirected) {
      throw new PresentationLoadError(
        'http',
        'A reviewed presentation asset returned an unacceptable response.',
      )
    }
    const contentType = response.headers.get('content-type')?.toLowerCase() ?? ''
    if (!/^application\/json(?:\s*;|$)/.test(contentType)) {
      throw new PresentationLoadError(
        'content-type',
        'A reviewed presentation asset was not served as application/json.',
      )
    }
    const declaredLength = response.headers.get('content-length')
    if (declaredLength !== null) {
      const declaredBytes = Number(declaredLength)
      if (
        !Number.isSafeInteger(declaredBytes) ||
        declaredBytes < 1 ||
        declaredBytes > maximumBytes
      ) {
        throw new PresentationLoadError(
          'size',
          'A reviewed presentation asset exceeded its byte bound.',
        )
      }
    }
    const bytes = await readBoundedResponseBytes(response, maximumBytes)
    let text: string
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    } catch {
      throw new PresentationLoadError(
        'utf8',
        'A reviewed presentation asset was not valid UTF-8.',
      )
    }
    try {
      return { bytes, value: JSON.parse(text) as unknown }
    } catch {
      throw new PresentationLoadError(
        'json',
        'A reviewed presentation asset was not valid JSON.',
      )
    }
  } catch (error) {
    if (error instanceof PresentationLoadError) throw error
    throw new PresentationLoadError(
      'network',
      'A reviewed presentation asset could not be loaded.',
    )
  } finally {
    globalThis.clearTimeout(timer)
  }
}

const assertSameOriginUrl = (url: URL, expectedOrigin: string): void => {
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:') ||
    url.origin !== expectedOrigin ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw new PresentationLoadError(
      'same-origin',
      'Presentation assets must be loaded from the application origin.',
    )
  }
}

const requireContentDigest = async (
  bytes: Uint8Array,
  expected: Sha256Digest,
  cryptoProvider: Crypto,
  label: `${LifecyclePhase} payload` | `${LifecyclePhase} attestation` | 'reviewed public key',
): Promise<void> => {
  if ((await sha256Digest(bytes, cryptoProvider)) !== expected) {
    throw new PresentationLoadError(
      'digest',
      `The ${label} did not match its reviewed content digest.`,
    )
  }
}

const readBoundedResponseBytes = async (
  response: Response,
  maximumBytes: number,
): Promise<Uint8Array> => {
  if (!response.body) {
    const buffer = await response.arrayBuffer()
    if (buffer.byteLength < 1 || buffer.byteLength > maximumBytes) {
      throw new PresentationLoadError(
        'size',
        'A reviewed presentation asset exceeded its byte bound.',
      )
    }
    return new Uint8Array(buffer)
  }

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let totalBytes = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    totalBytes += value.byteLength
    if (totalBytes > maximumBytes) {
      await reader.cancel()
      throw new PresentationLoadError(
        'size',
        'A reviewed presentation asset exceeded its byte bound.',
      )
    }
    chunks.push(value)
  }
  if (totalBytes < 1) {
    throw new PresentationLoadError(
      'size',
      'A reviewed presentation asset exceeded its byte bound.',
    )
  }
  const bytes = new Uint8Array(totalBytes)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return bytes
}
