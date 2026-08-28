import type { PresentationPayload, Sha256Digest } from './contracts'

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue }

const MAX_SAFE_INTEGER = 9_007_199_254_740_991
const TIMESTAMP =
  /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/
const TIMESTAMP_PREFIX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/

export const canonicalizeJson = (value: JsonValue): string => {
  const render = (item: JsonValue): string => {
    if (
      item === null ||
      typeof item === 'boolean' ||
      typeof item === 'number' ||
      typeof item === 'string'
    ) {
      return JSON.stringify(item)
    }
    if (Array.isArray(item)) {
      return `[${item.map(render).join(',')}]`
    }
    return `{${Object.keys(item)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${render(item[key]!)}`)
      .join(',')}}`
  }
  return render(normalizeJson(value))
}

export const presentationCanonicalPreimage = (payload: PresentationPayload): Uint8Array => {
  const preimage = structuredClone(payload) as unknown as Record<string, JsonValue>
  const athena = preimage.athena
  if (typeof athena !== 'object' || athena === null || Array.isArray(athena)) {
    throw new Error('Presentation Athena metadata is required.')
  }
  delete athena.resultDigest
  return new TextEncoder().encode(canonicalizeJson(preimage))
}

export const sha256Digest = async (
  value: BufferSource | string,
  cryptoProvider: Crypto = globalThis.crypto,
): Promise<Sha256Digest> => {
  if (!cryptoProvider?.subtle) {
    throw new Error('Web Crypto is unavailable.')
  }
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value
  const digest = await cryptoProvider.subtle.digest('SHA-256', bytes)
  const hexadecimal = Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('')
  return `sha256:${hexadecimal}`
}

const normalizeJson = (value: JsonValue): JsonValue => {
  if (value === null || typeof value === 'boolean') return value
  if (typeof value === 'string') {
    const normalized = assertUnicodeScalarText(value)
    return normalized.includes('T') ? normalizeTimestamp(normalized) : normalized
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Canonical JSON rejects non-finite numbers.')
    if (Object.is(value, -0)) throw new Error('Canonical JSON rejects negative zero.')
    if (Number.isInteger(value) && Math.abs(value) > MAX_SAFE_INTEGER) {
      throw new Error('Canonical JSON rejects integers outside the IEEE-754 safe range.')
    }
    return value
  }
  if (Array.isArray(value)) return value.map(normalizeJson)

  const normalized: Record<string, JsonValue> = {}
  for (const [rawKey, item] of Object.entries(value)) {
    const key = assertUnicodeScalarText(rawKey)
    if (Object.hasOwn(normalized, key)) {
      throw new Error('Canonical JSON rejects colliding NFC-normalized object keys.')
    }
    normalized[key] = normalizeJson(item)
  }
  return normalized
}

const assertUnicodeScalarText = (value: string): string => {
  const normalized = value.normalize('NFC')
  for (let index = 0; index < normalized.length; index += 1) {
    const code = normalized.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = normalized.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error('Canonical JSON rejects unpaired Unicode surrogates.')
      }
      index += 1
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error('Canonical JSON rejects unpaired Unicode surrogates.')
    }
  }
  return normalized
}

const normalizeTimestamp = (value: string): string => {
  const match = TIMESTAMP.exec(value)
  if (!match) {
    if (TIMESTAMP_PREFIX.test(value)) {
      throw new Error('Canonical timestamps require RFC 3339 Z or an explicit offset.')
    }
    return value
  }
  const fraction = match[2]
  if (fraction && fraction.length > 3 && [...fraction.slice(3)].some((digit) => digit !== '0')) {
    throw new Error('Canonical timestamps must be exactly representable in milliseconds.')
  }
  const parsed = new Date(value)
  if (Number.isNaN(parsed.valueOf())) return value
  return parsed.toISOString()
}
