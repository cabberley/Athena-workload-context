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
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/
const TIMESTAMP_PREFIX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/
const UTC_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(?:Z|\+00:00)$/

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
  const fraction = match[7]
  if (fraction && fraction.length > 3) {
    if (
      fraction.length > 6 ||
      [...fraction.slice(3)].some((digit) => digit !== '0')
    ) {
      return value
    }
  }
  if (!hasValidTimestampComponents(value, match)) return value
  const parsed = new Date(value)
  if (Number.isNaN(parsed.valueOf())) return value
  return parsed.toISOString()
}

export const canonicalizeUtcTimestamp = (value: unknown): string | null => {
  if (typeof value !== 'string') return null
  const match = UTC_TIMESTAMP.exec(value)
  if (!match || Number(match[1]) === 0 || !hasValidTimestampComponents(value, match)) {
    return null
  }
  const parsed = new Date(value)
  return Number.isNaN(parsed.valueOf()) ? null : parsed.toISOString()
}

const hasValidTimestampComponents = (
  value: string,
  match: RegExpExecArray,
): boolean => {
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const hour = Number(match[4])
  const minute = Number(match[5])
  const second = Number(match[6])
  const fraction = (match[7] ?? '').slice(0, 3).padEnd(3, '0')
  const offset = value.endsWith('Z') ? '+00:00' : value.slice(-6)
  const offsetHours = Number(offset.slice(1, 3))
  const offsetMinutes = Number(offset.slice(4, 6))
  if (
    year === 0 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHours > 23 ||
    offsetMinutes > 59
  ) {
    return false
  }
  const wallClock = new Date(Date.UTC(year, month - 1, day, hour, minute, second, Number(fraction)))
  return (
    wallClock.getUTCFullYear() === year &&
    wallClock.getUTCMonth() === month - 1 &&
    wallClock.getUTCDate() === day &&
    wallClock.getUTCHours() === hour &&
    wallClock.getUTCMinutes() === minute &&
    wallClock.getUTCSeconds() === second &&
    wallClock.getUTCMilliseconds() === Number(fraction)
  )
}
