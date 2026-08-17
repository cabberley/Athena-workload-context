import { caseFold as unicodeCaseFold } from 'unicode-case-folding'
import type { CanonicalWorkloadManifest, JsonObject, JsonValue } from './types'

const MAX_SAFE_INTEGER = 9_007_199_254_740_991
const TIMESTAMP = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/
const TIMESTAMP_PREFIX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/

const clone = <T>(value: T): T => structuredClone(value)

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
  if (fraction && fraction.length > 3) {
    throw new Error('Canonical timestamps must be exactly representable in milliseconds.')
  }
  const [dateText, timeText] = match[1]!.split('T')
  const [year, month, day] = dateText!.split('-').map(Number)
  const [hour, minute, second] = timeText!.split(':').map(Number)
  const offset = match[3]!
  const [offsetHour, offsetMinute] =
    offset === 'Z' ? [0, 0] : offset.slice(1).split(':').map(Number)
  const daysInMonth = new Date(Date.UTC(year!, month!, 0)).getUTCDate()
  if (
    year! < 1 ||
    month! < 1 ||
    month! > 12 ||
    day! < 1 ||
    day! > daysInMonth ||
    hour! > 23 ||
    minute! > 59 ||
    second! > 59 ||
    offsetHour! > 23 ||
    offsetMinute! > 59
  ) {
    return value
  }
  const parsed = new Date(value)
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toISOString()
}

const normalizeJson = (value: JsonValue): JsonValue => {
  if (value === null || typeof value === 'boolean') {
    return value
  }
  if (typeof value === 'string') {
    const normalized = assertUnicodeScalarText(value)
    return normalized.includes('T') ? normalizeTimestamp(normalized) : normalized
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('Canonical JSON rejects non-finite numbers.')
    }
    if (Object.is(value, -0)) {
      throw new Error('Canonical JSON rejects negative zero.')
    }
    if (Number.isInteger(value) && Math.abs(value) > MAX_SAFE_INTEGER) {
      throw new Error('Canonical JSON rejects integers outside the IEEE-754 safe range.')
    }
    return value
  }
  if (Array.isArray(value)) {
    return value.map(normalizeJson)
  }

  const normalized: JsonObject = {}
  for (const [rawKey, item] of Object.entries(value)) {
    const key = assertUnicodeScalarText(rawKey)
    if (Object.hasOwn(normalized, key)) {
      throw new Error('Canonical JSON rejects colliding NFC-normalized object keys.')
    }
    normalized[key] = normalizeJson(item)
  }
  return normalized
}

/**
 * RFC 8785 JSON Canonicalization Scheme rendering. JSON.stringify uses the
 * ECMAScript number and string serialization required by RFC 8785; keys are
 * ordered by UTF-16 code units before rendering.
 */
export const canonicalizeJson = (value: JsonValue): string => {
  const render = (item: JsonValue): string => {
    if (item === null || typeof item === 'boolean' || typeof item === 'number' || typeof item === 'string') {
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

const sha256 = async (value: string): Promise<string> => {
  const bytes = new TextEncoder().encode(value)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  const hexadecimal = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
  return `sha256:${hexadecimal}`
}

const materializeManifestDefaults = (manifest: CanonicalWorkloadManifest): void => {
  const root = manifest as unknown as JsonObject
  for (const name of ['relationships', 'constraints', 'controls', 'riskAcceptances', 'objectives']) {
    root[name] ??= []
  }

  const materializeSelector = (selector: JsonObject): void => {
    if (selector.selectorType === 'resourceType') {
      selector.locations ??= []
      selector.resourceGroups ??= []
    } else if (selector.selectorType === 'vmScaleSet') {
      selector.instanceIds ??= []
    }
    if (Array.isArray(selector.children)) {
      for (const child of selector.children) {
        if (typeof child === 'object' && child !== null && !Array.isArray(child)) {
          materializeSelector(child)
        }
      }
    }
  }

  const materializeCollections = (container: JsonObject): void => {
    if (Array.isArray(container.roles)) {
      for (const role of container.roles) {
        if (typeof role !== 'object' || role === null || Array.isArray(role)) continue
        role.status ??= 'approved'
        if (Array.isArray(role.selectors)) {
          for (const selector of role.selectors) {
            if (typeof selector === 'object' && selector !== null && !Array.isArray(selector)) {
              materializeSelector(selector)
            }
          }
        }
      }
    }
    if (Array.isArray(container.constraints)) {
      for (const constraint of container.constraints) {
        if (typeof constraint === 'object' && constraint !== null && !Array.isArray(constraint)) {
          constraint.protected ??= false
        }
      }
    }
    if (Array.isArray(container.riskAcceptances)) {
      for (const risk of container.riskAcceptances) {
        if (typeof risk === 'object' && risk !== null && !Array.isArray(risk)) {
          risk.linkedControlRefs ??= []
          risk.acceptedResourceBindings ??= []
        }
      }
    }
  }

  materializeCollections(root)
  for (const profile of Object.values(manifest.profiles)) {
    const profileObject = profile as unknown as JsonObject
    for (const name of [
      'roles',
      'relationships',
      'constraints',
      'controls',
      'riskAcceptances',
      'objectives',
      'ownership',
      'weakeningOverrides',
      'disabledRefs',
    ]) {
      profileObject[name] ??= []
    }
    materializeCollections(profileObject)
  }
}

const caseFold = (value: string): string => unicodeCaseFold(value.normalize('NFC'))

const comparePythonText = (left: string, right: string): number => {
  const leftCodePoints = Array.from(left, (character) => character.codePointAt(0)!)
  const rightCodePoints = Array.from(right, (character) => character.codePointAt(0)!)
  const length = Math.min(leftCodePoints.length, rightCodePoints.length)
  for (let index = 0; index < length; index += 1) {
    const difference = leftCodePoints[index]! - rightCodePoints[index]!
    if (difference !== 0) return difference
  }
  return leftCodePoints.length - rightCodePoints.length
}

const sortManifestCollections = (manifest: CanonicalWorkloadManifest): void => {
  const keyFields: Record<string, string[]> = {
    roles: ['roleId'],
    constraints: ['constraintId'],
    controls: ['controlId'],
    riskAcceptances: ['riskAcceptanceId'],
    objectives: ['objectiveId'],
    ownership: ['ownerRef'],
    weakeningOverrides: ['overrideId'],
    disabledRefs: ['targetKind', 'targetRef'],
  }

  const compareKeys = (left: JsonObject, right: JsonObject, keys: string[]): number => {
    for (const key of keys) {
      const result = comparePythonText(caseFold(String(left[key] ?? '')), caseFold(String(right[key] ?? '')))
      if (result !== 0) return result
    }
    return 0
  }

  const sortSelectorChildren = (selector: JsonObject): void => {
    if (!Array.isArray(selector.children)) return
    const children = selector.children.filter(
      (child): child is JsonObject => typeof child === 'object' && child !== null && !Array.isArray(child),
    )
    children.sort((left, right) => compareKeys(left, right, ['selectorId']))
    selector.children = children
    children.forEach(sortSelectorChildren)
  }

  const sortContainer = (container: JsonObject): void => {
    if (Array.isArray(container.relationships)) {
      container.relationships.sort((left, right) => {
        if (typeof left !== 'object' || left === null || Array.isArray(left)) return -1
        if (typeof right !== 'object' || right === null || Array.isArray(right)) return 1
        return compareKeys(
          { id: String(left.relationshipId ?? left.exceptionId ?? '') },
          { id: String(right.relationshipId ?? right.exceptionId ?? '') },
          ['id'],
        )
      })
    }
    for (const [name, keys] of Object.entries(keyFields)) {
      const collection = container[name]
      if (!Array.isArray(collection)) continue
      collection.sort((left, right) => {
        if (typeof left !== 'object' || left === null || Array.isArray(left)) return -1
        if (typeof right !== 'object' || right === null || Array.isArray(right)) return 1
        return compareKeys(left, right, keys)
      })
      if (name === 'roles') {
        for (const role of collection) {
          if (typeof role !== 'object' || role === null || Array.isArray(role) || !Array.isArray(role.selectors)) continue
          role.selectors.sort((left, right) => {
            if (typeof left !== 'object' || left === null || Array.isArray(left)) return -1
            if (typeof right !== 'object' || right === null || Array.isArray(right)) return 1
            return compareKeys(left, right, ['selectorId'])
          })
          for (const selector of role.selectors) {
            if (typeof selector === 'object' && selector !== null && !Array.isArray(selector)) {
              sortSelectorChildren(selector)
            }
          }
        }
      }
    }
  }

  sortContainer(manifest as unknown as JsonObject)
  const sortedProfiles = Object.keys(manifest.profiles)
    .sort((left, right) => comparePythonText(caseFold(left), caseFold(right)))
    .reduce<Record<string, typeof manifest.profiles[string]>>((result, key) => {
      result[key] = manifest.profiles[key]!
      sortContainer(result[key] as unknown as JsonObject)
      return result
    }, {})
  manifest.profiles = sortedProfiles
}

const digestPayload = (manifest: CanonicalWorkloadManifest, semantic: boolean): JsonObject => {
  const payload = clone(manifest)
  materializeManifestDefaults(payload)
  sortManifestCollections(payload)
  const compatibility = payload.compatibility as unknown as JsonObject
  delete compatibility.artifactDigest
  delete compatibility.semanticDigest
  if (semantic) {
    delete (payload.workload as unknown as JsonObject).displayName
    delete compatibility.schemaVersion
  }
  return payload as unknown as JsonObject
}

export const refreshCanonicalManifestDigests = async (
  manifest: CanonicalWorkloadManifest,
): Promise<CanonicalWorkloadManifest> => {
  const canonical = clone(manifest)
  materializeManifestDefaults(canonical)
  sortManifestCollections(canonical)
  canonical.compatibility.artifactDigest = await sha256(canonicalizeJson(digestPayload(canonical, false)))
  canonical.compatibility.semanticDigest = await sha256(canonicalizeJson(digestPayload(canonical, true)))
  return canonical
}
