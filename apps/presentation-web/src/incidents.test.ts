import { describe, expect, it } from 'vitest'
import { assertIncidentFeedFreshness } from './incidents'

const NOW = Date.parse('2026-09-04T04:00:00Z')

describe('incident feed freshness', () => {
  it('accepts a fresh signed aggregate even when incident entries are long-running', () => {
    expect(() =>
      assertIncidentFeedFreshness('2026-09-04T03:45:00Z', NOW),
    ).not.toThrow()
  })

  it('rejects a stale signed aggregate', () => {
    expect(() =>
      assertIncidentFeedFreshness('2026-09-04T03:44:59.999Z', NOW),
    ).toThrow('Active incident feed is outside its freshness window.')
  })

  it('rejects an aggregate outside the permitted future clock skew', () => {
    expect(() =>
      assertIncidentFeedFreshness('2026-09-04T04:01:00.001Z', NOW),
    ).toThrow('Active incident feed is outside its freshness window.')
  })
})
