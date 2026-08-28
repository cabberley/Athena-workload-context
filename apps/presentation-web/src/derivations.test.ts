import { parsePresentationPayload, type PresentationPayload } from './contracts'
import { deriveBlastRadius, deriveImpactLevel } from './derivations'
import { payloadFor } from './test/fixtures'

const parsedPayload = (phase: 'baseline' | 'faulted' | 'recovered') =>
  parsePresentationPayload(payloadFor(phase), phase)

describe('signed-field-only presentation derivations', () => {
  it('derives every allowed blast-radius state', () => {
    expect(deriveBlastRadius(parsedPayload('baseline'))).toBe('none-active')
    expect(deriveBlastRadius(parsedPayload('faulted'))).toBe('contained-web-tier')
    expect(deriveBlastRadius(parsedPayload('recovered'))).toBe('resolved')
  })

  it('derives availability, redundancy and operator attention exactly', () => {
    expect(deriveImpactLevel(parsedPayload('baseline'))).toEqual({
      availability: 'normal',
      redundancy: 'full',
      operatorAttention: 'normal',
    })
    expect(deriveImpactLevel(parsedPayload('faulted'))).toEqual({
      availability: 'warning',
      redundancy: 'reduced',
      operatorAttention: 'required',
    })
    expect(deriveImpactLevel(parsedPayload('recovered'))).toEqual({
      availability: 'normal',
      redundancy: 'full',
      operatorAttention: 'normal',
    })
  })

  it('fails closed for inconsistent blast-radius combinations', () => {
    const inconsistent = structuredClone(parsedPayload('faulted'))
    inconsistent.runtimeState.webTier.runningNodes = 0
    expect(() => deriveBlastRadius(inconsistent)).toThrow(/do not support/i)
  })

  it('fails closed rather than inferring unsupported multi-node impact', () => {
    const unsupported = structuredClone(parsedPayload('faulted'))
    unsupported.runtimeState.webTier.faultedNodes = 2
    expect(() => deriveImpactLevel(unsupported as PresentationPayload)).toThrow(
      /do not support/i,
    )
  })
})
