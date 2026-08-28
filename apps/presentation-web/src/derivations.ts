import type { PresentationPayload } from './contracts'

export type BlastRadius = 'none-active' | 'contained-web-tier' | 'resolved'
export type AvailabilityImpact = 'normal' | 'warning'
export type RedundancyImpact = 'full' | 'reduced'
export type OperatorAttention = 'normal' | 'required'

export interface ImpactLevel {
  availability: AvailabilityImpact
  redundancy: RedundancyImpact
  operatorAttention: OperatorAttention
}

export class DerivationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DerivationError'
  }
}

export const deriveBlastRadius = (payload: PresentationPayload): BlastRadius => {
  const webTier = payload.runtimeState.webTier
  if (
    payload.phase === 'baseline' &&
    payload.faultRun === undefined &&
    webTier.serviceState === 'healthy' &&
    webTier.faultedNodes === 0 &&
    webTier.runningNodes === webTier.expectedNodes
  ) {
    return 'none-active'
  }
  if (
    payload.phase === 'faulted' &&
    payload.faultRun?.afterPowerState === 'stopped' &&
    webTier.serviceState === 'degraded-redundancy' &&
    webTier.faultedNodes === 1 &&
    webTier.runningNodes >= 1 &&
    webTier.runningNodes + webTier.faultedNodes === webTier.expectedNodes
  ) {
    return 'contained-web-tier'
  }
  if (
    payload.phase === 'recovered' &&
    payload.faultRun?.afterPowerState === 'running' &&
    webTier.serviceState === 'recovered' &&
    webTier.faultedNodes === 0 &&
    webTier.runningNodes === webTier.expectedNodes
  ) {
    return 'resolved'
  }
  throw new DerivationError('Signed lifecycle fields do not support a blast-radius derivation.')
}

export const deriveImpactLevel = (payload: PresentationPayload): ImpactLevel => {
  const webTier = payload.runtimeState.webTier
  const availability: AvailabilityImpact =
    webTier.serviceState === 'degraded-redundancy'
      ? 'warning'
      : webTier.serviceState === 'healthy' || webTier.serviceState === 'recovered'
        ? 'normal'
        : failImpact()
  const redundancy: RedundancyImpact =
    webTier.faultedNodes === 0
      ? 'full'
      : webTier.faultedNodes === 1
        ? 'reduced'
        : failImpact()
  const operatorAttention: OperatorAttention =
    payload.argus.riskLevel === 'warning'
      ? 'required'
      : payload.argus.riskLevel === 'normal'
        ? 'normal'
        : failImpact()
  return { availability, redundancy, operatorAttention }
}

const failImpact = (): never => {
  throw new DerivationError('Signed lifecycle fields do not support an impact derivation.')
}
