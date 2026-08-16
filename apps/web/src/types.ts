export type EnvironmentName = 'Production' | 'Development' | 'Training'
export type ApprovalState = 'draft' | 'validation' | 'approved' | 'published'
export type RelationshipKind = 'declared' | 'observed' | 'inferred' | 'exception'

export interface AuthState {
  status: 'authenticated' | 'stubbed'
  user: string
  port: string
}

export interface CatalogItem {
  id: string
  name: string
  owner: string
  criticality: string
  zoneCount: number
  status: string
}

export interface ComparisonRow {
  environment: EnvironmentName
  topology: string
  policy: string
  residualRisk: string
  confidence: number
}

export interface TopologyRelationship {
  kind: RelationshipKind
  title: string
  detail: string
  clause: string
}

export interface ControlRecord {
  id: string
  name: string
  owner: string
  description: string
  status: 'active' | 'review' | 'accepted'
}

export interface RiskAcceptance {
  id: string
  description: string
  owner: string
  accepted: boolean
}

export interface EvidenceItem {
  id: string
  source: string
  summary: string
  clause: string
  manifestVersion: string
  confidence: number
}

export interface ManifestDraft {
  workloadName: string
  environment: EnvironmentName
  businessOwner: string
  runbook: string
  requiredRelationships: string[]
  optionalRelationships: string[]
  controls: ControlRecord[]
  riskAcceptances: RiskAcceptance[]
}

export interface ContextStudioSnapshot {
  environment: EnvironmentName
  auth: AuthState
  evidenceSource: string
  confidence: number
  manifestVersion: string
  approvalState: ApprovalState
  workloadCatalogue: CatalogItem[]
  comparison: ComparisonRow[]
  relationships: TopologyRelationship[]
  manifest: ManifestDraft
  controls: ControlRecord[]
  riskAcceptances: RiskAcceptance[]
  provenance: EvidenceItem[]
  validationMessages: string[]
}
