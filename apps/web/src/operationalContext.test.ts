import {
  computeOperationalBindingDigest,
  computeOperationalContentDigest,
  computeOperationalEvidenceInventoryDigest,
  computeOperationalReceiptId,
  computeOperationalReceiptDigest,
  validateOperationalContext,
} from './operationalContext'

const request = {
  workloadId: 'wl-synthetic-operational',
  manifestVersion: '1.2.3',
  profileId: 'production',
  draftId: 'draft-operational-001',
  draftRevision: 7,
  manifestDigest: `sha256:${'a'.repeat(64)}`,
  profileDigest: `sha256:${'b'.repeat(64)}`,
  asOf: '2026-09-08T00:05:00.000Z',
}

const evidenceInventory = [{
  evidenceRef: 'evidence-flow-001',
  evidenceDigest: `sha256:${'1'.repeat(64)}`,
}]

const snapshot = async () => {
  const snapshotId = 'snapshot-operational-001'
  const collectedAt = '2026-09-08T00:00:00.000Z'
  const expiresAt = '2026-09-08T01:00:00.000Z'
  const evidenceSource = 'Signed synthetic correlation output'
  const snapshotConfidence = 0.82
  const relationships = [{
    id: 'observed-web-worker',
    kind: 'observed' as const,
    source: 'web',
    target: 'worker',
    evidenceRefs: ['evidence-flow-001'],
    observedAt: '2026-09-08T00:00:00.000Z',
    confidence: 0.9,
    profileId: request.profileId,
  }]
  const findings = [{
    id: 'finding-connectivity',
    verdict: 'humanReviewRequired',
    summary: 'Synthetic connectivity requires review.',
    manifestVersion: request.manifestVersion,
    profileId: request.profileId,
    clause: '/profiles/production/relationships/0',
    evidenceRefs: ['evidence-flow-001'],
    residualRisk: null,
    controlState: 'unknown',
    confidence: 0.7,
  }]
  const evidenceInventoryDigest =
    await computeOperationalEvidenceInventoryDigest(evidenceInventory)
  const contentDigest = await computeOperationalContentDigest({
    evidenceSource,
    confidence: snapshotConfidence,
    relationships,
    findings,
  })
  const bindingDigest = await computeOperationalBindingDigest({
    workloadId: request.workloadId,
    manifestVersion: request.manifestVersion,
    profileId: request.profileId,
    draftId: request.draftId,
    draftRevision: request.draftRevision,
    manifestDigest: request.manifestDigest,
    profileDigest: request.profileDigest,
    snapshotId,
    collectedAt,
    expiresAt,
    evidenceInventoryDigest,
    contentDigest,
  })
  const receiptBase = {
    schemaVersion:
      'athena.context-api.operational-context-receipt.v1' as const,
    receiptId: 'operational-placeholder',
    issuedBy: {
      actorId: 'operational-context-service',
      kind: 'service' as const,
    },
    issuedAt: '2026-09-08T00:01:00.000Z',
    manifestId: request.workloadId,
    manifestVersion: request.manifestVersion,
    profileId: request.profileId,
    draftId: request.draftId,
    draftRevision: request.draftRevision,
    manifestDigest: request.manifestDigest,
    profileDigest: request.profileDigest,
    snapshotId,
    collectedAt,
    expiresAt,
    evidenceCount: evidenceInventory.length,
    evidenceInventoryDigest,
    contentDigest,
    bindingDigest,
    receiptDigest: `sha256:${'0'.repeat(64)}`,
  }
  const receipt = {
    ...receiptBase,
    receiptId: await computeOperationalReceiptId(receiptBase),
  }
  receipt.receiptDigest = await computeOperationalReceiptDigest(receipt)
  return {
  schemaVersion: 'athena.contextStudio.operationalContext.v1',
  workloadId: request.workloadId,
  manifestVersion: request.manifestVersion,
  profileId: request.profileId,
  draftId: request.draftId,
  draftRevision: request.draftRevision,
  manifestDigest: request.manifestDigest,
  profileDigest: request.profileDigest,
  receiptId: receipt.receiptId,
  snapshotId,
  collectedAt,
  expiresAt,
  evidenceSource,
  confidence: snapshotConfidence,
  evidenceInventory,
  evidenceInventoryDigest,
  contentDigest,
  bindingDigest,
  receipt: {
    schema_version: receipt.schemaVersion,
    receipt_id: receipt.receiptId,
    issued_by: {
      actor_id: receipt.issuedBy.actorId,
      kind: receipt.issuedBy.kind,
    },
    issued_at: receipt.issuedAt,
    manifest_id: receipt.manifestId,
    manifest_version: receipt.manifestVersion,
    profile_id: receipt.profileId,
    draft_id: receipt.draftId,
    draft_revision: receipt.draftRevision,
    manifest_digest: receipt.manifestDigest,
    profile_digest: receipt.profileDigest,
    snapshot_id: receipt.snapshotId,
    collected_at: receipt.collectedAt,
    expires_at: receipt.expiresAt,
    evidence_count: receipt.evidenceCount,
    evidence_inventory_digest: receipt.evidenceInventoryDigest,
    content_digest: receipt.contentDigest,
    binding_digest: receipt.bindingDigest,
    receipt_digest: receipt.receiptDigest,
  },
  relationships,
  findings,
  }
}

describe('operational context boundary', () => {
  it('accepts only exact evidence-bound relationships and findings', async () => {
    const result = await validateOperationalContext(await snapshot(), request)

    expect(result.relationships[0]).toMatchObject({
      kind: 'observed',
      evidenceRefs: ['evidence-flow-001'],
      profileId: 'production',
    })
    expect(result.findings[0]).toMatchObject({
      manifestVersion: '1.2.3',
      profileId: 'production',
    })
  })

  it('rejects cross-version findings and evidence-free relationships', async () => {
    const value = await snapshot()
    await expect(validateOperationalContext({
      ...value,
      relationships: [{ ...value.relationships[0], evidenceRefs: [] }],
    }, request)).rejects.toThrow(/requires evidence/i)
    await expect(validateOperationalContext({
      ...value,
      findings: [{ ...value.findings[0], manifestVersion: '9.9.9' }],
    }, request)).rejects.toThrow(/exact manifest\/profile binding/i)
    await expect(validateOperationalContext({
      ...value,
      relationships: [{
        ...value.relationships[0],
        evidenceRefs: ['unrelated-evidence'],
      }],
    }, request)).rejects.toThrow(/unknown evidence/i)
  })

  it('rejects an operational snapshot without evidence', async () => {
    const value = await snapshot()

    await expect(validateOperationalContext({
      ...value,
      evidenceInventory: [],
    }, request)).rejects.toThrow(/exact requested binding/i)
  })

  it('rejects a receipt from a different rendered snapshot', async () => {
    const value = await snapshot()

    await expect(validateOperationalContext({
      ...value,
      receipt: {
        ...value.receipt,
        snapshot_id: 'snapshot-substituted',
      },
    }, request)).rejects.toThrow(/exact rendered snapshot/i)
  })

  it('rejects substituted rendered findings under a valid receipt', async () => {
    const value = await snapshot()

    await expect(validateOperationalContext({
      ...value,
      findings: [{
        ...value.findings[0],
        verdict: 'healthy',
        summary: 'Forged healthy verdict.',
      }],
    }, request)).rejects.toThrow(/content digest is invalid/i)
  })
})
