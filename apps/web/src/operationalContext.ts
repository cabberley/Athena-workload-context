import { canonicalizeJson } from './canonical'
import type {
  Actor,
  ContextFinding,
  InferredTopologyRelationship,
  JsonValue,
  ObservedTopologyRelationship,
  OperationalContextRequest,
  OperationalContextReceipt,
  OperationalContextSnapshot,
} from './types'

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/
const DIGEST = /^sha256:[a-f0-9]{64}$/
const MAX_RECORDS = 1000

const record = (value: unknown, label: string): Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`Operational context returned an invalid ${label}.`)
  }
  return value as Record<string, unknown>
}

const jsonValue = (value: unknown): JsonValue => {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return value
  }
  if (Array.isArray(value)) {
    return value.map(jsonValue)
  }
  if (typeof value === 'object') {
    const result: Record<string, JsonValue> = {}
    for (const [key, item] of Object.entries(value)) {
      result[key] = jsonValue(item)
    }
    return result
  }
  throw new Error('Operational context contains a non-JSON value.')
}

const text = (
  value: unknown,
  label: string,
  maximum = 2048,
): string => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximum ||
    value !== value.trim()
  ) {
    throw new Error(`Operational context returned an invalid ${label}.`)
  }
  return value
}

const confidence = (value: unknown, label: string): number | null => {
  if (value === null) return null
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`Operational context returned an invalid ${label}.`)
  }
  return value
}

const stringArray = (value: unknown, label: string): string[] => {
  if (!Array.isArray(value) || value.length > 100) {
    throw new Error(`Operational context returned an invalid ${label}.`)
  }
  const result = value.map((item, index) => text(item, `${label}[${index}]`, 512))
  if (new Set(result).size !== result.length) {
    throw new Error(`Operational context returned duplicate ${label}.`)
  }
  return result
}

export const computeOperationalEvidenceInventoryDigest = async (
  inventory: Array<{ evidenceRef: string; evidenceDigest: string }>,
): Promise<string> => {
  const canonical = [...inventory]
    .sort((left, right) =>
      left.evidenceRef < right.evidenceRef
        ? -1
        : left.evidenceRef > right.evidenceRef
          ? 1
          : 0
    )
    .map((item) => ({
      evidenceDigest: item.evidenceDigest,
      evidenceRef: item.evidenceRef,
    }))
  const bytes = new TextEncoder().encode(JSON.stringify(canonical))
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return `sha256:${Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('')}`
}

const computeJsonDigest = async (value: unknown): Promise<string> => {
  const bytes = new TextEncoder().encode(JSON.stringify(value))
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return `sha256:${Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('')}`
}

export const computeOperationalReceiptDigest = async (
  receipt: Omit<OperationalContextReceipt, 'receiptDigest'>,
): Promise<string> => {
  const wire = {
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
  }
  const bytes = new TextEncoder().encode(
    canonicalizeJson(jsonValue(wire)),
  )
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return `sha256:${Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('')}`
}

export const computeOperationalContentDigest = async (content: {
  evidenceSource: string
  confidence: number | null
  relationships: Array<
    ObservedTopologyRelationship | InferredTopologyRelationship
  >
  findings: ContextFinding[]
}): Promise<string> => {
  const bytes = new TextEncoder().encode(
    canonicalizeJson(jsonValue({
      schemaVersion: 'athena.contextStudio.operationalContent.v1',
      evidenceSource: content.evidenceSource,
      confidence: content.confidence,
      relationships: content.relationships,
      findings: content.findings,
    })),
  )
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return `sha256:${Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('')}`
}

export const computeOperationalReceiptId = async (
  receipt: OperationalContextReceipt,
): Promise<string> => {
  const bytes = new TextEncoder().encode(
    canonicalizeJson(jsonValue({
      schemaVersion:
        'athena.context-api.operational-context-receipt-id.v1',
      issuedBy: {
        actor_id: receipt.issuedBy.actorId,
        kind: receipt.issuedBy.kind,
      },
      manifestId: receipt.manifestId,
      manifestVersion: receipt.manifestVersion,
      profileId: receipt.profileId,
      draftId: receipt.draftId,
      draftRevision: receipt.draftRevision,
      manifestDigest: receipt.manifestDigest,
      profileDigest: receipt.profileDigest,
      snapshotId: receipt.snapshotId,
      collectedAt: receipt.collectedAt,
      expiresAt: receipt.expiresAt,
      evidenceInventoryDigest: receipt.evidenceInventoryDigest,
      contentDigest: receipt.contentDigest,
      bindingDigest: receipt.bindingDigest,
    })),
  )
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  const hex = Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, '0'),
  ).join('')
  return `operational-${hex.slice(0, 32)}`
}

export const computeOperationalBindingDigest = async (binding: {
  workloadId: string
  manifestVersion: string
  profileId: string
  draftId: string
  draftRevision: number
  manifestDigest: string
  profileDigest: string
  snapshotId: string
  collectedAt: string
  expiresAt: string
  evidenceInventoryDigest: string
  contentDigest: string
}): Promise<string> => computeJsonDigest(binding)

const timestamp = (value: unknown, label: string): string => {
  const result = text(value, label, 64)
  if (!/(?:Z|[+-]\d{2}:\d{2})$/.test(result) || Number.isNaN(Date.parse(result))) {
    throw new Error(`Operational context returned an invalid ${label}.`)
  }
  return result
}

const parseOperationalReceipt = async (
    value: unknown,
    request: OperationalContextRequest,
    expected: {
      receiptId: string
      snapshotId: string
      collectedAt: string
      expiresAt: string
      evidenceCount: number
      evidenceInventoryDigest: string
      contentDigest: string
      bindingDigest: string
    },
  ): Promise<OperationalContextReceipt> => {
    const {
      receiptId,
      snapshotId,
      collectedAt,
      expiresAt,
      evidenceCount,
      evidenceInventoryDigest,
      contentDigest,
      bindingDigest,
    } = expected
    const item = record(value, 'receipt')
    const issuedByValue = record(item.issued_by, 'receipt.issued_by')
    const issuedBy: Actor = {
      actorId: text(issuedByValue.actor_id, 'receipt.issued_by.actor_id', 128),
      kind: text(
        issuedByValue.kind,
        'receipt.issued_by.kind',
        16,
      ) as Actor['kind'],
    }
    const issuedAt = timestamp(item.issued_at, 'receipt.issued_at')
    const receipt: OperationalContextReceipt = {
      schemaVersion: text(
        item.schema_version,
        'receipt.schema_version',
        64,
      ) as OperationalContextReceipt['schemaVersion'],
      receiptId: text(item.receipt_id, 'receipt.receipt_id', 128),
      issuedBy,
      issuedAt,
      manifestId: text(item.manifest_id, 'receipt.manifest_id', 128),
      manifestVersion: text(
        item.manifest_version,
        'receipt.manifest_version',
        64,
      ),
      profileId: text(item.profile_id, 'receipt.profile_id', 128),
      draftId: text(item.draft_id, 'receipt.draft_id', 128),
      draftRevision:
        typeof item.draft_revision === 'number' &&
        Number.isSafeInteger(item.draft_revision)
          ? item.draft_revision
          : -1,
      manifestDigest: text(
        item.manifest_digest,
        'receipt.manifest_digest',
        71,
      ),
      profileDigest: text(
        item.profile_digest,
        'receipt.profile_digest',
        71,
      ),
      snapshotId: text(item.snapshot_id, 'receipt.snapshot_id', 128),
      collectedAt: timestamp(item.collected_at, 'receipt.collected_at'),
      expiresAt: timestamp(item.expires_at, 'receipt.expires_at'),
      evidenceCount:
        typeof item.evidence_count === 'number' &&
        Number.isSafeInteger(item.evidence_count)
          ? item.evidence_count
          : -1,
      evidenceInventoryDigest: text(
        item.evidence_inventory_digest,
        'receipt.evidence_inventory_digest',
        71,
      ),
      contentDigest: text(
        item.content_digest,
        'receipt.content_digest',
        71,
      ),
      bindingDigest: text(
        item.binding_digest,
        'receipt.binding_digest',
        71,
      ),
      receiptDigest: text(
        item.receipt_digest,
        'receipt.receipt_digest',
        71,
      ),
    }
    if (
      receipt.schemaVersion !==
        'athena.context-api.operational-context-receipt.v1' ||
      receipt.receiptId !== receiptId ||
      !IDENTIFIER.test(receipt.receiptId) ||
      receipt.issuedBy.kind !== 'service' ||
      !IDENTIFIER.test(receipt.issuedBy.actorId) ||
      receipt.manifestId !== request.workloadId ||
      receipt.manifestVersion !== request.manifestVersion ||
      receipt.profileId !== request.profileId ||
      receipt.draftId !== request.draftId ||
      receipt.draftRevision !== request.draftRevision ||
      receipt.manifestDigest !== request.manifestDigest ||
      receipt.profileDigest !== request.profileDigest ||
      receipt.snapshotId !== snapshotId ||
      receipt.collectedAt !== collectedAt ||
      receipt.expiresAt !== expiresAt ||
      receipt.evidenceCount !== evidenceCount ||
      receipt.evidenceInventoryDigest !== evidenceInventoryDigest ||
      receipt.contentDigest !== contentDigest ||
      receipt.bindingDigest !== bindingDigest ||
      !DIGEST.test(receipt.receiptDigest) ||
      Date.parse(receipt.collectedAt) > Date.parse(receipt.issuedAt) ||
      Date.parse(receipt.issuedAt) >= Date.parse(receipt.expiresAt) ||
      receipt.receiptDigest !==
        await computeOperationalReceiptDigest(receipt) ||
      receipt.receiptId !== await computeOperationalReceiptId(receipt)
    ) {
      throw new Error(
        'Operational context receipt does not match the exact rendered snapshot.',
      )
    }
  return receipt
}

const parseRelationship = (
  value: unknown,
  request: OperationalContextRequest,
  index: number,
  evidenceInventory: Set<string>,
): ObservedTopologyRelationship | InferredTopologyRelationship => {
  const item = record(value, `relationships[${index}]`)
  const kind = text(item.kind, `relationships[${index}].kind`, 16)
  const id = text(item.id, `relationships[${index}].id`, 128)
  const profileId = text(item.profileId, `relationships[${index}].profileId`, 128)
  if (!IDENTIFIER.test(id) || profileId !== request.profileId) {
    throw new Error('Operational relationship escaped its exact profile binding.')
  }
  const common = {
    id,
    source: text(item.source, `relationships[${index}].source`),
    target: text(item.target, `relationships[${index}].target`),
    evidenceRefs: stringArray(
      item.evidenceRefs,
      `relationships[${index}].evidenceRefs`,
    ),
    confidence: confidence(
      item.confidence,
      `relationships[${index}].confidence`,
    ),
    profileId,
  }
  if (common.confidence === null || common.evidenceRefs.length === 0) {
    throw new Error('Operational relationship requires evidence and confidence.')
  }
  if (common.evidenceRefs.some((reference) => !evidenceInventory.has(reference))) {
    throw new Error('Operational relationship references unknown evidence.')
  }
  if (kind === 'observed') {
    return {
      ...common,
      kind,
      confidence: common.confidence,
      observedAt: timestamp(
        item.observedAt,
        `relationships[${index}].observedAt`,
      ),
    }
  }
  if (kind === 'inferred') {
    return {
      ...common,
      kind,
      confidence: common.confidence,
      hypothesis: text(
        item.hypothesis,
        `relationships[${index}].hypothesis`,
        1000,
      ),
    }
  }
  throw new Error('Operational context may contain only observed or inferred relationships.')
}

const parseFinding = (
  value: unknown,
  request: OperationalContextRequest,
  index: number,
  evidenceInventory: Set<string>,
): ContextFinding => {
  const item = record(value, `findings[${index}]`)
  const manifestVersion = text(
    item.manifestVersion,
    `findings[${index}].manifestVersion`,
    64,
  )
  const profileId = text(item.profileId, `findings[${index}].profileId`, 128)
  if (manifestVersion !== request.manifestVersion || profileId !== request.profileId) {
    throw new Error('Operational finding escaped its exact manifest/profile binding.')
  }
  const evidenceRefs = stringArray(
    item.evidenceRefs,
    `findings[${index}].evidenceRefs`,
  )
  if (evidenceRefs.length === 0) {
    throw new Error('Operational finding requires cited evidence.')
  }
  if (evidenceRefs.some((reference) => !evidenceInventory.has(reference))) {
    throw new Error('Operational finding references unknown evidence.')
  }
  return {
    id: text(item.id, `findings[${index}].id`, 128),
    verdict: text(item.verdict, `findings[${index}].verdict`, 64),
    summary: text(item.summary, `findings[${index}].summary`, 1000),
    manifestVersion,
    profileId,
    clause: text(item.clause, `findings[${index}].clause`, 512),
    evidenceRefs,
    residualRisk:
      item.residualRisk === null
        ? null
        : text(item.residualRisk, `findings[${index}].residualRisk`, 1000),
    controlState:
      item.controlState === null
        ? null
        : text(item.controlState, `findings[${index}].controlState`, 128),
    confidence: confidence(item.confidence, `findings[${index}].confidence`),
  }
}

export const validateOperationalContext = (
  value: unknown,
  request: OperationalContextRequest,
): Promise<OperationalContextSnapshot> => {
  return validateOperationalContextAsync(value, request)
}

const validateOperationalContextAsync = async (
  value: unknown,
  request: OperationalContextRequest,
): Promise<OperationalContextSnapshot> => {
  const payload = record(value, 'snapshot')
  const relationships = payload.relationships
  const findings = payload.findings
  const inventoryValue = payload.evidenceInventory
  if (
    payload.schemaVersion !== 'athena.contextStudio.operationalContext.v1' ||
    payload.workloadId !== request.workloadId ||
    payload.manifestVersion !== request.manifestVersion ||
    payload.profileId !== request.profileId ||
    payload.draftId !== request.draftId ||
    payload.draftRevision !== request.draftRevision ||
    payload.manifestDigest !== request.manifestDigest ||
    payload.profileDigest !== request.profileDigest ||
    !VERSION.test(request.manifestVersion) ||
    !DIGEST.test(request.manifestDigest) ||
    !DIGEST.test(request.profileDigest) ||
    !Number.isInteger(request.draftRevision) ||
    request.draftRevision < 1 ||
    !Array.isArray(relationships) ||
    relationships.length > MAX_RECORDS ||
    !Array.isArray(findings) ||
    findings.length > MAX_RECORDS ||
    !Array.isArray(inventoryValue) ||
    inventoryValue.length === 0 ||
    inventoryValue.length > MAX_RECORDS
  ) {
    throw new Error('Operational context does not match the exact requested binding.')
  }
  const evidenceInventory = inventoryValue.map((value, index) => {
    const item = record(value, `evidenceInventory[${index}]`)
    const evidenceRef = text(
      item.evidenceRef,
      `evidenceInventory[${index}].evidenceRef`,
      512,
    )
    const evidenceDigest = text(
      item.evidenceDigest,
      `evidenceInventory[${index}].evidenceDigest`,
      71,
    )
    if (!DIGEST.test(evidenceDigest)) {
      throw new Error('Operational context returned an invalid evidence digest.')
    }
    return { evidenceRef, evidenceDigest }
  })
  const evidenceRefs = evidenceInventory.map((item) => item.evidenceRef)
  if (new Set(evidenceRefs).size !== evidenceRefs.length) {
    throw new Error('Operational evidence inventory references must be unique.')
  }
  const evidenceInventoryDigest = text(
    payload.evidenceInventoryDigest,
    'snapshot.evidenceInventoryDigest',
    71,
  )
  if (
    !DIGEST.test(evidenceInventoryDigest) ||
    evidenceInventoryDigest !==
      await computeOperationalEvidenceInventoryDigest(evidenceInventory)
  ) {
    throw new Error('Operational evidence inventory digest is invalid.')
  }
  const evidenceInventorySet = new Set(evidenceRefs)
  const collectedAt = timestamp(payload.collectedAt, 'snapshot.collectedAt')
  const expiresAt = timestamp(payload.expiresAt, 'snapshot.expiresAt')
  const asOf = timestamp(request.asOf, 'request.asOf')
  if (
    Date.parse(collectedAt) > Date.parse(asOf) ||
    Date.parse(asOf) >= Date.parse(expiresAt)
  ) {
    throw new Error('Operational context snapshot is stale or future-dated.')
  }
  const snapshotId = text(payload.snapshotId, 'snapshot.snapshotId', 128)
  const receiptId = text(payload.receiptId, 'snapshot.receiptId', 128)
  if (!IDENTIFIER.test(receiptId)) {
    throw new Error('Operational context returned an invalid receipt identifier.')
  }
  const evidenceSource = text(
    payload.evidenceSource,
    'snapshot.evidenceSource',
    256,
  )
  const snapshotConfidence = confidence(
    payload.confidence,
    'snapshot.confidence',
  )
  const parsedRelationships = relationships.map((item, index) =>
    parseRelationship(item, request, index, evidenceInventorySet),
  )
  const parsedFindings = findings.map((item, index) =>
    parseFinding(item, request, index, evidenceInventorySet),
  )
  const relationshipIds = parsedRelationships.map((item) => item.id)
  const findingIds = parsedFindings.map((item) => item.id)
  if (
    new Set(relationshipIds).size !== relationshipIds.length ||
    new Set(findingIds).size !== findingIds.length
  ) {
    throw new Error('Operational context identifiers must be unique.')
  }
  const contentDigest = text(
    payload.contentDigest,
    'snapshot.contentDigest',
    71,
  )
  if (
    !DIGEST.test(contentDigest) ||
    contentDigest !== await computeOperationalContentDigest({
      evidenceSource,
      confidence: snapshotConfidence,
      relationships: parsedRelationships,
      findings: parsedFindings,
    })
  ) {
    throw new Error('Operational context content digest is invalid.')
  }
  const bindingDigest = text(payload.bindingDigest, 'snapshot.bindingDigest', 71)
  if (
    !DIGEST.test(bindingDigest) ||
    bindingDigest !== await computeOperationalBindingDigest({
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
  ) {
    throw new Error('Operational context binding digest is invalid.')
  }
  const receipt = await parseOperationalReceipt(
    payload.receipt,
    request,
    {
      receiptId,
      snapshotId,
      collectedAt,
      expiresAt,
      evidenceCount: evidenceInventory.length,
      evidenceInventoryDigest,
      contentDigest,
      bindingDigest,
    },
  )
  return {
    schemaVersion: 'athena.contextStudio.operationalContext.v1',
    workloadId: request.workloadId,
    manifestVersion: request.manifestVersion,
    profileId: request.profileId,
    draftId: request.draftId,
    draftRevision: request.draftRevision,
    manifestDigest: request.manifestDigest,
    profileDigest: request.profileDigest,
    receiptId,
    receipt,
    snapshotId,
    collectedAt,
    expiresAt,
    evidenceSource,
    confidence: snapshotConfidence,
    evidenceInventory,
    evidenceInventoryDigest,
    contentDigest,
    bindingDigest,
    relationships: parsedRelationships,
    findings: parsedFindings,
  }
}
