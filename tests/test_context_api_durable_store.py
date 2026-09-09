from __future__ import annotations

import json
import re
import runpy
from collections.abc import Iterator, Mapping
from copy import deepcopy
from pathlib import Path

import pytest
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError

import athena_context.api.durable as durable
from athena_context.api.authorization import RoleBasedAuthorization
from athena_context.api.domain import (
    AuditEvent,
    DraftRecord,
    MutationReceipt,
    MutationTarget,
    PublishedManifest,
    Role,
    RoleGrant,
    SupersedeCommand,
    Supersession,
)
from athena_context.api.durable import AzureTableContextStore
from athena_context.api.errors import (
    AuditIntegrityError,
    AuthorizationError,
    DuplicateVersionError,
    PersistenceConflictError,
)
from athena_context.api.evaluation_adapters import ContextServicePublishedContextReader
from athena_context.api.memory import InMemoryContextStore
from athena_context.api.selector_provenance import (
    DraftSelectorBaseline,
    SelectorProvenanceEntry,
    selector_provenance_digest,
)
from athena_context.api.service import ContextService
from athena_context.contracts import compute_artifact_digest
from context_api_support import (
    AGENT,
    APPROVER,
    AUDITOR,
    OPERATIONAL_CONTEXT_SERVICE,
    PUBLICATION_SERVICE,
    PUBLISHER,
    REVIEWER,
    StepClock,
    approve_draft,
    canonical_manifest,
    create_draft,
    publish_draft,
    transition,
)
from test_context_api_cohort_decisions import _decision_body, _post_decision
from test_context_api_cohorts import HUMAN, _build_harness, _load

_DURABLE_WORKLOAD_ID = "wl-athena-wc002-canonical"
_PRODUCTION_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_PRODUCTION_AUDIENCE = "api://athena-context"
_PRODUCTION_DELEGATED_SCOPE = "Athena.Context.Access"


def _production_environment() -> dict[str, str]:
    return {
        "ATHENA_CONTEXT_STORE_ENDPOINT": "https://syntheticstore.table.core.windows.net",
        "ATHENA_CONTEXT_STORE_TABLE_NAME": "AthenaContext",
        "ATHENA_CONTEXT_STORE_PARTITION_KEY": "synthetic-context",
        "ATHENA_CONTEXT_IDENTITY_CLIENT_ID": "synthetic-managed-identity",
        "ATHENA_CONTEXT_STORE_WORKLOAD_ID": _DURABLE_WORKLOAD_ID,
        "ATHENA_CONTEXT_AUTH_TENANT_ID": _PRODUCTION_TENANT_ID,
        "ATHENA_CONTEXT_AUTH_AUDIENCE": _PRODUCTION_AUDIENCE,
        "ATHENA_CONTEXT_AUTH_DELEGATED_SCOPE": _PRODUCTION_DELEGATED_SCOPE,
        "ATHENA_CONTEXT_ROLE_GRANTS_JSON": json.dumps(
            [
                {
                    "actor_id": "22222222-2222-2222-2222-222222222222",
                    "role": "proposer",
                    "scope": {
                        "scope_type": "workload",
                        "workload_id": _DURABLE_WORKLOAD_ID,
                    },
                }
            ]
        ),
    }


class _TableEntity(dict[str, object]):
    def __init__(self, data: Mapping[str, object], *, etag: str) -> None:
        super().__init__(deepcopy(dict(data)))
        self.metadata = {"etag": etag}


class _FakeTable:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], _TableEntity] = {}
        self._next_etag = 1
        self.submission_count = 0

    def query_entities(
        self,
        *,
        query_filter: str,
        results_per_page: int,
    ) -> Iterator[_TableEntity]:
        assert query_filter == "PartitionKey eq 'synthetic-context'"
        assert results_per_page == durable._MAX_PARTITION_ENTITIES + 1
        return iter(
            self._copy(entity)
            for _key, entity in sorted(self._rows.items())
            if entity["PartitionKey"] == "synthetic-context"
        )

    def submit_transaction(
        self,
        operations: list[
            tuple[str, Mapping[str, object]]
            | tuple[str, Mapping[str, object], Mapping[str, object]]
        ],
    ) -> None:
        self.submission_count += 1
        candidate = {
            key: self._copy(entity)
            for key, entity in self._rows.items()
        }
        next_etag = self._next_etag
        for operation in operations:
            action, entity, *options = operation
            partition_key = entity["PartitionKey"]
            row_key = entity["RowKey"]
            assert isinstance(partition_key, str)
            assert isinstance(row_key, str)
            key = (partition_key, row_key)
            if action == "create":
                if key in candidate:
                    raise ResourceExistsError("duplicate synthetic table entity")
            elif action == "update":
                assert len(options) == 1
                etag = options[0]["etag"]
                current = candidate.get(key)
                if current is None or current.metadata["etag"] != etag:
                    raise ResourceModifiedError("stale synthetic table entity")
            else:
                raise AssertionError(f"unexpected action {action!r}")
            candidate[key] = _TableEntity(entity, etag=str(next_etag))
            next_etag += 1
        self._rows = candidate
        self._next_etag = next_etag

    def replace_record_json(self, row_key: str, payload: Mapping[str, object]) -> None:
        entity = self._rows[("synthetic-context", row_key)]
        record_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        entity["recordJson"] = record_json
        entity["recordDigest"] = compute_artifact_digest(payload)

    def delete_record(self, row_key: str) -> None:
        del self._rows[("synthetic-context", row_key)]

    def delete_partition(self) -> None:
        self._rows.clear()

    @staticmethod
    def _copy(entity: _TableEntity) -> _TableEntity:
        return _TableEntity(entity, etag=entity.metadata["etag"])


@pytest.fixture
def durable_store_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[_FakeTable, type[AzureTableContextStore]]:
    table = _FakeTable()

    class _TableServiceClient:
        def __init__(self, *, endpoint: str, credential: object) -> None:
            assert endpoint == "https://syntheticstore.table.core.windows.net"
            assert type(credential) is object

        def get_table_client(self, table_name: str) -> _FakeTable:
            assert table_name == "AthenaContext"
            return table

    monkeypatch.setattr(
        durable,
        "production_managed_identity_credential",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(durable, "TableServiceClient", _TableServiceClient)
    return table, AzureTableContextStore


def _store(
    store_type: type[AzureTableContextStore],
    *,
    workload_id: str = _DURABLE_WORKLOAD_ID,
    allow_empty_partition_bootstrap: bool = False,
) -> AzureTableContextStore:
    return store_type(
        endpoint="https://syntheticstore.table.core.windows.net",
        table_name="AthenaContext",
        partition_key="synthetic-context",
        managed_identity_client_id="synthetic-managed-identity",
        workload_id=workload_id,
        allow_empty_partition_bootstrap=allow_empty_partition_bootstrap,
    )


def _initialized_store(
    store_type: type[AzureTableContextStore],
    *,
    workload_id: str = _DURABLE_WORKLOAD_ID,
) -> AzureTableContextStore:
    store = _store(
        store_type,
        workload_id=workload_id,
        allow_empty_partition_bootstrap=True,
    )
    store.initialize_empty_partition()
    return store


def _service(
    store: AzureTableContextStore | InMemoryContextStore,
    grants: list[RoleGrant] | None = None,
) -> ContextService:
    return ContextService(
        store=store,
        authorization=durable_role_authorization(grants),
        clock=StepClock(),
        publication_actor=PUBLICATION_SERVICE,
    )


def durable_role_authorization(
    additional_grants: list[RoleGrant] | None,
) -> RoleBasedAuthorization:
    return RoleBasedAuthorization(
        [
            RoleGrant(actor_id=AGENT.actor_id, role=Role.PROPOSER),
            RoleGrant(actor_id=APPROVER.actor_id, role=Role.APPROVER),
            RoleGrant(actor_id=REVIEWER.actor_id, role=Role.REVIEWER),
            RoleGrant(actor_id=PUBLISHER.actor_id, role=Role.PUBLISHER),
            RoleGrant(actor_id=AUDITOR.actor_id, role=Role.AUDITOR),
            RoleGrant(
                actor_id=OPERATIONAL_CONTEXT_SERVICE.actor_id,
                role=Role.OPERATIONAL_CONTEXT_ISSUER,
            ),
            *(additional_grants or []),
        ]
    )


def test_durable_store_reloads_immutable_versions_and_exact_supersession(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    _table, store_type = durable_store_factory
    first_service = _service(_initialized_store(store_type))
    first = approve_draft(
        first_service,
        create_draft(first_service, canonical_manifest(), draft_id="durable-v1"),
        key_prefix="durable-v1",
    )
    published_v1 = publish_draft(first_service, first, key_prefix="durable-v1")
    second = approve_draft(
        first_service,
        create_draft(
            first_service,
            canonical_manifest(version="1.1.0", display_suffix=" durable revision"),
            draft_id="durable-v2",
            previous_version="1.0.0",
        ),
        key_prefix="durable-v2",
    )
    published_v2 = publish_draft(first_service, second, key_prefix="durable-v2")
    first_service.supersede_version(
        PUBLISHER,
        published_v1.manifest_id,
        published_v1.manifest_version,
        "durable-supersede",
        SupersedeCommand(
            expected_revision=published_v1.source_draft_revision,
            expected_manifest_version=published_v1.manifest_version,
            expected_digest=published_v1.manifest_digest,
            replacement_version=published_v2.manifest_version,
            replacement_digest=published_v2.manifest_digest,
            reason="Supersede the immutable first synthetic version",
        ),
    )

    reloaded_service = _service(_store(store_type))
    original = reloaded_service.get_published(
        PUBLISHER,
        "1.0.0",
        manifest_id=published_v1.manifest_id,
    )
    replacement = reloaded_service.get_published(
        PUBLISHER,
        "1.1.0",
        manifest_id=published_v1.manifest_id,
    )

    assert original.published == published_v1
    assert original.supersession is not None
    assert original.supersession.replacement_version == replacement.published.manifest_version
    assert replacement.supersession is None
    runtime_reader = ContextServicePublishedContextReader(
        service=reloaded_service,
        reader_actor=PUBLISHER,
    )
    assert runtime_reader.get_published(
        published_v1.manifest_id,
        "1.0.0",
    ).published == published_v1
    with _store(store_type).transaction() as transaction, pytest.raises(
        DuplicateVersionError
    ):
        transaction.put_published(published_v1)


def test_durable_store_round_trips_cohort_authority_records(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    _table, store_type = durable_store_factory
    cohort = _build_harness()
    batch = _load(cohort)
    idempotency_key = "durable-cohort-authority"
    response = _post_decision(
        cohort,
        _decision_body(cohort, batch),
        idempotency_key,
    )
    assert response.status_code == 201
    decision_id = response.json()["decisionId"]
    with cohort.store.transaction() as transaction:
        baseline = transaction.get_draft_selector_baseline(cohort.draft_id)
        decision = transaction.get_cohort_decision(
            cohort.manifest.manifest_id,
            decision_id,
        )
        receipt = transaction.get_cohort_decision_receipt(
            HUMAN.actor_id,
            idempotency_key,
        )
    assert baseline is not None
    assert decision is not None
    assert receipt is not None
    assert len(decision.source_rejection_authorities) == 1
    authority = decision.source_rejection_authorities[0].model_copy(
        update={
            "member_fingerprints": [
                f"sha256:{index:064x}" for index in range(1000)
            ]
        }
    )
    decision = type(decision).model_validate(
        {
            **decision.model_dump(
                mode="python",
                by_alias=True,
                exclude_none=True,
            ),
            "sourceRejectionAuthorities": [
                authority.model_dump(
                    mode="python",
                    by_alias=True,
                    exclude_none=True,
                )
            ],
        }
    )
    assert not durable._record_json_fits_table_property_bound(
        decision.model_dump_json(by_alias=True, exclude_none=True)
    )

    store = _initialized_store(store_type)
    with store.transaction() as transaction:
        transaction.put_draft_selector_baseline(baseline)
        transaction.put_cohort_decision(decision)
        transaction.put_cohort_decision_receipt(receipt)

    with _store(store_type).transaction() as transaction:
        assert transaction.get_draft_selector_baseline(cohort.draft_id) == baseline
        assert transaction.get_cohort_decision(
            cohort.manifest.manifest_id,
            decision_id,
        ) == decision
        assert transaction.get_cohort_decision_receipt(
            HUMAN.actor_id,
            idempotency_key,
        ) == receipt


def test_durable_store_chunks_large_selector_baselines(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    table, store_type = durable_store_factory
    entries = tuple(
        SelectorProvenanceEntry(
            location="global",
            role_id=f"role-{index:04d}",
            selector_path=(
                "roles",
                f"role-{index:04d}",
                "selectors",
                f"selector-{index:04d}",
            ),
            selector_id=f"selector-{index:04d}",
            selector_variant="namePredicate",
            semantic_digest=f"sha256:{index:064x}",
        )
        for index in range(500)
    )
    baseline = DraftSelectorBaseline(
        draft_id="large-selector-baseline",
        manifest_id=_DURABLE_WORKLOAD_ID,
        manifest_version="1.0.0",
        source_manifest_digest="sha256:" + ("a" * 64),
        selector_provenance_digest=selector_provenance_digest(entries),
        entries=entries,
        captured_by=AGENT,
        captured_at=StepClock().now(),
    )
    assert not durable._record_json_fits_table_property_bound(
        baseline.model_dump_json(by_alias=True, exclude_none=True)
    )

    with _initialized_store(store_type).transaction() as transaction:
        transaction.put_draft_selector_baseline(baseline)

    kinds = [row["kind"] for row in table._rows.values()]
    assert kinds.count("draft-selector-baseline") == 1
    assert kinds.count("draft-selector-baseline-chunk") > 1
    with _store(store_type).transaction() as transaction:
        assert transaction.get_draft_selector_baseline(
            baseline.draft_id
        ) == baseline


def test_durable_store_row_keys_hash_untrusted_components_with_domain_separation() -> None:
    unsafe_component = "unsafe/\\#?\x00\r\n😀"
    draft_key = durable._row_key_for_draft(
        DraftRecord.model_construct(draft_id=unsafe_component)
    )
    published_key = durable._row_key_for_published(
        PublishedManifest.model_construct(
            manifest_id=unsafe_component,
            manifest_version="1.0.0",
        )
    )
    supersession_key = durable._row_key_for_supersession(
        Supersession.model_construct(
            manifest_id=unsafe_component,
            superseded_version="1.0.0",
        )
    )
    receipt_key = durable._row_key_for_receipt(
        MutationReceipt.model_construct(
            actor_id=unsafe_component,
            idempotency_key=unsafe_component,
        )
    )

    row_keys = (draft_key, published_key, supersession_key, receipt_key)
    assert len(set(row_keys)) == len(row_keys)
    assert all(
        re.fullmatch(r"(?:draft|published|supersession|receipt):[0-9a-f]{64}", key)
        for key in row_keys
    )
    assert all(character not in key for key in row_keys for character in "/\\#?\x00\r\n")
    assert durable._row_key_for_components(
        "published", "unsafe/a", "1.0.0"
    ) != durable._row_key_for_components("published", "unsafe", "a/1.0.0")
    assert durable._row_key_for_components(
        "published", unsafe_component, "1.0.0"
    ) != durable._row_key_for_components(
        "supersession", unsafe_component, "1.0.0"
    )


def test_durable_store_rejects_route_unsafe_workload_identifier(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    _table, store_type = durable_store_factory

    with pytest.raises(ValueError, match="workload ID is invalid"):
        _store(store_type, workload_id="wl/unsafe")


def test_durable_store_enforces_utf16_record_property_bound_before_submission(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    table, store_type = durable_store_factory
    service = _service(_initialized_store(store_type))
    draft = create_draft(
        service,
        canonical_manifest(),
        draft_id="utf16-property-bound",
    )
    receipt_template = MutationReceipt(
        actor_id=AGENT.actor_id,
        idempotency_key="utf16-exact-bound",
        operation="utf16_property_bound_test",
        target=MutationTarget(draft_id=draft.draft_id),
        request_digest="sha256:" + ("1" * 64),
        response_type="DraftRecord",
        response_json="{}",
    )
    template_json = receipt_template.model_dump_json(
        by_alias=True,
        exclude_none=True,
    )
    template_bound = len(template_json.encode("utf-16-le"))
    exact_payload_length = 2 + (
        (durable._MAX_RECORD_BYTES - template_bound) // 2
    )
    exact_bound_receipt = receipt_template.model_copy(
        update={"response_json": "x" * exact_payload_length}
    )
    exact_bound_json = exact_bound_receipt.model_dump_json(
        by_alias=True,
        exclude_none=True,
    )
    assert len(exact_bound_json.encode("utf-16-le")) == durable._MAX_RECORD_BYTES

    with _store(store_type).transaction() as transaction:
        transaction.put_receipt(exact_bound_receipt)

    oversized_receipt = exact_bound_receipt.model_copy(
        update={
            "idempotency_key": "utf16-over-bound",
            "response_json": "😀" + ("x" * exact_payload_length),
        }
    )
    oversized_json = oversized_receipt.model_dump_json(
        by_alias=True,
        exclude_none=True,
    )
    assert len(oversized_json.encode("utf-8")) < durable._MAX_RECORD_BYTES
    assert len(oversized_json.encode("utf-16-le")) > durable._MAX_RECORD_BYTES
    rows_before = deepcopy(table._rows)
    submissions_before = table.submission_count

    with pytest.raises(ValueError, match="property bound"), _store(
        store_type
    ).transaction() as transaction:
        transaction.put_receipt(oversized_receipt)

    assert table._rows == rows_before
    assert table.submission_count == submissions_before


def test_durable_store_uses_etag_conflicts_without_partially_writing_loser(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    _table, store_type = durable_store_factory
    seed = _service(_initialized_store(store_type))
    draft = create_draft(seed, canonical_manifest(), draft_id="optimistic-draft")
    first_transaction = _store(store_type).transaction()
    second_transaction = _store(store_type).transaction()
    first = first_transaction.__enter__()
    second = second_transaction.__enter__()
    first.put_draft(
        draft.model_copy(update={"revision": 2}),
        expected_revision=draft.revision,
    )
    second.put_draft(
        draft.model_copy(update={"revision": 2}),
        expected_revision=draft.revision,
    )
    second.put_receipt(
        MutationReceipt(
            actor_id=AGENT.actor_id,
            idempotency_key="losing-concurrent-receipt",
            operation="synthetic_concurrency_test",
            target=MutationTarget(draft_id=draft.draft_id),
            request_digest="sha256:" + ("1" * 64),
            response_type="DraftRecord",
            response_json="{}",
        )
    )

    first_transaction.__exit__(None, None, None)
    with pytest.raises(PersistenceConflictError):
        second_transaction.__exit__(None, None, None)

    with _store(store_type).transaction() as transaction:
        assert transaction.get_draft(draft.draft_id).revision == 2  # type: ignore[union-attr]
        assert transaction.get_receipt(AGENT.actor_id, "losing-concurrent-receipt") is None


def test_durable_store_rejects_foreign_workload_records_and_operations(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    _table, store_type = durable_store_factory
    workload_a = "wl-synthetic-durable-a"
    workload_b = "wl-synthetic-durable-b"
    service = _service(
        _initialized_store(store_type, workload_id=workload_a),
    )
    first_draft = approve_draft(
        service,
        create_draft(
            service,
            canonical_manifest(manifest_id=workload_a),
            draft_id="scoped-durable-a",
        ),
        key_prefix="scoped-durable-a",
    )
    first_published = publish_draft(
        service,
        first_draft,
        key_prefix="scoped-durable-a",
    )
    second_draft = approve_draft(
        service,
        create_draft(
            service,
            canonical_manifest(
                manifest_id=workload_a,
                version="1.1.0",
                display_suffix=" workload scope",
            ),
            draft_id="scoped-durable-b",
            previous_version=first_published.manifest_version,
        ),
        key_prefix="scoped-durable-b",
    )
    second_published = publish_draft(
        service,
        second_draft,
        key_prefix="scoped-durable-b",
    )
    supersession = service.supersede_version(
        PUBLISHER,
        workload_a,
        first_published.manifest_version,
        "scoped-durable-supersede",
        SupersedeCommand(
            expected_revision=first_published.source_draft_revision,
            expected_manifest_version=first_published.manifest_version,
            expected_digest=first_published.manifest_digest,
            replacement_version=second_published.manifest_version,
            replacement_digest=second_published.manifest_digest,
            reason="Supersede the scoped synthetic first version",
        ),
    )
    foreign_manifest = canonical_manifest(manifest_id=workload_b)
    foreign_published = first_published.model_copy(
        update={
            "manifest_id": workload_b,
            "manifest": foreign_manifest,
        }
    )
    foreign_supersession = supersession.model_copy(
        update={"manifest_id": workload_b}
    )
    foreign_audit = service.audit_history(AUDITOR, workload_a)[0].model_copy(
        update={"manifest_id": workload_b}
    )
    foreign_receipt = MutationReceipt(
        actor_id=AGENT.actor_id,
        idempotency_key="foreign-workload-receipt",
        operation="synthetic_scope_test",
        target=MutationTarget(manifest_id=workload_b),
        request_digest="sha256:" + ("1" * 64),
        response_type="DraftRecord",
        response_json="{}",
    )

    with pytest.raises(AuthorizationError, match="does not serve"):
        create_draft(
            service,
            foreign_manifest,
            draft_id="foreign-workload-draft",
        )
    with _store(store_type, workload_id=workload_a).transaction() as transaction:
        with pytest.raises(AuthorizationError, match="does not serve"):
            transaction.list_drafts(manifest_id=workload_b)
        with pytest.raises(AuthorizationError, match="does not serve"):
            transaction.get_published(workload_b, "1.0.0")
        with pytest.raises(AuthorizationError, match="does not serve"):
            transaction.list_published(manifest_id=workload_b)
        with pytest.raises(AuthorizationError, match="does not serve"):
            transaction.get_supersession(workload_b, "1.0.0")
        with pytest.raises(AuthorizationError, match="does not serve"):
            transaction.list_audit(manifest_id=workload_b)
        with pytest.raises(AuthorizationError, match="does not serve"):
            transaction.put_published(foreign_published)
        with pytest.raises(AuthorizationError, match="does not serve"):
            transaction.put_supersession(foreign_supersession)
        with pytest.raises(AuthorizationError, match="does not serve"):
            transaction.append_audit(foreign_audit)
        with pytest.raises(AuthorizationError, match="does not serve"):
            transaction.put_receipt(foreign_receipt)

    with pytest.raises(AuthorizationError):
        _service(_store(store_type, workload_id=workload_a)).get_published(
            PUBLISHER,
            "1.0.0",
            manifest_id=workload_b,
        )


def test_durable_store_detects_audit_chain_tampering(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    table, store_type = durable_store_factory
    service = _service(_initialized_store(store_type))
    draft = create_draft(
        service,
        canonical_manifest(),
        draft_id="tampered-audit",
    )
    entity = table._rows[("synthetic-context", "audit:00000001")]
    audit_payload = json.loads(str(entity["recordJson"]))
    audit_payload["event_digest"] = "sha256:" + ("0" * 64)
    table.replace_record_json("audit:00000001", audit_payload)
    tampered_audit = AuditEvent.model_validate_json(
        str(entity["recordJson"])
    )
    state = table._rows[("synthetic-context", "meta:state")]
    generation = state["generation"]
    assert type(generation) is int
    state.update(
        durable._partition_anchor(
            {
                str(entity["RowKey"]): entity
                for entity in table._rows.values()
            },
            [tampered_audit],
            generation=generation,
            workload_id=_DURABLE_WORKLOAD_ID,
        )
    )

    with pytest.raises(AuditIntegrityError, match="integrity digest"):
        _service(_store(store_type)).audit_history(AUDITOR, draft.manifest_id)


def test_durable_store_detects_deleted_final_audit_event(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    table, store_type = durable_store_factory
    service = _service(_initialized_store(store_type))
    create_draft(
        service,
        canonical_manifest(),
        draft_id="deleted-final-audit",
    )
    table.delete_record("audit:00000001")

    with pytest.raises(
        RuntimeError,
        match="state anchor",
    ), _store(store_type).transaction():
        pass


def test_durable_store_detects_deleted_immutable_published_manifest(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    table, store_type = durable_store_factory
    service = _service(_initialized_store(store_type))
    approved = approve_draft(
        service,
        create_draft(
            service,
            canonical_manifest(),
            draft_id="deleted-published",
        ),
        key_prefix="deleted-published",
    )
    published = publish_draft(
        service,
        approved,
        key_prefix="deleted-published",
    )
    table.delete_record(durable._row_key_for_published(published))

    with pytest.raises(
        RuntimeError,
        match="state anchor",
    ), _store(store_type).transaction():
        pass


def test_durable_store_requires_explicit_one_time_empty_partition_bootstrap(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    table, store_type = durable_store_factory
    disabled_store = _store(store_type)

    with pytest.raises(RuntimeError, match="bootstrap is not authorized"):
        disabled_store.initialize_empty_partition()
    with pytest.raises(
        RuntimeError,
        match="continuity root is absent",
    ), disabled_store.transaction():
        pass

    bootstrap_store = _store(
        store_type,
        allow_empty_partition_bootstrap=True,
    )
    bootstrap_store.initialize_empty_partition()
    state = table._rows[("synthetic-context", "meta:state")]
    assert state["generation"] == 1
    with pytest.raises(RuntimeError, match="bootstrap is not authorized"):
        bootstrap_store.initialize_empty_partition()
    with _store(store_type).transaction():
        pass

    with pytest.raises(RuntimeError, match="state anchor"), _store(
        store_type,
        workload_id="wl-different-configured-workload",
    ).transaction():
        pass

    table.delete_record("meta:state")
    with pytest.raises(
        RuntimeError,
        match="continuity root is absent",
    ), _store(store_type).transaction():
        pass


def test_durable_store_fails_closed_after_complete_partition_deletion(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    table, store_type = durable_store_factory
    service = _service(_initialized_store(store_type))
    draft = create_draft(
        service,
        canonical_manifest(),
        draft_id="deleted-partition",
    )
    table.delete_partition()
    next_etag_before = table._next_etag
    restarted = _service(_store(store_type))

    with pytest.raises(RuntimeError, match="continuity root is absent"):
        restarted.get_draft(AGENT, draft.draft_id)
    with pytest.raises(RuntimeError, match="continuity root is absent"):
        create_draft(
            restarted,
            canonical_manifest(),
            draft_id="must-not-reinitialize",
        )

    assert table._rows == {}
    assert table._next_etag == next_etag_before


def test_durable_store_rejects_partition_overflow_without_writing(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    table, store_type = durable_store_factory
    monkeypatch.setattr(durable, "_MAX_PARTITION_ENTITIES", 6)
    service = _service(_initialized_store(store_type))
    draft = create_draft(
        service,
        canonical_manifest(),
        draft_id="partition-boundary",
    )
    rows_before = deepcopy(table._rows)
    next_etag_before = table._next_etag

    with pytest.raises(RuntimeError, match="partition entity limit"):
        service.validate_draft(
            AGENT,
            draft.draft_id,
            "partition-boundary-validate",
            transition(draft, "Attempt to exceed the partition entity limit"),
        )

    assert table._rows == rows_before
    assert table._next_etag == next_etag_before
    reloaded = _service(_store(store_type))
    assert reloaded.get_draft(AGENT, draft.draft_id) == draft


def test_durable_store_warns_before_reaching_partition_hard_limit(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _table, store_type = durable_store_factory
    monkeypatch.setattr(durable, "_CAPACITY_WARNING_ENTITY_COUNT", 1)
    store = _initialized_store(store_type)

    with caplog.at_level("WARNING", logger=durable.__name__), store.transaction():
        pass

    assert (
        "event=athena_context_store_capacity_warning "
        "workload_id=wl-athena-wc002-canonical entity_count=1 capacity=4096"
    ) in caplog.text


def test_durable_store_preserves_in_memory_context_api_semantics(
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    _table, store_type = durable_store_factory
    in_memory_service = _service(InMemoryContextStore())
    durable_service = _service(_initialized_store(store_type))

    in_memory_draft = create_draft(
        in_memory_service,
        canonical_manifest(),
        draft_id="adapter-semantics",
    )
    durable_draft = create_draft(
        durable_service,
        canonical_manifest(),
        draft_id="adapter-semantics",
    )
    in_memory_validated = in_memory_service.validate_draft(
        AGENT,
        in_memory_draft.draft_id,
        "adapter-semantics-validate",
        transition(in_memory_draft, "Validate the in-memory adapter path"),
    )
    durable_validated = durable_service.validate_draft(
        AGENT,
        durable_draft.draft_id,
        "adapter-semantics-validate",
        transition(durable_draft, "Validate the in-memory adapter path"),
    )

    assert durable_draft == in_memory_draft
    assert durable_validated == in_memory_validated


def test_production_context_api_refuses_to_start_without_durable_store_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "ATHENA_CONTEXT_STORE_ENDPOINT",
        "ATHENA_CONTEXT_STORE_TABLE_NAME",
        "ATHENA_CONTEXT_STORE_PARTITION_KEY",
        "ATHENA_CONTEXT_IDENTITY_CLIENT_ID",
        "ATHENA_CONTEXT_STORE_WORKLOAD_ID",
        "ATHENA_CONTEXT_AUTH_TENANT_ID",
        "ATHENA_CONTEXT_AUTH_AUDIENCE",
        "ATHENA_CONTEXT_AUTH_DELEGATED_SCOPE",
        "ATHENA_CONTEXT_ROLE_GRANTS_JSON",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ATHENA_CONTEXT_STORE_BOOTSTRAP_ENABLED", raising=False)

    with pytest.raises(RuntimeError, match="must be configured for the Context API"):
        runpy.run_path(
            Path(__file__).parents[1] / "apps" / "context-api" / "main.py"
        )


def test_one_shot_bootstrap_initializes_the_durable_store(
    monkeypatch: pytest.MonkeyPatch,
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    table, _store_type = durable_store_factory
    for name, value in _production_environment().items():
        monkeypatch.setenv(name, value)

    namespace = runpy.run_path(
        Path(__file__).parents[1] / "apps" / "context-api" / "bootstrap.py"
    )
    namespace["initialize_context_store"]()

    assert ("synthetic-context", "meta:state") in table._rows


def test_production_context_api_composes_the_initialized_durable_store(
    monkeypatch: pytest.MonkeyPatch,
    durable_store_factory: tuple[_FakeTable, type[AzureTableContextStore]],
) -> None:
    table, store_type = durable_store_factory
    _initialized_store(store_type)
    for name, value in _production_environment().items():
        monkeypatch.setenv(name, value)

    namespace = runpy.run_path(
        Path(__file__).parents[1] / "apps" / "context-api" / "main.py"
    )

    assert namespace["app"].title == "Athena Context API"
    assert ("synthetic-context", "meta:state") in table._rows


def test_production_context_api_rejects_empty_partition_without_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _TableServiceClient:
        def __init__(self, *, endpoint: str, credential: object) -> None:
            assert endpoint == "https://syntheticstore.table.core.windows.net"
            assert type(credential) is object

        def get_table_client(self, table_name: str) -> _FakeTable:
            assert table_name == "AthenaContext"
            return _FakeTable()

    monkeypatch.setattr(
        durable,
        "production_managed_identity_credential",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(durable, "TableServiceClient", _TableServiceClient)
    for name, value in _production_environment().items():
        monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match="continuity root is absent"):
        runpy.run_path(
            Path(__file__).parents[1] / "apps" / "context-api" / "main.py"
        )


def test_production_context_api_rejects_runtime_bootstrap_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in _production_environment().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("ATHENA_CONTEXT_STORE_BOOTSTRAP_ENABLED", "true")

    with pytest.raises(RuntimeError, match="not supported by API startup"):
        runpy.run_path(
            Path(__file__).parents[1] / "apps" / "context-api" / "main.py"
        )


def test_production_context_api_rejects_missing_authentication_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in _production_environment().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ATHENA_CONTEXT_AUTH_TENANT_ID")

    with pytest.raises(RuntimeError, match="ATHENA_CONTEXT_AUTH_TENANT_ID"):
        runpy.run_path(
            Path(__file__).parents[1] / "apps" / "context-api" / "main.py"
        )


def test_production_context_api_requires_an_exact_delegated_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in _production_environment().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ATHENA_CONTEXT_AUTH_DELEGATED_SCOPE")

    with pytest.raises(RuntimeError, match="ATHENA_CONTEXT_AUTH_DELEGATED_SCOPE"):
        runpy.run_path(
            Path(__file__).parents[1] / "apps" / "context-api" / "main.py"
        )


@pytest.mark.parametrize(
    ("grants", "message"),
    [
        ("[]", "non-empty grant array"),
        (
            json.dumps(
                [
                    {
                        "actor_id": "22222222-2222-2222-2222-222222222222",
                        "role": "proposer",
                        "scope": {
                            "scope_type": "workload",
                            "workload_id": "wl-foreign-workload",
                        },
                    }
                ]
            ),
            "exact configured-workload grants",
        ),
    ],
)
def test_production_context_api_rejects_empty_or_foreign_role_grants(
    monkeypatch: pytest.MonkeyPatch,
    grants: str,
    message: str,
) -> None:
    for name, value in _production_environment().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("ATHENA_CONTEXT_ROLE_GRANTS_JSON", grants)

    with pytest.raises(RuntimeError, match=message):
        runpy.run_path(
            Path(__file__).parents[1] / "apps" / "context-api" / "main.py"
        )
