from __future__ import annotations

import base64
import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from typing import Any, Literal, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from athena_context.contracts import (
    CanonicalWorkloadManifest,
    CollectorIdentityEvidence,
    EvidenceEnvelopeResolver,
    EvidenceSnapshot,
    ResourceGroupScope,
    SnapshotCollector,
    SnapshotPublicationRecord,
    SuccessResponseCollectorAttempt,
    TrustedKeyAnchor,
    TrustedKeyRecord,
    canonicalize_json,
    canonicalize_manifest_payload,
    compute_artifact_digest,
    compute_authorized_scopes_digest,
    compute_collector_attempt_set_digest,
    compute_evidence_record_digest,
    compute_evidence_record_set_digest,
    compute_evidence_reference_set_digest,
    compute_evidence_snapshot_artifact_digest,
    compute_evidence_snapshot_semantic_digest,
    compute_jti_digest,
    compute_response_envelope_digest,
    compute_snapshot_attestation_preimage_digest,
    compute_token_verification_digest,
    compute_verified_claims_digest,
    sha256_hex,
)

_CANONICAL_MANIFEST_ID = "wl-athena-wc002-canonical"
_CANONICAL_SNAPSHOT_ID = "snap-111111111111"
_CANONICAL_TENANT_ID = "11111111-1111-1111-1111-111111111111"
_CANONICAL_SUBSCRIPTION_ID = _CANONICAL_TENANT_ID
_CANONICAL_RESOURCE_GROUP_NAME = "rg-athena-fixture"
_CANONICAL_KEY_VAULT_KEY_ID = (
    "https://athena-fixture.vault.azure.net/keys/athena-fixture/0123456789abcdef0123456789abcdef"
)
_CANONICAL_PRIVATE_KEY_PEM = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp8iFJUmsCLNwCyrP1+Dk6oI7h4GcFBV7RTBB1VYLJa6BOKxD
yuC1hHDld29U6Ifqd2Ose9okbRLFtqLDZc/RS2zNK1JffSOHJGTiEdfY2rK/+G0O
gT7pUYkUzR9d3hzx+rB9wc/bqIsvxHwfRAZ6OCOZTnAevzchDm+6/NX9vUQKWW8A
RsowVnMwGvV3AEu8NTFpCldZyJb1M+x68FpQ9XBf1M4h5h4MSr9ELw06p9ljPlG/
iams7ul6Z21FeFoxwKcthyo6ePQwrAdpeQ0WqfkptMN+ZJSLGFRprrM2HFtli8+o
OX+kCmiEu6zX0m6ud1/Rmj/Ov+f7XCbrUND9GQIDAQABAoIBABe2zNwifQkKdOAc
hXLcK6QE6IK0VsnfPWSKjQt+P/tr84H96w5Y00msUT/KbFmkotw2qhwj5A5x3vWm
LJrjvrpRNEXBZz3/JayHAQ2HkJ6x3ACHSCEMB3B0QQyQOIqvqaMxNce3vV1QNYip
CHGWFB6CKDrAuGp1/BtCac8u3vr/Jm5ApfeILyr9WS5V7+pY9Bw06g3RuQGdx16i
t5fOXX/DUsjNtc3LCfrtQq9eLy8e234c0I5IfuneFD6puzwF0dzLcOMhL5imiJpy
912sliLuHHKeJmvlZH9rktwo3v7liDLZfFZpOl15YaNHX79D+gL/hjSGIszitaiH
XS/arO8CgYEA2JdtEXBT1OuE5aT2ODSSw0labVZYoGcxOF3KL8P4pbj82yDAnDS8
KbYdTJ+J5/7lDNbLcVxfhsXwVvFetXUibzoanFGbZflx6Ndg+tTqOb0lw7HWVocz
yZDxz+S7AUVAdxJirjwoXRbnyEmIe8bJ1uHTwHAjbkXsxGMLXbVE1tcCgYEAxk+q
RT7YJ84GJqbUNi3MGAzezU6xIxyMrwLNfcuLyydZtoepre2bw5Aws5jLJERTZckP
5dWFcbJYQi2PakyMIEEiV7xE/HBEl3aogpY6CZrg/FC6NbbiYMQ6Dbr18MHroKtW
lcnpICNfhaxn4tQyfoTaavmr7hXBFm2aXHB6fY8CgYEA1l0wnoTdA6vCEYMuCbzG
0K8l53cBKmhXh6ET/ihoTKUE5V/KIg/zdxj+cJqp48ocKpPgMKcrCHmZgINNqCxx
U0Jfmf0O32N9wOSB4F+gHls9KC03pNYVhFaHbanFB+HhhrfUoPt7O37zEgDtKww5
Mgq6CAk0l+xvBIO+eRVyN2sCgYA09DjnXKyjlGQYFhw8i2YgVe94qzapxYnbgcgV
ezDNAqj2EKvCgdxCEFKw4m/8MzKBz3qrSKTlg1YF9dyB6gbQ5hOhkehp8CCgwVKl
7C97ORwyw+u1RCyW4k8OM4pQy7d7o8TvIodZyZhMPYlQDJGfLyKTxi+e17hDoOjD
HlXXCQKBgH+0uyQ8WIsQ5UZb5H+1pYxjP0mvrbstyyKFF8SW2lO6MLMPEVutu5tf
TJMu5/C91wnVmR0PmCz8ojNm2NSzh/CFgtKH/7wPRn9v3HNgTXx4GxzSkPQPVSOh
QuaQ0XCHOLs2QuqGX30n5cgiDIBxplo2kKGYcD9eeiv+KE304WcP
-----END RSA PRIVATE KEY-----
"""

_raw_private_key = load_pem_private_key(_CANONICAL_PRIVATE_KEY_PEM, None)
if not isinstance(_raw_private_key, rsa.RSAPrivateKey):
    raise TypeError("fixture key must be a valid RSA private key")
CANONICAL_PRIVATE_KEY = cast(rsa.RSAPrivateKey, _raw_private_key)


def _sha256(value: str | bytes) -> str:
    return sha256_hex(value)


def _published_at() -> datetime:
    return datetime(2025, 6, 1, 12, 0, tzinfo=UTC)


def _resource_id(resource_name: str) -> str:
    return (
        "/subscriptions/11111111-1111-1111-1111-111111111111/"
        f"resourceGroups/{_CANONICAL_RESOURCE_GROUP_NAME}/providers/Microsoft.Compute/"
        f"virtualMachines/{resource_name}"
    )


def _resource_group_scope() -> ResourceGroupScope:
    return ResourceGroupScope(
        scopeType="resourceGroup",
        tenantId=_CANONICAL_TENANT_ID,
        subscriptionId=_CANONICAL_SUBSCRIPTION_ID,
        resourceGroupName=_CANONICAL_RESOURCE_GROUP_NAME,
    )


def _trusted_key_anchor(
    *,
    key_vault_key_id: str = _CANONICAL_KEY_VAULT_KEY_ID,
) -> TrustedKeyAnchor:
    public_key = CANONICAL_PRIVATE_KEY.public_key()
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return TrustedKeyAnchor.from_key_vault_key_id(
        key_vault_key_id,
        public_key_fingerprint=_sha256(encoded),
    )


def _sign_payload(payload: dict[str, Any]) -> str:
    message = canonicalize_json(payload).encode("utf-8")
    signature = CANONICAL_PRIVATE_KEY.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def _make_trusted_key_record() -> TrustedKeyRecord:
    anchor = _trusted_key_anchor()
    public_key = CANONICAL_PRIVATE_KEY.public_key()
    return TrustedKeyRecord(
        anchor=anchor,
        public_key=public_key,
        enabled=True,
        activated_at=datetime(2025, 5, 1, tzinfo=UTC),
        retired_at=None,
        expires_at=datetime(2026, 5, 1, tzinfo=UTC),
    )


def _make_identity_evidence(
    *,
    attempt: SuccessResponseCollectorAttempt,
    derived_at: datetime | None = None,
    signed_at: datetime | None = None,
) -> CollectorIdentityEvidence:
    tenant_id = _CANONICAL_TENANT_ID
    trust_anchor = _CANONICAL_KEY_VAULT_KEY_ID
    issued_at = datetime(2025, 6, 1, 11, 0, tzinfo=UTC)
    verified_at = datetime(2025, 6, 1, 11, 30, tzinfo=UTC)
    derived_at = derived_at or datetime(2025, 6, 1, 11, 47, tzinfo=UTC)
    signed_at = signed_at or derived_at + timedelta(minutes=1)
    signing_anchor = _trusted_key_anchor()
    token_hash = _sha256("synthetic-token-01")
    verified_claims_payload = {
        "issuer": f"https://login.microsoftonline.com/{tenant_id}/v2.0",
        "audience": "api://athena-ingestion",
        "tenantId": tenant_id,
        "managedIdentityObjectId": "22222222-2222-2222-2222-222222222222",
        "managedIdentityClientId": "33333333-3333-3333-3333-333333333333",
        "subject": "22222222-2222-2222-2222-222222222222",
        "jtiDigest": compute_jti_digest("wc002-jti"),
        "issuedAt": issued_at,
        "notBefore": issued_at,
        "expiresAt": datetime(2025, 6, 1, 13, 0, tzinfo=UTC),
    }
    verified_claims_digest = compute_verified_claims_digest(verified_claims_payload)
    token_verification_payload = {
        "status": "valid",
        "verifiedAt": verified_at,
        "keyId": "kid-athena-fixture",
        "verifiedClaims": verified_claims_payload,
        "verifiedClaimsDigest": verified_claims_digest,
        "jtiDigest": verified_claims_payload["jtiDigest"],
    }
    token_verification_digest = compute_token_verification_digest(token_verification_payload)
    attempt_binding = {
        "attemptId": attempt.attempt_id,
        "attemptType": attempt.attempt_type,
        "attemptDigest": attempt.attempt_digest,
        "toolName": attempt.tool_name,
        "toolVersion": attempt.tool_version,
        "requestDigest": attempt.request_digest,
        "responseDigest": attempt.response_digest,
        "attemptStartedAt": attempt.attempt_started_at,
        "responseReceivedAt": attempt.response_received_at,
    }
    derivation_payload = {
        "derivationPreimageType": "athena.mcpCollectorAttemptDerivation",
        "derivationPreimageVersion": "1.0.0",
        "schemaVersion": "1.0.0",
        "semanticContractVersion": "1.0.0",
        "policyContractVersion": "1.0.0",
        "identityEvidenceId": "identity-111111111111",
        "tokenHash": token_hash,
        "tokenVerificationStatus": "valid",
        "tokenVerificationDigest": token_verification_digest,
        "verifiedClaimsDigest": verified_claims_digest,
        "jtiDigest": verified_claims_payload["jtiDigest"],
        "mcpHostId": "mcp-111111111111",
        "mcpHostTenantId": tenant_id,
        "mcpHostManagedIdentityObjectId": "22222222-2222-2222-2222-222222222222",
        "mcpHostManagedIdentityClientId": "33333333-3333-3333-3333-333333333333",
        "ingestionServiceId": "ingestion-111111111111",
        "ingestionAudience": "api://athena-ingestion",
        "toolAllowlistDigest": _sha256("tool-allowlist"),
        "derivedCollectorIdentityRef": "identity-111111111111",
        "attemptBinding": attempt_binding,
        "derivedAt": derived_at,
    }
    derivation_payload["derivationDigest"] = compute_artifact_digest(derivation_payload)
    signature_preimage = {
        "signaturePreimageType": "athena.trustedIngestionSignature",
        "signaturePreimageVersion": "1.0.0",
        "signatureAlgorithm": "RS256",
        "keyVaultKeyId": trust_anchor,
        "keyName": signing_anchor.key_name,
        "keyVersion": signing_anchor.key_version,
        "signedAt": signed_at,
        "trustAnchorRef": trust_anchor,
        "derivation": {
            key: value for key, value in derivation_payload.items() if key != "derivationDigest"
        },
    }
    signed_preimage_digest = compute_artifact_digest(signature_preimage)
    payload = {
        "identityEvidenceId": "identity-111111111111",
        "identityEvidenceType": "entraJwtTokenEvidence",
        "tokenHash": token_hash,
        "jwtHeader": {"alg": "RS256", "kid": "kid-athena-fixture", "typ": "JWT"},
        "trustAnchorRef": trust_anchor,
        "verifiedClaims": verified_claims_payload,
        "tokenVerification": {
            **token_verification_payload,
            "tokenVerificationDigest": token_verification_digest,
        },
        "ingestionDerivation": {
            **derivation_payload,
            "attemptBinding": attempt_binding,
            "derivedAt": derived_at,
        },
        "ingestionSignature": {
            "signatureAlgorithm": "RS256",
            "keyVaultKeyId": trust_anchor,
            "keyName": signing_anchor.key_name,
            "keyVersion": signing_anchor.key_version,
            "signedPreimageDigest": signed_preimage_digest,
            "signature": _sign_payload(signature_preimage),
            "signedAt": signed_at,
            "trustAnchorRef": trust_anchor,
        },
    }
    payload["identityEvidenceDigest"] = compute_artifact_digest(
        {key: value for key, value in payload.items() if key != "identityEvidenceDigest"}
    )
    return CollectorIdentityEvidence.model_validate(payload)


def _build_response_envelope() -> dict[str, Any]:
    received_at = "2025-06-01T11:45:00.000Z"
    return {
        "requestId": "req-wc002-canonical",
        "correlationId": "corr-wc002-canonical",
        "retryCount": 0,
        "transportLatencyMs": 42,
        "receivedAt": received_at,
        "items": [
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-db-01"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {
                    "environment": "production",
                    "workloadRole": "database",
                    "application": "app-111111111111",
                    "component": "component-222222222222",
                    "managedBy": "manual",
                },
                "state": "running",
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-worker-01"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {"environment": "production", "workloadRole": "worker"},
                "state": "running",
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-worker-02"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {"environment": "production", "workloadRole": "worker"},
                "state": "running",
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-web-01"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {"environment": "production", "workloadRole": "web-service"},
                "state": "running",
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-web-02"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "2",
                "tags": {"environment": "production", "workloadRole": "web-service"},
                "state": "running",
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-web-03"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "3",
                "tags": {"environment": "production", "workloadRole": "web-service"},
                "state": "running",
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-lb-01"),
                "resourceType": "Microsoft.Network/loadBalancers",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {"environment": "production", "workloadRole": "load-balancer"},
                "state": "running",
            },
            {
                "recordType": "observedRelationship",
                "relationship": {
                    "relationshipClass": "observed",
                    "relationshipId": "relationship-111111111111",
                    "kind": "dependsOn",
                    "source": {
                        "refKind": "resourceRef",
                        "resourceId": _resource_id("athena-worker-01"),
                    },
                    "target": {
                        "refKind": "resourceRef",
                        "resourceId": _resource_id("athena-db-01"),
                    },
                    "evidenceItemRef": "item-111111111111",
                    "observedAt": received_at,
                },
            },
            {
                "recordType": "observedRelationship",
                "relationship": {
                    "relationshipClass": "observed",
                    "relationshipId": "relationship-222222222222",
                    "kind": "calls",
                    "source": {
                        "refKind": "resourceRef",
                        "resourceId": _resource_id("athena-web-01"),
                    },
                    "target": {
                        "refKind": "resourceRef",
                        "resourceId": _resource_id("athena-lb-01"),
                    },
                    "evidenceItemRef": "item-222222222222",
                    "observedAt": received_at,
                },
            },
        ],
    }


def _canonical_snapshot_payload(
    *,
    record_materials: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    collected_at = datetime(2025, 6, 1, 11, 45, tzinfo=UTC)
    expires_at = datetime(2025, 6, 2, 0, 0, tzinfo=UTC)
    scope = _resource_group_scope()
    response_envelope = _build_response_envelope()
    response_digest = compute_response_envelope_digest(response_envelope)
    attempt_started_at = collected_at
    response_received_at = collected_at + timedelta(minutes=1)
    attempt_payload = {
        "attemptType": "successResponse",
        "attemptId": "attempt-111111111111",
        "attemptStartedAt": attempt_started_at,
        "toolName": "azure.resourceInventory.read",
        "toolVersion": "1.0.0",
        "requestDigest": _sha256("req-wc002-canonical"),
        "responseDigest": response_digest,
        "responseReceivedAt": response_received_at,
        "collectorIdentityEvidenceRef": "identity-111111111111",
    }
    attempt_payload["attemptDigest"] = compute_artifact_digest(attempt_payload)
    attempt = SuccessResponseCollectorAttempt.model_validate(attempt_payload)
    identity_evidence = _make_identity_evidence(
        attempt=attempt,
        derived_at=collected_at + timedelta(minutes=2),
        signed_at=collected_at + timedelta(minutes=3),
    )
    collector = SnapshotCollector(
        collectorType="azureMcpHost",
        collectorIdentityEvidenceRef="identity-111111111111",
        mcpHostId="mcp-111111111111",
        tenantId=_CANONICAL_TENANT_ID,
        trustAnchorRef=_CANONICAL_KEY_VAULT_KEY_ID,
        ingestionServiceId="ingestion-111111111111",
        ingestionAudience="api://athena-ingestion",
        toolAllowlistDigest=_sha256("tool-allowlist"),
    )

    if record_materials is None:
        record_materials = [
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-db-01"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {
                    "environment": "production",
                    "workloadRole": "database",
                    "application": "app-111111111111",
                    "component": "component-222222222222",
                    "managedBy": "manual",
                },
                "state": "running",
                "provenance": {
                    "collectorAttemptId": attempt.attempt_id,
                    "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                    "toolName": attempt.tool_name,
                    "toolVersion": attempt.tool_version,
                    "sourceResponseDigest": attempt.response_digest,
                    "sourceResponsePointer": "/items/0",
                },
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-worker-01"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {"environment": "production", "workloadRole": "worker"},
                "state": "running",
                "provenance": {
                    "collectorAttemptId": attempt.attempt_id,
                    "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                    "toolName": attempt.tool_name,
                    "toolVersion": attempt.tool_version,
                    "sourceResponseDigest": attempt.response_digest,
                    "sourceResponsePointer": "/items/1",
                },
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-worker-02"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {"environment": "production", "workloadRole": "worker"},
                "state": "running",
                "provenance": {
                    "collectorAttemptId": attempt.attempt_id,
                    "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                    "toolName": attempt.tool_name,
                    "toolVersion": attempt.tool_version,
                    "sourceResponseDigest": attempt.response_digest,
                    "sourceResponsePointer": "/items/2",
                },
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-web-01"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {"environment": "production", "workloadRole": "web-service"},
                "state": "running",
                "provenance": {
                    "collectorAttemptId": attempt.attempt_id,
                    "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                    "toolName": attempt.tool_name,
                    "toolVersion": attempt.tool_version,
                    "sourceResponseDigest": attempt.response_digest,
                    "sourceResponsePointer": "/items/3",
                },
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-web-02"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "2",
                "tags": {"environment": "production", "workloadRole": "web-service"},
                "state": "running",
                "provenance": {
                    "collectorAttemptId": attempt.attempt_id,
                    "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                    "toolName": attempt.tool_name,
                    "toolVersion": attempt.tool_version,
                    "sourceResponseDigest": attempt.response_digest,
                    "sourceResponsePointer": "/items/4",
                },
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-web-03"),
                "resourceType": "Microsoft.Compute/virtualMachines",
                "location": "australiaeast",
                "availabilityZone": "3",
                "tags": {"environment": "production", "workloadRole": "web-service"},
                "state": "running",
                "provenance": {
                    "collectorAttemptId": attempt.attempt_id,
                    "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                    "toolName": attempt.tool_name,
                    "toolVersion": attempt.tool_version,
                    "sourceResponseDigest": attempt.response_digest,
                    "sourceResponsePointer": "/items/5",
                },
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            },
            {
                "recordType": "resource",
                "resourceId": _resource_id("athena-lb-01"),
                "resourceType": "Microsoft.Network/loadBalancers",
                "location": "australiaeast",
                "availabilityZone": "1",
                "tags": {"environment": "production", "workloadRole": "load-balancer"},
                "state": "running",
                "provenance": {
                    "collectorAttemptId": attempt.attempt_id,
                    "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                    "toolName": attempt.tool_name,
                    "toolVersion": attempt.tool_version,
                    "sourceResponseDigest": attempt.response_digest,
                    "sourceResponsePointer": "/items/6",
                },
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            },
            {
                "recordType": "observedRelationship",
                "relationship": {
                    "relationshipClass": "observed",
                    "relationshipId": "relationship-111111111111",
                    "kind": "dependsOn",
                    "source": {
                        "refKind": "resourceRef",
                        "resourceId": _resource_id("athena-worker-01"),
                    },
                    "target": {
                        "refKind": "resourceRef",
                        "resourceId": _resource_id("athena-db-01"),
                    },
                    "evidenceItemRef": "item-111111111111",
                    "observedAt": collected_at,
                },
                "provenance": {
                    "collectorAttemptId": attempt.attempt_id,
                    "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                    "toolName": attempt.tool_name,
                    "toolVersion": attempt.tool_version,
                    "sourceResponseDigest": attempt.response_digest,
                    "sourceResponsePointer": "/items/7",
                },
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            },
            {
                "recordType": "observedRelationship",
                "relationship": {
                    "relationshipClass": "observed",
                    "relationshipId": "relationship-222222222222",
                    "kind": "calls",
                    "source": {
                        "refKind": "resourceRef",
                        "resourceId": _resource_id("athena-web-01"),
                    },
                    "target": {
                        "refKind": "resourceRef",
                        "resourceId": _resource_id("athena-lb-01"),
                    },
                    "evidenceItemRef": "item-222222222222",
                    "observedAt": collected_at,
                },
                "provenance": {
                    "collectorAttemptId": attempt.attempt_id,
                    "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                    "toolName": attempt.tool_name,
                    "toolVersion": attempt.tool_version,
                    "sourceResponseDigest": attempt.response_digest,
                    "sourceResponsePointer": "/items/8",
                },
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
            },
        ]

    evidence_records: list[dict[str, Any]] = []
    for material in record_materials:
        material_copy = deepcopy(material)
        material_copy["itemDigest"] = compute_evidence_record_digest(material_copy)
        evidence_records.append(material_copy)

    evidence_refs: list[dict[str, Any]] = []
    for material in evidence_records:
        provenance = cast(dict[str, Any], material["provenance"])
        source_response_pointer = str(provenance["sourceResponsePointer"])
        evidence_refs.append(
            {
                "refType": "evidenceItem",
                "snapshotId": _CANONICAL_SNAPSHOT_ID,
                "snapshotArtifactDigest": "sha256:placeholder",
                "snapshotSemanticDigest": "sha256:placeholder",
                "itemDigest": material["itemDigest"],
                "collectorAttemptId": attempt.attempt_id,
                "collectorAttemptDigest": attempt.attempt_digest,
                "collectorToolName": attempt.tool_name,
                "collectorToolVersion": attempt.tool_version,
                "collectorAttemptAt": attempt.response_received_at,
                "collectorIdentityEvidenceRef": collector.collector_identity_evidence_ref,
                "sourceResponseDigest": attempt.response_digest,
                "sourceResponsePointer": source_response_pointer,
            }
        )

    compatibility: dict[str, Any] = {
        "artifactKind": "evidenceSnapshot",
        "schemaVersion": "1.0.0",
        "semanticContractVersion": "1.0.0",
        "policyContractVersion": "1.0.0",
        "minimumReaderVersion": "1.0.0",
        "requiresCapabilities": [],
        "producedBy": {"producerId": "athena.contracts", "version": "1.0.0"},
        "extensionPolicy": "rejectUnknownDecisionFields",
        "artifactDigest": "sha256:placeholder",
        "semanticDigest": "sha256:placeholder",
    }
    payload: dict[str, Any] = {
        "snapshotId": _CANONICAL_SNAPSHOT_ID,
        "compatibility": compatibility,
        "authorizedScopes": [scope.model_dump(mode="json", by_alias=True)],
        "collectedAt": collected_at,
        "expiresAt": expires_at,
        "collector": collector.model_dump(mode="json", by_alias=True),
        "collectorAttempts": [attempt.model_dump(mode="python", by_alias=True)],
        "evidenceRecords": evidence_records,
        "identityEvidence": [identity_evidence.model_dump(mode="python", by_alias=True)],
        "evidenceRefs": evidence_refs,
    }
    semantic_digest = compute_evidence_snapshot_semantic_digest(payload)
    compatibility["semanticDigest"] = semantic_digest
    for evidence_ref in evidence_refs:
        evidence_ref["snapshotSemanticDigest"] = semantic_digest
    artifact_digest = compute_evidence_snapshot_artifact_digest(payload)
    compatibility["artifactDigest"] = artifact_digest
    for evidence_ref in evidence_refs:
        evidence_ref["snapshotArtifactDigest"] = artifact_digest
    attestation_payload: dict[str, Any] = {
        "attestationType": "trustedSnapshotPublication",
        "attestationVersion": "1.0.0",
        "artifactKind": compatibility["artifactKind"],
        "schemaVersion": compatibility["schemaVersion"],
        "semanticContractVersion": compatibility["semanticContractVersion"],
        "policyContractVersion": compatibility["policyContractVersion"],
        "snapshotId": payload["snapshotId"],
        "artifactDigest": compatibility["artifactDigest"],
        "semanticDigest": compatibility["semanticDigest"],
        "identityEvidenceDigests": sorted(
            set(identity["identityEvidenceDigest"] for identity in payload["identityEvidence"])
        ),
        "identityEvidenceSetDigest": compute_artifact_digest(
            sorted(
                {
                    identity["identityEvidenceDigest"]
                    for identity in payload["identityEvidence"]
                }
            )
        ),
        "collectedAt": collected_at,
        "expiresAt": expires_at,
        "authorizedScopesDigest": compute_authorized_scopes_digest(payload),
        "collectorAttemptSetDigest": compute_collector_attempt_set_digest(payload),
        "evidenceRecordSetDigest": compute_evidence_record_set_digest(payload),
        "evidenceReferenceSetDigest": compute_evidence_reference_set_digest(payload),
        "attestedAt": collected_at + timedelta(minutes=4),
        "signatureAlgorithm": "RS256",
        "keyVaultKeyId": _CANONICAL_KEY_VAULT_KEY_ID,
        "keyName": "athena-fixture",
        "keyVersion": "0123456789abcdef0123456789abcdef",
        "trustAnchorRef": _CANONICAL_KEY_VAULT_KEY_ID,
    }
    attestation_payload["signedPreimageDigest"] = compute_snapshot_attestation_preimage_digest(
        attestation_payload
    )
    attestation_payload["signature"] = _sign_payload(
        {
            key: value
            for key, value in attestation_payload.items()
            if key not in {"signedPreimageDigest", "signature"}
        }
    )
    payload["snapshotAttestation"] = attestation_payload
    return payload


def _canonical_manifest_payload() -> dict[str, Any]:
    scope = _resource_group_scope()
    profiles: dict[str, Any] = {}
    for profile_id, continuity_required in {
        "production": True,
        "development": False,
        "training": True,
    }.items():
        profiles[profile_id] = {
            "profileId": profile_id,
            "profileType": profile_id,
            "settings": {
                "continuity": {
                    "zoneLossContinuityRequired": continuity_required,
                }
            },
            "relationships": [
                {
                    "relationshipClass": "declared",
                    "relationshipId": f"{profile_id}-worker-depends-db",
                    "kind": "dependsOn",
                    "source": {"endpointType": "role", "roleRef": "worker"},
                    "target": {"endpointType": "role", "roleRef": "database-primary"},
                    "ownerRef": "ops-owner",
                    "profiles": [profile_id],
                    "sourceClause": "/constraints/worker-db-zone-colocation",
                },
                {
                    "relationshipClass": "declared",
                    "relationshipId": f"{profile_id}-web-depends-db",
                    "kind": "dependsOn",
                    "source": {"endpointType": "role", "roleRef": "web"},
                    "target": {"endpointType": "role", "roleRef": "database-primary"},
                    "ownerRef": "ops-owner",
                    "profiles": [profile_id],
                    "sourceClause": "/constraints/web-zone-distribution",
                },
                {
                    "relationshipClass": "declared",
                    "relationshipId": f"{profile_id}-web-protected-by-lb",
                    "kind": "protectedBy",
                    "source": {"endpointType": "role", "roleRef": "web"},
                    "target": {"endpointType": "role", "roleRef": "load-balancer"},
                    "ownerRef": "ops-owner",
                    "profiles": [profile_id],
                    "sourceClause": "/constraints/web-zone-distribution",
                },
            ],
            "constraints": [
                {
                    "constraintId": "db-singleton-supported",
                    "constraintType": "supportedSingleton",
                    "findingKind": "technologyConstraint",
                    "governanceScope": {
                        "governanceScopeType": "clause",
                        "manifestId": _CANONICAL_MANIFEST_ID,
                        "profileId": profile_id,
                        "clausePath": "/constraints/db-singleton-supported",
                        "ownerRef": "ops-owner",
                    },
                    "ownerRef": "ops-owner",
                    "profiles": [profile_id],
                    "proofRequirement": {
                        "proofKind": "cardinalityProof",
                        "roleRef": "database-primary",
                        "expected": {"cardinalityKind": "exactlyOne"},
                    },
                    "failureVerdict": "violation",
                    "successVerdict": "expectedConstraint",
                    "protected": True,
                },
                {
                    "constraintId": "db-zone-loss-spof",
                    "constraintType": "supportedSingleton",
                    "findingKind": "actualSpof",
                    "governanceScope": {
                        "governanceScopeType": "clause",
                        "manifestId": _CANONICAL_MANIFEST_ID,
                        "profileId": profile_id,
                        "clausePath": "/constraints/db-zone-loss-spof",
                        "ownerRef": "ops-owner",
                    },
                    "ownerRef": "ops-owner",
                    "profiles": [profile_id],
                    "proofRequirement": {
                        "proofKind": "cardinalityProof",
                        "roleRef": "database-primary",
                        "expected": {"cardinalityKind": "exactlyOne"},
                    },
                    "failureVerdict": "violation",
                    "successVerdict": "observation",
                    "riskAcceptanceRef": "ra-db-zone-loss",
                    "protected": True,
                },
                {
                    "constraintId": "db-zone-loss-acceptance",
                    "constraintType": "supportedSingleton",
                    "findingKind": "riskAcceptance",
                    "governanceScope": {
                        "governanceScopeType": "clause",
                        "manifestId": _CANONICAL_MANIFEST_ID,
                        "profileId": profile_id,
                        "clausePath": "/constraints/db-zone-loss-acceptance",
                        "ownerRef": "ops-owner",
                    },
                    "ownerRef": "ops-owner",
                    "profiles": [profile_id],
                    "proofRequirement": {
                        "proofKind": "cardinalityProof",
                        "roleRef": "database-primary",
                        "expected": {"cardinalityKind": "exactlyOne"},
                    },
                    "failureVerdict": "violation",
                    "successVerdict": "observation",
                    "riskAcceptanceRef": "ra-db-zone-loss",
                    "riskAcceptanceClauseRef": "db-zone-loss-spof",
                    "protected": True,
                },
                {
                    "constraintId": "worker-db-zone-colocation",
                    "constraintType": "zoneColocation",
                    "findingKind": "architectureConstraint",
                    "governanceScope": {
                        "governanceScopeType": "clause",
                        "manifestId": _CANONICAL_MANIFEST_ID,
                        "profileId": profile_id,
                        "clausePath": "/constraints/worker-db-zone-colocation",
                        "ownerRef": "ops-owner",
                    },
                    "ownerRef": "ops-owner",
                    "profiles": [profile_id],
                    "proofRequirement": {
                        "proofKind": "zoneColocationProof",
                        "subjectRoleRef": "worker",
                        "anchorRoleRef": "database-primary",
                    },
                    "failureVerdict": "violation",
                    "successVerdict": "pass",
                    "protected": True,
                },
                {
                    "constraintId": "web-zone-distribution",
                    "constraintType": "zoneDistribution",
                    "findingKind": "architectureConstraint",
                    "governanceScope": {
                        "governanceScopeType": "clause",
                        "manifestId": _CANONICAL_MANIFEST_ID,
                        "profileId": profile_id,
                        "clausePath": "/constraints/web-zone-distribution",
                        "ownerRef": "ops-owner",
                    },
                    "ownerRef": "ops-owner",
                    "profiles": [profile_id],
                    "proofRequirement": {
                        "proofKind": "zoneDistributionProof",
                        "roleRef": "web",
                        "minimumDistinctZones": (
                            3 if profile_id in {"production", "training"} else 1
                        ),
                    },
                    "failureVerdict": "violation",
                    "successVerdict": "pass",
                    "protected": True,
                },
            ],
            "riskAcceptances": [
                {
                    "riskAcceptanceId": "ra-db-zone-loss",
                    "governanceScope": {
                        "governanceScopeType": "clause",
                        "manifestId": _CANONICAL_MANIFEST_ID,
                        "profileId": profile_id,
                        "clausePath": "/constraints/db-zone-loss-spof",
                        "ownerRef": "ops-owner",
                    },
                    "riskKind": "availability",
                    "riskRating": "high",
                    "residualRiskStatement": (
                        "A single-zone database failure remains an accepted residual risk "
                        "for synthetic evaluation."
                    ),
                    "rationaleRef": "synthetic://risk/db-zone-loss",
                    "acceptedBy": "synthetic-approver",
                    "ownedBy": "ops-owner",
                    "acceptedAt": "2025-01-01T00:00:00.000Z",
                    "expiresAt": "2025-12-31T00:00:00.000Z",
                    "linkedControlRefs": ["control-db-failover-runbook"],
                    "acceptedResourceBindings": [
                        {"roleRef": "database-primary", "resourceId": _resource_id("athena-db-01")}
                    ],
                    "profiles": [profile_id],
                    "status": "approved",
                }
            ],
            "controls": [
                {
                    "controlKind": "manualFailoverRunbook",
                    "controlId": "control-db-failover-runbook",
                    "governanceScope": {
                        "governanceScopeType": "clause",
                        "manifestId": _CANONICAL_MANIFEST_ID,
                        "profileId": profile_id,
                        "clausePath": "/constraints/db-zone-loss-spof",
                        "ownerRef": "ops-owner",
                    },
                    "ownerRef": "ops-owner",
                    "profiles": [profile_id],
                    "health": "effective",
                    "runbookRef": "synthetic://runbooks/db-failover",
                    "lastReviewedAt": "2025-01-01T00:00:00.000Z",
                }
            ],
            "weakeningOverrides": [
                {
                    "overrideId": "dev-continuity",
                    "reason": "continuityRelaxation",
                    "targetPath": (
                        "/resolvedProfiles/development/settings/continuity/"
                        "zoneLossContinuityRequired"
                    ),
                    "targetRef": "zoneLossContinuityRequired",
                    "ownerRef": "ops-owner",
                    "rationale": "Development does not claim continuity through zone loss.",
                    "approvedBy": "synthetic-approver",
                    "status": "approved",
                    "acceptedAt": "2025-01-01T00:00:00.000Z",
                    "expiresAt": "2025-12-31T00:00:00.000Z",
                    "profiles": ["development"],
                },
                {
                    "overrideId": "dev-web-zones",
                    "reason": "zoneRequirementRelaxation",
                    "targetPath": (
                        "/resolvedProfiles/development/constraints/"
                        "web-zone-distribution/proofRequirement/"
                        "minimumDistinctZones"
                    ),
                    "targetRef": "web-zone-distribution",
                    "ownerRef": "ops-owner",
                    "rationale": "One web zone is sufficient for synthetic development.",
                    "approvedBy": "synthetic-approver",
                    "status": "approved",
                    "acceptedAt": "2025-01-01T00:00:00.000Z",
                    "expiresAt": "2025-12-31T00:00:00.000Z",
                    "profiles": ["development"],
                },
            ]
            if profile_id == "development"
            else [],
        }

    payload: dict[str, Any] = {
        "manifestId": _CANONICAL_MANIFEST_ID,
        "manifestVersion": "1.0.0",
        "cloud": "azureCloud",
        "workload": {
            "displayName": "Synthetic WC-002 canonical workload",
            "environments": ["production", "development", "training"],
            "allowedEvidenceScopes": [scope.model_dump(mode="json", by_alias=True)],
        },
        "profiles": profiles,
        "roles": [
            {
                "roleId": "database-primary",
                "kind": "singletonDatabase",
                "cardinality": {"cardinalityKind": "exactlyOne"},
                "selectors": [
                    {
                        "selectorType": "namePredicate",
                        "selectorId": "database-name",
                        "prefix": "athena-db-",
                        "maxMatches": 10,
                    }
                ],
                "ownerRef": "ops-owner",
                "status": "approved",
            },
            {
                "roleId": "worker",
                "kind": "worker",
                "cardinality": {"cardinalityKind": "oneOrMore"},
                "selectors": [
                    {
                        "selectorType": "namePredicate",
                        "selectorId": "worker-name",
                        "prefix": "athena-worker-",
                        "maxMatches": 20,
                    }
                ],
                "ownerRef": "ops-owner",
                "status": "approved",
            },
            {
                "roleId": "web",
                "kind": "webService",
                "cardinality": {"cardinalityKind": "oneOrMore"},
                "selectors": [
                    {
                        "selectorType": "namePredicate",
                        "selectorId": "web-name",
                        "prefix": "athena-web-",
                        "maxMatches": 20,
                    }
                ],
                "ownerRef": "ops-owner",
                "status": "approved",
            },
            {
                "roleId": "load-balancer",
                "kind": "loadBalancer",
                "cardinality": {"cardinalityKind": "exactlyOne"},
                "selectors": [
                    {
                        "selectorType": "namePredicate",
                        "selectorId": "load-balancer-name",
                        "prefix": "athena-lb-",
                        "maxMatches": 10,
                    }
                ],
                "ownerRef": "ops-owner",
                "status": "approved",
            },
        ],
        "relationships": [
            {
                "relationshipClass": "declared",
                "relationshipId": "worker-depends-db",
                "kind": "dependsOn",
                "source": {"endpointType": "role", "roleRef": "worker"},
                "target": {"endpointType": "role", "roleRef": "database-primary"},
                "ownerRef": "ops-owner",
                "profiles": ["production", "development", "training"],
                "sourceClause": "/constraints/worker-db-zone-colocation",
            },
            {
                "relationshipClass": "declared",
                "relationshipId": "web-protected-by-lb",
                "kind": "protectedBy",
                "source": {"endpointType": "role", "roleRef": "web"},
                "target": {"endpointType": "role", "roleRef": "load-balancer"},
                "ownerRef": "ops-owner",
                "profiles": ["production", "development", "training"],
                "sourceClause": "/constraints/web-zone-distribution",
            },
        ],
        "constraints": [
            {
                "constraintId": "db-singleton-supported",
                "constraintType": "supportedSingleton",
                "findingKind": "technologyConstraint",
                "governanceScope": {
                    "governanceScopeType": "clause",
                    "manifestId": _CANONICAL_MANIFEST_ID,
                    "profileId": "production",
                    "clausePath": "/constraints/db-singleton-supported",
                    "ownerRef": "ops-owner",
                },
                "ownerRef": "ops-owner",
                "profiles": ["production", "development", "training"],
                "proofRequirement": {
                    "proofKind": "cardinalityProof",
                    "roleRef": "database-primary",
                    "expected": {"cardinalityKind": "exactlyOne"},
                },
                "failureVerdict": "violation",
                "successVerdict": "expectedConstraint",
                "protected": True,
            },
            {
                "constraintId": "db-zone-loss-spof",
                "constraintType": "supportedSingleton",
                "findingKind": "actualSpof",
                "governanceScope": {
                    "governanceScopeType": "clause",
                    "manifestId": _CANONICAL_MANIFEST_ID,
                    "profileId": "production",
                    "clausePath": "/constraints/db-zone-loss-spof",
                    "ownerRef": "ops-owner",
                },
                "ownerRef": "ops-owner",
                "profiles": ["production", "development", "training"],
                "proofRequirement": {
                    "proofKind": "cardinalityProof",
                    "roleRef": "database-primary",
                    "expected": {"cardinalityKind": "exactlyOne"},
                },
                "failureVerdict": "violation",
                "successVerdict": "observation",
                "riskAcceptanceRef": "ra-db-zone-loss",
                "protected": True,
            },
            {
                "constraintId": "db-zone-loss-acceptance",
                "constraintType": "supportedSingleton",
                "findingKind": "riskAcceptance",
                "governanceScope": {
                    "governanceScopeType": "clause",
                    "manifestId": _CANONICAL_MANIFEST_ID,
                    "profileId": "production",
                    "clausePath": "/constraints/db-zone-loss-acceptance",
                    "ownerRef": "ops-owner",
                },
                "ownerRef": "ops-owner",
                "profiles": ["production", "development", "training"],
                "proofRequirement": {
                    "proofKind": "cardinalityProof",
                    "roleRef": "database-primary",
                    "expected": {"cardinalityKind": "exactlyOne"},
                },
                "failureVerdict": "violation",
                "successVerdict": "observation",
                "riskAcceptanceRef": "ra-db-zone-loss",
                "riskAcceptanceClauseRef": "db-zone-loss-spof",
                "protected": True,
            },
            {
                "constraintId": "worker-db-zone-colocation",
                "constraintType": "zoneColocation",
                "findingKind": "architectureConstraint",
                "governanceScope": {
                    "governanceScopeType": "clause",
                    "manifestId": _CANONICAL_MANIFEST_ID,
                    "profileId": "production",
                    "clausePath": "/constraints/worker-db-zone-colocation",
                    "ownerRef": "ops-owner",
                },
                "ownerRef": "ops-owner",
                "profiles": ["production", "development", "training"],
                "proofRequirement": {
                    "proofKind": "zoneColocationProof",
                    "subjectRoleRef": "worker",
                    "anchorRoleRef": "database-primary",
                },
                "failureVerdict": "violation",
                "successVerdict": "pass",
                "protected": True,
            },
            {
                "constraintId": "web-zone-distribution",
                "constraintType": "zoneDistribution",
                "findingKind": "architectureConstraint",
                "governanceScope": {
                    "governanceScopeType": "clause",
                    "manifestId": _CANONICAL_MANIFEST_ID,
                    "profileId": "production",
                    "clausePath": "/constraints/web-zone-distribution",
                    "ownerRef": "ops-owner",
                },
                "ownerRef": "ops-owner",
                "profiles": ["production", "development", "training"],
                "proofRequirement": {
                    "proofKind": "zoneDistributionProof",
                    "roleRef": "web",
                    "minimumDistinctZones": 3,
                },
                "failureVerdict": "violation",
                "successVerdict": "pass",
                "protected": True,
            },
        ],
        "controls": [
            {
                "controlKind": "manualFailoverRunbook",
                "controlId": "control-db-failover-runbook",
                "governanceScope": {
                    "governanceScopeType": "clause",
                    "manifestId": _CANONICAL_MANIFEST_ID,
                    "profileId": "production",
                    "clausePath": "/constraints/db-zone-loss-spof",
                    "ownerRef": "ops-owner",
                },
                "ownerRef": "ops-owner",
                "profiles": ["production", "development", "training"],
                "health": "effective",
                "runbookRef": "synthetic://runbooks/db-failover",
                "lastReviewedAt": "2025-01-01T00:00:00.000Z",
            }
        ],
        "riskAcceptances": [
            {
                "riskAcceptanceId": "ra-db-zone-loss",
                "governanceScope": {
                    "governanceScopeType": "clause",
                    "manifestId": _CANONICAL_MANIFEST_ID,
                    "profileId": "production",
                    "clausePath": "/constraints/db-zone-loss-spof",
                    "ownerRef": "ops-owner",
                },
                "riskKind": "availability",
                "riskRating": "high",
                "residualRiskStatement": (
                    "Synthetic singleton database zone loss stays as an explicit "
                    "residual risk."
                ),
                "rationaleRef": "synthetic://risk/db-zone-loss",
                "acceptedBy": "synthetic-approver",
                "ownedBy": "ops-owner",
                "acceptedAt": "2025-01-01T00:00:00.000Z",
                "expiresAt": "2025-12-31T00:00:00.000Z",
                "linkedControlRefs": ["control-db-failover-runbook"],
                "acceptedResourceBindings": [
                    {"roleRef": "database-primary", "resourceId": _resource_id("athena-db-01")}
                ],
                "profiles": ["production", "development", "training"],
                "status": "approved",
            }
        ],
        "objectives": [],
        "ownership": [
            {
                "ownerRef": "ops-owner",
                "ownerRole": "operationsOwner",
                "authorityRef": "synthetic://teams/operations",
            }
        ],
        "compatibility": {
            "artifactKind": "workloadManifest",
            "schemaVersion": "1.0.0",
            "semanticContractVersion": "1.0.0",
            "policyContractVersion": "1.0.0",
            "minimumReaderVersion": "1.0.0",
            "requiresCapabilities": [],
            "producedBy": {"producerId": "athena.contracts", "version": "1.0.0"},
            "extensionPolicy": "rejectUnknownDecisionFields",
            "artifactDigest": "sha256:placeholder",
            "semanticDigest": "sha256:placeholder",
        },
        "audit": {
            "publishedBy": "human-approved-context-api",
            "publishedAt": "2025-06-01T00:00:00.000Z",
            "approvalStatus": "approved",
        },
    }
    canonical = canonicalize_manifest_payload(payload)
    CanonicalWorkloadManifest.model_validate(canonical)
    return canonical


@dataclass(frozen=True, slots=True)
class FixtureBundle:
    canonical_manifest: CanonicalWorkloadManifest
    canonical_snapshot: EvidenceSnapshot
    trusted_key_anchor: TrustedKeyAnchor
    trusted_key_record: TrustedKeyRecord
    publication_record: SnapshotPublicationRecord
    key_resolver: Callable[[TrustedKeyAnchor], TrustedKeyRecord | None]
    publication_resolver: Callable[[str], SnapshotPublicationRecord | None]
    envelope_resolver: EvidenceEnvelopeResolver
    manifest_digest: str
    snapshot_artifact_digest: str
    snapshot_semantic_digest: str

    @property
    def manifest(self) -> CanonicalWorkloadManifest:
        return self.canonical_manifest

    @property
    def snapshot(self) -> EvidenceSnapshot:
        return self.canonical_snapshot


def _make_fixture_bundle() -> FixtureBundle:
    manifest_payload = _canonical_manifest_payload()
    manifest = CanonicalWorkloadManifest.model_validate(manifest_payload)
    snapshot_payload = _canonical_snapshot_payload()
    snapshot = EvidenceSnapshot.model_validate(snapshot_payload)
    trusted_key_anchor = _trusted_key_anchor()
    trusted_key_record = _make_trusted_key_record()
    publication_record = SnapshotPublicationRecord(
        snapshot_id=snapshot.snapshot_id,
        artifact_digest=snapshot.compatibility.artifact_digest,
        semantic_digest=snapshot.compatibility.semantic_digest,
        schema_version=snapshot.compatibility.schema_version,
        semantic_contract_version=snapshot.compatibility.semantic_contract_version,
        published_at=snapshot.snapshot_attestation.attested_at + timedelta(seconds=1),
    )

    def key_resolver(resolved_anchor: TrustedKeyAnchor) -> TrustedKeyRecord | None:
        return trusted_key_record if resolved_anchor == trusted_key_anchor else None

    def publication_resolver(snapshot_id: str) -> SnapshotPublicationRecord | None:
        return publication_record if snapshot_id == publication_record.snapshot_id else None

    def envelope_resolver(
        attempt_id: str,
        kind: Literal["response", "failure"],
        digest: str,
    ) -> dict[str, Any] | None:
        response_envelope = _build_response_envelope()
        if kind == "response" and digest == compute_response_envelope_digest(response_envelope):
            return response_envelope
        if kind == "failure":
            return {"error": {"code": "notFound", "status": "404"}}
        return None

    return FixtureBundle(
        canonical_manifest=manifest,
        canonical_snapshot=snapshot,
        trusted_key_anchor=trusted_key_anchor,
        trusted_key_record=trusted_key_record,
        publication_record=publication_record,
        key_resolver=key_resolver,
        publication_resolver=publication_resolver,
        envelope_resolver=envelope_resolver,
        manifest_digest=manifest.compute_artifact_digest_value(),
        snapshot_artifact_digest=snapshot.compatibility.artifact_digest,
        snapshot_semantic_digest=snapshot.compatibility.semantic_digest,
    )


_CANONICAL_FIXTURE = _make_fixture_bundle()


def make_canonical_fixture() -> FixtureBundle:
    return deepcopy(_CANONICAL_FIXTURE)


def canonical_fixture() -> FixtureBundle:
    return make_canonical_fixture()


def load_canonical_fixture() -> FixtureBundle:
    return make_canonical_fixture()


def load_fixture() -> FixtureBundle:
    return make_canonical_fixture()


def make_mutation_fixture() -> FixtureBundle:
    bundle = _deepcopy_fixtured_bundle()
    snapshot = EvidenceSnapshot.model_validate(bundle.canonical_snapshot.model_dump(mode="json"))
    target = next(
        record
        for record in snapshot.evidence_records
        if getattr(record, "resource_id", None) == _resource_id("athena-db-01")
    )
    object.__setattr__(target, "resource_id", _resource_id("athena-db-02"))
    return FixtureBundle(
        canonical_manifest=bundle.canonical_manifest,
        canonical_snapshot=snapshot,
        trusted_key_anchor=bundle.trusted_key_anchor,
        trusted_key_record=bundle.trusted_key_record,
        publication_record=bundle.publication_record,
        key_resolver=bundle.key_resolver,
        publication_resolver=bundle.publication_resolver,
        envelope_resolver=bundle.envelope_resolver,
        manifest_digest=bundle.manifest_digest,
        snapshot_artifact_digest=bundle.snapshot_artifact_digest,
        snapshot_semantic_digest=bundle.snapshot_semantic_digest,
    )


def mutation_fixture() -> FixtureBundle:
    return make_mutation_fixture()


def make_missing_evidence_fixture() -> FixtureBundle:
    bundle = _deepcopy_fixtured_bundle()
    snapshot = EvidenceSnapshot.model_validate(bundle.canonical_snapshot.model_dump(mode="json"))
    object.__setattr__(
        snapshot,
        "evidence_records",
        [
            record
            for record in snapshot.evidence_records
            if getattr(record, "resource_id", None) != _resource_id("athena-web-03")
        ],
    )
    return FixtureBundle(
        canonical_manifest=bundle.canonical_manifest,
        canonical_snapshot=snapshot,
        trusted_key_anchor=bundle.trusted_key_anchor,
        trusted_key_record=bundle.trusted_key_record,
        publication_record=bundle.publication_record,
        key_resolver=bundle.key_resolver,
        publication_resolver=bundle.publication_resolver,
        envelope_resolver=bundle.envelope_resolver,
        manifest_digest=bundle.manifest_digest,
        snapshot_artifact_digest=bundle.snapshot_artifact_digest,
        snapshot_semantic_digest=bundle.snapshot_semantic_digest,
    )


def missing_evidence_fixture() -> FixtureBundle:
    return make_missing_evidence_fixture()


def make_conflicting_evidence_fixture() -> FixtureBundle:
    bundle = _deepcopy_fixtured_bundle()
    snapshot = EvidenceSnapshot.model_validate(bundle.canonical_snapshot.model_dump(mode="json"))
    target = next(
        record
        for record in snapshot.evidence_records
        if getattr(record, "resource_id", None) == _resource_id("athena-web-02")
    )
    object.__setattr__(target, "availability_zone", "3")
    return FixtureBundle(
        canonical_manifest=bundle.canonical_manifest,
        canonical_snapshot=snapshot,
        trusted_key_anchor=bundle.trusted_key_anchor,
        trusted_key_record=bundle.trusted_key_record,
        publication_record=bundle.publication_record,
        key_resolver=bundle.key_resolver,
        publication_resolver=bundle.publication_resolver,
        envelope_resolver=bundle.envelope_resolver,
        manifest_digest=bundle.manifest_digest,
        snapshot_artifact_digest=bundle.snapshot_artifact_digest,
        snapshot_semantic_digest=bundle.snapshot_semantic_digest,
    )


def conflicting_evidence_fixture() -> FixtureBundle:
    return make_conflicting_evidence_fixture()


def make_tampered_fixture(*, kind: str = "resource-zone") -> FixtureBundle:
    bundle = _deepcopy_fixtured_bundle()
    snapshot = EvidenceSnapshot.model_validate(bundle.canonical_snapshot.model_dump(mode="json"))
    if kind == "resource-zone":
        target = next(
            record
            for record in snapshot.evidence_records
            if getattr(record, "resource_id", None) == _resource_id("athena-web-02")
        )
        object.__setattr__(target, "availability_zone", "3")
    elif kind == "missing-record":
        object.__setattr__(
            snapshot,
            "evidence_records",
            [
                record
                for record in snapshot.evidence_records
                if getattr(record, "resource_id", None) != _resource_id("athena-web-03")
            ],
        )
    elif kind == "attestation":
        object.__setattr__(
            snapshot.snapshot_attestation,
            "attested_at",
            snapshot.snapshot_attestation.attested_at - timedelta(minutes=1),
        )
    else:
        object.__setattr__(snapshot.compatibility, "artifact_digest", "sha256:" + "9" * 64)
    return FixtureBundle(
        canonical_manifest=bundle.canonical_manifest,
        canonical_snapshot=snapshot,
        trusted_key_anchor=bundle.trusted_key_anchor,
        trusted_key_record=bundle.trusted_key_record,
        publication_record=bundle.publication_record,
        key_resolver=bundle.key_resolver,
        publication_resolver=bundle.publication_resolver,
        envelope_resolver=bundle.envelope_resolver,
        manifest_digest=bundle.manifest_digest,
        snapshot_artifact_digest=bundle.snapshot_artifact_digest,
        snapshot_semantic_digest=bundle.snapshot_semantic_digest,
    )


def tampered_fixture(*, kind: str = "resource-zone") -> FixtureBundle:
    return make_tampered_fixture(kind=kind)


def unsafe_fixture(*, kind: str = "resource-zone") -> FixtureBundle:
    return make_tampered_fixture(kind=kind)


def load_canonical_manifest() -> CanonicalWorkloadManifest:
    return make_canonical_fixture().canonical_manifest


def load_canonical_snapshot() -> EvidenceSnapshot:
    return make_canonical_fixture().canonical_snapshot


def _load_fixture_resource(name: str) -> dict[str, Any]:
    package = files("athena_context.data.fixtures")
    return json.loads(package.joinpath(name).read_text(encoding="utf-8"))


def load_canonical_manifest_resource() -> dict[str, Any]:
    return _load_fixture_resource("canonical-manifest.json")


def load_canonical_snapshot_resource() -> dict[str, Any]:
    return _load_fixture_resource("canonical-evidence-snapshot.json")


def load_canonical_fixture_resource() -> dict[str, Any]:
    return _load_fixture_resource("canonical-fixture.json")


def make_canonical_fixture_from_resources() -> FixtureBundle:
    manifest = CanonicalWorkloadManifest.model_validate(load_canonical_manifest_resource())
    snapshot = EvidenceSnapshot.model_validate(load_canonical_snapshot_resource())
    trusted_key_anchor = _trusted_key_anchor()
    trusted_key_record = _make_trusted_key_record()
    publication_record = SnapshotPublicationRecord(
        snapshot_id=snapshot.snapshot_id,
        artifact_digest=snapshot.compatibility.artifact_digest,
        semantic_digest=snapshot.compatibility.semantic_digest,
        schema_version=snapshot.compatibility.schema_version,
        semantic_contract_version=snapshot.compatibility.semantic_contract_version,
        published_at=snapshot.snapshot_attestation.attested_at + timedelta(seconds=1),
    )

    def key_resolver(resolved_anchor: TrustedKeyAnchor) -> TrustedKeyRecord | None:
        return trusted_key_record if resolved_anchor == trusted_key_anchor else None

    def publication_resolver(snapshot_id: str) -> SnapshotPublicationRecord | None:
        return publication_record if snapshot_id == publication_record.snapshot_id else None

    def envelope_resolver(
        attempt_id: str,
        kind: Literal["response", "failure"],
        digest: str,
    ) -> dict[str, Any] | None:
        response_envelope = _build_response_envelope()
        if kind == "response" and digest == compute_response_envelope_digest(response_envelope):
            return response_envelope
        if kind == "failure":
            return {"error": {"code": "notFound", "status": "404"}}
        return None

    return FixtureBundle(
        canonical_manifest=manifest,
        canonical_snapshot=snapshot,
        trusted_key_anchor=trusted_key_anchor,
        trusted_key_record=trusted_key_record,
        publication_record=publication_record,
        key_resolver=key_resolver,
        publication_resolver=publication_resolver,
        envelope_resolver=envelope_resolver,
        manifest_digest=manifest.compute_artifact_digest_value(),
        snapshot_artifact_digest=snapshot.compatibility.artifact_digest,
        snapshot_semantic_digest=snapshot.compatibility.semantic_digest,
    )


def _deepcopy_fixtured_bundle() -> FixtureBundle:
    return deepcopy(_CANONICAL_FIXTURE)


__all__ = [
    "FixtureBundle",
    "canonical_fixture",
    "conflicting_evidence_fixture",
    "load_canonical_fixture",
    "load_canonical_manifest",
    "load_canonical_manifest_resource",
    "load_canonical_snapshot",
    "load_canonical_snapshot_resource",
    "load_canonical_fixture_resource",
    "load_fixture",
    "make_canonical_fixture",
    "make_canonical_fixture_from_resources",
    "make_conflicting_evidence_fixture",
    "make_missing_evidence_fixture",
    "make_mutation_fixture",
    "make_tampered_fixture",
    "missing_evidence_fixture",
    "mutation_fixture",
    "tampered_fixture",
    "unsafe_fixture",
    "_CANONICAL_MANIFEST_ID",
    "_CANONICAL_SNAPSHOT_ID",
    "_CANONICAL_KEY_VAULT_KEY_ID",
    "_CANONICAL_PRIVATE_KEY_PEM",
]
