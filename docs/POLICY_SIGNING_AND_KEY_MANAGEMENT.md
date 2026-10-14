# DNS-SHIELD Policy Authentication & Key Management Architecture

## 1. Overview
DNS-SHIELD employs asymmetric digital signatures using Ed25519 (via the standard, actively maintained `cryptography` Python package) to guarantee authenticity, integrity, and non-repudiation of security policies distributed from the hosted management plane to endpoint protection agents.

### Guarantees
- **Authenticity**: Only the publisher possessing the server-side private key can sign valid policy envelopes.
- **Integrity**: Every policy rule, allowlist entry, blocked record type, tenant ID, and timestamp is bound into a canonical JSON representation covered by the digital signature and a SHA-256 content digest.
- **Server-Side Private Key Isolation**: The private signing key (`priv_hex`, 32 bytes / 64 hex characters) is stored strictly on the server and is never transmitted to endpoints or logged in telemetry.
- **Rollback Prevention**: Endpoints persist the latest verified active policy version and content hash in a local SQLite database (`policy_metadata` table). Replays of older policy versions are strictly rejected.
- **Idempotency**: Submitting an identical policy payload matching the currently active version and content hash is treated as a safe no-op (`status: "no_change"`, `action: "noop"`). Submitting conflicting policy content under an already-issued version is rejected as a `Version conflict`.

---

## 2. Canonical Envelope Specification
The policy envelope canonicalizes the following fields using deterministic key sorting and compact formatting:
```json
{
  "allowlist": ["internal.corp"],
  "blocked_record_types": ["ANY", "TXT"],
  "custom_blocked_domains": ["exfil.test", "malware.test"],
  "key_id": "key-2026-v1",
  "signed_at": 1700000000.123,
  "tenant_id": "ten_abc123",
  "version": 2
}
```
Binary representation: UTF-8 encoded bytes of `json.dumps(envelope, sort_keys=True, separators=(",", ":"))`.

---

## 3. Trusted Key Provisioning & Keyring Architecture

### Provisioning
1. During tenant onboarding, an Ed25519 keypair is generated:
   - Private key is persisted in the server database (`tenants.policy_signing_key`).
   - Public verification key (`policy_public_key`, 32 bytes / 64 hex characters) is distributed to endpoints via device enrollment or administrative configuration.
2. Endpoint protection agents are provisioned with:
   - `trusted_public_key_hex`: Pinned publisher verification key.
   - `expected_tenant_id`: Bound tenant identifier.
   - `db_path`: Local SQLite persistence store (`%ProgramData%\DNS-SHIELD\dns_shield.db`).

### Key Rotation Workflow
To rotate publisher signing keys without endpoint downtime:
1. **Key Generation**: Generate a new Ed25519 keypair with an incremented key identifier (e.g., `key-2027-v1`).
2. **Keyring Distribution**: Endpoints maintain a trusted keyring dictionary:
   ```python
   trusted_keyring = {
       "key-2026-v1": "6f8c...public_key_1...",
       "key-2027-v1": "a3b2...public_key_2...",
   }
   ```
3. **Graceful Cutover**:
   - The publisher continues signing policies with `key-2026-v1` until all active endpoints have received the updated keyring.
   - The publisher switches active signing to `key-2027-v1`.
   - Endpoints verify incoming envelopes using the key matching the envelope's `key_id`.
4. **Decommissioning**: Once all endpoints have updated and previous policy versions are retired, the old key ID is removed from the active keyring.

---

## 4. Rollback Protection and SQLite Persistence

Endpoint state is saved in the `policy_metadata` table:
```sql
CREATE TABLE IF NOT EXISTS policy_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL
);
```

Stored keys:
- `active_version`: Monotonically increasing integer version.
- `active_content_hash`: SHA-256 hexadecimal digest of active rules.

### Service Restart Behavior
When the DNS-SHIELD service starts or restarts:
1. `EndpointPolicyVerifier` queries `policy_metadata` for `active_version` and `active_content_hash`.
2. Any inbound policy with `version < active_version` is rejected with `Policy rollback detected`.
3. An inbound policy with `version == active_version`:
   - If `content_hash == active_content_hash`: Verified as an idempotent no-op (`action: "noop"`).
   - If `content_hash != active_content_hash`: Rejected with `Version conflict: different policy content submitted with existing version`.
4. An inbound policy with `version > active_version`: Verified via Ed25519 signature; if valid, persisted to disk and applied.
