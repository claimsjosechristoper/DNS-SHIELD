"""
DNS-SHIELD Asymmetric Ed25519 Policy Authentication & Verification Engine.

Provides genuine asymmetric digital signature generation (server-side private key)
and endpoint verification (client-side trusted public key) using the standard
maintained 'cryptography' library.

Security Guarantees:
1. Authenticity: Only the server holding the private signing key can issue valid policies.
2. Integrity: Every policy component is covered by SHA-256 and Ed25519 digital signature.
3. Rollback Protection: Persists current active policy version and hash across service restarts.
4. Idempotency: Submitting identical policy content with the same version is an idempotent no-op.
   Submitting conflicting content with an existing version is strictly rejected.
5. Key Rotation & Provisioning: Endpoints pin the publisher public key, supporting
   versioned key identifiers (key_id).
"""

import hashlib
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger("DNSShield.PolicyVerifier")


class PolicyVerificationError(Exception):
    """Raised when policy verification fails any authenticity, integrity, or rollback check."""
    pass


def generate_publisher_keypair() -> Tuple[str, str]:
    """Generates a fresh Ed25519 asymmetric keypair, returning (private_raw_hex, public_raw_hex)."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_hex = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()

    pub_hex = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    return priv_hex, pub_hex


def canonicalize_envelope(
    tenant_id: str,
    version: int,
    custom_rules: List[str],
    allowlist: List[str],
    blocked_types: List[str],
    signed_at: float,
    key_id: Optional[str] = None,
) -> bytes:
    """
    Produces deterministic, sort-ordered canonical JSON bytes covering
    tenant identity, policy contents, version, and signing metadata.
    """
    envelope = {
        "allowlist": sorted(str(d).lower().strip() for d in allowlist),
        "blocked_record_types": sorted(str(t).upper().strip() for t in blocked_types),
        "custom_blocked_domains": sorted(str(d).lower().strip() for d in custom_rules),
        "key_id": key_id or "key-1",
        "signed_at": round(float(signed_at), 3),
        "tenant_id": str(tenant_id).strip(),
        "version": int(version),
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_policy_content_hash(
    custom_rules: List[str],
    allowlist: List[str],
    blocked_types: List[str],
) -> str:
    """Computes SHA-256 digest of policy rules only (used for idempotency comparisons)."""
    payload = {
        "allowlist": sorted(str(d).lower().strip() for d in allowlist),
        "blocked_record_types": sorted(str(t).upper().strip() for t in blocked_types),
        "custom_blocked_domains": sorted(str(d).lower().strip() for d in custom_rules),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def sign_policy_envelope(
    private_key_hex: str,
    tenant_id: str,
    version: int,
    custom_rules: List[str],
    allowlist: List[str],
    blocked_types: List[str],
    signed_at: float,
    key_id: Optional[str] = None,
) -> str:
    """Server-side asymmetric signing using Ed25519 private key."""
    priv_bytes = bytes.fromhex(private_key_hex)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    canonical_bytes = canonicalize_envelope(
        tenant_id=tenant_id,
        version=version,
        custom_rules=custom_rules,
        allowlist=allowlist,
        blocked_types=blocked_types,
        signed_at=signed_at,
        key_id=key_id,
    )
    signature = private_key.sign(canonical_bytes)
    return signature.hex()


class EndpointPolicyVerifier:
    """
    Client-side verification engine run on the protected endpoint/gateway.
    Stores trusted public verification key (or keyring for rotation) and maintains
    persisted rollback state across service restarts.
    """

    def __init__(
        self,
        trusted_public_key_hex: Optional[str] = None,
        expected_tenant_id: str = "",
        db_path: Optional[str] = None,
        tenant_id: Optional[str] = None,
        signing_key: Optional[Any] = None,  # for backward compatibility
        current_version: int = 0,
        trusted_keyring: Optional[Dict[str, str]] = None,
    ):
        self.expected_tenant_id = expected_tenant_id or tenant_id or ""
        self.db_path = db_path
        self.active_version = int(current_version)
        self.active_content_hash = ""

        # Keyring support for seamless key rotation
        self.keyring: Dict[str, ed25519.Ed25519PublicKey] = {}
        if trusted_keyring:
            for kid, pub_hex in trusted_keyring.items():
                self.keyring[kid] = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))

        if trusted_public_key_hex:
            key_input = trusted_public_key_hex
        elif signing_key is not None:
            key_input = signing_key
        else:
            key_input = None

        if isinstance(key_input, bytes):
            try:
                decoded = key_input.decode("utf-8")
                if len(decoded) == 64:
                    key_hex = decoded
                else:
                    key_hex = key_input.hex()
            except UnicodeDecodeError:
                key_hex = key_input.hex()
        elif isinstance(key_input, str):
            key_hex = key_input
        else:
            key_hex = None

        if key_hex:
            try:
                pub_bytes = bytes.fromhex(key_hex)
                self.public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                self.keyring["key-1"] = self.public_key
            except Exception as e:
                logger.warning(f"Failed to parse public key hex: {e}")
                self.public_key = None
        else:
            self.public_key = None

        self._load_persisted_state()

    @property
    def current_version(self) -> int:
        return self.active_version

    @current_version.setter
    def current_version(self, value: int):
        self.active_version = int(value)

    def _load_persisted_state(self):
        """Loads last verified policy version and hash from SQLite database."""
        if not self.db_path or not Path(self.db_path).exists():
            return
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS policy_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
            """)
            cur.execute("SELECT value FROM policy_metadata WHERE key = 'active_version'")
            row_v = cur.fetchone()
            if row_v:
                self.active_version = int(row_v[0])

            cur.execute("SELECT value FROM policy_metadata WHERE key = 'active_content_hash'")
            row_h = cur.fetchone()
            if row_h:
                self.active_content_hash = row_h[0]
            conn.close()
        except Exception as e:
            logger.warning(f"Could not load persisted policy state: {e}")

    def persist_state(self, version: int, content_hash: str):
        """Persists the verified active policy version and hash to survive service restarts."""
        self.active_version = version
        self.active_content_hash = content_hash
        if not self.db_path:
            return
        try:
            conn = sqlite3.connect(self.db_path)
            now = time.time()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
            """)
            conn.execute("""
                INSERT OR REPLACE INTO policy_metadata (key, value, updated_at)
                VALUES ('active_version', ?, ?)
            """, (str(version), now))
            conn.execute("""
                INSERT OR REPLACE INTO policy_metadata (key, value, updated_at)
                VALUES ('active_content_hash', ?, ?)
            """, (content_hash, now))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to persist verified policy state: {e}")

    def verify_and_process(self, incoming_policy: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates incoming policy:
        1. Tenant identity check
        2. Content integrity (SHA-256) check
        3. Asymmetric Ed25519 publisher signature verification
        4. Idempotency vs. Conflict vs. Rollback handling
        5. Persists state on activation
        """
        if not isinstance(incoming_policy, dict):
            raise PolicyVerificationError("Policy payload must be a JSON dictionary.")

        # Required fields check with flexible aliases
        tenant_id = str(incoming_policy.get("tenant_id") or incoming_policy.get("publisher_id") or "")
        if not tenant_id:
            raise PolicyVerificationError("Missing required policy envelope field: 'tenant_id'")

        if self.expected_tenant_id and tenant_id != self.expected_tenant_id:
            raise PolicyVerificationError(
                f"Tenant identity mismatch: policy issued for '{tenant_id}', expected '{self.expected_tenant_id}'."
            )

        if "version" not in incoming_policy:
            raise PolicyVerificationError("Missing required policy envelope field: 'version'")

        try:
            version = int(incoming_policy["version"])
            custom_rules = list(incoming_policy.get("custom_rules") or incoming_policy.get("custom_blocked_domains") or [])
            allowlist = list(incoming_policy.get("allowlist") or incoming_policy.get("allowlisted_domains") or [])
            blocked_types = list(incoming_policy.get("blocked_types") or incoming_policy.get("blocked_record_types") or [])
            signed_at = float(incoming_policy.get("signed_at", time.time()))
            sig_hex = str(incoming_policy.get("signature") or incoming_policy.get("publisher_signature") or "")
            key_id = str(incoming_policy.get("key_id", "key-1"))
        except (ValueError, TypeError) as exc:
            raise PolicyVerificationError(f"Policy schema typing error: {exc}")

        if not sig_hex:
            raise PolicyVerificationError("Missing publisher signature in policy envelope.")

        # Compute incoming content hash
        content_hash = compute_policy_content_hash(custom_rules, allowlist, blocked_types)

        # 1. Idempotency & Conflict Check on Equal Version
        if version == self.active_version:
            if content_hash == self.active_content_hash:
                logger.info(f"Incoming policy v{version} matches active policy: idempotent no-op.")
                return {
                    "status": "no_change",
                    "version": version,
                    "content_hash": content_hash,
                    "action": "noop",
                }
            else:
                raise PolicyVerificationError(
                    f"Version conflict: different policy content submitted with existing version {version}. "
                    f"Policy versions must be strictly monotonic."
                )

        # 2. Rollback Protection on Older Version
        if version < self.active_version:
            raise PolicyVerificationError(
                f"Policy rollback detected: incoming version {version} is older than active version {self.active_version}."
            )

        # 3. Integrity checksum check (tamper detection)
        if "integrity_sha256" in incoming_policy and incoming_policy["integrity_sha256"]:
            if incoming_policy["integrity_sha256"] != content_hash:
                raise PolicyVerificationError(
                    f"Integrity checksum mismatch: computed {content_hash}, header contained {incoming_policy['integrity_sha256']}"
                )

        # 4. Select verification key (supporting rotation via key_id)
        pub_key = self.keyring.get(key_id) or self.public_key
        if not pub_key:
            raise PolicyVerificationError(f"No trusted public verification key found for key_id '{key_id}'.")

        # 5. Asymmetric Signature Verification
        canonical_bytes = canonicalize_envelope(
            tenant_id=tenant_id,
            version=version,
            custom_rules=custom_rules,
            allowlist=allowlist,
            blocked_types=blocked_types,
            signed_at=signed_at,
            key_id=key_id,
        )
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            pub_key.verify(sig_bytes, canonical_bytes)
        except (ValueError, InvalidSignature) as exc:
            raise PolicyVerificationError(f"Publisher digital signature verification failed (asymmetric): {exc}")

        # 6. Valid Forward Progression: Persist verified active state
        self.persist_state(version, content_hash)
        logger.info(f"Policy v{version} successfully authenticated and verified for activation.")
        return {
            "status": "verified",
            "version": version,
            "tenant_id": tenant_id,
            "custom_rules": custom_rules,
            "allowlist": allowlist,
            "blocked_types": blocked_types,
            "content_hash": content_hash,
            "integrity_sha256": content_hash,
            "signed_at": signed_at,
            "key_id": key_id,
            "action": "activate",
        }

    verify_and_prepare = verify_and_process


# Aliases for compatibility
PolicyVerifier = EndpointPolicyVerifier
compute_policy_hash = compute_policy_content_hash
canonicalize_policy = canonicalize_envelope


def compute_publisher_signature(
    private_key: Any,
    tenant_id: str,
    version: int,
    custom_rules: Any,
    signed_at: float,
    key_id: Optional[str] = "key-1",
    allowlist: Optional[List[str]] = None,
    blocked_types: Optional[List[str]] = None,
) -> str:
    """Helper alias for publisher signing."""
    if isinstance(private_key, bytes):
        priv_hex = private_key.hex()
    else:
        priv_hex = str(private_key)

    rules = custom_rules if isinstance(custom_rules, list) else []
    allows = allowlist or []
    b_types = blocked_types or (["ANY"] if not isinstance(custom_rules, list) else [])

    return sign_policy_envelope(
        private_key_hex=priv_hex,
        tenant_id=tenant_id,
        version=version,
        custom_rules=rules,
        allowlist=allows,
        blocked_types=b_types,
        signed_at=signed_at,
        key_id=key_id,
    )
