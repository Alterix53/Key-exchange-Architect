import os
import json
import base64
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes

if TYPE_CHECKING:
    from .storage_backend import KdcTicketStorage


class KDC:
    """Key Distribution Center with pluggable ticket storage.

    Default backend: SqlServerKdcTicketStorage (falls back to JSON file
    only when no storage is provided and DB is unreachable).
    """

    def __init__(self, key_store, pki=None, data_dir: str = "data",
                 ticket_storage: Optional['KdcTicketStorage'] = None):
        self.key_store = key_store
        self.pki = pki
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)

        if ticket_storage is not None:
            self.storage = ticket_storage
        else:
            try:
                from .db import get_working_connection_string
                from .storage_backend import SqlServerKdcTicketStorage
                conn_str = get_working_connection_string()
                self.storage = SqlServerKdcTicketStorage(conn_str)
            except Exception:
                self.storage = None

        self.tickets: Dict[str, Dict[str, Any]] = self._load_tickets()

    # ---- persistence helpers ----

    def _load_tickets(self) -> Dict[str, Dict[str, Any]]:
        if self.storage is not None:
            try:
                return self.storage.load_all_tickets()
            except Exception:
                return {}
        return {}

    def _save_ticket(self, ticket_id: str) -> None:
        rec = self.tickets.get(ticket_id)
        if rec is None:
            return
        if self.storage is not None:
            self.storage.save_ticket({"ticket_id": ticket_id, **rec})

    # ---- Entity Master Key Management ----

    def create_entity_master_key(self, entity_id: str, ttl_days: int = 365) -> Optional[str]:
        """Create master key for entity (Alice, Bob, etc.)
        
        Args:
            entity_id: User/entity identifier
            ttl_days: Key time-to-live in days (default: 365)
            
        Returns:
            key_id if successful, None if failed
        """
        try:
            key_id = self.key_store.generate_entity_master_key(entity_id, ttl_days=ttl_days)
            return key_id
        except Exception as e:
            print(f"[KDC] Error creating master key for {entity_id}: {e}")
            return None

    def get_entity_master_key(self, entity_id: str) -> Optional[bytes]:
        """Get entity's master key for encryption/decryption
        
        Args:
            entity_id: User/entity identifier
            
        Returns:
            Decrypted key bytes if found, None otherwise
        """
        try:
            key_bytes = self.key_store.get_entity_master_key(entity_id)
            return key_bytes
        except Exception as e:
            print(f"[KDC] Error getting master key for {entity_id}: {e}")
            return None

    def rotate_entity_key(self, entity_id: str) -> Optional[str]:
        """Rotate entity master key (create new version)
        
        Args:
            entity_id: User/entity identifier
            
        Returns:
            new_key_id if successful, None if failed
        """
        try:
            new_key_id = self.key_store.rotate_entity_master_key(entity_id)
            return new_key_id
        except Exception as e:
            print(f"[KDC] Error rotating master key for {entity_id}: {e}")
            return None

    def revoke_entity_key(self, entity_id: str) -> bool:
        """Revoke entity master key (mark inactive)
        
        Args:
            entity_id: User/entity identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.key_store.revoke_entity_master_key(entity_id)
            return True
        except Exception as e:
            print(f"[KDC] Error revoking master key for {entity_id}: {e}")
            return False

    def list_entity_keys(self, entity_id: str) -> Optional[list]:
        """List all keys for an entity
        
        Args:
            entity_id: User/entity identifier
            
        Returns:
            List of key metadata, None if failed
        """
        try:
            keys = self.key_store.list_keys(owner=entity_id)
            return keys
        except Exception as e:
            print(f"[KDC] Error listing keys for {entity_id}: {e}")
            return None

    # ---- public API ----

    def issue_session_ticket(self, ida: str, idb: str, requested_ttl: int = 300) -> Optional[Dict[str, Any]]:
        """Issue session key Ks for ida <-> idb using RSA public keys from PKI certificates.

        Returns dict with:
          enc_ks_for_a  — RSA-OAEP(PubA, Ks)       Alice decrypts with PrivA
          ticket_for_b  — RSA-OAEP(PubB, {Ks,ida,ttl})  Bob decrypts with PrivB
          ticket_id, ttl, issued_at
        """
        if not self.pki:
            print("[KDC] PKI not configured — cannot issue session ticket")
            return None

        try:
            cert_a = self.pki.lookup(ida)
            cert_b = self.pki.lookup(idb)
        except Exception as e:
            print(f"[KDC] PKI lookup failed: {e}")
            return None

        if not cert_a or not cert_b:
            print(f"[KDC] Certificate not found for {'ida' if not cert_a else 'idb'}")
            return None

        # Reject expired certificates
        now = datetime.utcnow()
        try:
            exp_a = cert_a.not_valid_after_utc.replace(tzinfo=None)
            exp_b = cert_b.not_valid_after_utc.replace(tzinfo=None)
        except AttributeError:
            exp_a = cert_a.not_valid_after
            exp_b = cert_b.not_valid_after
        if now > exp_a or now > exp_b:
            print("[KDC] One or both certificates are expired")
            return None

        pub_a = cert_a.public_key()
        pub_b = cert_b.public_key()

        ks = os.urandom(32)
        ks_b64 = base64.b64encode(ks).decode('utf-8')
        ticket_id = secrets.token_hex(16)
        ttl = min(int(requested_ttl), 3600)
        issued_at = datetime.utcnow().isoformat() + "Z"
        expires_at = (datetime.utcnow() + timedelta(seconds=ttl)).isoformat() + "Z"

        oaep = asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )

        # enc_ks_for_a = RSA-OAEP(PubA, Ks) — only Alice can decrypt with PrivA
        enc_ks_for_a = base64.b64encode(pub_a.encrypt(ks, oaep)).decode('utf-8')

        # ticket_for_b = RSA-OAEP(PubB, {Ks, ida, ttl, issued_at}) — only Bob can decrypt with PrivB
        ticket_payload = json.dumps({"ks": ks_b64, "ida": ida, "ttl": ttl, "issued_at": issued_at}).encode('utf-8')
        ticket_for_b = base64.b64encode(pub_b.encrypt(ticket_payload, oaep)).decode('utf-8')

        self.tickets[ticket_id] = {
            "ticket_for_b": ticket_for_b,
            "ida": ida,
            "idb": idb,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "used": False,
        }
        self._save_ticket(ticket_id)

        return {
            "enc_ks_for_a": enc_ks_for_a,
            "ticket_for_b": ticket_for_b,
            "ticket_id": ticket_id,
            "ttl": ttl,
            "issued_at": issued_at,
        }

    def validate_ticket(self, ticket_id: str) -> bool:
        rec = self.tickets.get(ticket_id)
        if not rec:
            if self.storage is not None:
                rec = self.storage.load_ticket(ticket_id)
                if rec:
                    self.tickets[ticket_id] = rec
            if not rec:
                return False
        if rec.get("used"):
            return False
        expires_at = rec.get("expires_at")
        if expires_at:
            exp = datetime.fromisoformat(expires_at.replace("Z", ""))
            if datetime.utcnow() > exp:
                return False
        return True

    def mark_ticket_used(self, ticket_id: str) -> None:
        if ticket_id in self.tickets:
            self.tickets[ticket_id]["used"] = True
        if self.storage is not None:
            self.storage.mark_used(ticket_id)

    def get_ticket_record(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        return self.tickets.get(ticket_id)

