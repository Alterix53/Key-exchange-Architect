import os
import json
import base64
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, TYPE_CHECKING

from .secure_transmission import encrypt_json_with_key, decrypt_json_with_key

if TYPE_CHECKING:
    from .storage_backend import KdcTicketStorage


class KDC:
    """Key Distribution Center with pluggable ticket storage.

    Default backend: SqlServerKdcTicketStorage (falls back to JSON file
    only when no storage is provided and DB is unreachable).
    """

    def __init__(self, key_store, data_dir: str = "data",
                 ticket_storage: Optional['KdcTicketStorage'] = None):
        self.key_store = key_store
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

    # ---- public API ----

    def issue_session_ticket(self, ida: str, idb: str, requested_ttl: int = 300) -> Optional[Dict[str, str]]:
        """Issue a session key Ks for ida <-> idb and return response envelope encrypted for A."""
        try:
            ka = self.key_store.get_entity_master_key(ida)
            kb = self.key_store.get_entity_master_key(idb)
        except Exception:
            return None

        ks = os.urandom(32)
        ks_b64 = base64.b64encode(ks).decode('utf-8')

        ticket_id = secrets.token_hex(16)
        ttl = min(int(requested_ttl), 3600)
        issued_at = datetime.utcnow().isoformat() + "Z"
        expires_at = (datetime.utcnow() + timedelta(seconds=ttl)).isoformat() + "Z"

        ticket_payload = {
            "ticket_id": ticket_id,
            "ks": ks_b64,
            "ida": ida,
            "ttl": ttl,
            "issued_at": issued_at,
        }

        ticket_blob = encrypt_json_with_key(kb, ticket_payload)

        response_for_a = {
            "ks": ks_b64,
            "ticket": ticket_blob["enc"],
            "ticket_nonce": ticket_blob["nonce"],
            "ticket_id": ticket_id,
            "ttl": ttl,
            "issued_at": issued_at,
        }

        envelope_for_a = encrypt_json_with_key(ka, response_for_a)

        self.tickets[ticket_id] = {
            "ks": ks_b64,
            "ida": ida,
            "idb": idb,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "used": False,
        }
        self._save_ticket(ticket_id)

        return envelope_for_a

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

    def decrypt_keyreq(self, ida: str, enc_b64: str, nonce_b64: str) -> Optional[Dict[str, Any]]:
        try:
            ka = self.key_store.get_entity_master_key(ida)
            return decrypt_json_with_key(ka, enc_b64, nonce_b64)
        except Exception:
            return None

    def decrypt_ticket_for_b(self, idb: str, ticket_enc_b64: str, ticket_nonce_b64: str) -> Optional[Dict[str, Any]]:
        try:
            kb = self.key_store.get_entity_master_key(idb)
            return decrypt_json_with_key(kb, ticket_enc_b64, ticket_nonce_b64)
        except Exception:
            return None
