import os
import json
import base64
import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from .secure_transmission import encrypt_json_with_key, decrypt_json_with_key


class KDC:
    """Simple Key Distribution Center skeleton.

    - Stores tickets in data/kdc_tickets.json
    - issue_session_ticket(ida, idb, requested_ttl) returns an envelope encrypted for A
      that contains the session key (Ks) and an opaque ticket for B (encrypted under Kb).
    - get_ticket(ticket_id) and mark_ticket_used allow server-side enforcement.
    """

    def __init__(self, key_store, data_dir: str = "data"):
        self.key_store = key_store
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.tickets_file = os.path.join(self.data_dir, "kdc_tickets.json")
        self.tickets: Dict[str, Dict[str, Any]] = self._load_tickets()

    def _load_tickets(self) -> Dict[str, Dict[str, Any]]:
        if os.path.exists(self.tickets_file):
            try:
                with open(self.tickets_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data
            except Exception:
                return {}
        return {}

    def _save_tickets(self) -> None:
        with open(self.tickets_file, "w", encoding="utf-8") as f:
            json.dump(self.tickets, f, indent=2, ensure_ascii=False)

    def issue_session_ticket(self, ida: str, idb: str, requested_ttl: int = 300) -> Optional[Dict[str, str]]:
        """Issue a session key Ks for ida <-> idb and return response envelope encrypted for A.

        Response envelope is a dict: { 'enc': ..., 'nonce': ..., 'alg': 'AES-256-GCM' }
        That decrypted payload for A contains: ks (base64), ticket (base64 blob), ticket_nonce, ticket_id, ttl, issued_at
        """
        # Validate inputs and policy
        try:
            # Retrieve entity master keys (raw bytes). KeyStore must provide get_entity_master_key
            ka = self.key_store.get_entity_master_key(ida)
            kb = self.key_store.get_entity_master_key(idb)
        except Exception as e:
            # Missing keys or not permitted
            return None

        # Generate session key
        ks = os.urandom(32)
        ks_b64 = base64.b64encode(ks).decode('utf-8')

        # Ticket metadata
        ticket_id = secrets.token_hex(16)
        ttl = min(int(requested_ttl), 3600)
        issued_at = datetime.utcnow().isoformat() + "Z"
        expires_at = (datetime.utcnow() + timedelta(seconds=ttl)).isoformat() + "Z"

        ticket_payload = {
            "ticket_id": ticket_id,
            "ks": ks_b64,
            "ida": ida,
            "ttl": ttl,
            "issued_at": issued_at
        }

        # Encrypt ticket for B under Kb
        ticket_blob = encrypt_json_with_key(kb, ticket_payload)
        # ticket_blob contains enc and nonce

        # Build response for A
        response_for_a = {
            "ks": ks_b64,
            "ticket": ticket_blob["enc"],
            "ticket_nonce": ticket_blob["nonce"],
            "ticket_id": ticket_id,
            "ttl": ttl,
            "issued_at": issued_at
        }

        # Encrypt response under Ka
        envelope_for_a = encrypt_json_with_key(ka, response_for_a)

        # Persist ticket record (server-side enforcement)
        self.tickets[ticket_id] = {
            "ks": ks_b64,
            "ida": ida,
            "idb": idb,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "used": False
        }
        self._save_tickets()

        return envelope_for_a

    def validate_ticket(self, ticket_id: str) -> bool:
        rec = self.tickets.get(ticket_id)
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
            self._save_tickets()

    def get_ticket_record(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        return self.tickets.get(ticket_id)

    def decrypt_keyreq(self, ida: str, enc_b64: str, nonce_b64: str) -> Optional[Dict[str, Any]]:
        """Decrypt a KEYREQ envelope sent by ida (encrypted under Ka)."""
        try:
            ka = self.key_store.get_entity_master_key(ida)
            payload = decrypt_json_with_key(ka, enc_b64, nonce_b64)
            return payload
        except Exception:
            return None

    def decrypt_ticket_for_b(self, idb: str, ticket_enc_b64: str, ticket_nonce_b64: str) -> Optional[Dict[str, Any]]:
        try:
            kb = self.key_store.get_entity_master_key(idb)
            payload = decrypt_json_with_key(kb, ticket_enc_b64, ticket_nonce_b64)
            return payload
        except Exception:
            return None
