"""
Terminal relay server for 2 encrypted clients.
"""

import argparse
import base64
import json
import socket
import threading
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.audit_logging import AuditEventType, AuditLogger
from src.secure_transmission import SecureTransmissionChannel


def send_json(sock: socket.socket, payload: Dict) -> None:
    data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    sock.sendall(data)


@dataclass
class ClientConnection:
    client_id: str
    sock: socket.socket
    file_reader: Any
    public_key: Any
    write_lock: threading.Lock = field(default_factory=threading.Lock)

    def send(self, payload: Dict) -> None:
        with self.write_lock:
            send_json(self.sock, payload)


class RelayServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.channel = SecureTransmissionChannel()
        self.audit = AuditLogger("demo_audit")
        self.clients: Dict[str, ClientConnection] = {}
        self.clients_lock = threading.Lock()
        self.shared_session_key: Optional[bytes] = None

        self.ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca_public_key = self.ca_private_key.public_key()

    def _public_key_pem(self) -> str:
        return self.ca_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def _build_certificate(self, client_id: str, client_public_pem: str) -> Dict:
        issued_at = datetime.now()
        cert_payload = {
            "serial": base64.b16encode(hashlib.sha256(f"{client_id}:{issued_at.isoformat()}".encode("utf-8")).digest()[:8]).decode("ascii"),
            "issuer": "IAM-Relay-Server-CA",
            "subject": client_id,
            "valid_from": issued_at.isoformat(),
            "valid_to": (issued_at + timedelta(days=30)).isoformat(),
            "server_public_key": self._public_key_pem(),
            "client_public_key_fingerprint": hashlib.sha256(client_public_pem.encode("utf-8")).hexdigest(),
        }
        signing_input = json.dumps(cert_payload, sort_keys=True)
        cert_signature = self.channel.sign_message(signing_input, self.ca_private_key)
        cert_payload["signature"] = cert_signature
        return cert_payload

    def _try_share_session_key(self) -> None:
        with self.clients_lock:
            if len(self.clients) != 2 or self.shared_session_key is not None:
                return

            self.shared_session_key = base64.b64encode(os.urandom(32))
            key_b64_text = self.shared_session_key.decode("utf-8")

            for conn in self.clients.values():
                encrypted_key = self.channel.encrypt_rsa_oaep(key_b64_text, conn.public_key)
                conn.send(
                    {
                        "type": "session_key",
                        "algorithm": "RSA-OAEP + AES-256-GCM",
                        "encrypted_key": encrypted_key,
                    }
                )

    def _relay_message(self, sender_id: str, message: Dict) -> None:
        with self.clients_lock:
            if sender_id not in self.clients:
                return
            recipients = [cid for cid in self.clients.keys() if cid != sender_id]
            if not recipients:
                return
            recipient_id = recipients[0]
            recipient_conn = self.clients[recipient_id]

        relay_payload = {
            "type": "relay",
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "algorithm": message.get("algorithm", "AES-256-GCM"),
            "nonce": message.get("nonce"),
            "ciphertext": message.get("ciphertext"),
            "tag": message.get("tag"),
            "associated_data": message.get("associated_data", ""),
            "timestamp": message.get("timestamp", datetime.now().isoformat()),
        }

        print(f"[LOG] Đang chuyển tiếp tin nhắn mã hóa từ Client {sender_id} sang Client {recipient_id}.")
        recipient_conn.send(relay_payload)

        self.audit.log_event(
            AuditEventType.MESSAGE_RECEIVED,
            user_id=sender_id,
            resource="relay_server",
            action="forward_encrypted_message",
            details={"from": sender_id, "to": recipient_id},
        )

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple) -> None:
        file_reader = client_sock.makefile("r", encoding="utf-8")
        client_id: Optional[str] = None

        try:
            hello_line = file_reader.readline()
            if not hello_line:
                return

            hello = json.loads(hello_line)
            if hello.get("type") != "hello":
                send_json(client_sock, {"type": "error", "message": "Expected hello message"})
                return

            client_id = hello.get("client_id", "")
            public_key_pem = hello.get("public_key", "")

            if not client_id or not public_key_pem:
                send_json(client_sock, {"type": "error", "message": "Missing client_id/public_key"})
                return

            public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

            with self.clients_lock:
                if len(self.clients) >= 2:
                    send_json(client_sock, {"type": "error", "message": "Server only supports 2 clients"})
                    return
                if client_id in self.clients:
                    send_json(client_sock, {"type": "error", "message": "client_id already connected"})
                    return

                conn = ClientConnection(client_id=client_id, sock=client_sock, file_reader=file_reader, public_key=public_key)
                self.clients[client_id] = conn

            cert = self._build_certificate(client_id, public_key_pem)
            conn.send({"type": "cert", "certificate": cert})
            print(f"[CERT] Certificate đã cấp cho {client_id}: {json.dumps(cert, indent=2, ensure_ascii=False)}")

            self.audit.log_event(
                AuditEventType.USER_LOGIN,
                user_id=client_id,
                resource="relay_server",
                action="connect_client",
                details={"ip": client_addr[0], "port": client_addr[1]},
            )

            self._try_share_session_key()

            while True:
                raw_line = file_reader.readline()
                if not raw_line:
                    break

                data = json.loads(raw_line)
                if data.get("type") == "chat":
                    self.audit.log_event(
                        AuditEventType.MESSAGE_SENT,
                        user_id=client_id,
                        resource="relay_server",
                        action="receive_encrypted_message",
                        details={"sender": client_id},
                    )
                    self._relay_message(client_id, data)

        except Exception as exc:
            self.audit.log_event(
                AuditEventType.SYSTEM_ERROR,
                user_id=client_id or "unknown",
                resource="relay_server",
                action="handle_client",
                result="failed",
                details={"error": str(exc)},
            )
        finally:
            if client_id:
                with self.clients_lock:
                    self.clients.pop(client_id, None)
                    self.shared_session_key = None
            try:
                file_reader.close()
            except Exception:
                pass
            try:
                client_sock.close()
            except Exception:
                pass

    def start(self) -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)

        print(f"[START] Server đang lắng nghe tại {self.host}:{self.port}")
        while True:
            client_sock, client_addr = server_sock.accept()
            thread = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
            thread.start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Relay server for 2 encrypted clients")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind")
    args = parser.parse_args()

    server = RelayServer(args.host, args.port)
    server.start()


if __name__ == "__main__":
    main()
