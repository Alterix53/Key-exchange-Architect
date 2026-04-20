"""
Terminal relay server for 2 encrypted clients.
Sử dụng PKI với X.509 v3 certificates (Section 14.4 + 14.5).
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
from src.public_key_distribution import (
    CertificateAuthority, PKISystem, create_csr,
    load_csr_from_pem, serialize_cert_to_pem,
    verify_certificate_chain, print_cert_info, _get_cn,
)


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

        # === PKI System (Section 14.5) ===
        self.ca = CertificateAuthority()
        self.pki = self.ca.pki  # Access full PKI system

        # === Server Certificate (mutual auth) ===
        self._setup_server_cert()

    def _setup_server_cert(self):
        """Tạo certificate cho server (mutual authentication)."""
        server_cert_path = os.path.join(self.pki.data_dir, "server_cert.pem")
        server_key_path = os.path.join(self.pki.data_dir, "server_private.pem")

        if os.path.exists(server_cert_path) and os.path.exists(server_key_path):
            from src.public_key_distribution import load_cert_from_pem_file
            self.server_cert = load_cert_from_pem_file(server_cert_path)
            with open(server_key_path, "rb") as f:
                self.server_private_key = serialization.load_pem_private_key(f.read(), password=None)
            print("[Server] Đã tải Server Certificate từ disk.")
        else:
            # Sinh key pair + CSR cho server
            self.server_private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
            csr = create_csr("relay-server", "IAM Security System", self.server_private_key)

            # RA xử lý CSR → Intermediate CA cấp cert
            self.server_cert = self.pki.issue_cert_from_csr(csr, is_server=True)

            # Persist
            from src.public_key_distribution import _save_private_key, _save_certificate
            _save_private_key(self.server_private_key, server_key_path)
            _save_certificate(self.server_cert, server_cert_path)
            print("[Server] Đã tạo Server Certificate mới.")

        print_cert_info(self.server_cert, "Server Certificate")

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
            # Hỗ trợ cả CSR flow mới và public_key flow cũ
            csr_pem = hello.get("csr_pem", "")
            public_key_pem = hello.get("public_key", "")

            if not client_id:
                send_json(client_sock, {"type": "error", "message": "Missing client_id"})
                return

            if not csr_pem and not public_key_pem:
                send_json(client_sock, {"type": "error", "message": "Missing csr_pem or public_key"})
                return

            with self.clients_lock:
                if len(self.clients) >= 2:
                    send_json(client_sock, {"type": "error", "message": "Server only supports 2 clients"})
                    return
                if client_id in self.clients:
                    send_json(client_sock, {"type": "error", "message": "client_id already connected"})
                    return

            # === Xử lý CSR hoặc public_key ===
            if csr_pem:
                # New flow: CSR → RA → Intermediate CA → cert
                csr = load_csr_from_pem(csr_pem)
                public_key = csr.public_key()

                self.audit.log_event(
                    AuditEventType.CERT_CSR_RECEIVED,
                    user_id=client_id,
                    resource="pki",
                    action="receive_csr",
                    details={"subject": _get_cn(csr.subject)},
                )

                # RA xử lý CSR
                client_cert = self.pki.issue_cert_from_csr(csr, is_server=False)
                if client_cert is None:
                    send_json(client_sock, {"type": "error", "message": "CSR rejected by RA"})
                    self.audit.log_event(
                        AuditEventType.CERT_VERIFICATION_FAILED,
                        user_id=client_id, resource="pki",
                        action="csr_rejected", result="failed",
                    )
                    return

                # Lấy cert chain
                cert_chain_pems = self.pki.get_cert_chain_pems(client_cert)
                crls_pem = self.pki.get_all_crls_pem()

                self.audit.log_event(
                    AuditEventType.CERT_ISSUED,
                    user_id=client_id, resource="pki",
                    action="issue_certificate",
                    details={"serial": format(client_cert.serial_number, "x")[:16]},
                )

                # Gửi cert chain + server cert chain cho client (mutual auth)
                server_chain_pems = self.pki.get_cert_chain_pems(self.server_cert)
                conn_payload = {
                    "type": "welcome",
                    "client_cert_chain": cert_chain_pems,
                    "server_cert_chain": server_chain_pems,
                    "root_ca_pem": self.pki.root_ca.get_cert_pem(),
                    "crls_pem": crls_pem,
                }

            else:
                # Legacy flow: public_key → backward compat
                public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
                cert_dict = self.ca.issue_certificate(client_id, public_key_pem)

                conn_payload = {
                    "type": "cert",
                    "certificate": cert_dict,
                }

            conn = ClientConnection(
                client_id=client_id, sock=client_sock,
                file_reader=file_reader, public_key=public_key,
            )

            with self.clients_lock:
                self.clients[client_id] = conn

            conn.send(conn_payload)
            print(f"[CERT] Certificate đã cấp cho {client_id}")

            self.audit.log_event(
                AuditEventType.USER_LOGIN,
                user_id=client_id,
                resource="relay_server",
                action="connect_client",
                details={"ip": client_addr[0], "port": client_addr[1]},
            )

            # Thông báo peer connected
            with self.clients_lock:
                if len(self.clients) == 2:
                    client_ids = list(self.clients.keys())
                    self.clients[client_ids[0]].send({"type": "peer_joined", "peer_id": client_ids[1], "initiator": True})
                    self.clients[client_ids[1]].send({"type": "peer_joined", "peer_id": client_ids[0], "initiator": False})

            while True:
                raw_line = file_reader.readline()
                if not raw_line:
                    break

                data = json.loads(raw_line)

                # API: Request Certificate theo username
                if data.get("type") == "cert_request":
                    target_id = data.get("target_id")
                    target_cert = self.ca.get_certificate(target_id)
                    if target_cert:
                        conn.send({"type": "cert_response", "target_id": target_id, "certificate": target_cert})
                        print(f"[SERVER] Đã trả Certificate chain của {target_id} cho {client_id}")
                    else:
                        conn.send({"type": "error", "message": "Certificate not found"})

                # API: Directory Request
                elif data.get("type") == "directory_request":
                    users = list(self.ca.cert_repository.keys())
                    conn.send({"type": "directory_response", "users": users})

                # API: CRL Request (Section 14.5)
                elif data.get("type") == "crl_request":
                    crls_pem = self.pki.get_all_crls_pem()
                    conn.send({"type": "crl_response", "crls_pem": crls_pem})
                    print(f"[SERVER] Đã gửi CRL cho {client_id}")

                # API: Revocation Request (Section 14.5)
                elif data.get("type") == "revoke_request":
                    target_id = data.get("target_id")
                    success = self.pki.revoke(target_id)
                    conn.send({"type": "revoke_response", "target_id": target_id, "success": success})
                    if success:
                        self.audit.log_event(
                            AuditEventType.CERT_REVOKED,
                            user_id=client_id, resource="pki",
                            action="revoke_certificate",
                            details={"revoked_subject": target_id},
                        )

                # Relay session key
                elif data.get("type") == "relay_session_key":
                    target_id = data.get("target_id")
                    if target_id in self.clients:
                        self.clients[target_id].send(data)
                        print(f"[SERVER] Đã chuyển tiếp session_key từ {client_id} sang {target_id}")

                # Chat message
                elif data.get("type") == "chat":
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

        print(f"\n[START] Server đang lắng nghe tại {self.host}:{self.port}")
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
