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
from src.public_key_distribution import CertificateAuthority


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

        # [MODIFIED] Sử dụng CertificateAuthority từ module public_key_distribution thay vì hardcode
        self.ca = CertificateAuthority()

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

            # [MODIFIED] Cấp phát chứng chỉ và lưu trong repository của CA (Bao gồm đồng bộ xuống Disk)
            cert = self.ca.issue_certificate(client_id, public_key_pem)
            conn.send({"type": "cert", "certificate": cert})
            print(f"[CERT] Certificate đã cấp cho {client_id}")

            self.audit.log_event(
                AuditEventType.USER_LOGIN,
                user_id=client_id,
                resource="relay_server",
                action="connect_client",
                details={"ip": client_addr[0], "port": client_addr[1]},
            )

            # [MODIFIED] Thông báo peer connected để Client tự request certificate thay vì Server chia sẻ key
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
                
                # [NEW] API Request Certificate theo username
                if data.get("type") == "cert_request":
                    target_id = data.get("target_id")
                    target_cert = self.ca.get_certificate(target_id)
                    if target_cert:
                        conn.send({"type": "cert_response", "target_id": target_id, "certificate": target_cert})
                        print(f"[SERVER] Đã trả Certificate của {target_id} cho {client_id}")
                    else:
                        conn.send({"type": "error", "message": "Certificate not found"})
                        
                # [NEW] API Directory Request (Xem danh sách user đã đăng ký)
                elif data.get("type") == "directory_request":
                    users = list(self.ca.cert_repository.keys())
                    conn.send({"type": "directory_response", "users": users})
                    
                # [NEW] Chuyển tiếp session key từ initiator sang peer
                elif data.get("type") == "relay_session_key":
                    target_id = data.get("target_id")
                    if target_id in self.clients:
                        self.clients[target_id].send(data)
                        print(f"[SERVER] Đã chuyển tiếp session_key từ {client_id} sang {target_id}")

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
