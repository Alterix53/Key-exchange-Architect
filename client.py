"""
Terminal client for encrypted relay chat.
"""

import argparse
import base64
import json
import socket
import threading
import os
from datetime import datetime
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.secure_transmission import SecureTransmissionChannel


def send_json(sock: socket.socket, payload: Dict[str, Any]) -> None:
    data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    sock.sendall(data)


class RelayClient:
    def __init__(self, client_id: str, host: str, port: int):
        self.client_id = client_id
        self.host = host
        self.port = port
        self.channel = SecureTransmissionChannel()

        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        self.sock: Optional[socket.socket] = None
        self.reader = None
        self.running = True
        self.session_key: Optional[bytes] = None
        self._send_lock = threading.Lock()
        
        # [NEW] Các biến dùng cho quá trình phân phối khóa công khai
        self.peer_id: Optional[str] = None
        self.peer_public_key: Any = None
        
        # Load Pinned CA Public Key (Fail closed if not exists)
        ca_cert_path = "data/ca_public.pem"
        if not os.path.exists(ca_cert_path):
            raise FileNotFoundError(f"Pinned CA public key not found at {ca_cert_path}. System is failing closed.")
        with open(ca_cert_path, "r") as f:
            self.ca_public_key_pem = f.read()
        print("[INIT] Đã tải thành công Pinned CA Public Key cục bộ.")

    def _public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def _recv_json(self) -> Optional[Dict[str, Any]]:
        if isinstance(self.reader, type(None)):
            return None
        line = self.reader.readline()
        if not line:
            return None
        return json.loads(line)

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.reader = self.sock.makefile("r", encoding="utf-8")

        send_json(
            self.sock,
            {
                "type": "hello",
                "client_id": self.client_id,
                "public_key": self._public_key_pem(),
            },
        )

        while self.session_key is None:
            packet = self._recv_json()
            if packet is None:
                raise ConnectionError("Server closed connection during handshake")

            packet_type = packet.get("type")
            if packet_type == "error":
                raise RuntimeError(packet.get("message", "Server error"))

            if packet_type == "cert":
                cert = packet.get("certificate", "")
                print(f"[STATUS] Đã nhận Certificate của chính mình từ Server.")
                continue
                
            # [NEW] Lắng nghe sự kiện đối tác kết nối
            if packet_type == "peer_joined":
                self.peer_id = packet.get("peer_id")
                initiator = packet.get("initiator")
                if initiator:
                    # Gửi yêu cầu lấy certificate của peer
                    send_json(self.sock, {"type": "cert_request", "target_id": self.peer_id})
                    print(f"[STATUS] Đang yêu cầu Certificate của {self.peer_id}...")
                else:
                    print(f"[STATUS] Đang chờ initiator {self.peer_id} thiết lập kết nối...")
                continue
                
            # [NEW] Nhận certificate của peer từ CA (Server) và verify
            if packet_type == "cert_response":
                cert = packet.get("certificate")
                print(f"[STATUS] Đã nhận Certificate của {packet.get('target_id')}")
                
                from src.public_key_distribution import verify_certificate, extract_public_key
                import os
                
                # Verify Certificate với identity ràng buộc (expected_subject)
                is_valid = verify_certificate(cert, self.ca_public_key_pem, expected_subject=self.peer_id)
                if not is_valid:
                    print("[ERROR] Certificate không hợp lệ! Từ chối kết nối.")
                    raise RuntimeError("Invalid peer certificate - Có thể bị MITM hoặc chứng chỉ không hợp lệ!")
                
                print("[STATUS] Certificate hợp lệ. Trích xuất public key thành công.")
                self.peer_public_key = extract_public_key(cert)
                
                # Client A sử dụng RSA Public Key của Client B để gửi Session Key (End-to-End Key Exchange)
                self.session_key = os.urandom(32)
                
                encrypted_key = self.channel.encrypt_rsa_oaep(
                    base64.b64encode(self.session_key).decode("utf-8"), 
                    self.peer_public_key
                )
                
                send_json(self.sock, {
                    "type": "relay_session_key", 
                    "target_id": self.peer_id, 
                    "encrypted_key": encrypted_key
                })
                print("[STATUS] Đã tạo và gửi AES session key cho peer thông qua RSA mã hóa.")
                continue

            # [MODIFIED] Xử lý nhận session_key trực tiếp từ peer (không phải từ Server chia sẻ nữa)
            if packet_type == "relay_session_key":
                encrypted_key = packet.get("encrypted_key", "")
                key_b64 = self.channel.decrypt_rsa_oaep(encrypted_key, self.private_key)
                self.session_key = base64.b64decode(key_b64)
                print("[STATUS] Đã giải mã thành công Session key nhận được từ peer. Kết nối End-to-End ESTABLISHED.")

    def _receive_loop(self) -> None:
        while self.running:
            try:
                packet = self._recv_json()
                if packet is None:
                    print("[STATUS] Kết nối bị đóng bởi Server.")
                    self.running = False
                    break

                if packet.get("type") != "relay":
                    if packet.get("type") == "directory_response":
                        users = packet.get("users", [])
                        print("\n--- [DIRECTORY] Danh sách users có trong PKI Repository ---")
                        for u in users:
                            print(f" - {u}")
                        print("----------------------------------------------------------\n")
                    continue

                encrypted_view = {
                    "nonce": packet.get("nonce", ""),
                    "ciphertext": packet.get("ciphertext", ""),
                    "tag": packet.get("tag", ""),
                }
                print(f"[RECEIVED] Tin nhắn mã hóa nhận được: {json.dumps(encrypted_view, ensure_ascii=False)}")

                session_key = self.session_key
                if session_key is None:
                    print("[STATUS] Chưa có session key để giải mã.")
                    self.running = False
                    break

                plaintext = self.channel.decrypt_aes_256_gcm(
                    packet.get("nonce", ""),
                    packet.get("ciphertext", ""),
                    packet.get("tag", ""),
                    session_key,
                    packet.get("associated_data", ""),
                )
                print(f"[DECRYPT] Tin nhắn sau khi giải mã: {plaintext}")
            except Exception as exc:
                print(f"[STATUS] Lỗi nhận/giải mã: {exc}")
                self.running = False
                break

    def _send_chat(self, plaintext: str) -> None:
        if not self.session_key:
            raise RuntimeError("Session key chưa sẵn sàng")

        associated_data = f"{self.client_id}:relay"
        nonce, ciphertext, tag = self.channel.encrypt_aes_256_gcm(
            plaintext,
            self.session_key,
            associated_data,
        )

        print(f"[INPUT] Tin nhắn ban đầu: {plaintext}")
        print(f"[ENCRYPT] Tin nhắn sau khi mã hóa: {json.dumps({'nonce': nonce, 'ciphertext': ciphertext, 'tag': tag}, ensure_ascii=False)}")

        payload = {
            "type": "chat",
            "sender_id": self.client_id,
            "algorithm": "AES-256-GCM",
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag,
            "associated_data": associated_data,
            "timestamp": datetime.now().isoformat(),
        }
        if self.sock is None:
            raise RuntimeError("Socket chưa được khởi tạo")
        with self._send_lock:
            send_json(self.sock, payload)

    def run(self) -> None:
        self.connect()

        receiver = threading.Thread(target=self._receive_loop, daemon=True)
        receiver.start()

        while self.running:
            try:
                message = input("")
            except EOFError:
                break
            except KeyboardInterrupt:
                break

            if not message.strip():
                continue
            if message.strip().lower() in {"quit", "exit"}:
                self.running = False
                break
            
            if message.strip().lower() == "list_users":
                if self.sock:
                    with self._send_lock:
                        send_json(self.sock, {"type": "directory_request"})
                continue

            self._send_chat(message)

        self.running = False
        try:
            if self.sock is not None:
                self.sock.close()
        except Exception:
            pass
        try:
            if self.reader is not None:
                self.reader.close()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted terminal client")
    parser.add_argument("--name", required=True, help="Client ID")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=5000, help="Server port")
    args = parser.parse_args()

    client = RelayClient(client_id=args.name, host=args.host, port=args.port)
    client.run()


if __name__ == "__main__":
    main()
