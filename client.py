"""
Terminal client for encrypted relay chat.
Sử dụng X.509 certificate chain validation (Section 14.4 + 14.5).
"""

import argparse
import base64
import json
import socket
import threading
import os
from datetime import datetime
from typing import Any, Dict, Optional, List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.secure_transmission import SecureTransmissionChannel
from src.public_key_distribution import (
    create_csr, serialize_csr_to_pem,
    verify_certificate_chain, check_revocation,
    load_cert_from_pem, print_cert_info, _get_cn,
    verify_certificate, extract_public_key,
)


def send_json(sock: socket.socket, payload: Dict[str, Any]) -> None:
    data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    sock.sendall(data)


class RelayClient:
    def __init__(self, client_id: str, host: str, port: int):
        self.client_id = client_id
        self.host = host
        self.port = port
        self.channel = SecureTransmissionChannel()

        # Sinh RSA key pair
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        # Tạo CSR (Certificate Signing Request) — Section 14.5
        self.csr = create_csr(client_id, "IAM Security System", self.private_key)
        print(f"[INIT] Đã tạo CSR cho: {client_id}")

        self.sock: Optional[socket.socket] = None
        self.reader = None
        self.running = True
        self.session_key: Optional[bytes] = None
        self._send_lock = threading.Lock()

        # PKI-related state
        self.peer_id: Optional[str] = None
        self.peer_public_key: Any = None
        self.my_cert_chain: Optional[List[str]] = None
        self.root_ca_pem: Optional[str] = None
        self.crls_pem: Optional[List[str]] = None

        # Load Pinned Root CA cert (trust anchor — Section 14.5 Initialization)
        ca_cert_path = "data/root_ca_cert.pem"
        if os.path.exists(ca_cert_path):
            with open(ca_cert_path, "r") as f:
                self.trusted_root_pem = f.read()
            print("[INIT] Đã tải Pinned Root CA Certificate (trust anchor).")
        else:
            # Fallback: thử load old format
            old_ca_path = "data/ca_public.pem"
            if os.path.exists(old_ca_path):
                with open(old_ca_path, "r") as f:
                    self.trusted_root_pem = f.read()
                print("[INIT] Đã tải CA Public Key (legacy format).")
            else:
                # Server chưa chạy lần nào → sẽ nhận Root CA cert từ server
                self.trusted_root_pem = None
                print("[INIT] ⚠ Chưa có Root CA cert local. Sẽ nhận từ server (first-time setup).")

    def _csr_pem(self) -> str:
        return serialize_csr_to_pem(self.csr)

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

        # === Gửi CSR thay vì raw public key ===
        send_json(
            self.sock,
            {
                "type": "hello",
                "client_id": self.client_id,
                "csr_pem": self._csr_pem(),
                "public_key": self._public_key_pem(),  # backward compat
            },
        )
        print(f"[STATUS] Đã gửi CSR cho server.")

        while self.session_key is None:
            packet = self._recv_json()
            if packet is None:
                raise ConnectionError("Server closed connection during handshake")

            packet_type = packet.get("type")
            if packet_type == "error":
                raise RuntimeError(packet.get("message", "Server error"))

            # === New flow: nhận welcome với cert chains ===
            if packet_type == "welcome":
                self._handle_welcome(packet)
                continue

            # Legacy flow: nhận cert dict
            if packet_type == "cert":
                cert = packet.get("certificate", {})
                print(f"[STATUS] Đã nhận Certificate (legacy format).")
                continue

            # Peer joined
            if packet_type == "peer_joined":
                self.peer_id = packet.get("peer_id")
                initiator = packet.get("initiator")
                if initiator:
                    send_json(self.sock, {"type": "cert_request", "target_id": self.peer_id})
                    print(f"[STATUS] Đang yêu cầu Certificate chain của {self.peer_id}...")
                else:
                    print(f"[STATUS] Đang chờ initiator {self.peer_id} thiết lập kết nối...")
                continue

            # Nhận certificate response
            if packet_type == "cert_response":
                self._handle_cert_response(packet)
                continue

            # Nhận session key
            if packet_type == "relay_session_key":
                encrypted_key = packet.get("encrypted_key", "")
                key_b64 = self.channel.decrypt_rsa_oaep(encrypted_key, self.private_key)
                self.session_key = base64.b64decode(key_b64)
                print("[STATUS] ✓ Đã giải mã Session key từ peer. End-to-End ESTABLISHED.")

    def _handle_welcome(self, packet: Dict):
        """
        Xử lý welcome message từ server (new PKI flow).
        Bao gồm: client cert chain + server cert chain + root CA + CRLs.
        """
        self.my_cert_chain = packet.get("client_cert_chain", [])
        server_chain_pems = packet.get("server_cert_chain", [])
        root_ca_pem = packet.get("root_ca_pem", "")
        self.crls_pem = packet.get("crls_pem", [])

        # Lưu root CA cert nếu chưa có (first-time initialization — Section 14.5)
        if root_ca_pem:
            if self.trusted_root_pem is None:
                self.trusted_root_pem = root_ca_pem
                # Persist root CA cert
                os.makedirs("data", exist_ok=True)
                with open("data/root_ca_cert.pem", "w") as f:
                    f.write(root_ca_pem)
                print("[PKI] Đã lưu Root CA cert (Initialization — Section 14.5)")
            self.root_ca_pem = root_ca_pem

        # === Verify Server Certificate Chain (Mutual Authentication) ===
        if server_chain_pems and self.trusted_root_pem:
            print("\n[PKI] === VERIFY SERVER CERTIFICATE CHAIN ===")
            is_valid, msg = verify_certificate_chain(
                server_chain_pems, self.trusted_root_pem, self.crls_pem
            )
            if not is_valid:
                raise RuntimeError(f"Server certificate chain không hợp lệ: {msg}")

            server_cert = load_cert_from_pem(server_chain_pems[0])
            print_cert_info(server_cert, "Server Certificate (đã verify)")
            print(f"[PKI] ✓ Server certificate chain hợp lệ — Mutual Auth thành công!")
        else:
            print("[PKI] ⚠ Bỏ qua server cert verification (legacy mode)")

        # In thông tin client certificate
        if self.my_cert_chain:
            my_cert = load_cert_from_pem(self.my_cert_chain[0])
            print_cert_info(my_cert, "My Certificate (được CA cấp)")
            print(f"[STATUS] ✓ Đã nhận certificate chain ({len(self.my_cert_chain)} certs)")

    def _handle_cert_response(self, packet: Dict):
        """
        Xử lý cert response: verify certificate chain của peer.
        """
        cert_data = packet.get("certificate", {})
        target_id = packet.get("target_id", "")
        print(f"\n[PKI] === VERIFY PEER CERTIFICATE: {target_id} ===")

        # Thử new flow trước (chain_pems)
        chain_pems = cert_data.get("chain_pems")
        crls_pem = cert_data.get("crls_pem", self.crls_pem)

        if chain_pems and self.trusted_root_pem:
            # === X.509 Certificate Chain Validation (Section 14.4) ===
            is_valid, msg = verify_certificate_chain(
                chain_pems, self.trusted_root_pem, crls_pem
            )
            if not is_valid:
                print(f"[PKI] ❌ Certificate chain không hợp lệ: {msg}")
                raise RuntimeError(f"Invalid peer certificate chain — {msg}")

            # Kiểm tra subject khớp peer_id
            leaf_cert = load_cert_from_pem(chain_pems[0])
            leaf_cn = _get_cn(leaf_cert.subject)
            if leaf_cn != self.peer_id:
                print(f"[PKI] ❌ Subject mismatch: cert CN={leaf_cn}, expected={self.peer_id}")
                raise RuntimeError("Certificate subject does not match peer identity!")

            # Kiểm tra CRL (revocation check — Section 14.5)
            if crls_pem:
                is_revoked, rev_msg = check_revocation(chain_pems[0], crls_pem)
                if is_revoked:
                    print(f"[PKI] ❌ Peer certificate đã bị thu hồi: {rev_msg}")
                    raise RuntimeError(f"Peer certificate revoked: {rev_msg}")
                print(f"[PKI] ✓ CRL check passed — certificate chưa bị thu hồi")

            print_cert_info(leaf_cert, f"Peer Certificate: {target_id} (đã verify chain)")
            print(f"[PKI] ✓ Certificate chain hợp lệ cho: {target_id}")

            self.peer_public_key = leaf_cert.public_key()

        else:
            # Legacy flow
            ca_pub = self.trusted_root_pem or ""
            is_valid = verify_certificate(cert_data, ca_pub, expected_subject=self.peer_id)
            if not is_valid:
                raise RuntimeError("Invalid peer certificate!")
            self.peer_public_key = extract_public_key(cert_data)

        # === Tạo và gửi session key (RSA-OAEP hybrid encryption) ===
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
        print("[STATUS] ✓ Đã tạo và gửi AES-256 session key (mã hóa bằng RSA-OAEP).")

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
                    elif packet.get("type") == "crl_response":
                        crls = packet.get("crls_pem", [])
                        print(f"\n[CRL] Đã nhận {len(crls)} CRL từ server.")
                        self.crls_pem = crls
                    elif packet.get("type") == "revoke_response":
                        success = packet.get("success", False)
                        target = packet.get("target_id", "?")
                        if success:
                            print(f"\n[PKI] ✓ Đã thu hồi certificate của {target}")
                        else:
                            print(f"\n[PKI] ❌ Không thể thu hồi certificate của {target}")
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

        print("\n" + "=" * 50)
        print("  Commands: gõ tin nhắn để chat")
        print("  list_users  — xem danh sách users trong PKI")
        print("  get_crl     — lấy CRL mới nhất")
        print("  quit/exit   — thoát")
        print("=" * 50 + "\n")

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

            if message.strip().lower() == "get_crl":
                if self.sock:
                    with self._send_lock:
                        send_json(self.sock, {"type": "crl_request"})
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
