"""
CLI Interactive Client for IAM Backend Server
"""

import argparse
import base64
import json
import socket
import threading
import os
import sys
import time
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, List, Tuple

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from src.audit_logging import AuditLogger
from src.secure_transmission import SecureTransmissionChannel, ReplayProtector
from src.public_key_distribution import (
    verify_certificate_chain,
    create_csr,
    serialize_csr_to_pem,
    load_cert_from_pem,
)
from src.kdc import KDC
from src.secure_transmission import encrypt_json_with_key, decrypt_json_with_key


CA_PULLIC_KEY_SRC = "pki/root/certs/root.crt"

# Private key directories
KEYSTORE_DIR    = os.path.join("data", "client_keystore")   # {KEYSTORE_DIR}/{user_id}/identity/identity_key_v{N}.pem  — encrypted

# ANSI Colors
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_success(msg: str):
    print(f"{Colors.OKGREEN}✓ {msg}{Colors.ENDC}")

def print_error(msg: str):
    print(f"{Colors.FAIL}✗ {msg}{Colors.ENDC}")

def print_header(msg: str):
    print(f"\n{Colors.OKCYAN}{Colors.BOLD}--- {msg} ---{Colors.ENDC}")


class IAMDemoClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.reader = None
        self.session_id: Optional[str] = None
        self.user_info: Optional[Dict] = None

        # Local keystore passphrase policy: reuse login password (in-memory only)
        self._keystore_passphrase: Optional[str] = None
        self._ks_name: str = ""  # set at login: username (or user_id fallback)

        # Crypto
        self.channel = SecureTransmissionChannel()
        self.replay_protector = ReplayProtector(time_window_seconds=30)

        # NOTE: This keypair is used for the initial mutual-auth/login proof.
        # The CSR/certificate identity key is loaded from the client keystore after login.
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        # E2E Chat state
        self.in_chat_mode = False
        self.chat_peer_id: Optional[str] = None
        self.chat_session_key: Optional[bytes] = None
        self.chat_session_expires_at: Optional[datetime] = None
        self.chat_peer_public_key: Any = None
        self.ca_public_key_pem: Optional[str] = None
        self.server_public_key: Any = None
        self.server_nonce: Optional[str] = None
        self.pending_login_nonce: Optional[str] = None
        self.client_cert_chain: Optional[List[str]] = None
        self.current_crls: List[str] = []

        # E2E Chat invite/accept handshake state
        self.pending_chat_invite: Optional[Dict] = None
        self.pending_ticket: Optional[str] = None
        self.pending_ticket_id: Optional[str] = None
        self._chat_ready_event = threading.Event()
        self._chat_accepted = False

        self._receive_thread = None
        self._running = False
        
        # Async responses routing
        self.pending_responses: Dict[str, Dict] = {}
        self._response_cv = threading.Condition()

        # Audit: SQL Server only (same connection as configured in src.db)
        self.audit_logger = AuditLogger("demo_audit")

    def _public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def _extract_cn_from_cert_pem(self, cert_pem: str) -> str:
        cert = load_cert_from_pem(cert_pem)
        for attr in cert.subject:
            if getattr(attr.oid, "_name", "") == "commonName":
                return attr.value
        return "Unknown"

    def _extract_public_key_from_chain(self, cert_chain: List[str]) -> Any:
        if not cert_chain:
            raise ValueError("Certificate chain is empty")
        leaf_cert = load_cert_from_pem(cert_chain[0])
        return leaf_cert.public_key()

    def _client_keystore_root(self) -> str:
        return KEYSTORE_DIR

    def _identity_keystore_dir(self, user_id: str) -> str:
        return os.path.join(self._client_keystore_root(), str(user_id), "identity")

    def _identity_metadata_path(self, user_id: str) -> str:
        return os.path.join(self._identity_keystore_dir(user_id), "metadata.json")

    def _identity_key_path(self, user_id: str, version: int) -> str:
        return os.path.join(self._identity_keystore_dir(user_id), f"identity_key_v{version}.pem")

    def _load_identity_metadata(self, user_id: str) -> Dict[str, Any]:
        meta_path = self._identity_metadata_path(user_id)
        if not os.path.exists(meta_path):
            return {
                "active_version": 0,
                "algorithm": "RSA",
                "key_size": 2048,
                "created_at": None,
                "rotated_at": None,
            }
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_identity_metadata(self, user_id: str, meta: Dict[str, Any]) -> None:
        os.makedirs(self._identity_keystore_dir(user_id), exist_ok=True)
        with open(self._identity_metadata_path(user_id), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)

    def _archive_dir(self, user_id: str) -> str:
        return os.path.join(self._client_keystore_root(), str(user_id), "archive")

    def _cleanup_old_identity_keys(self, user_id: str, keep_version: int) -> None:
        """Archive old identity keys instead of deleting.

        Old private keys are moved to archive/ so encrypted data from previous
        key versions can still be decrypted. Active key stays in identity/.
        """
        ks_dir = self._identity_keystore_dir(user_id)
        archive_dir = self._archive_dir(user_id)
        keep_name = f"identity_key_v{int(keep_version)}.pem"
        archived = []

        try:
            for name in os.listdir(ks_dir):
                if not (name.startswith("identity_key_v") and name.endswith(".pem")):
                    continue
                if name == keep_name:
                    continue
                src = os.path.join(ks_dir, name)
                os.makedirs(archive_dir, exist_ok=True)
                dst = os.path.join(archive_dir, name)
                try:
                    os.rename(src, dst)
                    archived.append(name)
                except Exception as e:
                    print(f"{Colors.WARNING}[KEYSTORE] ⚠ Không thể archive key '{name}': {e}{Colors.ENDC}")
        except FileNotFoundError:
            return

        if archived:
            # Ghi metadata cho archive
            meta_path = os.path.join(archive_dir, "archive_metadata.json")
            archive_meta = {}
            if os.path.exists(meta_path):
                with open(meta_path, "r", encoding="utf-8") as f:
                    archive_meta = json.load(f)
            for name in archived:
                v = name.replace("identity_key_v", "").replace(".pem", "")
                archive_meta[f"v{v}"] = {
                    "filename": name,
                    "archived_at": datetime.now().isoformat(),
                    "reason": "superseded_by_new_key",
                }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(archive_meta, f, indent=2, ensure_ascii=False)
            print(f"{Colors.OKCYAN}[KEY ROTATE] Archived old keys: {', '.join(archived)}{Colors.ENDC}")

    def _load_or_create_identity_key(self, user_id: str, passphrase: str) -> Tuple[Any, int, bool]:
        """Load active identity key from client keystore.

        Returns:
            (private_key_obj, active_version, created_new)
        """
        if not passphrase:
            raise ValueError("Thiếu passphrase để mở keystore (password đăng nhập).")

        os.makedirs(self._identity_keystore_dir(user_id), exist_ok=True)
        meta = self._load_identity_metadata(user_id)
        active_v = int(meta.get("active_version") or 0)

        if active_v > 0:
            key_path = self._identity_key_path(user_id, active_v)
            if os.path.exists(key_path):
                try:
                    with open(key_path, "rb") as f:
                        key_bytes = f.read()
                    priv = serialization.load_pem_private_key(
                        key_bytes,
                        password=passphrase.encode("utf-8"),
                        backend=default_backend(),
                    )
                    return priv, active_v, False
                except Exception as e:
                    print(f"{Colors.WARNING}[KESTORE] ⚠ Không mở được identity key v{active_v} (có thể do đổi password). Sẽ tạo key mới. Lỗi: {e}{Colors.ENDC}")

        # Create brand-new identity key (rotate-from-zero or recovery)
        new_v = active_v + 1
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        enc = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        key_path = self._identity_key_path(user_id, new_v)
        with open(key_path, "wb") as f:
            f.write(pem)

        print(f"{Colors.OKCYAN}[KEYSTORE] Identity key lưu tại: {key_path} (encrypted bằng login password){Colors.ENDC}")

        now = datetime.now().isoformat()
        meta.update({
            "active_version": new_v,
            "algorithm": "RSA",
            "key_size": 2048,
            "created_at": meta.get("created_at") or now,
            "rotated_at": now,
        })
        self._save_identity_metadata(user_id, meta)
        self._cleanup_old_identity_keys(user_id, keep_version=new_v)

        return priv, new_v, True

    def _rotate_identity_key(self, user_id: str, passphrase: str) -> Tuple[Any, int]:
        """Hard rotate: generate a completely new key and mark it active."""
        meta = self._load_identity_metadata(user_id)
        old_v = int(meta.get("active_version") or 0)
        new_v = old_v + 1

        os.makedirs(self._identity_keystore_dir(user_id), exist_ok=True)

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        enc = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        key_path = self._identity_key_path(user_id, new_v)
        with open(key_path, "wb") as f:
            f.write(pem)

        now = datetime.now().isoformat()
        meta.update({
            "active_version": new_v,
            "algorithm": "RSA",
            "key_size": 2048,
            "created_at": meta.get("created_at") or now,
            "rotated_at": now,
        })
        self._save_identity_metadata(user_id, meta)
        self._cleanup_old_identity_keys(user_id, keep_version=new_v)

        print(f"{Colors.OKCYAN}[KEY ROTATE] Created new key (discarded old). v{old_v} -> v{new_v}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[KEY ROTATE] Identity key lưu tại: {key_path} (encrypted bằng login password){Colors.ENDC}")

        return priv, new_v

    def _perform_hello_csr(self) -> bool:
        """hello {CSR} -> welcome {client_cert_chain, server_cert_chain}."""
        if not self.user_info:
            print_error("Thiếu thông tin user để tạo CSR.")
            return False
        if not self.ca_public_key_pem:
            print_error("Thiếu trusted root certificate để verify chain.")
            return False

        user_id = self.user_info.get("user_id")
        if not user_id:
            print_error("Thiếu user_id để ràng buộc subject của CSR.")
            return False

        csr = create_csr(user_id, "IAM Security System", self.private_key)
        print(f"{Colors.OKCYAN}[CSR] → Đang gửi CSR (key hiện tại trong keystore) để xin certificate mới...{Colors.ENDC}")
        res = self._sync_request(
            {
                "type": "hello",
                "csr_pem": serialize_csr_to_pem(csr),
            },
            "welcome"
        )
        if not res:
            return False

        client_cert_chain = res.get("client_cert_chain") or []
        server_cert_chain = res.get("server_cert_chain") or []
        crls = res.get("crls") or []

        if not client_cert_chain or not server_cert_chain:
            print_error("welcome payload thiếu certificate chain.")
            return False

        server_valid, server_msg = verify_certificate_chain(
            server_cert_chain,
            self.ca_public_key_pem,
            crl_pems=crls,
        )
        if not server_valid:
            print_error(f"Server chain không hợp lệ: {server_msg}")
            return False

        if self._extract_cn_from_cert_pem(server_cert_chain[0]) != "IAM-Server":
            print_error("Server leaf certificate subject không phải IAM-Server.")
            return False

        client_valid, client_msg = verify_certificate_chain(
            client_cert_chain,
            self.ca_public_key_pem,
            crl_pems=crls,
        )
        if not client_valid:
            print_error(f"Client chain không hợp lệ: {client_msg}")
            return False

        if self._extract_cn_from_cert_pem(client_cert_chain[0]) != user_id:
            print_error("Client certificate subject không khớp user_id hiện tại.")
            return False

        self.client_cert_chain = client_cert_chain
        self.current_crls = crls
        self.server_public_key = self._extract_public_key_from_chain(server_cert_chain)
        print_success("Hoàn tất hello/welcome với CSR và verify chain thành công.")
        return True

    def connect(self):
        try:
            # Load CA PublicKey (PINNED TRUSTED ROOT)
            ca_path = CA_PULLIC_KEY_SRC
            if os.path.exists(ca_path):
                with open(ca_path, "r", encoding="utf-8") as f:
                    self.ca_public_key_pem = f.read()
            else:
                print_error(f"LỖI: Không tìm thấy Trusted CA Root tại '{ca_path}'!")
                print_error("Hệ thống từ chối kết nối để bảo vệ khỏi MITM (Fail-Closed).")
                sys.exit(1)

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            # --- MUTUAL AUTH: XÁC THỰC SERVER TRƯỚC KHI TIẾP TỤC ---
            print(f"{Colors.OKCYAN}[MUTUAL AUTH] Đang đợi xác thực từ Server...{Colors.ENDC}")
            
            # Khởi tạo reader từ socket
            self.reader = self.sock.makefile("r", encoding="utf-8")
            
            # Set timeout ngắn để không block mãi mãi nếu không nhận được hello
            self.sock.settimeout(5.0)
            hello_line = self.reader.readline()
            self.sock.settimeout(None) # Reset timeout
            
            if not hello_line:
                print_error("LỖI: Không nhận được phản hồi từ server.")
                sys.exit(1)
                
            try:
                server_hello = json.loads(hello_line)
                if server_hello.get("type") != "server_hello" or "server_cert_chain" not in server_hello:
                    print_error("LỖI: Server protocol mismatch hoặc thiếu server_cert_chain.")
                    sys.exit(1)

                server_cert_chain = server_hello.get("server_cert_chain") or []
                server_crls = server_hello.get("crls") or []
                is_valid, verify_msg = verify_certificate_chain(
                    server_cert_chain,
                    self.ca_public_key_pem,
                    crl_pems=server_crls,
                )
                if not is_valid:
                    print_error(f"[CRITICAL] Server chain không hợp lệ: {verify_msg}")
                    sys.exit(1)

                if self._extract_cn_from_cert_pem(server_cert_chain[0]) != "IAM-Server":
                    print_error("[CRITICAL] Leaf certificate của server không có subject IAM-Server.")
                    sys.exit(1)

                self.server_nonce = server_hello.get("server_nonce")
                server_signature = server_hello.get("server_signature")
                if not self.server_nonce or not server_signature:
                    print_error("LỖI: Server hello thiếu nonce hoặc signature.")
                    sys.exit(1)

                self.current_crls = server_crls
                self.server_public_key = self._extract_public_key_from_chain(server_cert_chain)
                server_hello_message = f"{self.server_nonce}|IAM-Server"
                if not self.channel.verify_signature(server_hello_message, server_signature, self.server_public_key):
                    print_error("[CRITICAL] Server proof-of-possession không hợp lệ. Kết nối bị từ chối.")
                    sys.exit(1)
                    
                print_success("Đã xác minh chứng chỉ Server (IAM-Server) thành công! Kết nối an toàn.")
            except json.JSONDecodeError:
                print_error("LỖI: Phản hồi từ server không phải định dạng JSON.")
                sys.exit(1)
            # --- END MUTUAL AUTH ---

            # Khởi động luồng nhận dữ liệu
            self._running = True
            self._receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self._receive_thread.start()
            
        except Exception as e:
            print_error(f"Không thể kết nối đến máy chủ: {e}")
            sys.exit(1)

    def _send_req(self, req: Dict) -> None:
        if self.session_id:
            req["session_id"] = self.session_id
            
        import secrets
        if "timestamp" not in req:
            req["timestamp"] = datetime.now().isoformat()
        if "msg_nonce" not in req:
            req["msg_nonce"] = secrets.token_hex(16)
            
        data = (json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8")
        self.sock.sendall(data)

    def _sync_request(self, req: Dict, wait_for_type: str, timeout: int = 5) -> Optional[Dict]:
        """Gửi request và đợi block để nhận response (dành cho Menu flow)"""
        with self._response_cv:
            if wait_for_type in self.pending_responses:
                del self.pending_responses[wait_for_type]
            if "error" in self.pending_responses:
                del self.pending_responses["error"]

            if req:
                self._send_req(req)

            # tính thời gian chờ, timeout nếu quá lâu
            start_time = time.time()
            while time.time() - start_time < timeout:
                if wait_for_type in self.pending_responses:
                    res = self.pending_responses.pop(wait_for_type)
                    return res
                if "error" in self.pending_responses:
                    res = self.pending_responses.pop("error")
                    print_error(res.get("message", "Unknown error"))
                    return None
                self._response_cv.wait(0.1)
                
            print_error("Request timed out.")
            return None

    def _receive_loop(self):
        while self._running:

            try:
                line = self.reader.readline()
                if not line:
                    break
                    
                data = json.loads(line)
                
                # Check Anti-Replay
                if not self.replay_protector.check_replay(data.get("timestamp"), data.get("msg_nonce")):
                    print(f"\n{Colors.WARNING}[CẢNH BÁO] Đã chặn một message không hợp lệ hoặc Replay Attack từ client/server!{Colors.ENDC}")
                    continue
                    
                req_type = data.get("type", "")
                
                # Chat mode handlers
                if self.in_chat_mode:
                    if req_type == "relayed_chat_msg":
                        self._handle_chat_message(data)
                        continue

                # Chat invite/handshake handlers (work outside chat mode)
                if req_type == "peer_chat_invite":
                    if self.in_chat_mode:
                        # Đang bận chat — tự động từ chối để Initiator không chờ vô ích
                        self._send_req({
                            "type": "relay",
                            "relay_type": "chat_decline",
                            "target_id": data.get("sender_id", ""),
                        })
                        continue
                    self.pending_chat_invite = data
                    sender = data.get("sender_id", "?")
                    print(f"\n{Colors.OKCYAN}[INVITE] {sender} mời bạn chat E2E (Peer-to-peer). Chọn '5. Chế độ chat' ở menu để phản hồi.{Colors.ENDC}")
                    continue
                
                if req_type == "peer_chat_invite_kdc":
                    if self.in_chat_mode:
                        # Đang bận chat — tự động từ chối
                        self._send_req({
                            "type": "relay",
                            "relay_type": "chat_decline",
                            "target_id": data.get("sender_id", ""),
                        })
                        continue
                    
                    # Handle KDC invite - decrypt ticket and extract session key
                    ticket_enc = data.get("ticket")
                    ticket_id = data.get("ticket_id")
                    sender_id = data.get("sender_id", "?")
                    
                    if ticket_enc and ticket_id:
                        self.pending_ticket = ticket_enc
                        self.pending_ticket_id = ticket_id
                        self.chat_peer_id = sender_id
                        print(f"\n{Colors.OKCYAN}[INVITE-KDC] {sender_id} mời bạn chat E2E (via KDC). Chọn '5b. Chế độ chat KDC' ở menu để phản hồi.{Colors.ENDC}")
                    else:
                        print(f"\n{Colors.FAIL}[ERROR] KDC invite không hợp lệ từ {sender_id}{Colors.ENDC}")
                    continue

                if req_type == "peer_chat_accept" and not self.in_chat_mode:
                    self._handle_chat_accept(data)
                    continue

                if req_type == "peer_chat_accept_kdc" and not self.in_chat_mode:
                    # Alice receives confirmation that Bob accepted KDC chat
                    sender = data.get("sender_id", "?")
                    self._chat_accepted = True
                    self._chat_ready_event.set()
                    continue

                if req_type == "kdc_session_key" and not self.in_chat_mode:
                    # Bob receives session key from server after accepting
                    with self._response_cv:
                        self.pending_responses["kdc_session_key"] = data
                        self._response_cv.notify_all()
                    continue

                if req_type == "peer_chat_decline" and not self.in_chat_mode:
                    sender = data.get("sender_id", "?")
                    print(f"\n{Colors.FAIL}[CHAT] {sender} đã từ chối lời mời chat.{Colors.ENDC}")
                    self._chat_accepted = False
                    self._chat_ready_event.set()
                    continue

                if req_type == "peer_joined":
                    joined = data.get("username") or data.get("user_id") or "unknown"
                    print(f"\n{Colors.OKCYAN}[INFO] {joined} vừa online.{Colors.ENDC}")
                    continue

                # Nếu là error mà in chat mode thì in ra
                if req_type == "error" and self.in_chat_mode:
                    print(f"\n{Colors.FAIL}[LỖI] {data.get('message')}{Colors.ENDC}")
                    continue

                # Đẩy vào pending responses để sync_request xử lý
                with self._response_cv:
                    self.pending_responses[req_type] = data
                    self._response_cv.notify_all()
                    
            except Exception as e:
                # print_error(f"Receive loop error: {e}")
                break
        self._running = False

    # ------------------ CHAT FLOW HANDLERS ------------------

    def _handle_chat_message(self, data: Dict):
        try:
            if not self.chat_session_key:
                print(f"\n{Colors.WARNING}[CẢNH BÁO] Nhận được tin nhắn nhưng chưa có session key!{Colors.ENDC}")
                return
            sender = data.get("sender_id")
            nonce = data.get("nonce", "")
            ciphertext = data.get("ciphertext", "")
            tag = data.get("tag", "")
            assoc_data = data.get("associated_data", "")
            plaintext = self.channel.decrypt_aes_256_gcm(nonce, ciphertext, tag, self.chat_session_key, assoc_data)
            print(f"\n{Colors.OKBLUE}[{sender}] {plaintext}{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}[LỖI DECRYPT] {str(e)}{Colors.ENDC}")

    def _handle_chat_accept(self, data: Dict):
        """Chạy từ receive thread: Initiator nhận chat_accept từ Responder."""
        try:
            sender_id = data.get("sender_id", "")
            sender_cert_chain = data.get("sender_cert_chain")
            crls = data.get("crls") or self.current_crls
            signature = data.get("signature", "")

            if not sender_cert_chain or not signature or not sender_id:
                print(f"\n{Colors.FAIL}[CHAT ACCEPT] Thiếu cert hoặc chữ ký từ {sender_id}. Từ chối.{Colors.ENDC}")
                self._chat_accepted = False
                self._chat_ready_event.set()
                return

            if not self.ca_public_key_pem:
                print(f"\n{Colors.FAIL}[CHAT ACCEPT] Thiếu trusted CA key. Từ chối.{Colors.ENDC}")
                self._chat_accepted = False
                self._chat_ready_event.set()
                return

            is_valid, chain_msg = verify_certificate_chain(sender_cert_chain, self.ca_public_key_pem, crl_pems=crls)
            if not is_valid:
                print(f"\n{Colors.FAIL}[CHAT ACCEPT] Cert của {sender_id} không hợp lệ: {chain_msg}{Colors.ENDC}")
                self._chat_accepted = False
                self._chat_ready_event.set()
                return

            subject_cn = self._extract_cn_from_cert_pem(sender_cert_chain[0])
            if subject_cn != sender_id:
                print(f"\n{Colors.FAIL}[CHAT ACCEPT] Subject mismatch: expected={sender_id}, got={subject_cn}{Colors.ENDC}")
                self._chat_accepted = False
                self._chat_ready_event.set()
                return

            peer_pub_key = self._extract_public_key_from_chain(sender_cert_chain)
            my_id = self.user_info.get("user_id", "") if self.user_info else ""
            # Responder đã ký: "accept|initiator_id|responder_id"
            accept_msg = f"accept|{my_id}|{sender_id}"
            if not self.channel.verify_signature(accept_msg, signature, peer_pub_key):
                print(f"\n{Colors.FAIL}[CHAT ACCEPT] Chữ ký chấp nhận của {sender_id} KHÔNG HỢP LỆ!{Colors.ENDC}")
                self._chat_accepted = False
                self._chat_ready_event.set()
                return

            print(f"\n{Colors.OKGREEN}✓ {sender_id} đã chấp nhận lời mời chat và xác thực thành công!{Colors.ENDC}")
            self._chat_accepted = True
            self._chat_ready_event.set()
        except Exception as e:
            print(f"\n{Colors.FAIL}[CHAT ACCEPT] Lỗi xử lý: {e}{Colors.ENDC}")
            self._chat_accepted = False
            self._chat_ready_event.set()

    # ------------------ MENUS & UI ------------------

    def show_auth_menu(self):
        while not self.session_id:
            print(f"\n{Colors.HEADER}╔══════════════════════════════════════╗")
            print(f"║   IAM Key Management System          ║")
            print(f"╚══════════════════════════════════════╝{Colors.ENDC}")
            print("  1. Đăng nhập (Log in)")
            print("  2. Đăng ký (Sign up)")
            print("  0. Thoát")
            
            choice = input(f"\nChọn: ")
            if choice == "1":
                self.do_login()
            elif choice == "2":
                self.do_register()
            elif choice == "0":
                print("Tạm biệt!")
                self._running = False
                sys.exit(0)
            else:
                print_error("Lựa chọn không hợp lệ.")

    def do_login(self):
        print_header("Đăng nhập")
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        client_nonce = secrets.token_urlsafe(16)
        self.pending_login_nonce = client_nonce

        if not self.server_nonce:
            print_error("Thiếu server nonce cho mutual auth.")
            return

        client_proof = self.channel.sign_message(
            f"{self.server_nonce}|{client_nonce}|{username}",
            self.private_key
        )
        
        res = self._sync_request({
            "type": "login",
            "username": username,
            "password": password,
            "client_public_key": self._public_key_pem(),
            "client_nonce": client_nonce,
            "client_proof": client_proof
        }, "login_ok")
        
        if res:
            server_proof = res.get("server_auth_proof")
            if not server_proof or not self.server_public_key:
                print_error("Thiếu server_auth_proof hoặc public key của server.")
                self.session_id = None
                return

            expected_server_message = f"{res.get('session_id')}|{client_nonce}|login_ok"
            if not self.channel.verify_signature(expected_server_message, server_proof, self.server_public_key):
                print_error("Server authentication proof không hợp lệ. Hủy phiên.")
                self.session_id = None
                return

            self.session_id = res.get("session_id")
            self.user_info = res.get("user")
            self.username = username
            print_success(f"Đăng nhập thành công! Xin chào, {self.user_info.get('username')}.")

            # Keystore policy: reuse login password as passphrase (in-memory only)
            self._keystore_passphrase = password

            # Load/Create identity key from client keystore (this key signs CSR and binds the new certificate)
            # Dùng username làm tên thư mục keystore (dễ nhận biết hơn user_id hash).
            # self._ks_name được lưu lại để mọi thao tác keystore sau (rotate, archive...)
            # đều dùng cùng một path — tránh tạo thư mục trùng lặp.
            user_info = self.user_info or {}
            user_id: str = str(user_info.get("user_id") or "")
            self._ks_name: str = str(user_info.get("username") or user_id)
            if not self._ks_name:
                print_error("Không xác định được keystore name. Hủy đăng nhập.")
                self.session_id = None
                self.user_info = None
                self._keystore_passphrase = None
                return
            try:
                identity_priv, identity_v, created_new = self._load_or_create_identity_key(self._ks_name, self._keystore_passphrase)
            except Exception as e:
                print_error(f"Không thể mở/tạo identity key trong client keystore: {e}")
                self.session_id = None
                self.user_info = None
                self._keystore_passphrase = None
                return

            self.private_key = identity_priv
            self.public_key = self.private_key.public_key()

            if created_new:
                print(f"{Colors.OKCYAN}[KEYSTORE] ✓ Đã tạo identity key mới v{identity_v} trong keystore (RSA-2048, encrypted).{Colors.ENDC}")
            else:
                print(f"{Colors.OKCYAN}[KEYSTORE] ✓ Đã tải identity key v{identity_v} từ keystore (RSA-2048, encrypted).{Colors.ENDC}")

            # Chỉ gửi public key lên server khi vừa sinh key mới
            # (created_new = False nghĩa là key đã tồn tại và đã được đăng ký trước đó)
            if created_new:
                pub_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")
                key_id = f"user_{user_id}_identity_v{identity_v}"
                purpose = "initial public key" if identity_v == 1 else "new public key"
                reg_res = self._sync_request({
                    "type": "register_pubkey",
                    "key_id": key_id,
                    "public_key_pem": pub_pem,
                    "purpose": purpose,
                }, "register_pubkey_ok")
                if reg_res:
                    print(f"{Colors.OKCYAN}[KEYSTORE] ✓ Public key đã lưu trên server: {key_id} ({purpose}).{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}[KEYSTORE] ⚠ Không thể lưu public key lên server (tiếp tục đăng nhập).{Colors.ENDC}")

            if not self._perform_hello_csr():
                print_error("Không thể hoàn tất hello/welcome với CSR. Hủy phiên đăng nhập.")
                self.session_id = None
                self.user_info = None
                self._keystore_passphrase = None
                return

    def do_register(self):
        print_header("Đăng ký tài khoản mới")
        username = input("Username: ").strip()
        email = input("Email: ").strip()
        password = input("Password: ").strip()
        confirm = input("Xác nhận Password: ").strip()
        
        if password != confirm:
            print_error("Mật khẩu không khớp!")
            return
            
        res = self._sync_request({
            "type": "register",
            "username": username,
            "email": email,
            "password": password
        }, "register_ok")
        
        if res:
            print_success("Đăng ký thành công! Vui lòng đăng nhập.")

    def show_main_menu(self):
        while self.session_id and self._running:
            if not self.user_info:
                break
            role_str = ", ".join(self.user_info.get("roles", []))
            username = self.user_info.get('username')
            
            print(f"\n{Colors.HEADER}╔══════════════════════════════════════════╗")
            print(f"║  Xin chào, {username}! (Role: {role_str})")
            print(f"╠══════════════════════════════════════════╣{Colors.ENDC}")
            print("  1. Quản lý khóa (Key Management)")
            print("  2. Xem chứng chỉ (Certificate)")
            print("  3. Xem audit log")
            print("  4. Xem danh sách users")
            print("  5. Chế độ chat mã hóa E2E (Peer-to-peer)")
            print("  5b. Chế độ chat mã hóa E2E (via KDC)")
            print("  0. Đăng xuất")
            print(f"{Colors.HEADER}╚══════════════════════════════════════════╝{Colors.ENDC}")
            
            choice = input("\nChọn chức năng: ")
            
            if choice == "1":
                self.show_key_menu()
            elif choice == "2":
                self.do_cert_info()
            elif choice == "3":
                self.do_audit_logs()
            elif choice == "4":
                self.do_list_users()
            elif choice == "5":
                self.do_chat_e2e()
            elif choice == "5b":
                self.do_chat_e2e_kdc()
            elif choice == "0":
                self.session_id = None
                self.user_info = None
                self._keystore_passphrase = None
                self.client_cert_chain = None
                print_success("Đã đăng xuất.")
            else:
                print_error("Không hợp lệ!")

    # ------------------ COMPONENT ACTIONS ------------------

    def show_key_menu(self):
        while self.session_id:
            print_header("Quản lý khóa")
            print("  1. Sinh khóa mới (Generate Key)")
            print("  2. Liệt kê khóa (List Keys)")
            print("  0. ← Quay lại")
            
            choice = input("\nChọn: ")
            if choice == "1":
                self.do_key_gen()
            elif choice == "2":
                self.do_key_list()
            elif choice == "0":
                break
            else:
                print_error("Lựa chọn không hợp lệ.")

    def do_key_gen(self):
        print_header("Sinh khóa mới")
        print("Thuật toán được hỗ trợ:")
        print("  1. RSA-2048 (Bất đối xứng)")
        
        algo_c = input("Chọn (1): ")
        private_key_password = None
        algo = "RSA-2048"
        
        print("Khóa Bất đối xứng (RSA) sẽ được trả về dạng file .pem cho bạn lưu giữ.")
        pwd = input("Nhập mật khẩu bảo vệ khóa Private Key (Enter để bỏ qua nếu không cần): ").strip()
        if pwd:
            private_key_password = pwd
        
        name = input("Tên khóa: ")
        purp = input("Mục đích: ")
        
        req_payload = {
            "type": "key_gen",
            "algorithm": algo,
            "key_name": name,
            "purpose": purp
        }
        if private_key_password:
            req_payload["private_key_password"] = private_key_password
            
        res = self._sync_request(req_payload, "key_gen_ok")
        if res:
            key_id = res.get('key_id')
            print_success(f"Khóa '{name}' ({algo}) đã được sinh thành công! (ID: {key_id})")
            
            private_pem = res.get("private_key_pem")
            public_pem  = res.get("public_key_pem")
            if private_pem or public_pem:
                try:
                    os.makedirs("data", exist_ok=True)
                    if private_pem:
                        priv_path = f"data/{name}_private.pem"
                        with open(priv_path, "w", encoding="utf-8") as f:
                            f.write(private_pem)
                        print_success(f"Đã lưu Private Key tại: {priv_path}")
                    if public_pem:
                        pub_path = f"data/{name}_public.pem"
                        with open(pub_path, "w", encoding="utf-8") as f:
                            f.write(public_pem)
                        print_success(f"Đã lưu Public Key  tại: {pub_path}")
                except Exception as e:
                    print_error(f"Không thể lưu key ra file: {e}")

    def do_key_list(self):
        print_header("Danh sách KHÓA")
        res = self._sync_request({"type": "key_list"}, "key_list_res")
        if res:
            keys = res.get("keys", [])
            if not keys:
                print("Chưa có khóa nào.")
            for k in keys:
                if k.get('is_expired'):
                    active = "Hết hạn"
                else:
                    active = "Hoạt động" if k['is_active'] else "Đã vô hiệu"
                print(f" • {k['key_id']} | {k['algorithm']} | {k['purpose']} | {active}")

    def do_cert_info(self):
        print_header("Chứng chỉ (Certificate)")
        res = self._sync_request({
            "type": "cert_req"
        }, "cert_info")
        if res:
            cert_chain = res.get("cert_chain") or []
            crls = res.get("crls") or []

            if not cert_chain:
                print_error("Server không trả cert_chain.")
                return

            if not self.ca_public_key_pem:
                print_error("Thiếu trusted root certificate để xác minh chain.")
                return

            is_valid, msg = verify_certificate_chain(
                cert_chain,
                self.ca_public_key_pem,
                crl_pems=crls,
            )
            if is_valid:
                print_success(f"Chứng chỉ hiện tại hợp lệ: {msg}")
            else:
                print_error(f"Chứng chỉ hiện tại không hợp lệ: {msg}")

            cert_info = {
                "subject": res.get("subject"),
                "serial_number": res.get("serial_number"),
                "cert_chain_len": len(cert_chain),
                "crl_count": len(crls),
            }
            
            # Interactive menu
            while True:
                print("\n" + "─" * 50)
                print("📋 Lựa chọn thao tác với chứng chỉ:")
                print("  1. Xem chi tiết chứng chỉ")
                print("  2. Xin thu hồi chứng chỉ (nếu bị lộ)")
                print("  3. Quay lại menu chính")
                print("─" * 50)
                
                choice = input("Nhập lựa chọn (1-3): ").strip()
                
                if choice == "1":
                    print("\n" + json.dumps(cert_info, indent=2, ensure_ascii=False))
                    
                elif choice == "2":
                    print_header("Thu hồi Chứng chỉ")
                    confirm = input("⚠️  Bạn có chắc muốn thu hồi chứng chỉ? (yes/no): ").strip().lower()
                    if confirm == "yes":
                        revoke_res = self._sync_request({
                            "type": "revoke_cert"
                        }, "revoke_cert_ok")
                        if revoke_res:
                            print_success(revoke_res.get("message", "Chứng chỉ đã được thu hồi thành công"))
                            crls_updated = revoke_res.get("crls", [])
                            print(f"ℹ️  CRL đã được cập nhật ({len(crls_updated)} entries)")

                            # After revoke: rotate identity key (brand-new) and request a new certificate via CSR
                            try:
                                if not self.user_info or not self._keystore_passphrase:
                                    raise ValueError("Thiếu user_info hoặc passphrase để rotate key")

                                self.current_crls = crls_updated

                                new_priv, new_v = self._rotate_identity_key(self._ks_name, self._keystore_passphrase)
                                self.private_key = new_priv
                                self.public_key = self.private_key.public_key()

                                print(f"{Colors.OKCYAN}[CERT] Bạn đã rotate key. Hệ thống sẽ xin chứng chỉ mới gắn với key mới ngay bây giờ.{Colors.ENDC}")
                                if not self._perform_hello_csr():
                                    print_error("Rotate key xong nhưng xin chứng chỉ mới thất bại. Bạn có thể thử đăng nhập lại.")
                                else:
                                    print_success("Đã xin chứng chỉ mới thành công (CSR mới + key mới).")
                            except Exception as e:
                                print_error(f"Không thể rotate key / xin chứng chỉ mới: {e}")

                            break
                    else:
                        print_error("Đã hủy yêu cầu thu hồi")
                    
                elif choice == "3":
                    print("Quay lại menu chính...")
                    break
                    
                else:
                    print_error("Lựa chọn không hợp lệ")


    def do_audit_logs(self):
        print_header("Audit Logs")
        res = self._sync_request({"type": "audit_query"}, "audit_logs")
        if res:
            logs = res.get("logs", [])
            for log in logs[-10:]: # Hien 10 cai moi nhat
                timestamp = log.get("timestamp", "")[:19].replace("T", " ")
                print(f"[{timestamp}] {log['user_id']} | {log['event_type']} | {log['action']} | {log['result']}")

    def do_list_users(self):
        print_header("Danh sách Users")
        res = self._sync_request({"type": "directory"}, "directory_list")
        if res:
            for u in res.get("users", []):
                status = f"{Colors.OKGREEN}Online{Colors.ENDC}" if u['online'] else "Offline"
                roles = ','.join(u['roles'])
                print(f" • {u['username']} (ID: {u['user_id']}) | Vai trò: {roles} | {status}")

    def do_chat_directory(self):
        print_header("Danh bạ Chat E2E")
        res = self._sync_request({"type": "chat_directory"}, "chat_directory_response")
        if res:
            online_users = [u for u in res.get("users", []) if u['online']]
            if not online_users:
                print("  (Không có ai đang online)")
                return
            for u in online_users:
                cert_status = "Có" if u['has_cert'] else "Không"
                print(f" • {u['username']} (ID: {u['user_id']}) | Đã ĐK Cert: {cert_status}")

    def do_chat_e2e(self):
        print_header("Chế độ Chat Mã hóa E2E (Peer-to-peer)")
        if self.pending_chat_invite:
            self._do_chat_respond()
        else:
            self._do_chat_initiate()

    def do_chat_e2e_kdc(self):
        """E2E Chat using KDC for session key distribution"""
        print_header("Chế độ Chat Mã hóa E2E (via KDC)")
        
        # Case 1: Responding to pending KDC invite
        if self.pending_ticket and self.chat_peer_id:
            print(f"Đang chờ trả lời lời mời từ {self.chat_peer_id}...")
            
            # Confirm acceptance
            confirm = input(f"Bạn có muốn chấp nhận chat với {self.chat_peer_id}? (y/n): ").strip().lower()
            if confirm != 'y':
                print_error("Đã từ chối lời mời chat.")
                self._reset_chat_state()
                return
            
            # Send accept to server with ticket_id
            ticket_id = self.pending_ticket_id
            self._send_req({
                "type": "relay",
                "relay_type": "chat_accept_kdc",
                "target_id": self.chat_peer_id,
                "ticket_id": ticket_id
            })
            
            print_success("Đã gửi xác nhận. Đang chờ session key...")
            
            # Wait for session key response
            res = self._sync_request({}, wait_for_type="kdc_session_key", timeout=10)
            if not res or res.get('error'):
                print_error(f"Không nhận được session key: {res.get('error') if res else 'timeout'}")
                self._reset_chat_state()
                return
            
            # Decrypt ticket_for_b bằng private key của Bob — server không biết Ks
            ticket_for_b = res.get("ticket_for_b")
            if not ticket_for_b:
                print_error("Ticket từ KDC không hợp lệ")
                self._reset_chat_state()
                return

            try:
                oaep = asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
                ticket_data = json.loads(
                    self.private_key.decrypt(base64.b64decode(ticket_for_b), oaep)
                )
                self.chat_session_key = base64.b64decode(ticket_data["ks"])
                ttl_b = int(ticket_data.get("ttl") or 300)
                issued_at_str = ticket_data.get("issued_at")
                if issued_at_str:
                    issued_at_dt = datetime.fromisoformat(issued_at_str.replace("Z", "")).replace(tzinfo=timezone.utc)
                    self.chat_session_expires_at = issued_at_dt + timedelta(seconds=ttl_b)
                else:
                    self.chat_session_expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_b)
            except Exception as e:
                print_error(f"Không giải mã được ticket: {e}")
                self._reset_chat_state()
                return

            print_success("✅ Nhận session key từ KDC. Sẵn sàng chat.")
            
            # Enter chat mode
            self.in_chat_mode = True
            print(f"\n{Colors.WARNING}--- Chat với {self.chat_peer_id} via KDC (gõ 'back' để thoát) ---{Colors.ENDC}")
            self._run_chat_loop()
            return
        
        # Case 2: Initiating new KDC chat (like before)
        print("Chế độ này sử dụng KDC để cấp phát session key với TTL tự động")
        
        # Show user directory
        self.do_chat_directory()
        
        target_uid = input("\nNhập Username hoặc User ID muốn chat: ").strip()
        if not target_uid:
            return
        
        ttl = input("Thời gian sử dụng session key (TTL) tính bằng giây (Enter = 300): ").strip()
        try:
            ttl = int(ttl) if ttl else 300
        except ValueError:
            ttl = 300
        
        # Step 1: Request session key from KDC
        print(f"\n[1] Đang yêu cầu session key từ KDC cho {target_uid}...")
        success = self.request_session_key_via_kdc(target_uid, ttl=ttl)
        if not success:
            print_error("KDC session key request failed")
            return
        
        # Step 2: Send chat invite with KDC ticket
        print(f"[2] Đang gửi lời mời chat với KDC ticket tới {target_uid}...")
        self._send_req({
            "type": "relay",
            "relay_type": "chat_invite_kdc",
            "target_id": target_uid,
            "ticket": self.pending_ticket,
            "ticket_id": self.pending_ticket_id,
        })
        
        print_success(f"Đã gửi lời mời chat KDC tới {target_uid}. Đang chờ phản hồi (tối đa 60s)...")
        
        # Step 3: Wait for acceptance
        self._chat_ready_event.clear()
        self._chat_accepted = False
        responded = self._chat_ready_event.wait(timeout=60)
        
        if not responded:
            print_error("Hết thời gian chờ. Lời mời không được phản hồi.")
            self._reset_chat_state()
            return
        
        if not self._chat_accepted:
            print_error(f"{target_uid} đã từ chối hoặc xác thực thất bại.")
            self._reset_chat_state()
            return
        
        # Step 4: Enter chat mode with KDC session key
        self.in_chat_mode = True
        print(f"\n{Colors.WARNING}--- Chat với {target_uid} via KDC (gõ 'back' để thoát) ---{Colors.ENDC}")
        self._run_chat_loop()

    # ── Initiator flow ──────────────────────────────────────────────

    def _do_chat_initiate(self):
        self.do_chat_directory()
        target_uid = input("\nNhập Username hoặc User ID muốn chat: ").strip()
        if not target_uid:
            return

        # 1. Lấy và xác minh cert của đối tác
        print("[1] Đang lấy Certificate của đối tác...")
        res = self._sync_request({
            "type": "relay",
            "relay_type": "cert_request",
            "target_id": target_uid,
        }, "cert_response")
        if not res:
            return


        resolved_target_id = res.get("target_id", target_uid) # lấy id của đối tác từ response để so khớp với CN trong cert, fallback về target_uid nếu server không trả
        cert_chain = res.get("cert_chain") or [] # lấy certificate chain của đối tác, nếu server không trả về thì mặc định là empty list để verify_certificate_chain xử lý và báo
        crls = res.get("crls") or [] # lấy CRL list từ response, nếu server không trả về thì fallback về current_crls của client

        if not self.ca_public_key_pem:
            print_error("Thiếu trusted CA key.")
            return

        is_valid, verify_msg = verify_certificate_chain(cert_chain, self.ca_public_key_pem, crl_pems=crls)
        if not is_valid:
            print_error(f"Certificate chain KHÔNG HỢP LỆ: {verify_msg}")
            return

        subject_cn = self._extract_cn_from_cert_pem(cert_chain[0])
        if subject_cn != resolved_target_id:
            print_error(f"Subject cert mismatch: expected={resolved_target_id}, got={subject_cn}")
            return

        print_success(f"Certificate của {resolved_target_id} hợp lệ.")
        self.current_crls = crls

        # lấy public key của người cần chat
        # mục đích: 1. verify chữ ký của Bob trong bước accept
        #        2. mã hóa session key khi gửi invite (Sign-then-Encrypt)
        self.chat_peer_public_key = self._extract_public_key_from_chain(cert_chain)
        self.chat_peer_id = resolved_target_id

        # 2. Tạo session key, Sign-then-Encrypt (hybrid)
        print("[2] Tạo Session Key và ký (Sign-then-Encrypt)...")
        self.chat_session_key = os.urandom(32) # tạo sessino key 32 byte 
        session_key_b64 = base64.b64encode(self.chat_session_key).decode()
        my_id = self.user_info.get("user_id", "") if self.user_info else ""

        # Sign: ràng buộc session key với danh tính cả 2 bên
        sign_msg = f"{session_key_b64}|{my_id}|{resolved_target_id}"
        signature = self.channel.sign_message(sign_msg, self.private_key)

        # Hybrid encrypt: AES-GCM mã hóa bundle, RSA-OAEP mã hóa AES key
        ek = os.urandom(32)
        bundle = json.dumps({
            "session_key": session_key_b64,
            "signature": signature,
            "sender_id": my_id,
            "target_id": resolved_target_id,
        })
        nonce_b, ct_b, tag_b = self.channel.encrypt_aes_256_gcm(bundle, ek)
        encrypted_ek = self.channel.encrypt_rsa_oaep(
            base64.b64encode(ek).decode(), self.chat_peer_public_key
        )

        # 3. Gửi chat_invite
        self._send_req({
            "type": "relay",
            "relay_type": "chat_invite",
            "target_id": resolved_target_id,
            "encrypted_ek": encrypted_ek,
            "nonce": nonce_b,
            "ciphertext": ct_b,
            "tag": tag_b,
        })
        print_success(f"Đã gửi lời mời chat tới {resolved_target_id}. Đang chờ phản hồi (tối đa 60s)...")

        # 4. Chờ Bob accept / decline
        self._chat_ready_event.clear()
        self._chat_accepted = False
        responded = self._chat_ready_event.wait(timeout=60)

        if not responded:
            print_error("Hết thời gian chờ. Lời mời không được phản hồi.")
            self._reset_chat_state()
            return

        if not self._chat_accepted:
            print_error(f"{resolved_target_id} đã từ chối hoặc xác thực thất bại.")
            self._reset_chat_state()
            return

        # 5. Vào chat mode
        self.in_chat_mode = True
        print(f"\n{Colors.WARNING}--- Chat với {resolved_target_id} (gõ 'back' để thoát) ---{Colors.ENDC}")
        self._run_chat_loop()

    # ── Responder flow ──────────────────────────────────────────────

    def _do_chat_respond(self):
        invite = self.pending_chat_invite
        self.pending_chat_invite = None
        if invite is None:
            return
        sender_id = invite.get("sender_id", "?")

        answer = input(f"\n{Colors.OKCYAN}{sender_id} mời bạn chat E2E. Chấp nhận? (y/n): {Colors.ENDC}").strip().lower()
        if answer != "y":
            self._send_req({
                "type": "relay",
                "relay_type": "chat_decline",
                "target_id": sender_id,
            })
            print("Đã từ chối lời mời.")
            return

        # Narrow Optional types thành str/List[str] rõ ràng để type-checker hài lòng
        sender_cert_chain: List[str] = invite.get("sender_cert_chain") or []
        crls: List[str] = invite.get("crls") or self.current_crls
        encrypted_ek: str = invite.get("encrypted_ek") or ""
        nonce_b: str = invite.get("nonce") or ""
        ct_b: str = invite.get("ciphertext") or ""
        tag_b: str = invite.get("tag") or ""

        if not all([sender_cert_chain, encrypted_ek, nonce_b, ct_b, tag_b]):
            print_error("Lời mời thiếu dữ liệu cần thiết. Hủy.")
            return

        if not self.ca_public_key_pem:
            print_error("Thiếu trusted CA key. Hủy.")
            return

        # 1. Xác minh cert Alice
        print(f"{Colors.OKCYAN}[MUTUAL AUTH] Đang xác minh chứng chỉ của {sender_id}...{Colors.ENDC}")
        is_valid, chain_msg = verify_certificate_chain(sender_cert_chain, self.ca_public_key_pem, crl_pems=crls)
        if not is_valid:
            print_error(f"Cert chain của {sender_id} không hợp lệ: {chain_msg}")
            return

        subject_cn = self._extract_cn_from_cert_pem(sender_cert_chain[0])
        if subject_cn != sender_id:
            print_error(f"Subject mismatch: expected={sender_id}, got={subject_cn}")
            return

        print_success(f"Chứng chỉ của {sender_id} hợp lệ.")
        peer_pub_key = self._extract_public_key_from_chain(sender_cert_chain)
        self.current_crls = crls

        # 2. Decrypt-then-Verify (hybrid)
        try:
            ek_b64 = self.channel.decrypt_rsa_oaep(encrypted_ek, self.private_key)
            ek = base64.b64decode(ek_b64)
            bundle_json = self.channel.decrypt_aes_256_gcm(nonce_b, ct_b, tag_b, ek)
            bundle = json.loads(bundle_json)
        except Exception as e:
            print_error(f"Giải mã thất bại: {e}")
            return

        session_key_b64 = bundle.get("session_key", "")
        signature = bundle.get("signature", "")
        bundle_sender = bundle.get("sender_id", "")
        bundle_target = bundle.get("target_id", "")
        my_id = self.user_info.get("user_id", "") if self.user_info else ""

        # Kiểm tra identity binding trong bundle
        if bundle_sender != sender_id or bundle_target != my_id:
            print_error(f"Bundle identity mismatch: sender={bundle_sender}, target={bundle_target}")
            return

        # Verify chữ ký của Alice (Sign-then-Encrypt: verify sau decrypt)
        sign_msg = f"{session_key_b64}|{bundle_sender}|{bundle_target}"
        if not self.channel.verify_signature(sign_msg, signature, peer_pub_key):
            print_error(f"Chữ ký số của {sender_id} KHÔNG HỢP LỆ! Từ chối.")
            return

        print_success(f"Xác minh danh tính {sender_id} thành công. Đã nhận session key.")
        self.chat_session_key = base64.b64decode(session_key_b64)
        self.chat_peer_id = sender_id
        self.chat_peer_public_key = peer_pub_key

        # 3. Gửi chat_accept kèm chữ ký xác nhận
        accept_msg = f"accept|{sender_id}|{my_id}"
        accept_sig = self.channel.sign_message(accept_msg, self.private_key)
        self._send_req({
            "type": "relay",
            "relay_type": "chat_accept",
            "target_id": sender_id,
            "signature": accept_sig,
        })

        # 4. Vào chat mode
        self.in_chat_mode = True
        print(f"\n{Colors.WARNING}--- Chat với {sender_id} (gõ 'back' để thoát) ---{Colors.ENDC}")
        self._run_chat_loop()

    # ── Shared chat UI ──────────────────────────────────────────────

    def _run_chat_loop(self):
        my_id = self.user_info.get("user_id", "") if self.user_info else ""
        session_key = self.chat_session_key
        if session_key is None:
            return
        expires_at = self.chat_session_expires_at
        if expires_at:
            remaining = (expires_at - datetime.now(timezone.utc)).seconds
            print(f"{Colors.WARNING}[KDC] Session key hết hạn sau {remaining}s. Kết nối sẽ tự ngắt.{Colors.ENDC}")
        try:
            while True:
                if expires_at and datetime.now(timezone.utc) >= expires_at:
                    print(f"\n{Colors.FAIL}[KDC] Session key đã hết hạn. Kết nối bị ngắt.{Colors.ENDC}")
                    break
                msg = input("")
                if msg.strip().lower() == "back":
                    break
                if not msg.strip():
                    continue
                if expires_at and datetime.now(timezone.utc) >= expires_at:
                    print(f"\n{Colors.FAIL}[KDC] Session key hết hạn trong khi nhập. Tin nhắn không được gửi.{Colors.ENDC}")
                    break

                # associated_data ràng buộc cả sender lẫn receiver
                assoc_data = f"{my_id}:{self.chat_peer_id}"
                nonce, ciphertext, tag = self.channel.encrypt_aes_256_gcm(
                    msg, session_key, assoc_data
                )
                print(f"{Colors.WARNING}[ENCRYPT] nonce={nonce[:10]}... ct={ciphertext[:20]}...{Colors.ENDC}")
                self._send_req({
                    "type": "relay",
                    "relay_type": "chat_msg",
                    "target_id": self.chat_peer_id,
                    "algorithm": "AES-256-GCM",
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "tag": tag,
                    "associated_data": assoc_data,
                })
        except Exception as e:
            print_error(f"Chat error: {e}")
        finally:
            self._reset_chat_state()

    def _reset_chat_state(self):
        self.in_chat_mode = False
        self.chat_peer_id = None
        self.chat_session_key = None
        self.chat_session_expires_at = None
        self.chat_peer_public_key = None
        self.pending_ticket = None
        self.pending_ticket_id = None

    def request_session_key_via_kdc(self, peer_id: str, ttl: int = 300) -> bool:
        """Request a session key from KDC for communication with peer_id.
        
        Flow:
        1. Client sends plaintext kdc_keyreq to server (connection is X.509 authenticated)
        2. Server validates peer, issues session ticket
        3. Receive kdc_keyresp with plaintext session_key + encrypted ticket
        4. Extract session key
        5. Store session key + ticket for chat
        6. Return True if success
        """
        try:
            if not self.session_id:
                print_error("Not authenticated")
                return False
            
            my_id = self.user_info.get('user_id') if self.user_info else None
            if not my_id:
                print_error("User ID not found")
                return False
            
            # Send plaintext KDC request to server
            req = {
                "type": "kdc_keyreq",
                "peer_id": peer_id,
                "requested_ttl": ttl
            }
            self._send_req(req)
            
            # Wait for response (kdc_keyresp) via sync
            res = self._sync_request({}, wait_for_type="kdc_keyresp", timeout=10)
            if not res or res.get('error'):
                print_error(f"KDC response failed: {res.get('error') if res else 'timeout'}")
                return False
            
            # Extract RSA-encrypted response
            enc_ks = res.get('enc_ks')
            ticket_for_b = res.get('ticket_for_b')
            ticket_id = res.get('ticket_id')
            ttl_resp = res.get('ttl')

            if not enc_ks or not ticket_for_b or not ticket_id:
                print_error("Incomplete KDC response")
                return False

            # Decrypt Ks with local private key — server never sees Ks in plaintext
            oaep = asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
            ks = self.private_key.decrypt(base64.b64decode(enc_ks), oaep)
            self.chat_session_key = ks
            self.pending_ticket = ticket_for_b   # RSA-OAEP(PubB, {Ks,ida,ttl,issued_at}) — forward cho Bob
            self.pending_ticket_id = ticket_id
            self.chat_peer_id = peer_id
            if ttl_resp:
                issued_at_str = res.get("issued_at")
                if issued_at_str:
                    issued_at_dt = datetime.fromisoformat(issued_at_str.replace("Z", "")).replace(tzinfo=timezone.utc)
                    self.chat_session_expires_at = issued_at_dt + timedelta(seconds=int(ttl_resp))
                else:
                    self.chat_session_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(ttl_resp))

            print_success(f"✅ Nhận session key từ KDC (TTL: {ttl_resp}s)")
            return True
            
        except Exception as e:
            print_error(f"KDC request error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def handle_forwarded_ticket(self, data: Dict):
        """Handle incoming ticket forwarded by peer. Decrypt using local entity master key."""
        try:
            ticket_enc = data.get('ticket')
            ticket_nonce = data.get('ticket_nonce')
            ticket_id = data.get('ticket_id')

            kb = None
            try:
                kb = self.channel_key  # placeholder: client must have local entity master key
            except Exception:
                kb = None

            if not kb:
                print_error("Missing local entity master key to decrypt ticket")
                return False

            payload = decrypt_json_with_key(kb, ticket_enc, ticket_nonce)
            ks_b64 = payload.get('ks')
            ida = payload.get('ida')
            ttl = payload.get('ttl')
            issued_at = payload.get('issued_at')

            # Verify TTL
            # ...simple check omitted for brevity...

            self.chat_session_key = base64.b64decode(ks_b64)
            print_success(f"Received session key from ticket {ticket_id}. Ready to perform challenge/response.")

            # Perform challenge-response: B -> A
            nonce_b = secrets.token_urlsafe(16)
            chal = {
                "type": "kdc_challenge",
                "nonce_b": nonce_b,
                "ts": datetime.utcnow().isoformat() + "Z"
            }
            enc_chal = self.channel.encrypt_aes_256_gcm(json.dumps(chal), self.chat_session_key)
            chal_msg = {
                "type": "kdc_challenge_forward",
                "to": ida,
                "nonce": enc_chal[0],
                "ciphertext": enc_chal[1],
                "tag": enc_chal[2]
            }
            self._send_req(chal_msg)
            return True
        except Exception as e:
            print_error(f"Error handling ticket: {e}")
            return False

    def run(self):
        self.connect()
        while self._running:
            try:
                if not self.session_id:
                    self.show_auth_menu()
                else:
                    self.show_main_menu()
            except KeyboardInterrupt:
                print("\nThoát...")
                self._running = False
                break
            except Exception as e:
                print_error(f"Lỗi: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IAM Interactive CLI Client")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=5000, help="Server port")
    args = parser.parse_args()

    client = IAMDemoClient(args.host, args.port)
    client.run()
