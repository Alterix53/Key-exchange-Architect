"""
IAM Backend Server
Chuyển đổi từ Relay Chat đơn giản sang API Backend tích hợp toàn bộ các module IAM.
"""

import argparse
import base64
import json
import socket
import threading
import os
import sys
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Import các components từ IAM Core Module
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from src.identity_management import IdentityManagementSystem, Role, Permission
from src.key_management import KeyStore
from src.audit_logging import AuditLogger, AuditEventType
from src.public_key_distribution import CertificateAuthority
from src.secure_transmission import SecureTransmissionChannel, ReplayProtector
from src.kdc import KDC

def send_json(sock: socket.socket, payload: Dict) -> None:
    try:
        data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
        sock.sendall(data)
    except Exception as e:
        print(f"[ERROR] Failed to send JSON payload: {e}")

@dataclass
class ClientConnection:
    sock: socket.socket
    file_reader: Any
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    server_nonce: Optional[str] = None
    write_lock: threading.Lock = field(default_factory=threading.Lock)

    def send(self, payload: Dict) -> None:
        import secrets
        if "timestamp" not in payload:
            payload["timestamp"] = datetime.now().isoformat()
        if "msg_nonce" not in payload:
            payload["msg_nonce"] = secrets.token_hex(16)
        with self.write_lock:
            send_json(self.sock, payload)

class IAMBackendServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        
        # 1. Khởi tạo IAM Modules
        print("[INIT] Đang tải các phân hệ IAM (Backend: sqlserver)...")

        from src.db import get_working_connection_string
        from src.storage_backend import SqlServerUserStorage, SqlServerKeyStorage, SqlServerAuditStorage
        conn_str = get_working_connection_string()
        user_storage = SqlServerUserStorage(conn_str)
        key_storage = SqlServerKeyStorage(conn_str)
        audit_storage = SqlServerAuditStorage(conn_str)

        self.iam = IdentityManagementSystem("demo_identity", storage=user_storage)
        self.key_store = KeyStore("demo_keys", storage=key_storage)
        self.audit_logger = AuditLogger("demo_audit", storage=audit_storage)
            
        self.ca = CertificateAuthority(data_dir="data")
        
        # --- MUTUAL AUTH: Khởi tạo Server Identity ---
        server_priv_path = "data/server_private.pem"
        server_cert_path = "data/server_cert.pem"
        
        if os.path.exists(server_priv_path) and os.path.exists(server_cert_path):
            with open(server_priv_path, "rb") as f:
                self.server_private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(server_cert_path, "r", encoding="utf-8") as f:
                self.server_cert_pem = f.read()
            print("[SERVER] Đã tải Server Certificate từ file.")
        else:
            print("[SERVER] Khởi tạo Server Identity mới...")
            self.server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(server_priv_path, "wb") as f:
                f.write(self.server_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            server_pub_pem = self.server_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
            
            # Yêu cầu CA cấp chứng chỉ với Subject là IAM-Server
            self.server_cert_pem = self.ca.issue_certificate("IAM-Server", server_pub_pem)
            with open(server_cert_path, "w", encoding="utf-8") as f:
                f.write(self.server_cert_pem)
            print("[SERVER] Đã tạo và cấp Server Certificate mới (IAM-Server).")
        # --- END MUTUAL AUTH ---
        
        self.channel = SecureTransmissionChannel()
        self.replay_protector = ReplayProtector(time_window_seconds=30)
        
        self.clients: Dict[socket.socket, ClientConnection] = {}
        self.clients_lock = threading.Lock()
        
        # Cho E2E Chat
        self.active_users: Dict[str, ClientConnection] = {} # user_id -> ClientConnection

        # Initialize KDC when key_store available
        try:
            if hasattr(self, 'key_store') and self.key_store is not None:
                self.kdc = KDC(self.key_store)
            else:
                self.kdc = None
        except Exception:
            self.kdc = None

    # ------------- [CORE: SESSIONS & AUTH] -------------

    def _require_auth(self, req: Dict, conn: ClientConnection) -> Optional[str]:
        """Validate session, return user_id if valid, else None"""
        session_id = req.get("session_id")
        if not session_id:
            conn.send({"type": "error", "message": "auth_required: Missing session_id"})
            return None
            
        is_valid = self.iam.validate_session(session_id)
        if not is_valid:
            conn.send({"type": "error", "message": "auth_required: Invalid or expired session"})
            return None
            
        session_obj = self.iam.sessions.get(session_id)
        if not session_obj:
            conn.send({"type": "error", "message": "auth_required: Invalid session"})
            return None
        
        # Liên kết kết nối với user
        session_obj = self.iam.sessions.get(session_id)
        with self.clients_lock:
            conn.session_id = session_id
            conn.user_id = session_obj.user_id
            self.active_users[session_obj.user_id] = conn
            
        return session_obj.user_id

    def _check_permission(self, user_id: str, resource: str, action: str) -> bool:
        """Kiểm tra quyền qua RBAC"""
        perm = Permission(resource, action)
        has_perm = self.iam.check_permission(user_id, perm)
        if not has_perm:
            self.audit_logger.log_event(AuditEventType.PERMISSION_DENIED, user_id, resource, action, "failed")
        else:
            self.audit_logger.log_event(AuditEventType.PERMISSION_GRANTED, user_id, resource, action, "success")
        return has_perm

    # ------------- [HANDLERS: API ROUTES] -------------

    def handle_login(self, req: Dict, conn: ClientConnection, ip: str) -> None:
        """Xử lý đăng nhập"""
        username = req.get("username", "")
        password = req.get("password", "")
        client_public_key_pem = req.get("client_public_key")
        client_nonce = req.get("client_nonce")
        client_proof = req.get("client_proof")
        
        session = self.iam.authenticate_user(username, password, ip)
        if session:
            if not client_public_key_pem or not client_nonce or not client_proof or not conn.server_nonce:
                conn.send({"type": "error", "message": "Mutual auth failed: missing client proof material"})
                return

            try:
                client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode("utf-8"))
            except Exception:
                conn.send({"type": "error", "message": "Mutual auth failed: invalid client public key"})
                return

            proof_message = f"{conn.server_nonce}|{client_nonce}|{username}"
            if not self.channel.verify_signature(proof_message, client_proof, client_public_key):
                conn.send({"type": "error", "message": "Mutual auth failed: invalid client proof"})
                return

            self.audit_logger.log_event(AuditEventType.USER_LOGIN, session.user_id, "backend", "login", "success", ip_address=ip)
            user_info = self.iam.users[session.user_id].to_dict()
            with self.clients_lock:
                conn.session_id = session.session_id
                conn.user_id = session.user_id
                self.active_users[session.user_id] = conn

            server_auth_proof = self.channel.sign_message(
                f"{session.session_id}|{client_nonce}|login_ok",
                self.server_private_key
            )
                
            conn.send({
                "type": "login_ok",
                "session_id": session.session_id,
                "user": user_info,
                "server_auth_proof": server_auth_proof,
                "server_cert": self.server_cert_pem
            })
        else:
            self.audit_logger.log_event(AuditEventType.USER_FAILED_LOGIN, username, "backend", "login", "failed", ip_address=ip)
            conn.send({"type": "error", "message": "Sai tên đăng nhập hoặc mật khẩu"})

    def handle_register(self, req: Dict, conn: ClientConnection, ip: str) -> None:
        """Xử lý đăng ký tài khoản"""
        username = req.get("username")
        password = req.get("password")
        email = req.get("email")
        
        if not all([username, password, email]):
            conn.send({"type": "error", "message": "Thiếu thông tin đăng ký"})
            return
            
        try:
            # Kiểm tra trùng username
            users_dict = {u.username: u for u in self.iam.users.values()}
            if username in users_dict:
                conn.send({"type": "error", "message": "Tên đăng nhập đã tồn tại"})
                return
                
            user = self.iam.create_user(username, email, password, [Role.USER])
            self.audit_logger.log_event(AuditEventType.USER_CREATED, user.user_id, "backend", "register", "success", ip_address=ip)
            conn.send({"type": "register_ok", "message": "Đăng ký thành công"})
        except Exception as e:
            conn.send({"type": "error", "message": f"Lỗi đăng ký: {str(e)}"})

    def handle_cert_request(self, req: Dict, conn: ClientConnection, user_id: str) -> None:
        """Khi client muốn lấy certificate (kèm public key của CA)"""
        public_key_pem = req.get("public_key")
        if public_key_pem:
            # Client gui public key len de cap chung chi
            cert = self.ca.issue_certificate(user_id, public_key_pem)
            conn.send({"type": "cert_info", "certificate": cert, "ca_public_key": self.ca.get_public_key_pem()})
        else:
            # Client chi hoi current cert, not implementing right now
            conn.send({"type": "error", "message": "Please provide public_key to issue cert"})

    def handle_directory(self, req: Dict, conn: ClientConnection, user_id: str) -> None:
        """Lấy danh sách Users & active status"""
        if not self._check_permission(user_id, "users", "read"):
            conn.send({"type": "error", "message": "Access Denied: users:read"})
            return
            
        users_list = []
        for uid, user in self.iam.users.items():
            users_list.append({
                "user_id": uid,
                "username": user.username,
                "roles": [r.value for r in user.roles],
                "online": uid in self.active_users
            })
        conn.send({"type": "directory_list", "users": users_list})

    def handle_chat_directory(self, req: Dict, conn: ClientConnection, user_id: str) -> None:
        """Lấy danh bạ thu gọn phục vụ riêng cho E2E Chat"""
        if not self._check_permission(user_id, "chat", "discover"):
            conn.send({"type": "error", "message": "Access Denied: chat:discover"})
            return
            
        chat_users = []
        for uid, user in self.iam.users.items():
            if not user.is_active:
                continue
            # Chỉ trả về các trường cần thiết phục vụ chat (ẩn role, email...)
            chat_users.append({
                "user_id": uid,
                "username": user.username,
                "online": uid in self.active_users,
                "has_cert": self.ca.get_certificate(uid) is not None
            })
        conn.send({"type": "chat_directory_response", "users": chat_users})

    def handle_audit_query(self, req: Dict, conn: ClientConnection, user_id: str) -> None:
        """Lấy audit logs"""
        if not self._check_permission(user_id, "audit", "read"):
            conn.send({"type": "error", "message": "Access Denied: audit:read"})
            return
            
        logs = self.audit_logger.get_all_logs(limit=20)
        conn.send({"type": "audit_logs", "logs": logs})

    def handle_key_list(self, req: Dict, conn: ClientConnection, user_id: str) -> None:
        """Liệt kê khóa"""
        if not self._check_permission(user_id, "keys", "read"):
            conn.send({"type": "error", "message": "Access Denied: keys:read"})
            return
            
        # Admin thấy hết, user chỉ thấy của mình
        owner_filter = None
        user_obj = self.iam.users.get(user_id)
        if Role.ADMIN not in user_obj.roles:
            owner_filter = user_id
            
        keys = self.key_store.list_keys(owner=owner_filter)
        conn.send({"type": "key_list_res", "keys": keys})

    def handle_key_gen(self, req: Dict, conn: ClientConnection, user_id: str) -> None:
        """Sinh khóa mới"""
        if not self._check_permission(user_id, "keys", "create"):
            conn.send({"type": "error", "message": "Access Denied: keys:create"})
            return
            
        algorithm = req.get("algorithm", "AES-256")
        key_name = req.get("key_name", f"key_{datetime.now().timestamp()}")
        purpose = req.get("purpose", "General")
        private_key_password = req.get("private_key_password")
        
        try:
            private_key_pem = None
            if algorithm.startswith("AES"):
                k_id = self.key_store.generate_symmetric_key(key_name, user_id, purpose, algorithm)
            elif algorithm.startswith("RSA"):
                k_id, _, private_key_pem = self.key_store.generate_asymmetric_key_pair(
                    key_name, user_id, purpose, private_key_password=private_key_password
                )
            else:
                raise ValueError("Unsupported algorithm")
                
            self.audit_logger.log_event(AuditEventType.KEY_GENERATED, user_id, "backend", "key_gen", "success", details={"key_id": k_id, "algo": algorithm})
            
            res_payload = {
                "type": "key_gen_ok", 
                "key_id": k_id, 
                "message": "Đã sinh khóa thành công"
            }
            if private_key_pem:
                res_payload["private_key_pem"] = private_key_pem
                
            conn.send(res_payload)
        except Exception as e:
            conn.send({"type": "error", "message": str(e)})

    def process_kdc_keyreq(self, requester_id: str, enc_b64: str, nonce_b64: str) -> Dict[str, Any]:
        """Process a KDC KEYREQ from requester_id. Returns envelope dict or error."""
        if not self.kdc:
            return {"error": "KDC not initialized"}

        # Decrypt and parse KEYREQ
        payload = self.kdc.decrypt_keyreq(requester_id, enc_b64, nonce_b64)
        if not payload:
            return {"error": "Invalid KEYREQ or cannot decrypt"}

        idb = payload.get('idb')
        requested_ttl = int(payload.get('requested_ttl', 300))

        envelope = self.kdc.issue_session_ticket(requester_id, idb, requested_ttl)
        if not envelope:
            return {"error": "Failed to issue ticket"}

        # Return envelope (contains enc/nonce) to be sent back to requester
        return {"type": "kdc_keyresp", "enc": envelope.get('enc'), "nonce": envelope.get('nonce'), "alg": envelope.get('alg')}

    def process_forward_ticket(self, sender_id: str, recipient_id: str, ticket_enc: str, ticket_nonce: str, ticket_id: str) -> Dict[str, Any]:
        """Process a forwarded ticket: validate and (optionally) relay. Returns status."""
        if not self.kdc:
            return {"error": "KDC not initialized"}

        # Validate ticket record on server-side
        if not self.kdc.validate_ticket(ticket_id):
            return {"error": "Ticket invalid or expired/used"}

        # Optionally mark as used now or wait until B confirms
        # Here we do not mark used yet; B should confirm after successful handshake

        # Prepare relay envelope for recipient (server simply wraps data for relay)
        relay = {
            "type": "forward_ticket",
            "from": sender_id,
            "ticket": ticket_enc,
            "ticket_nonce": ticket_nonce,
            "ticket_id": ticket_id
        }
        return relay

    # ------------- [E2E RELAY ROUTING] -------------

    def _resolve_target_user_id(self, target_ref: Any) -> Optional[str]:
        """Resolve target reference to canonical user_id, ưu tiên username trước."""
        if target_ref is None:
            return None

        target = str(target_ref).strip()
        if not target:
            return None

        target_lower = target.lower()

        # Ưu tiên username để nhập liệu thân thiện cho người dùng
        for uid, user in self.iam.users.items():
            if user.username.lower() == target_lower:
                return str(uid)

        if target in self.iam.users:
            return target

        for uid, user in self.iam.users.items():
            uid_str = str(uid)
            if uid_str.lower() == target_lower:
                return uid_str

        return None

    def handle_relay(self, req: Dict, conn: ClientConnection, user_id: str) -> None:
        """Trung chuyển gói tin E2E: chat, cert_request (để chat), session_key"""
        target_id = req.get("target_id")
        relay_type = req.get("relay_type")
        
        if not target_id:
            return

        resolved_target_id = self._resolve_target_user_id(target_id)
        if not resolved_target_id:
            conn.send({"type": "error", "message": f"Target user '{target_id}' does not exist"})
            return

        with self.clients_lock:
            target_conn = self.active_users.get(resolved_target_id)

        if not target_conn:
            conn.send({"type": "error", "message": "Target user is completely offline"})
            return
        
        # E2E - Client muốn lấy cert của ng khác để chat
        if relay_type == "get_cert":
            target_cert = self.ca.get_certificate(resolved_target_id)
            if target_cert:
                conn.send({"type": "peer_cert_response", "target_id": resolved_target_id, "certificate": target_cert})
            else:
                conn.send({"type": "error", "message": f"Certificate for {resolved_target_id} not found"})
        
        # E2E - Gửi Session Key
        elif relay_type == "session_key":
            req["type"] = "peer_session_key"
            req["sender_id"] = user_id
            req["sender_cert"] = self.ca.get_certificate(user_id)
            req["target_id"] = resolved_target_id
            del req["relay_type"]
            target_conn.send(req)
            
        # E2E - Chat Message
        elif relay_type == "chat_msg":
            self.audit_logger.log_event(AuditEventType.MESSAGE_RECEIVED, user_id, "backend", "relay", "success", details={"to": resolved_target_id})
            payload = {
                "type": "relayed_chat_msg",
                "sender_id": user_id,
                "target_id": resolved_target_id,
                "algorithm": req.get("algorithm"),
                "nonce": req.get("nonce"),
                "ciphertext": req.get("ciphertext"),
                "tag": req.get("tag"),
                "associated_data": req.get("associated_data"),
                "timestamp": req.get("timestamp", datetime.now().isoformat()),
            }
            target_conn.send(payload)

    # ------------- [SERVER LOOP] -------------

    def _handle_client(self, client_sock: socket.socket, client_addr: tuple) -> None:
        conn = ClientConnection(sock=client_sock, file_reader=client_sock.makefile("r", encoding="utf-8"))
        with self.clients_lock:
            self.clients[client_sock] = conn
            
        # Send Welcome JSON
        # --- MUTUAL AUTH: Send Server Certificate ---
        conn.server_nonce = secrets.token_urlsafe(24)
        server_hello_signature = self.channel.sign_message(
            f"{conn.server_nonce}|IAM-Server",
            self.server_private_key
        )
        conn.send({
            "type": "server_hello", 
            "certificate": self.server_cert_pem,
            "server_nonce": conn.server_nonce,
            "server_signature": server_hello_signature,
            "message": "Connected to IAM Backend Server. Please login or register."
        })
        
        ip = client_addr[0]
        
        try:
            while True:
                raw_line = conn.file_reader.readline()
                if not raw_line:
                    break
                    
                req = json.loads(raw_line)
                
                # Chống replay attack (Kiểm tra xem req có timestamp/msg_nonce hợp lệ không)
                if not self.replay_protector.check_replay(req.get("timestamp"), req.get("msg_nonce")):
                    print(f"[X] Blocked replayed or invalid payload from {client_addr}")
                    conn.send({"type": "error", "message": "Replay attack detected or invalid timestamp/msg_nonce"})
                    continue
                
                req_type = req.get("type")
                
                # Public Endpoints
                if req_type == "login":
                    self.handle_login(req, conn, ip)
                    continue
                elif req_type == "register":
                    self.handle_register(req, conn, ip)
                    continue
                
                # Authenticated Endpoints
                user_id = self._require_auth(req, conn)
                if not user_id:
                    continue
                    
                if req_type == "cert_req":
                    self.handle_cert_request(req, conn, user_id)
                elif req_type == "directory":
                    self.handle_directory(req, conn, user_id)
                elif req_type == "chat_directory":
                    self.handle_chat_directory(req, conn, user_id)
                elif req_type == "audit_query":
                    self.handle_audit_query(req, conn, user_id)
                elif req_type == "key_list":
                    self.handle_key_list(req, conn, user_id)
                elif req_type == "key_gen":
                    self.handle_key_gen(req, conn, user_id)
                elif req_type == "relay":
                    self.handle_relay(req, conn, user_id)
                else:
                    conn.send({"type": "error", "message": f"Unknown request type: {req_type}"})
                    
        except Exception as e:
            import traceback
            print(f"[ERROR] Connection handling failed for {client_addr}: {e}")
            traceback.print_exc()
        finally:
            with self.clients_lock:
                if client_sock in self.clients:
                    del self.clients[client_sock]
                if conn.user_id and conn.user_id in self.active_users:
                    if self.active_users[conn.user_id] == conn:
                        del self.active_users[conn.user_id]
            try:
                conn.file_reader.close()
                client_sock.close()
            except:
                pass


    def start(self) -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(10)

        print(f"[START] IAM API Server đang lắng nghe tại {self.host}:{self.port}")
        self.audit_logger.log_event(AuditEventType.USER_LOGIN, "system", "backend", "start_server", "success")
        
        while True:
            client_sock, client_addr = server_sock.accept()
            thread = threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True)
            thread.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IAM Backend Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind")
    args = parser.parse_args()

    server = IAMBackendServer(args.host, args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[STOP] Shutting down IAM Backend Server...")
        sys.exit(0)
