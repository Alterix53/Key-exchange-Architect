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
        print("[INIT] Đang tải các phân hệ IAM...")
        self.iam = IdentityManagementSystem("demo_identity")
        self.key_store = KeyStore("demo_keys")
        self.audit_logger = AuditLogger("demo_audit")
        self.ca = CertificateAuthority(data_dir="data")
        self.channel = SecureTransmissionChannel()
        self.replay_protector = ReplayProtector(time_window_seconds=30)
        
        self.clients: Dict[socket.socket, ClientConnection] = {}
        self.clients_lock = threading.Lock()
        
        # Cho E2E Chat
        self.active_users: Dict[str, ClientConnection] = {} # user_id -> ClientConnection

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
        
        session = self.iam.authenticate_user(username, password, ip)
        if session:
            self.audit_logger.log_event(AuditEventType.USER_LOGIN, session.user_id, "backend", "login", "success", ip_address=ip)
            user_info = self.iam.users[session.user_id].to_dict()
            with self.clients_lock:
                conn.session_id = session.session_id
                conn.user_id = session.user_id
                self.active_users[session.user_id] = conn
                
            conn.send({
                "type": "login_ok",
                "session_id": session.session_id,
                "user": user_info
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
        
        try:
            if algorithm.startswith("AES"):
                k_id = self.key_store.generate_symmetric_key(key_name, user_id, purpose, algorithm)
            elif algorithm.startswith("RSA"):
                k_id, _ = self.key_store.generate_asymmetric_key_pair(key_name, user_id, purpose)
            else:
                raise ValueError("Unsupported algorithm")
                
            self.audit_logger.log_event(AuditEventType.KEY_GENERATED, user_id, "backend", "key_gen", "success", details={"key_id": k_id, "algo": algorithm})
            conn.send({"type": "key_gen_ok", "key_id": k_id, "message": "Đã sinh khóa thành công"})
        except Exception as e:
            conn.send({"type": "error", "message": str(e)})

    # ------------- [E2E RELAY ROUTING] -------------

    def handle_relay(self, req: Dict, conn: ClientConnection, user_id: str) -> None:
        """Trung chuyển gói tin E2E: chat, cert_request (để chat), session_key"""
        target_id = req.get("target_id")
        relay_type = req.get("relay_type")
        
        if not target_id:
            return
            
        if target_id not in self.active_users:
            conn.send({"type": "error", "message": "Target user is completely offline"})
            return
            
        target_conn = self.active_users[target_id]
        
        # E2E - Client muốn lấy cert của ng khác để chat
        if relay_type == "get_cert":
            target_cert = self.ca.get_certificate(target_id)
            if target_cert:
                conn.send({"type": "peer_cert_response", "target_id": target_id, "certificate": target_cert})
            else:
                conn.send({"type": "error", "message": f"Certificate for {target_id} not found"})
        
        # E2E - Gửi Session Key
        elif relay_type == "session_key":
            req["type"] = "peer_session_key"
            req["sender_id"] = user_id
            req["sender_cert"] = self.ca.get_certificate(user_id)
            del req["relay_type"]
            target_conn.send(req)
            
        # E2E - Chat Message
        elif relay_type == "chat_msg":
            self.audit_logger.log_event(AuditEventType.MESSAGE_RECEIVED, user_id, "backend", "relay", "success", details={"to": target_id})
            payload = {
                "type": "relayed_chat_msg",
                "sender_id": user_id,
                "target_id": target_id,
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
        conn.send({
            "type": "welcome", 
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
