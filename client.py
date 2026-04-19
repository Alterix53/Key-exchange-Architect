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
from datetime import datetime
from typing import Any, Dict, Optional, List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from src.secure_transmission import SecureTransmissionChannel, ReplayProtector
from src.public_key_distribution import verify_certificate, extract_public_key

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
        
        # Crypto
        self.channel = SecureTransmissionChannel()
        self.replay_protector = ReplayProtector(time_window_seconds=30)
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        
        # E2E Chat state
        self.in_chat_mode = False
        self.chat_peer_id: Optional[str] = None
        self.chat_session_key: Optional[bytes] = None
        self.chat_peer_public_key: Any = None
        self.ca_public_key_pem: Optional[str] = None

        self._receive_thread = None
        self._running = False
        
        # Async responses routing
        self.pending_responses: Dict[str, Dict] = {}
        self._response_cv = threading.Condition()

    def _public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.reader = self.sock.makefile("r", encoding="utf-8")
            self._running = True
            
            # Khởi động luồng nhận dữ liệu
            self._receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self._receive_thread.start()
            
            # Load CA PublicKey (PINNED TRUSTED ROOT)
            ca_path = "data/ca_public.pem"
            if os.path.exists(ca_path):
                with open(ca_path, "r") as f:
                    self.ca_public_key_pem = f.read()
            else:
                print_error(f"LỖI: Không tìm thấy Trusted CA Root tại '{ca_path}'!")
                print_error("Hệ thống từ chối kết nối để bảo vệ khỏi MITM (Fail-Closed).")
                sys.exit(1)

            import time
            time.sleep(0.5) # Để kịp nhận dòng welcome
            
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

            self._send_req(req)
            
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
                    elif req_type == "peer_session_key":
                        self._handle_peer_session_key(data)
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
            print(f"\n{Colors.OKBLUE}[DECRYPT] {sender}: {plaintext}{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}[LỖI DECRYPT] {str(e)}{Colors.ENDC}")

    def _handle_peer_session_key(self, data: Dict):
        try:
            encrypted_key = data.get("encrypted_key", "")
            signature = data.get("signature", "")
            sender_cert = data.get("sender_cert", "")
            sender_id = data.get("sender_id", "")
            
            if not signature or not sender_cert:
                print(f"\n{Colors.FAIL}[LỖI MUTUAL AUTH] Gói tin Session Key thiếu Chữ ký hoặc Chứng chỉ từ {sender_id}. Bị từ chối!{Colors.ENDC}")
                return
                
            # Trích xuất Public Key của người gửi từ Chứng chỉ đính kèm
            peer_pub_key = extract_public_key(sender_cert)
            
            # Giải mã lấy Raw Session Key (vẫn dạng base64)
            key_b64 = self.channel.decrypt_rsa_oaep(encrypted_key, self.private_key)
            
            # Verify chữ ký bằng đúng Raw Session Key b64
            is_valid_sig = self.channel.verify_signature(key_b64, signature, peer_pub_key)
            if not is_valid_sig:
                print(f"\n{Colors.FAIL}[LỖI MUTUAL AUTH] Chữ ký số từ {sender_id} KHÔNG HỢP LỆ! Nghi ngờ giả mạo. Bị từ chối!{Colors.ENDC}")
                return
                
            self.chat_session_key = base64.b64decode(key_b64)
            print(f"\n{Colors.OKGREEN}[STATUS] Mutual Auth thành công! Đã nhận session key từ {sender_id}. Sẵn sàng Chat!{Colors.ENDC}")
        except Exception as e:
            print(f"\n{Colors.FAIL}[LỖI KEY XCHG] Không thể giải mã/xác nhận session key: {str(e)}{Colors.ENDC}")

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
        
        res = self._sync_request({
            "type": "login",
            "username": username,
            "password": password
        }, "login_ok")
        
        if res:
            self.session_id = res.get("session_id")
            self.user_info = res.get("user")
            self.username = username
            print_success(f"Đăng nhập thành công! Xin chào, {self.user_info.get('username')}.")
            
            # --- START FIX PERSISTENT RSA KEYS CHO E2E ---
            os.makedirs("demo_keys", exist_ok=True)
            priv_path = os.path.join("demo_keys", f"{self.user_info.get('user_id')}_private.pem")
            
            from cryptography.hazmat.backends import default_backend
            if os.path.exists(priv_path):
                # Tải khóa cũ nếu đã có
                with open(priv_path, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
                self.public_key = self.private_key.public_key()
            else:
                # Lưu khóa mới nếu chưa có
                with open(priv_path, "wb") as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
            
            # Tự động cập nhật PKI Certificate ngầm định với CA mỗi khi login
            # Để luôn public key mới nhất / hoặc có sẵn trên Server
            self._sync_request({
                "type": "cert_req",
                "public_key": self._public_key_pem()
            }, "cert_info")
            # --- END FIX ---

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
            role_str = ", ".join(self.user_info.get("roles", []))
            username = self.user_info.get('username')
            
            print(f"\n{Colors.HEADER}╔══════════════════════════════════════════╗")
            print(f"║  Xin chào, {username}! (Role: {role_str})")
            print(f"╠══════════════════════════════════════════╣{Colors.ENDC}")
            print("  1. 🔑 Quản lý khóa (Key Management)")
            print("  2. 📜 Xem chứng chỉ (Certificate)")
            print("  3. 📋 Xem audit log")
            print("  4. 👥 Xem danh sách users")
            print("  5. 💬 Chế độ chat mã hóa E2E")
            print("  0. 🚪 Đăng xuất")
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
            elif choice == "0":
                self.session_id = None
                self.user_info = None
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
        print("Chọn thuật toán:")
        print("  1. AES-256 (Đối xứng)")
        print("  2. AES-128 (Đối xứng)")
        print("  3. RSA-2048 (Bất đối xứng)")
        
        algo_c = input("Chọn: ")
        algo = "AES-256"
        if algo_c == "2": algo = "AES-128"
        elif algo_c == "3": algo = "RSA-2048"
        
        name = input("Tên khóa: ")
        purp = input("Mục đích: ")
        
        res = self._sync_request({
            "type": "key_gen",
            "algorithm": algo,
            "key_name": name,
            "purpose": purp
        }, "key_gen_ok")
        if res:
            print_success(f"Khóa '{name}' ({algo}) đã được sinh thành công! (ID: {res.get('key_id')})")

    def do_key_list(self):
        print_header("Danh sách KHÓA")
        res = self._sync_request({"type": "key_list"}, "key_list_res")
        if res:
            keys = res.get("keys", [])
            if not keys:
                print("Chưa có khóa nào.")
            for k in keys:
                active = "Hoạt động" if k['is_active'] else "Đã vô hiệu"
                print(f" • {k['key_id']} | {k['algorithm']} | {k['purpose']} | {active}")

    def do_cert_info(self):
        print_header("Chứng chỉ (Certificate)")
        res = self._sync_request({
            "type": "cert_req",
            "public_key": self._public_key_pem()
        }, "cert_info")
        if res:
            cert = res.get("certificate", {})
            # BỎ QUA CA Public Key từ network để tránh bị MITM
            # self.ca_public_key_pem = res.get("ca_public_key")
            print_success("Đã nhận chứng chỉ từ CA.")
            print(json.dumps(cert, indent=2))

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
            for u in res.get("users", []):
                status = f"{Colors.OKGREEN}Online{Colors.ENDC}" if u['online'] else "Offline"
                cert_status = "Có" if u['has_cert'] else "Không"
                print(f" • {u['username']} (ID: {u['user_id']}) | Trạng thái: {status} | Đã ĐK Cert: {cert_status}")

    def do_chat_e2e(self):
        print_header("Chế độ Chat Mã hóa E2E")
        self.do_chat_directory() # Show danh bạ thu gọn

        target_uid = input("\nNhập User ID muốn chat: ").strip()
        if not target_uid:
            return
            
        print("[1] Đang lấy Certificate của đối tác...")
        res = self._sync_request({
            "type": "relay",
            "relay_type": "get_cert",
            "target_id": target_uid
        }, "peer_cert_response")
        
        if not res:
            return
            
        cert = res.get("certificate")
        if not self.ca_public_key_pem:
            print_error("Thiếu public key của CA để xác minh!")
            return
            
        is_valid = verify_certificate(cert, self.ca_public_key_pem, expected_subject=target_uid)
        if not is_valid:
            print_error("Certificate KHÔNG HỢP LỆ! Dừng kết nối.")
            return
            
        print_success("Certificate hợp lệ.")
        self.chat_peer_public_key = extract_public_key(cert)
        
        print("[2] Khởi tạo Key Exchange (RSA) và Ký hiệu (Digital Signature)...")
        self.chat_session_key = os.urandom(32)
        session_key_b64 = base64.b64encode(self.chat_session_key).decode("utf-8")
        
        # Mã hóa bằng Public Key của đối tác
        encrypted_key = self.channel.encrypt_rsa_oaep(
            session_key_b64, 
            self.chat_peer_public_key
        )
        
        # Ký điện tử Payload (giữ tính nguyên vẹn và xác thực bằng Private Key của mình)
        signature = self.channel.sign_message(session_key_b64, self.private_key)
        
        self._send_req({
            "type": "relay",
            "relay_type": "session_key",
            "target_id": target_uid,
            "encrypted_key": encrypted_key,
            "signature": signature
        })
        print_success("Đã gửi Session Key. Sẵn sàng chat!")
        
        self.in_chat_mode = True
        self.chat_peer_id = target_uid
        
        print(f"\n{Colors.WARNING}--- Bắt đầu Chat (gõ 'back' để thoát) ---{Colors.ENDC}")
        try:
            while True:
                msg = input("")
                if msg.strip() == "back":
                    break
                if not msg.strip():
                    continue
                    
                assoc_data = f"{self.user_info.get('user_id')}:relay"
                nonce, ciphertext, tag = self.channel.encrypt_aes_256_gcm(msg, self.chat_session_key, assoc_data)
                
                # In ra log ENCRYPT
                print(f"{Colors.WARNING}[ENCRYPT] {json.dumps({'nonce': nonce[:10]+'...', 'ciphertext': ciphertext[:20]+'...'}, ensure_ascii=False)}{Colors.ENDC}")
                
                self._send_req({
                    "type": "relay",
                    "relay_type": "chat_msg",
                    "target_id": self.chat_peer_id,
                    "algorithm": "AES-256-GCM",
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "tag": tag,
                    "associated_data": assoc_data
                })
        except Exception as e:
            print_error(f"Chat error: {e}")
        finally:
            self.in_chat_mode = False
            self.chat_peer_id = None
            self.chat_session_key = None

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
