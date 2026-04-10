"""
IAM System - Main Integration Module
Tích hợp tất cả các component
"""

from .key_management import KeyStore
from .identity_management import IdentityManagementSystem, Role, Permission
from .secure_transmission import SecureTransmissionChannel, SecureMessage
from .audit_logging import AuditLogger, AuditEventType
from typing import Optional
import os


class IAMSystem:
    """Hệ thống quản lý danh tính, khóa, và truyền dữ liệu an toàn"""
    
    def __init__(self, base_path: str = "iam_system_data"):
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)
        
        # Khởi tạo các module
        self.key_store = KeyStore(os.path.join(base_path, "keys"))
        self.identity_mgmt = IdentityManagementSystem(
            os.path.join(base_path, "identity")
        )
        self.transmission = SecureTransmissionChannel()
        self.audit_logger = AuditLogger(os.path.join(base_path, "audit"))
    
    def initialize_admin_user(self) -> str:
        """Tạo người dùng admin mặc định"""
        try:
            admin = self.identity_mgmt.create_user(
                username="admin",
                email="admin@system.local",
                password="AdminPassword@123",
                roles=[Role.ADMIN]
            )
            
            self.audit_logger.log_event(
                AuditEventType.USER_CREATED,
                "system",
                "users",
                "create_admin_user",
                "success",
                {"user_id": admin.user_id, "username": "admin"}
            )
            
            return admin.user_id
        except Exception as e:
            self.audit_logger.log_event(
                AuditEventType.SYSTEM_ERROR,
                "system",
                "users",
                "create_admin_user",
                "failed",
                {"error": str(e)}
            )
            raise
    
    def setup_key_hierarchy(self, owner_id: str):
        """Thiết lập cấp bậc khóa"""
        # Master Key đã được tạo tự động
        
        # Tạo khóa dữ liệu
        data_key_id = self.key_store.generate_symmetric_key(
            f"data_key_{owner_id}",
            owner_id,
            "Data Encryption",
            "AES-256"
        )
        
        # Tạo khóa giao tiếp
        comm_key_id = self.key_store.generate_symmetric_key(
            f"communication_key_{owner_id}",
            owner_id,
            "Communication Encryption",
            "AES-256"
        )
        
        # Tạo cặp RSA cho chữ ký
        rsa_key_id, rsa_pub_id = self.key_store.generate_asymmetric_key_pair(
            f"signature_key_{owner_id}",
            owner_id,
            "Message Signing",
            2048
        )
        
        self.audit_logger.log_event(
            AuditEventType.KEY_GENERATED,
            owner_id,
            "keys",
            "setup_key_hierarchy",
            "success",
            {
                "data_key": data_key_id,
                "comm_key": comm_key_id,
                "rsa_key": rsa_key_id
            }
        )
        
        return {
            'data_key': data_key_id,
            'comm_key': comm_key_id,
            'rsa_key': rsa_key_id,
            'rsa_pub': rsa_pub_id
        }
    
    def authenticate_and_authorize(self, username: str, password: str,
                                  resource: str, action: str,
                                  ip_address: Optional[str] = None) -> bool:
        """Xác thực người dùng và phân quyền"""
        # Xác thực
        session = self.identity_mgmt.authenticate_user(
            username, password, ip_address
        )
        
        if session is None:
            self.audit_logger.log_event(
                AuditEventType.USER_FAILED_LOGIN,
                username,
                "users",
                "login",
                "failed",
                {"reason": "invalid_credentials"},
                ip_address
            )
            return False
        
        # Ghi lại đăng nhập thành công
        self.audit_logger.log_event(
            AuditEventType.USER_LOGIN,
            session.user_id,
            "sessions",
            "login",
            "success",
            {"session_id": session.session_id},
            ip_address
        )
        
        # Phân quyền
        permission = Permission(resource, action)
        has_permission = self.identity_mgmt.check_permission(
            session.user_id,
            permission
        )
        
        if has_permission:
            self.audit_logger.log_event(
                AuditEventType.PERMISSION_GRANTED,
                session.user_id,
                resource,
                action,
                "success"
            )
        else:
            self.audit_logger.log_event(
                AuditEventType.PERMISSION_DENIED,
                session.user_id,
                resource,
                action,
                "failed"
            )
        
        return has_permission
    
    def access_key(self, user_id: str, key_id: str) -> bool:
        """Truy cập khóa với kiểm soát quyền"""
        permission = Permission("keys", "read")
        
        if not self.identity_mgmt.check_permission(user_id, permission):
            self.audit_logger.log_event(
                AuditEventType.PERMISSION_DENIED,
                user_id,
                "keys",
                f"access_{key_id}",
                "failed"
            )
            return False
        
        self.audit_logger.log_event(
            AuditEventType.KEY_ACCESSED,
            user_id,
            "keys",
            f"access_{key_id}",
            "success"
        )
        
        return True
    
    def send_encrypted_message(self, sender_id: str, recipient_id: str,
                               message_content: str, encryption_key: bytes) -> dict:
        """Gửi thông điệp được mã hóa"""
        message = SecureMessage(sender_id, recipient_id, message_content)
        encrypted_msg = self.transmission.send_secure_message(message, encryption_key)
        
        self.audit_logger.log_event(
            AuditEventType.MESSAGE_SENT,
            sender_id,
            "messages",
            f"send_to_{recipient_id}",
            "success",
            {"message_id": message.message_id, "algorithm": "AES-256-GCM"}
        )
        
        return encrypted_msg
    
    def receive_encrypted_message(self, recipient_id: str,
                                 encrypted_message: dict,
                                 decryption_key: bytes) -> Optional[str]:
        """Nhận và giải mã thông điệp"""
        plaintext = self.transmission.receive_secure_message(
            encrypted_message,
            decryption_key
        )
        
        if plaintext:
            self.audit_logger.log_event(
                AuditEventType.MESSAGE_RECEIVED,
                recipient_id,
                "messages",
                f"receive_from_{encrypted_message['sender_id']}",
                "success",
                {"message_id": encrypted_message['message_id']}
            )
        else:
            self.audit_logger.log_event(
                AuditEventType.MESSAGE_DECRYPTION_FAILED,
                recipient_id,
                "messages",
                "decrypt",
                "failed",
                {"message_id": encrypted_message['message_id']}
            )
        
        return plaintext
    
    def enable_mfa_for_user(self, user_id: str) -> str:
        """Bật MFA cho người dùng"""
        mfa_secret = self.identity_mgmt.enable_mfa(user_id)
        
        self.audit_logger.log_event(
            AuditEventType.MFA_ENABLED,
            user_id,
            "users",
            "enable_mfa",
            "success"
        )
        
        return mfa_secret
    
    def rotate_key(self, user_id: str, key_id: str) -> str:
        """Xoay vòng khóa"""
        new_key_id = self.key_store.rotate_key(key_id)
        
        self.audit_logger.log_event(
            AuditEventType.KEY_ROTATED,
            user_id,
            "keys",
            f"rotate_{key_id}",
            "success",
            {"new_key_id": new_key_id}
        )
        
        return new_key_id
    
    def get_system_audit_report(self) -> dict:
        """Lấy báo cáo kiểm tra hệ thống"""
        all_logs = self.audit_logger.get_all_logs()
        
        return {
            'total_events': len(all_logs),
            'users_count': len(self.identity_mgmt.users),
            'keys_count': len(self.key_store.keys_metadata),
            'recent_events': all_logs[-10:],
            'system_status': 'operational'
        }
