"""
Identity and Access Management (IAM) Module
Quản lý danh tính người dùng, xác thực, và phân quyền truy cập
"""

import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, TYPE_CHECKING
from enum import Enum
import secrets
import base64

if TYPE_CHECKING:
    from .storage_backend import UserStorage, SessionStorage


class Role(Enum):
    """Các vai trò trong hệ thống"""
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    GUEST = "guest"


class Permission:
    """Quyền truy cập"""
    def __init__(self, resource: str, action: str):
        self.resource = resource
        self.action = action
    
    def __eq__(self, other):
        return self.resource == other.resource and self.action == other.action
    
    def __hash__(self):
        return hash((self.resource, self.action))
    
    def __str__(self):
        return f"{self.resource}:{self.action}"


class RoleBasedAccessControl:
    """Kiểm soát truy cập dựa trên vai trò (RBAC)"""
    def __init__(self):
        self.role_permissions: Dict[Role, Set[Permission]] = {
            Role.ADMIN: {
                Permission("keys", "create"),
                Permission("keys", "read"),
                Permission("keys", "update"),
                Permission("keys", "delete"),
                Permission("keys", "rotate"),
                Permission("users", "create"),
                Permission("users", "read"),
                Permission("users", "update"),
                Permission("users", "delete"),
                Permission("audit", "read"),
                Permission("chat", "discover"),
                Permission("chat", "send"),
                Permission("chat", "receive"),
            },
            Role.MANAGER: {
                Permission("keys", "read"),
                Permission("keys", "rotate"),
                Permission("users", "read"),
                Permission("users", "update"),
                Permission("audit", "read"),
            },
            Role.USER: {
                Permission("keys", "create"),
                Permission("keys", "read"),
                Permission("audit", "read_own"),
                Permission("chat", "discover"),
                Permission("chat", "send"),
                Permission("chat", "receive"),

            },
            Role.GUEST: {
                Permission("keys", "read_public"),
            }
        }
    
    def has_permission(self, role: Role, permission: Permission) -> bool:
        """Kiểm tra quyền"""
        return permission in self.role_permissions.get(role, set())
    
    def add_permission(self, role: Role, permission: Permission):
        """Thêm quyền cho vai trò"""
        if role not in self.role_permissions:
            self.role_permissions[role] = set()
        self.role_permissions[role].add(permission)
    
    def remove_permission(self, role: Role, permission: Permission):
        """Xóa quyền từ vai trò"""
        if role in self.role_permissions:
            self.role_permissions[role].discard(permission)


class MFAProvider:
    """Multi-Factor Authentication Provider"""
    def __init__(self):
        self.mfa_secrets: Dict[str, str] = {}
        self.mfa_attempts: Dict[str, int] = {}
    
    def generate_mfa_secret(self, user_id: str) -> str:
        """Sinh mã MFA"""
        secret = secrets.token_urlsafe(32)
        self.mfa_secrets[user_id] = secret
        self.mfa_attempts[user_id] = 0
        return secret
    
    def verify_mfa(self, user_id: str, code: str) -> bool:
        """Xác minh mã MFA"""
        if user_id not in self.mfa_secrets:
            return False
        
        attempts = self.mfa_attempts.get(user_id, 0)
        if attempts >= 5:  # Giới hạn 5 lần thử
            return False
        
        secret = self.mfa_secrets[user_id]
        # Trong thực tế sẽ dùng TOTP/HOTP, ở đây đơn giản hóa
        is_valid = code == secret[:6]  # So sánh với 6 ký tự đầu
        
        if not is_valid:
            self.mfa_attempts[user_id] = attempts + 1
        else:
            self.mfa_attempts[user_id] = 0
        
        return is_valid


class User:
    """Người dùng trong hệ thống"""
    def __init__(self, user_id: str, username: str, email: str, 
                 password_hash: str, roles: List[Role]):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.roles = roles
        self.created_at = datetime.now()
        self.last_login: Optional[datetime] = None
        self.is_active = True
        self.mfa_enabled = False
        self.mfa_secret: Optional[str] = None
        self.groups: List[str] = []
        self.attributes: Dict[str, str] = {}
    
    def to_dict(self):
        return {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'password_hash': self.password_hash,
            'roles': [role.value for role in self.roles],
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'status': 'active' if self.is_active else 'inactive',
            'mfa_enabled': self.mfa_enabled,
            'mfa_secret': self.mfa_secret,
            'groups': self.groups,
            'attributes': self.attributes
        }


class Session:
    """Phiên làm việc của người dùng"""
    def __init__(self, session_id: str, user_id: str, 
                 duration_minutes: int = 60):
        self.session_id = session_id
        self.user_id = user_id
        self.created_at = datetime.now()
        self.expires_at = datetime.now() + timedelta(minutes=duration_minutes)
        self.is_active = True
        self.ip_address: Optional[str] = None
        self.user_agent: Optional[str] = None
        self.mfa_verified = False
    
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at
    
    def to_dict(self):
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'is_active': self.is_active,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'mfa_verified': self.mfa_verified
        }


class IdentityManagementSystem:
    """Hệ thống quản lý danh tính"""
    def __init__(self, storage_path: str = "iam_storage",
                 storage: Optional['UserStorage'] = None,
                 session_storage: Optional['SessionStorage'] = None,
                 key_store: Optional['KeyStore'] = None):
        self.storage_path = storage_path
        
        if storage is not None:
            self.storage = storage
        else:
            from .db import get_working_connection_string
            from .storage_backend import SqlServerUserStorage

            conn_str = get_working_connection_string()
            self.storage = SqlServerUserStorage(conn_str)

        if session_storage is not None:
            self.session_storage = session_storage
        else:
            from .db import get_working_connection_string
            from .storage_backend import SqlServerSessionStorage
            conn_str = get_working_connection_string()
            self.session_storage = SqlServerSessionStorage(conn_str)
        
        # Store reference to KeyStore (optional, for auto key generation on user creation)
        self.key_store = key_store
        
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.rbac = RoleBasedAccessControl()
        self.mfa = MFAProvider()
        
        self._load_users()
        self._load_sessions()
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> str:
        """Băm mật khẩu với salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )
        
        return f"{salt}${password_hash.hex()}"
    
    def verify_password(self, password: str, password_hash: Optional[str]) -> bool:
        """Xác minh mật khẩu"""
        if not password_hash or '$' not in password_hash:
            return False

        salt = password_hash.split('$')[0]
        new_hash = self.hash_password(password, salt)
        return new_hash == password_hash
    
    def create_user(self, username: str, email: str, password:  str,
                   roles: Optional[List[Role]] = None) -> User:
        """Tạo người dùng mới và tự động sinh initial account key"""
        if roles is None:
            roles = [Role.USER]
        
        user_id = secrets.token_hex(8)
        password_hash = self.hash_password(password)
        
        user = User(user_id, username, email, password_hash, roles)
        self.users[user_id] = user
        
        self._save_user(user)
        
        # Auto-generate initial account key and store to keystore
        if self.key_store is not None:
            try:
                key_id = f"user_{user_id}_initial"
                self.key_store.generate_symmetric_key(
                    key_id=key_id,
                    owner=user_id,
                    purpose="initial account Key",
                    algorithm="AES-256"
                )
                print(f"[IAM] ✓ Generated initial key for user {username}: {key_id}")
            except Exception as e:
                print(f"[IAM] ⚠ Failed to generate initial key for user {username}: {e}")
        
        return user
    
    def authenticate_user(self, username: str, password: str, 
                         ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> Optional[Session]:
        """Xác thực người dùng"""
        # Tìm user theo username
        user = None
        for u in self.users.values():
            if u.username == username:
                user = u
                break
        
        if user is None or not user.is_active:
            return None
        
        # Xác minh mật khẩu
        if not self.verify_password(password, user.password_hash):
            return None
        
        # Tạo phiên
        session_id = secrets.token_hex(16)
        session = Session(session_id, user.user_id)
        session.ip_address = ip_address
        session.user_agent = user_agent
        
        # Nếu MFA được bật, cần xác minh MFA
        if user.mfa_enabled:
            session.mfa_verified = False  # Chờ xác minh MFA
        else:
            session.mfa_verified = True
        
        self.sessions[session_id] = session
        user.last_login = datetime.now()
        self._persist_session(session)
        
        return session
    
    def validate_session(self, session_id: str) -> bool:
        """Xác thực phiên"""
        session = self.sessions.get(session_id)
        
        if session is None:
            return False
        
        if session.is_expired():
            session.is_active = False
            return False
        
        if not session.is_active:
            return False
        
        if not session.mfa_verified:
            return False
        
        return True
    
    def get_user_permissions(self, user_id: str) -> Set[Permission]:
        """Lấy quyền của người dùng"""
        user = self.users.get(user_id)
        if user is None:
            return set()
        
        permissions = set()
        for role in user.roles:
            permissions.update(self.rbac.role_permissions.get(role, set()))
        
        return permissions
    
    def check_permission(self, user_id: str, permission: Permission) -> bool:
        """Kiểm tra quyền của người dùng"""
        permissions = self.get_user_permissions(user_id)
        return permission in permissions
    
    def enable_mfa(self, user_id: str) -> str:
        """Bật MFA cho người dùng"""
        user = self.users.get(user_id)
        if user is None:
            raise ValueError(f"Người dùng {user_id} không tồn tại")
        
        mfa_secret = self.mfa.generate_mfa_secret(user_id)
        user.mfa_enabled = True
        user.mfa_secret = mfa_secret
        self._save_user(user)
        
        return mfa_secret
    
    def verify_mfa(self, user_id: str, code: str) -> bool:
        """Xác minh MFA"""
        return self.mfa.verify_mfa(user_id, code)
    
    def logout(self, session_id: str):
        """Đăng xuất"""
        if session_id in self.sessions:
            self.sessions[session_id].is_active = False
            self.session_storage.deactivate_session(session_id)
    
    def _save_user(self, user: User):
        """Lưu người dùng qua storage backend"""
        self.storage.save_user(user.to_dict())
    
    def _load_users(self):
        """Tải các người dùng từ storage backend"""
        for data in self.storage.load_all_users():
            user = User(
                data['user_id'],
                data['username'],
                data['email'],
                data.get('password_hash', ''),
                [Role(r) for r in data.get('roles', ['user'])]
            )
            status = data.get('status', 'active')
            user.is_active = (status == 'active') if status else data.get('is_active', True)
            user.mfa_enabled = data.get('mfa_enabled', False)
            user.mfa_secret = data.get('mfa_secret')
            user.groups = data.get('groups', [])
            user.attributes = data.get('attributes', {})

            if user.mfa_secret and user.mfa_enabled:
                self.mfa.mfa_secrets[user.user_id] = user.mfa_secret
                self.mfa.mfa_attempts[user.user_id] = 0

            if data.get('created_at'):
                try:
                    user.created_at = datetime.fromisoformat(data['created_at'])
                except (ValueError, TypeError):
                    pass
            if data.get('last_login'):
                try:
                    user.last_login = datetime.fromisoformat(data['last_login'])
                except (ValueError, TypeError):
                    pass

            self.users[user.user_id] = user

    def _persist_session(self, session: Session):
        """Lưu session vào persistence layer."""
        self.session_storage.save_session(session.to_dict())

    def _load_sessions(self):
        """Khôi phục các session active từ DB."""
        for data in self.session_storage.load_active_sessions():
            session = Session(data['session_id'], data['user_id'])
            if data.get('created_at'):
                try:
                    session.created_at = datetime.fromisoformat(data['created_at'])
                except (ValueError, TypeError):
                    pass
            if data.get('expires_at'):
                try:
                    session.expires_at = datetime.fromisoformat(data['expires_at'])
                except (ValueError, TypeError):
                    pass
            session.is_active = data.get('is_active', True)
            session.ip_address = data.get('ip_address')
            session.user_agent = data.get('user_agent')
            session.mfa_verified = data.get('mfa_verified', False)
            if session.is_expired():
                self.session_storage.deactivate_session(session.session_id)
                continue
            self.sessions[session.session_id] = session
    
    def list_users(self) -> List[Dict]:
        """Liệt kê người dùng"""
        return [user.to_dict() for user in self.users.values()]
    
    def update_user_roles(self, user_id: str, roles: List[Role]):
        """Cập nhật vai trò người dùng"""
        user = self.users.get(user_id)
        if user is None:
            raise ValueError(f"Người dùng {user_id} không tồn tại")
        
        user.roles = roles
        self._save_user(user)
    
    def deactivate_user(self, user_id: str):
        """Vô hiệu hóa người dùng"""
        user = self.users.get(user_id)
        if user is None:
            raise ValueError(f"Người dùng {user_id} không tồn tại")
        
        user.is_active = False
        self._save_user(user)
