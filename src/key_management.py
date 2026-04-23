"""
Key Management Module
Quản lý sinh ra, lưu trữ, phân phối, và xoay vòng khóa
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, TYPE_CHECKING
from cryptography.hazmat.primitives.asymmetric import rsa, padding

if TYPE_CHECKING:
    from .storage_backend import KeyStorage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import secrets
import base64


class KeyMetadata:
    """Metadata cho mỗi khóa"""
    def __init__(self, key_id: str, owner: str, algorithm: str, key_size: int, 
                 purpose: str, expiry_days: int = 365,
                 private_key_password_protected: bool = False):
        self.key_id = key_id
        self.owner = owner
        self.algorithm = algorithm
        self.key_size = key_size
        self.purpose = purpose
        self.private_key_password_protected = private_key_password_protected
        self.created_at = datetime.now()
        self.expires_at = datetime.now() + timedelta(days=expiry_days)
        self.last_rotated = datetime.now()
        self.is_active = True
        self.version = 1
        
    def to_dict(self):
        return {
            'key_id': self.key_id,
            'owner': self.owner,
            'algorithm': self.algorithm,
            'key_size': self.key_size,
            'purpose': self.purpose,
            'private_key_password_protected': self.private_key_password_protected,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'last_rotated': self.last_rotated.isoformat(),
            'is_active': self.is_active,
            'version': self.version
        }
    
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at


class KeyStore:
    """Lưu trữ khóa an toàn"""
    def __init__(self, storage_path: str = "keys_storage", storage: Optional['KeyStorage'] = None):
        self.storage_path = storage_path
        
        if storage is not None:
            self.storage = storage
        else:
            from .db import get_working_connection_string
            from .storage_backend import SqlServerKeyStorage

            conn_str = get_working_connection_string()
            self.storage = SqlServerKeyStorage(conn_str)
            
        self.keys_metadata: Dict[str, KeyMetadata] = {}
        self.master_key = self._load_or_create_master_key()
        
    def _load_or_create_master_key(self) -> bytes:
        """Tạo hoặc tải Master Key để mã hóa khóa khác"""
        return self.storage.load_or_create_master_key()
    
    def generate_symmetric_key(self, key_id: str, owner: str, purpose: str, 
                              algorithm: str = "AES-256") -> str:
        """Sinh khóa đối xứng"""
        if algorithm == "AES-256":
            key = secrets.token_bytes(32)  # Tạo khóa 256 bits
            key_size = 256
        elif algorithm == "AES-128":
            key = secrets.token_bytes(16)  # Tạo khóa 128 bits
            key_size = 128
        else:
            raise ValueError(f"Không hỗ trợ thuật toán: {algorithm}")
        
        # lưu metadata của khóa
        metadata = KeyMetadata(key_id, owner, algorithm, key_size, purpose)
        self.keys_metadata[key_id] = metadata
        
        # Mã hóa khóa trước khi lưu
        encrypted_key = self._encrypt_key(key)
        self._save_encrypted_key(key_id, encrypted_key, metadata)
        
        return key_id
    
    def generate_asymmetric_key_pair(self, key_id: str, owner: str, purpose: str,
                                    key_size: int = 2048,
                                    private_key_password: Optional[str] = None) -> Tuple[str, str, str]:
        """Sinh cặp khóa RSA"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        metadata = KeyMetadata(
            key_id,
            owner,
            "RSA",
            key_size,
            purpose,
            private_key_password_protected=bool(private_key_password)
        )
        self.keys_metadata[key_id] = metadata
        
        # Bảo vệ private key bằng password (nếu có), sau đó tiếp tục mã hóa bằng master key.
        if private_key_password:
            pem_encryption = serialization.BestAvailableEncryption(
                private_key_password.encode('utf-8')
            )
        else:
            pem_encryption = serialization.NoEncryption()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=pem_encryption
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        encrypted_private = self._encrypt_key(private_pem)
        self._save_private_key(key_id, encrypted_private, metadata)
        self._save_public_key(key_id, public_pem)
        
        return key_id, f"{key_id}_pub", private_pem.decode('utf-8')
    
    def _encrypt_key(self, key: bytes) -> bytes:
        """Mã hóa khóa bằng Master Key (AES-256-GCM, có xác thực toàn vẹn)"""
        nonce = os.urandom(12)  # 96-bit nonce cho GCM
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(key) + encryptor.finalize()
        tag = encryptor.tag

        # Format: b"GCM1" + nonce(12) + tag(16) + ciphertext
        return b"GCM1" + nonce + tag + ciphertext
    
    def _decrypt_key(self, encrypted_key: bytes) -> bytes:
        """Giải mã khóa bằng Master Key.

        Ưu tiên định dạng mới AES-GCM; giữ tương thích ngược với dữ liệu cũ AES-CBC.
        """
        if encrypted_key.startswith(b"GCM1"):
            nonce = encrypted_key[4:16]
            tag = encrypted_key[16:32]
            ciphertext = encrypted_key[32:]

            cipher = Cipher(
                algorithms.AES(self.master_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()

        # Legacy fallback: AES-CBC + PKCS7
        iv = encrypted_key[:16]
        ciphertext = encrypted_key[16:]

        cipher = Cipher(algorithms.AES(self.master_key), modes.CBC(iv),
                       backend=default_backend())
        decryptor = cipher.decryptor()
        padded_key = decryptor.update(ciphertext) + decryptor.finalize()

        from cryptography.hazmat.primitives import padding as sym_padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        key = unpadder.update(padded_key) + unpadder.finalize()

        return key
    
    def _save_encrypted_key(self, key_id: str, encrypted_key: bytes, metadata: KeyMetadata):
        """Lưu khóa được mã hóa"""
        self.storage.save_key_bytes(key_id, encrypted_key)
        self.storage.save_metadata(key_id, metadata.to_dict())
    
    def _save_private_key(self, key_id: str, encrypted_key: bytes, metadata: KeyMetadata):
        """Lưu khóa riêng RSA được mã hóa"""
        self.storage.save_private_key_bytes(key_id, encrypted_key)
        self.storage.save_metadata(key_id, metadata.to_dict())
    
    def _save_public_key(self, key_id: str, public_key: bytes):
        """Lưu khóa công khai RSA"""
        self.storage.save_public_key_bytes(key_id, public_key)
    
    def get_symmetric_key(self, key_id: str) -> Optional[bytes]:
        """Lấy khóa đối xứng"""
        if key_id not in self.keys_metadata:
            self._load_metadata(key_id)
        
        metadata = self.keys_metadata.get(key_id)
        if not metadata or metadata.is_expired():
            raise ValueError(f"Khóa {key_id} hết hạn hoặc không tồn tại")
        
        encrypted_key = self.storage.load_key_bytes(key_id)
        if encrypted_key is None:
            return None
        
        return self._decrypt_key(encrypted_key)
    
    def get_private_key(self, key_id: str, private_key_password: Optional[str] = None):
        """Lấy khóa riêng RSA"""
        if key_id not in self.keys_metadata:
            self._load_metadata(key_id)
        
        metadata = self.keys_metadata.get(key_id)
        if not metadata or metadata.is_expired():
            raise ValueError(f"Khóa {key_id} hết hạn hoặc không tồn tại")
        
        encrypted_key = self.storage.load_private_key_bytes(key_id)
        if encrypted_key is None:
            return None
        
        private_pem = self._decrypt_key(encrypted_key)
        password_bytes = None
        if private_key_password is not None:
            password_bytes = private_key_password.encode('utf-8')

        return serialization.load_pem_private_key(
            private_pem,
            password=password_bytes,
            backend=default_backend()
        )
    
    def get_public_key(self, key_id: str):
        """Lấy khóa công khai RSA"""
        public_pem = self.storage.load_public_key_bytes(key_id)
        if public_pem is None:
            return None
        
        return serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
    
    def rotate_key(self, key_id: str, private_key_password: Optional[str] = None):
        """Xoay vòng khóa (tạo khóa mới, lưu khóa cũ)"""
        if key_id not in self.keys_metadata:
            self._load_metadata(key_id)

        metadata = self.keys_metadata.get(key_id)
        if metadata is None:
            raise ValueError(f"Metadata của khóa {key_id} không tồn tại")
        
        # Tạo phiên bản mới
        new_version = metadata.version + 1
        new_key_id = f"{key_id}_v{new_version}"
        
        if metadata.algorithm.startswith("RSA"):
            if metadata.private_key_password_protected and not private_key_password:
                raise ValueError(
                    "Khóa RSA hiện tại dùng password protection. "
                    "Cần cung cấp private_key_password để rotate và giữ nguyên policy bảo vệ."
                )
            self.generate_asymmetric_key_pair(new_key_id, metadata.owner, 
                                              metadata.purpose, metadata.key_size,
                                              private_key_password=private_key_password)
        else:
            self.generate_symmetric_key(new_key_id, metadata.owner, 
                                       metadata.purpose, metadata.algorithm)
        
        # Đánh dấu khóa cũ không còn hoạt động
        metadata.is_active = False
        metadata.last_rotated = datetime.now()
        
        return new_key_id
    
    def _load_metadata(self, key_id: str):
        """Tải metadata từ file"""
        data = self.storage.load_metadata(key_id)
        if data is not None:
            metadata = KeyMetadata(
                data['key_id'], data['owner'], data['algorithm'],
                data['key_size'], data['purpose'],
                private_key_password_protected=data.get('private_key_password_protected', False)
            )
            # Khôi phục đầy đủ metadata từ storage để tránh sai lệch vòng đời khóa
            created_at_raw = data.get('created_at') or data.get('creation_date')
            expires_at_raw = data.get('expires_at')
            last_rotated_raw = data.get('last_rotated')

            if created_at_raw:
                metadata.created_at = datetime.fromisoformat(created_at_raw)
            if expires_at_raw:
                metadata.expires_at = datetime.fromisoformat(expires_at_raw)
            if last_rotated_raw:
                metadata.last_rotated = datetime.fromisoformat(last_rotated_raw)

            metadata.is_active = data['is_active']
            metadata.version = data['version']
            self.keys_metadata[key_id] = metadata
    
    def list_keys(self, owner: Optional[str] = None) -> list:
        """Liệt kê các khóa"""
        keys = []
        for key_id in self.storage.list_key_ids():
            if key_id not in self.keys_metadata:
                self._load_metadata(key_id)

            metadata = self.keys_metadata.get(key_id)
            if metadata is None:
                continue

            # Tự động đồng bộ trạng thái key hết hạn thành inactive.
            if metadata.is_expired() and metadata.is_active:
                metadata.is_active = False
                self.storage.save_metadata(key_id, metadata.to_dict())

            if owner is None or metadata.owner == owner:
                item = metadata.to_dict()
                item['is_expired'] = metadata.is_expired()
                if item['is_expired']:
                    item['is_active'] = False
                keys.append(item)
        
        return keys
    
    def revoke_key(self, key_id: str):
        """Thu hồi khóa"""
        if key_id not in self.keys_metadata:
            self._load_metadata(key_id)

        metadata = self.keys_metadata.get(key_id)
        if metadata is None:
            raise ValueError(f"Metadata của khóa {key_id} không tồn tại")

        metadata.is_active = False
        
        # Cập nhật metadata
        self.storage.save_metadata(key_id, metadata.to_dict())
