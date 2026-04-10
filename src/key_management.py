"""
Key Management Module
Quản lý sinh ra, lưu trữ, phân phối, và xoay vòng khóa
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import secrets
import base64


class KeyMetadata:
    """Metadata cho mỗi khóa"""
    def __init__(self, key_id: str, owner: str, algorithm: str, key_size: int, 
                 purpose: str, expiry_days: int = 365):
        self.key_id = key_id
        self.owner = owner
        self.algorithm = algorithm
        self.key_size = key_size
        self.purpose = purpose
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
    def __init__(self, storage_path: str = "keys_storage"):
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)
        self.keys_metadata: Dict[str, KeyMetadata] = {}
        self.master_key = self._load_or_create_master_key()
        
    def _load_or_create_master_key(self) -> bytes:
        """Tạo hoặc tải Master Key để mã hóa khóa khác"""
        master_key_path = os.path.join(self.storage_path, "master.key")
        if os.path.exists(master_key_path):
            with open(master_key_path, 'rb') as f:
                return f.read()
        else:
            master_key = secrets.token_bytes(32)  # 256-bit key
            with open(master_key_path, 'wb') as f:
                f.write(master_key)
            os.chmod(master_key_path, 0o600)  # Read/write for owner only
            return master_key
    
    def generate_symmetric_key(self, key_id: str, owner: str, purpose: str, 
                              algorithm: str = "AES-256") -> str:
        """Sinh khóa đối xứng"""
        if algorithm == "AES-256":
            key = secrets.token_bytes(32)  # 256 bits
            key_size = 256
        elif algorithm == "AES-128":
            key = secrets.token_bytes(16)  # 128 bits
            key_size = 128
        else:
            raise ValueError(f"Không hỗ trợ thuật toán: {algorithm}")
        
        metadata = KeyMetadata(key_id, owner, algorithm, key_size, purpose)
        self.keys_metadata[key_id] = metadata
        
        # Mã hóa khóa trước khi lưu
        encrypted_key = self._encrypt_key(key)
        self._save_encrypted_key(key_id, encrypted_key, metadata)
        
        return key_id
    
    def generate_asymmetric_key_pair(self, key_id: str, owner: str, purpose: str,
                                    key_size: int = 2048) -> Tuple[str, str]:
        """Sinh cặp khóa RSA"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        metadata = KeyMetadata(key_id, owner, "RSA", key_size, purpose)
        self.keys_metadata[key_id] = metadata
        
        # Mã hóa khóa riêng trước khi lưu
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        encrypted_private = self._encrypt_key(private_pem)
        self._save_private_key(key_id, encrypted_private, metadata)
        self._save_public_key(key_id, public_pem)
        
        return key_id, f"{key_id}_pub"
    
    def _encrypt_key(self, key: bytes) -> bytes:
        """Mã hóa khóa bằng Master Key"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.master_key), modes.CBC(iv), 
                       backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Padding
        from cryptography.hazmat.primitives import padding as sym_padding
        padder = sym_padding.PKCS7(128).padder()
        padded_key = padder.update(key) + padder.finalize()
        
        ciphertext = encryptor.update(padded_key) + encryptor.finalize()
        return iv + ciphertext
    
    def _decrypt_key(self, encrypted_key: bytes) -> bytes:
        """Giải mã khóa bằng Master Key"""
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
        key_path = os.path.join(self.storage_path, f"{key_id}.key")
        with open(key_path, 'wb') as f:
            f.write(encrypted_key)
        os.chmod(key_path, 0o600)
        
        # Lưu metadata
        metadata_path = os.path.join(self.storage_path, f"{key_id}.meta")
        with open(metadata_path, 'w') as f:
            json.dump(metadata.to_dict(), f, indent=2)
    
    def _save_private_key(self, key_id: str, encrypted_key: bytes, metadata: KeyMetadata):
        """Lưu khóa riêng RSA được mã hóa"""
        key_path = os.path.join(self.storage_path, f"{key_id}_private.pem")
        with open(key_path, 'wb') as f:
            f.write(encrypted_key)
        os.chmod(key_path, 0o600)
        
        metadata_path = os.path.join(self.storage_path, f"{key_id}.meta")
        with open(metadata_path, 'w') as f:
            json.dump(metadata.to_dict(), f, indent=2)
    
    def _save_public_key(self, key_id: str, public_key: bytes):
        """Lưu khóa công khai RSA"""
        key_path = os.path.join(self.storage_path, f"{key_id}_public.pem")
        with open(key_path, 'wb') as f:
            f.write(public_key)
    
    def get_symmetric_key(self, key_id: str) -> Optional[bytes]:
        """Lấy khóa đối xứng"""
        if key_id not in self.keys_metadata:
            self._load_metadata(key_id)
        
        metadata = self.keys_metadata.get(key_id)
        if not metadata or metadata.is_expired():
            raise ValueError(f"Khóa {key_id} hết hạn hoặc không tồn tại")
        
        key_path = os.path.join(self.storage_path, f"{key_id}.key")
        if not os.path.exists(key_path):
            return None
        
        with open(key_path, 'rb') as f:
            encrypted_key = f.read()
        
        return self._decrypt_key(encrypted_key)
    
    def get_private_key(self, key_id: str):
        """Lấy khóa riêng RSA"""
        if key_id not in self.keys_metadata:
            self._load_metadata(key_id)
        
        metadata = self.keys_metadata.get(key_id)
        if not metadata or metadata.is_expired():
            raise ValueError(f"Khóa {key_id} hết hạn hoặc không tồn tại")
        
        key_path = os.path.join(self.storage_path, f"{key_id}_private.pem")
        if not os.path.exists(key_path):
            return None
        
        with open(key_path, 'rb') as f:
            encrypted_key = f.read()
        
        private_pem = self._decrypt_key(encrypted_key)
        return serialization.load_pem_private_key(
            private_pem,
            password=None,
            backend=default_backend()
        )
    
    def get_public_key(self, key_id: str):
        """Lấy khóa công khai RSA"""
        key_path = os.path.join(self.storage_path, f"{key_id}_public.pem")
        if not os.path.exists(key_path):
            return None
        
        with open(key_path, 'rb') as f:
            public_pem = f.read()
        
        return serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )
    
    def rotate_key(self, key_id: str):
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
            self.generate_asymmetric_key_pair(new_key_id, metadata.owner, 
                                              metadata.purpose, metadata.key_size)
        else:
            self.generate_symmetric_key(new_key_id, metadata.owner, 
                                       metadata.purpose, metadata.algorithm)
        
        # Đánh dấu khóa cũ không còn hoạt động
        metadata.is_active = False
        metadata.last_rotated = datetime.now()
        
        return new_key_id
    
    def _load_metadata(self, key_id: str):
        """Tải metadata từ file"""
        metadata_path = os.path.join(self.storage_path, f"{key_id}.meta")
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                data = json.load(f)
                metadata = KeyMetadata(
                    data['key_id'], data['owner'], data['algorithm'],
                    data['key_size'], data['purpose']
                )
                metadata.is_active = data['is_active']
                metadata.version = data['version']
                self.keys_metadata[key_id] = metadata
    
    def list_keys(self, owner: Optional[str] = None) -> list:
        """Liệt kê các khóa"""
        keys = []
        for filename in os.listdir(self.storage_path):
            if filename.endswith('.meta'):
                key_id = filename.replace('.meta', '')
                if key_id not in self.keys_metadata:
                    self._load_metadata(key_id)

                metadata = self.keys_metadata.get(key_id)
                if metadata is None:
                    continue

                if owner is None or metadata.owner == owner:
                    keys.append(metadata.to_dict())
        
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
        metadata_path = os.path.join(self.storage_path, f"{key_id}.meta")
        with open(metadata_path, 'w') as f:
            json.dump(metadata.to_dict(), f, indent=2)
