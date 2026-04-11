"""
Secure Transmission Module
Quản lý truyền dữ liệu an toàn sử dụng mã hóa
"""

import json
import base64
from typing import Dict, List, Optional, Tuple, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.backends import default_backend
import os
import secrets
from datetime import datetime


class SecureMessage:
    """Thông điệp được bảo vệ"""
    def __init__(self, sender_id: str, recipient_id: str, content: str):
        self.message_id = secrets.token_hex(16)
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.content = content
        self.timestamp = datetime.now()
        self.encrypted_content = None
        self.signature = None
        self.algorithm = None


class SecureTransmissionChannel:
    """Kênh truyền dữ liệu an toàn"""
    
    def __init__(self):
        self.encryption_cache: Dict[str, bytes] = {}
        self.message_log: List[Dict] = []
    
    # ============ Mã hóa đối xứng ============
    
    def encrypt_aes_256_cbc(self, plaintext: str, key: bytes) -> Tuple[str, str]:
        """
        Mã hóa AES-256-CBC
        Trả về: (iv_base64, ciphertext_base64)
        """
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Padding
        from cryptography.hazmat.primitives import padding
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        return base64.b64encode(iv).decode(), base64.b64encode(ciphertext).decode()
    
    def decrypt_aes_256_cbc(self, iv_base64: str, ciphertext_base64: str, 
                           key: bytes) -> str:
        """Giải mã AES-256-CBC"""
        iv = base64.b64decode(iv_base64)
        ciphertext = base64.b64decode(ciphertext_base64)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        from cryptography.hazmat.primitives import padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')
    
    def encrypt_aes_256_gcm(self, plaintext: str, key: bytes, 
                           associated_data: str = "") -> Tuple[str, str, str]:
        """
        Mã hóa AES-256-GCM (với xác thực)
        Trả về: (nonce_base64, ciphertext_base64, tag_base64)
        """
        nonce = os.urandom(12)  # 96-bit nonce cho GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data.encode('utf-8'))
        
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
        return (
            base64.b64encode(nonce).decode(),
            base64.b64encode(ciphertext).decode(),
            base64.b64encode(encryptor.tag).decode()
        )
    
    def decrypt_aes_256_gcm(self, nonce_base64: str, ciphertext_base64: str,
                           tag_base64: str, key: bytes,
                           associated_data: str = "") -> str:
        """Giải mã AES-256-GCM với xác thực"""
        nonce = base64.b64decode(nonce_base64)
        ciphertext = base64.b64decode(ciphertext_base64)
        tag = base64.b64decode(tag_base64)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        if associated_data:
            decryptor.authenticate_additional_data(associated_data.encode('utf-8'))
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')
    
    # ============ Mã hóa bất đối xứng ============
    
    def encrypt_rsa_oaep(self, plaintext: str, public_key) -> str:
        """Mã hóa RSA-OAEP"""
        ciphertext = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()
    
    def decrypt_rsa_oaep(self, ciphertext_base64: str, private_key) -> str:
        """Giải mã RSA-OAEP"""
        ciphertext = base64.b64decode(ciphertext_base64)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')
    
    # ============ Chữ ký số ============
    
    def sign_message(self, message_content: str, private_key) -> str:
        """Ký thông điệp bằng RSA"""
        signature = private_key.sign(
            message_content.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def verify_signature(self, message_content: str, signature_base64: str,
                        public_key) -> bool:
        """Xác minh chữ ký"""
        try:
            signature = base64.b64decode(signature_base64)
            public_key.verify(
                signature,
                message_content.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    # ============ HMAC ============
    
    def generate_hmac(self, message: str, key: bytes) -> str:
        """Tạo HMAC-SHA256"""
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(message.encode('utf-8'))
        return base64.b64encode(h.finalize()).decode()
    
    def verify_hmac(self, message: str, hmac_value: str, key: bytes) -> bool:
        """Xác minh HMAC"""
        try:
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(message.encode('utf-8'))
            h.verify(base64.b64decode(hmac_value))
            return True
        except Exception:
            return False
    
    # ============ Quản lý phiên SSL/TLS ============
    
    def create_tls_session(self, client_id: str, server_id: str) -> Dict[str, Any]:
        """Mô phỏng tạo phiên TLS"""
        session_id = secrets.token_hex(32)
        
        # Tạo khóa phiên (symmetric key)
        session_key = os.urandom(32)  # AES-256
        
        # Master secret (trong TLS thực tế được tính toán phức tạp hơn)
        master_secret = os.urandom(48)
        
        return {
            'session_id': session_id,
            'client_id': client_id,
            'server_id': server_id,
            'session_key': base64.b64encode(session_key).decode(),
            'master_secret': base64.b64encode(master_secret).decode(),
            'created_at': datetime.now().isoformat(),
            'cipher_suite': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        }
    
    # ============ Truyền dữ liệu an toàn ============
    
    def send_secure_message(self, message: SecureMessage, key: bytes,
                           use_gcm: bool = True) -> Dict[str, str]:
        """Gửi thông điệp an toàn"""
        if use_gcm:
            nonce, ciphertext, tag = self.encrypt_aes_256_gcm(
                message.content, key,
                f"{message.sender_id}:{message.recipient_id}"
            )
            encrypted_message = {
                'message_id': message.message_id,
                'sender_id': message.sender_id,
                'recipient_id': message.recipient_id,
                'timestamp': message.timestamp.isoformat(),
                'algorithm': 'AES-256-GCM',
                'nonce': nonce,
                'ciphertext': ciphertext,
                'tag': tag,
                'associated_data': f"{message.sender_id}:{message.recipient_id}"
            }
        else:
            iv, ciphertext = self.encrypt_aes_256_cbc(message.content, key)
            encrypted_message = {
                'message_id': message.message_id,
                'sender_id': message.sender_id,
                'recipient_id': message.recipient_id,
                'timestamp': message.timestamp.isoformat(),
                'algorithm': 'AES-256-CBC',
                'iv': iv,
                'ciphertext': ciphertext
            }
        
        self.message_log.append(encrypted_message)
        return encrypted_message
    
    def receive_secure_message(self, encrypted_message: Dict[str, str],
                              key: bytes) -> Optional[str]:
        """Nhận và giải mã thông điệp an toàn"""
        try:
            if encrypted_message['algorithm'] == 'AES-256-GCM':
                plaintext = self.decrypt_aes_256_gcm(
                    encrypted_message['nonce'],
                    encrypted_message['ciphertext'],
                    encrypted_message['tag'],
                    key,
                    encrypted_message.get('associated_data', '')
                )
            else:  # AES-256-CBC
                plaintext = self.decrypt_aes_256_cbc(
                    encrypted_message['iv'],
                    encrypted_message['ciphertext'],
                    key
                )
            return plaintext
        except Exception as e:
            print(f"Lỗi giải mã: {e}")
            return None
    
    def get_message_log(self, sender_id: Optional[str] = None,
                       recipient_id: Optional[str] = None) -> list:
        """Lấy nhật ký thông điệp"""
        logs = self.message_log
        
        if sender_id:
            logs = [m for m in logs if m['sender_id'] == sender_id]
        
        if recipient_id:
            logs = [m for m in logs if m['recipient_id'] == recipient_id]
        
        return logs
