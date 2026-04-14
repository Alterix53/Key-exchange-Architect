import base64
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, Optional, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import os

class CertificateAuthority:
    """Quản lý cấp phát, lưu trữ và thu hồi chứng chỉ (Certificate Authority) với tích hợp Persistent Data"""
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.cert_repository_file = os.path.join(self.data_dir, "certificates.json")
        self.crl: set = set()  # Certificate Revocation List
        
        # Load Certificates từ Disk
        self.cert_repository: Dict[str, Dict] = self._load_certificates()

        # Load hoặc Sinh khóa CA (Persistent CA key pair)
        ca_priv_path = os.path.join(self.data_dir, "ca_private.pem")
        ca_pub_path = os.path.join(self.data_dir, "ca_public.pem")

        if os.path.exists(ca_priv_path) and os.path.exists(ca_pub_path):
            with open(ca_priv_path, "rb") as f:
                self.ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(ca_pub_path, "rb") as f:
                self.ca_public_key = serialization.load_pem_public_key(f.read())
            print("[CA] Tải khóa CA từ tệp thành công.")
        else:
            self.ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.ca_public_key = self.ca_private_key.public_key()
            
            with open(ca_priv_path, "wb") as f:
                f.write(self.ca_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(ca_pub_path, "wb") as f:
                f.write(self.ca_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ))
            print("[CA] Khởi tạo hệ thống khóa CA mới và lưu vào đĩa (data/ca_private.pem, data/ca_public.pem).")

    def _load_certificates(self) -> Dict[str, Dict]:
        if os.path.exists(self.cert_repository_file):
            with open(self.cert_repository_file, "r") as f:
                return json.load(f)
        return {}

    def _save_certificates(self):
        with open(self.cert_repository_file, "w") as f:
            json.dump(self.cert_repository, f, indent=4)
        
    def get_public_key_pem(self) -> str:
        """Lấy Public Key của CA để phân phối cho Client"""
        return self.ca_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def issue_certificate(self, subject: str, public_key_pem: str) -> Dict:
        """Tạo chứng chỉ cho một User/Client mới"""
        issued_at = datetime.now()
        
        # Cấu trúc chứng chỉ
        cert_payload = {
            "serial_number": base64.b16encode(hashlib.sha256(f"{subject}:{issued_at.isoformat()}".encode("utf-8")).digest()[:8]).decode("ascii"),
            "issuer": "IAM-Relay-Server-CA",
            "subject": subject,
            "public_key": public_key_pem,
            "valid_from": issued_at.isoformat(),
            "valid_to": (issued_at + timedelta(days=30)).isoformat(),  # Certificate expiration check (BONUS)
        }
        
        # Ký chứng chỉ
        signing_input = json.dumps(cert_payload, sort_keys=True).encode("utf-8")
        signature = self.ca_private_key.sign(
            signing_input,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        cert_payload["signature"] = base64.b64encode(signature).decode("utf-8")
        
        # Lưu vào repository và disk
        self.cert_repository[subject] = cert_payload
        self._save_certificates()
        return cert_payload

    def get_certificate(self, subject: str) -> Optional[Dict]:
        """Truy xuất chứng chỉ bằng Username/ID"""
        return self.cert_repository.get(subject)

    def revoke_certificate(self, serial_number: str) -> None:
        """Thu hồi chứng chỉ (Thêm vào CRL) - Tùy chọn nâng cao"""
        self.crl.add(serial_number)

def verify_certificate(cert: Dict, ca_public_key_pem: str, expected_subject: str = None, crl: set = None) -> bool:
    """
    Xác minh tính hợp lệ của chứng chỉ:
    1. Kiểm tra cấu trúc
    2. Chữ ký số từ CA
    3. Hết hạn (Expiration)
    4. Bị thu hồi chưa (CRL)
    """
    try:
        # Check required fields structure
        required_fields = ["serial_number", "issuer", "subject", "public_key", "valid_from", "valid_to", "signature"]
        if not all(field in cert for field in required_fields):
            print("[ERROR] Certificate lacks required fields.")
            return False

        # Bind identity to certificate usage: Check Subject
        if expected_subject and cert.get("subject") != expected_subject:
            print(f"[ERROR] Certificate subject '{cert.get('subject')}' does KHÔNG khớp với user dự kiến '{expected_subject}'!")
            return False

        # Check Revocation (Bonus)
        if crl and cert.get("serial_number") in crl:
            print("[ERROR] Certificate has been revoked (in CRL).")
            return False

        # Check Expiration (Bonus)
        valid_to = datetime.fromisoformat(cert.get("valid_to"))
        if datetime.now() > valid_to:
            print("[ERROR] Certificate is expired.")
            return False

        # Extract signature and payload
        signature_b64 = cert.get("signature")
        signature = base64.b64decode(signature_b64)
        
        payload_copy = cert.copy()
        del payload_copy["signature"]
        signing_input = json.dumps(payload_copy, sort_keys=True).encode("utf-8")
        
        # Verify signature
        ca_public_key = serialization.load_pem_public_key(ca_public_key_pem.encode("utf-8"))
        ca_public_key.verify(
            signature,
            signing_input,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        print("[ERROR] Invalid certificate signature.")
        return False
    except Exception as e:
        print(f"[ERROR] Certificate verification failed: {e}")
        return False

def extract_public_key(cert: Dict) -> Any:
    """Trích xuất Public Key Object từ Cert để sử dụng chia sẻ khóa"""
    public_key_pem = cert.get("public_key")
    if not public_key_pem:
        raise ValueError("No public key in certificate")
    return serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
