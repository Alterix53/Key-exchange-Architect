import base64
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

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

    def _load_certificates(self) -> Dict[str, str]:
        if os.path.exists(self.cert_repository_file):
            try:
                with open(self.cert_repository_file, "r") as f:
                    data = json.load(f)
                    # Lọc bỏ các format certificate JSON cũ (chỉ chấp nhận chuỗi PEM)
                    return {k: v for k, v in data.items() if isinstance(v, str)}
            except Exception:
                return {}
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

    def issue_certificate(self, subject: str, public_key_pem: str) -> str:
        """Tạo chứng chỉ X.509 chuẩn cho một User/Client mới"""
        issued_at = datetime.utcnow()
        valid_to = issued_at + timedelta(days=30)
        
        # Load public key từ PEM
        client_public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        
        # Thiết lập thông tin Subject và Issuer
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject),
        ])
        issuer_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "IAM-Relay-Server-CA"),
        ])
        
        # Build chứng chỉ X.509
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject_name)
        cert_builder = cert_builder.issuer_name(issuer_name)
        cert_builder = cert_builder.public_key(client_public_key)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(issued_at)
        cert_builder = cert_builder.not_valid_after(valid_to)
        
        # Ký chứng chỉ bằng Private Key của CA (mặc định với RSA dùng PKCS1v15 padding)
        certificate = cert_builder.sign(
            self.ca_private_key, hashes.SHA256()
        )
        
        # Xuất ra chuỗi PEM
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        
        # Lưu vào repository và disk
        self.cert_repository[subject] = cert_pem
        self._save_certificates()
        return cert_pem

    def get_certificate(self, subject: str) -> Optional[str]:
        """Truy xuất chứng chỉ bằng Username/ID"""
        cert = self.cert_repository.get(subject)
        if isinstance(cert, dict):
            return None # Bỏ qua chứng chỉ định dạng cũ nếu vô tình sót
        return cert

    def revoke_certificate(self, serial_number: Union[str, int]) -> None:
        """Thu hồi chứng chỉ (Thêm vào CRL) - Tùy chọn nâng cao"""
        self.crl.add(serial_number)

def verify_certificate(cert_pem: str, ca_public_key_pem: str, expected_subject: str = None, crl: set = None) -> bool:
    """
    Xác minh tính hợp lệ của chứng chỉ X.509:
    1. Chữ ký số từ CA
    2. Hết hạn (Expiration)
    3. Hợp lệ Subject 
    4. Bị thu hồi chưa (CRL)
    """
    try:
        # Load X.509 Certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        ca_public_key = serialization.load_pem_public_key(ca_public_key_pem.encode("utf-8"))
        
        # 1. Verify signature
        # Hàm verify của public key rsa hỗ trợ kiểm tra chữ ký cho Data Payload (tbs_certificate_bytes)
        # padding thường được sử dụng cho chứng chỉ X.509 ký bằng RSA là PKCS1v15
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )

        # 2. Bind identity to certificate usage: Check Subject
        if expected_subject:
            cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not cn_attributes or cn_attributes[0].value != expected_subject:
                cn = cn_attributes[0].value if cn_attributes else "Unknown"
                print(f"[ERROR] Certificate subject '{cn}' does KHÔNG khớp với user dự kiến '{expected_subject}'!")
                return False

        # 3. Check Revocation (Bonus)
        if crl and cert.serial_number in crl:
            print("[ERROR] Certificate has been revoked (in CRL).")
            return False

        # 4. Check Expiration (Bonus)
        now = datetime.utcnow()
        if now < cert.not_valid_before or now > cert.not_valid_after:
            print("[ERROR] Certificate is expired or not yet valid.")
            return False

        return True
    except InvalidSignature:
        print("[ERROR] Invalid certificate signature.")
        return False
    except Exception as e:
        print(f"[ERROR] Certificate verification failed: {e}")
        return False

def extract_public_key(cert_pem: str) -> Any:
    """Trích xuất Public Key Object từ Cert để sử dụng chia sẻ khóa"""
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    return cert.public_key()
