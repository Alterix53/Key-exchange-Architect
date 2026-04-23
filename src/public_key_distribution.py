"""
Public Key Infrastructure (PKI) Module — X.509 v3 Certificates
==============================================================

Minh họa Section 14.4 (X.509 Certificates) và 14.5 (Public-Key Infrastructure).

Thành phần:
    - RootCA:               Root Certificate Authority (self-signed)
    - IntermediateCA:       Intermediate CA (signed by Root CA)
    - RegistrationAuthority: RA — xác minh CSR trước khi CA cấp cert
    - CertificateRepository: Kho lưu trữ certificate & CRL
    - Utility functions:    Tạo CSR, validate chain, kiểm tra CRL, ...
"""

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


# =============================================================================
#  Certificate Repository — Kho lưu trữ certificate
# =============================================================================

class CertificateRepository:
    """
    Kho lưu trữ tập trung cho certificate và CRL.
    Tương ứng với "Repository" trong mô hình PKI (Section 14.5).
    """

    def __init__(self, data_dir: str = "pki_data"):
        self.data_dir = data_dir
        self.certs_dir = os.path.join(data_dir, "certificates")
        os.makedirs(self.certs_dir, exist_ok=True)

        # In-memory index: subject_cn → cert PEM path
        self.index_file = os.path.join(data_dir, "cert_index.json")
        self.index: Dict[str, Dict[str, str]] = self._load_index()

    def _load_index(self) -> Dict:
        if os.path.exists(self.index_file):
            with open(self.index_file, "r") as f:
                return json.load(f)
        return {}

    def _save_index(self):
        with open(self.index_file, "w") as f:
            json.dump(self.index, f, indent=2)

    def store_certificate(self, cert: x509.Certificate, label: str = "") -> str:
        """Lưu certificate vào repository, trả về path."""
        serial_hex = format(cert.serial_number, "x")
        subject_cn = _get_cn(cert.subject)
        filename = f"{subject_cn}_{serial_hex[:16]}.pem"
        filepath = os.path.join(self.certs_dir, filename)

        with open(filepath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self.index[subject_cn] = {
            "serial": serial_hex,
            "file": filepath,
            "issuer": _get_cn(cert.issuer),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "label": label,
        }
        self._save_index()
        return filepath

    def get_certificate(self, subject_cn: str) -> Optional[x509.Certificate]:
        """Tra cứu certificate theo subject Common Name."""
        info = self.index.get(subject_cn)
        if not info or not os.path.exists(info["file"]):
            return None
        return load_cert_from_pem_file(info["file"])

    def list_certificates(self) -> List[Dict[str, str]]:
        """Liệt kê tất cả certificate trong repository."""
        return [
            {"subject": cn, **info}
            for cn, info in self.index.items()
        ]

    def remove_certificate(self, subject_cn: str) -> bool:
        """Xóa certificate khỏi repository."""
        if subject_cn in self.index:
            try:
                os.remove(self.index[subject_cn]["file"])
            except OSError:
                pass
            del self.index[subject_cn]
            self._save_index()
            return True
        return False


# =============================================================================
#  Root Certificate Authority
# =============================================================================

class RootCA:
    """
    Root Certificate Authority — CA gốc (self-signed).
    
    Chức năng:
        - Tự sinh self-signed X.509 v3 Root CA certificate
        - Ký certificate cho Intermediate CA
        - Quản lý CRL (Certificate Revocation List)
    """

    def __init__(self, data_dir: str = "pki_data", cn: str = "IAM Root CA",
                 org: str = "IAM Security System", validity_years: int = 10):
        """ Khởi tạo Root CA. Nếu đã tồn tại thì tải lên, nếu không thì tạo mới.
        Args:
            data_dir: Thư mục lưu trữ dữ liệu PKI
            cn: Common Name cho Root CA
            org: Organization Name cho Root CA
            validity_years: Số năm hiệu lực của Root CA
        """
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)

        self.private_dir = os.path.join(data_dir, "root", "private")
        self.certs_dir = os.path.join(data_dir, "root", "certs")
        os.makedirs(self.private_dir, exist_ok=True)
        os.makedirs(self.certs_dir, exist_ok=True)

        self.ca_key_path = os.path.join(self.private_dir, "root.key")
        self.ca_cert_path = os.path.join(self.certs_dir, "root.crt")
        self.crl_path = os.path.join(self.certs_dir, "root.crl")

        self._revoked_serials: List[Tuple[int, datetime]] = []

        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            # Load existing Root CA
            with open(self.ca_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            self.certificate = load_cert_from_pem_file(self.ca_cert_path)
            self._load_crl()
            print(f"[Root CA] Đã tải Root CA từ {data_dir}")
        else:
            # Generate new Root CA
            self.private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096
            )
            self.certificate = self._create_self_signed_cert(cn, org, validity_years)

            # Persist
            _save_private_key(self.private_key, self.ca_key_path)
            _save_certificate(self.certificate, self.ca_cert_path)
            self._generate_crl()
            print(f"[Root CA] Đã tạo Root CA mới: CN={cn}")

    def _create_self_signed_cert(self, cn: str, org: str, validity_years: int) -> x509.Certificate:
        """Tạo self-signed Root CA certificate (X.509 v3)."""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])

        now = datetime.utcnow()
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365 * validity_years))
            # === X.509 v3 Extensions ===
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.private_key.public_key()),
                critical=False,
            )
        )

        return builder.sign(self.private_key, hashes.SHA256())

    def sign_intermediate_ca(self, csr: x509.CertificateSigningRequest,
                             validity_years: int = 5) -> x509.Certificate:
        """Ký certificate cho Intermediate CA từ CSR."""
        _verify_csr_signature(csr)

        now = datetime.utcnow()
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365 * validity_years))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.private_key.public_key()
                ),
                critical=False,
            )
        )

        return builder.sign(self.private_key, hashes.SHA256())

    def revoke_certificate(self, serial_number: int):
        """Thu hồi certificate bằng serial number."""
        self._revoked_serials.append((serial_number, datetime.utcnow()))
        self._generate_crl()
        print(f"[Root CA] Đã thu hồi certificate serial={format(serial_number, 'x')[:16]}...")

    def _generate_crl(self):
        """Sinh CRL (Certificate Revocation List) và lưu ra file."""
        now = datetime.utcnow()
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.certificate.subject)
            .last_update(now)
            .next_update(now + timedelta(days=7))
        )

        for serial, revocation_date in self._revoked_serials:
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revocation_date)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)

        crl = builder.sign(self.private_key, hashes.SHA256())
        with open(self.crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

    def _load_crl(self):
        """Tải CRL từ file."""
        if os.path.exists(self.crl_path):
            with open(self.crl_path, "rb") as f:
                crl = x509.load_pem_x509_crl(f.read())
            for revoked in crl:
                self._revoked_serials.append(
                    (revoked.serial_number, revoked.revocation_date)
                )

    def get_crl(self) -> x509.CertificateRevocationList:
        """Lấy CRL hiện tại."""
        with open(self.crl_path, "rb") as f:
            return x509.load_pem_x509_crl(f.read())

    def get_crl_pem(self) -> str:
        """Lấy CRL dạng PEM string."""
        with open(self.crl_path, "rb") as f:
            return f.read().decode("utf-8")

    def get_cert_pem(self) -> str:
        """Lấy Root CA certificate dạng PEM string."""
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


# =============================================================================
#  Intermediate Certificate Authority
# =============================================================================

class IntermediateCA:
    """
    Intermediate Certificate Authority — CA trung gian.

    Chức năng:
        - Nhận certificate từ Root CA
        - Cấp end-entity certificate cho client/server
        - Quản lý CRL riêng
    """

    def __init__(self, root_ca: RootCA, data_dir: str = "pki_data",
                 cn: str = "IAM Intermediate CA", org: str = "IAM Security System",
                 validity_years: int = 5):
        self.data_dir = data_dir

        self.private_dir = os.path.join(data_dir, "intermediate", "private")
        self.certs_dir = os.path.join(data_dir, "intermediate", "certs")
        os.makedirs(self.private_dir, exist_ok=True)
        os.makedirs(self.certs_dir, exist_ok=True)

        self.ca_key_path = os.path.join(self.private_dir, "intermediate.key")
        self.ca_cert_path = os.path.join(self.certs_dir, "intermediate.crt")
        self.crl_path = os.path.join(self.certs_dir, "intermediate.crl")

        self._revoked_serials: List[Tuple[int, datetime]] = []

        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            with open(self.ca_key_path, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            self.certificate = load_cert_from_pem_file(self.ca_cert_path)
            self._load_crl()
            print(f"[Intermediate CA] Đã tải Intermediate CA từ {data_dir}")
        else:
            # Sinh key pair + CSR
            self.private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=3072
            )
            csr = create_csr(cn, org, self.private_key)

            # Root CA ký CSR → cert cho Intermediate CA
            self.certificate = root_ca.sign_intermediate_ca(csr, validity_years)

            _save_private_key(self.private_key, self.ca_key_path)
            _save_certificate(self.certificate, self.ca_cert_path)
            self._generate_crl()
            print(f"[Intermediate CA] Đã tạo mới Intermediate CA: CN={cn}")

    def issue_certificate(self, csr: x509.CertificateSigningRequest,
                          validity_days: int = 365,
                          is_server: bool = False) -> x509.Certificate:
        """
        Cấp end-entity certificate từ CSR.
        (Được gọi sau khi RA đã xác minh CSR.)
        """
        _verify_csr_signature(csr)

        now = datetime.utcnow()
        subject_cn = _get_cn(csr.subject)

        # KeyUsage khác nhau cho server vs client
        key_usage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )

        # ExtendedKeyUsage
        if is_server:
            ext_usage = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
        else:
            ext_usage = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])

        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(key_usage, critical=True)
            .add_extension(ext_usage, critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.private_key.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(subject_cn),
                ]),
                critical=False,
            )
        )

        cert = builder.sign(self.private_key, hashes.SHA256())
        print(f"[Intermediate CA] Đã cấp certificate cho: {subject_cn}")
        return cert

    def revoke_certificate(self, serial_number: int):
        """Thu hồi certificate."""
        self._revoked_serials.append((serial_number, datetime.utcnow()))
        self._generate_crl()
        print(f"[Intermediate CA] Đã thu hồi certificate serial={format(serial_number, 'x')[:16]}...")

    def _generate_crl(self):
        now = datetime.utcnow()
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.certificate.subject)
            .last_update(now)
            .next_update(now + timedelta(days=7))
        )
        for serial, rev_date in self._revoked_serials:
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(rev_date)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)

        crl = builder.sign(self.private_key, hashes.SHA256())
        with open(self.crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

    def _load_crl(self):
        if os.path.exists(self.crl_path):
            with open(self.crl_path, "rb") as f:
                crl = x509.load_pem_x509_crl(f.read())
            for revoked in crl:
                self._revoked_serials.append(
                    (revoked.serial_number, revoked.revocation_date)
                )

    def get_crl(self) -> x509.CertificateRevocationList:
        with open(self.crl_path, "rb") as f:
            return x509.load_pem_x509_crl(f.read())

    def get_crl_pem(self) -> str:
        with open(self.crl_path, "rb") as f:
            return f.read().decode("utf-8")

    def get_cert_pem(self) -> str:
        return self.certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


# =============================================================================
#  Registration Authority (RA)
# =============================================================================

class RegistrationAuthority:
    """
    Registration Authority — Xác minh danh tính trước khi CA cấp certificate.

    Quy trình (Section 14.5 — PKIX Management Functions):
        1. End Entity gửi CSR (Certificate Signing Request)
        2. RA kiểm tra:
           a) CSR có chữ ký hợp lệ (chứng minh sở hữu private key)
           b) Subject name hợp lệ
           c) Không trùng với cert đã cấp (trừ renewal)
        3. Nếu hợp lệ → chuyển CSR cho Intermediate CA cấp cert
        4. Nếu không → từ chối
    """

    def __init__(self, intermediate_ca: IntermediateCA,
                 repository: CertificateRepository):
        self.ca = intermediate_ca
        self.repository = repository

    def process_csr(self, csr: x509.CertificateSigningRequest,
                    is_server: bool = False,
                    validity_days: int = 365) -> Optional[x509.Certificate]:
        """
        Xử lý CSR: xác minh → cấp certificate.

        Returns:
            Certificate nếu thành công, None nếu từ chối.
        """
        subject_cn = _get_cn(csr.subject)
        print(f"[RA] Nhận CSR từ: {subject_cn}")

        # === Bước 1: Verify CSR signature (chứng minh sở hữu private key) ===
        if not _verify_csr_signature(csr, raise_on_fail=False):
            print(f"[RA] ❌ CSR signature không hợp lệ! Từ chối.")
            return None

        print(f"[RA] ✓ CSR signature hợp lệ (client chứng minh sở hữu private key)")

        # === Bước 2: Kiểm tra subject name ===
        if not subject_cn or len(subject_cn.strip()) == 0:
            print(f"[RA] ❌ Subject name rỗng! Từ chối.")
            return None

        print(f"[RA] ✓ Subject name hợp lệ: {subject_cn}")

        # === Bước 3: Kiểm tra trùng lặp ===
        existing = self.repository.get_certificate(subject_cn)
        if existing is not None:
            # Kiểm tra cert cũ còn hiệu lực không
            if existing.not_valid_after > datetime.utcnow():
                print(f"[RA] ⚠ Certificate cho {subject_cn} đã tồn tại và còn hiệu lực.")
                print(f"[RA]   → Xử lý như Key Pair Update: thu hồi cert cũ, cấp cert mới.")
                self.ca.revoke_certificate(existing.serial_number)
                self.repository.remove_certificate(subject_cn)

        # === Bước 4: Chuyển CSR cho Intermediate CA cấp cert ===
        print(f"[RA] → Chuyển CSR cho Intermediate CA để cấp certificate...")
        cert = self.ca.issue_certificate(csr, validity_days=validity_days, is_server=is_server)

        # Lưu vào repository
        self.repository.store_certificate(cert, label="server" if is_server else "client")

        print(f"[RA] ✓ Certificate đã cấp thành công cho: {subject_cn}")
        return cert

    def process_renewal(self, csr: x509.CertificateSigningRequest,
                        validity_days: int = 365) -> Optional[x509.Certificate]:
        """
        Gia hạn certificate (Key Pair Update — Section 14.5).

        Client tạo key pair mới → gửi CSR mới → RA thu hồi cert cũ → cấp cert mới.
        """
        subject_cn = _get_cn(csr.subject)
        print(f"[RA] Yêu cầu gia hạn certificate cho: {subject_cn}")

        # Thu hồi cert cũ nếu có
        existing = self.repository.get_certificate(subject_cn)
        if existing is not None:
            self.ca.revoke_certificate(existing.serial_number)
            self.repository.remove_certificate(subject_cn)
            print(f"[RA] Đã thu hồi certificate cũ.")

        # Cấp cert mới
        return self.process_csr(csr, validity_days=validity_days)

    def process_revocation(self, subject_cn: str) -> bool:
        """
        Xử lý yêu cầu thu hồi certificate (Revocation Request — Section 14.5).
        """
        existing = self.repository.get_certificate(subject_cn)
        if existing is None:
            print(f"[RA] ❌ Không tìm thấy certificate cho: {subject_cn}")
            return False

        self.ca.revoke_certificate(existing.serial_number)
        self.repository.remove_certificate(subject_cn)
        print(f"[RA] ✓ Đã thu hồi certificate cho: {subject_cn}")
        return True


# =============================================================================
#  PKI System — Tích hợp toàn bộ thành phần
# =============================================================================

class PKISystem:
    """
    Hệ thống PKI hoàn chỉnh, tích hợp tất cả thành phần.
    Tạo 1 instance duy nhất trên server để quản lý toàn bộ PKI.
    """

    def __init__(self, data_dir: str = "pki"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)

        print("=" * 60)
        print("  KHỞI TẠO HỆ THỐNG PKI (Public Key Infrastructure)")
        print("=" * 60)

        # 1. Certificate Repository - thư mục CA
        self.repository = CertificateRepository(data_dir)

        # 2. Root CA
        self.root_ca = RootCA(data_dir)

        # 3. Intermediate CA (signed by Root)
        self.intermediate_ca = IntermediateCA(self.root_ca, data_dir)

        # Store CA certs vào repository
        self.repository.store_certificate(self.root_ca.certificate, "Root CA")
        self.repository.store_certificate(self.intermediate_ca.certificate, "Intermediate CA")

        # 4. Registration Authority
        self.ra = RegistrationAuthority(self.intermediate_ca, self.repository)

        print("=" * 60)
        print("  PKI đã sẵn sàng.")
        print(f"  Root CA:         {_get_cn(self.root_ca.certificate.subject)}")
        print(f"  Intermediate CA: {_get_cn(self.intermediate_ca.certificate.subject)}")
        print("=" * 60)

    def issue_cert_from_csr(self, csr: x509.CertificateSigningRequest,
                            is_server: bool = False) -> Optional[x509.Certificate]:
        """Xử lý CSR qua RA → Intermediate CA → cấp cert."""
        return self.ra.process_csr(csr, is_server=is_server)

    def get_cert_chain_pems(self, end_entity_cert: x509.Certificate) -> List[str]:
        """
        Trả về certificate chain dạng PEM strings:
        [end_entity_pem, intermediate_pem, root_pem]
        """
        return [
            end_entity_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            self.intermediate_ca.get_cert_pem(),
            self.root_ca.get_cert_pem(),
        ]

    def get_ca_chain_pems(self) -> List[str]:
        """Trả về CA chain: [intermediate_pem, root_pem]"""
        return [
            self.intermediate_ca.get_cert_pem(),
            self.root_ca.get_cert_pem(),
        ]

    def get_all_crls_pem(self) -> List[str]:
        """Trả về tất cả CRL dạng PEM."""
        return [
            self.root_ca.get_crl_pem(),
            self.intermediate_ca.get_crl_pem(),
        ]

    def revoke(self, subject_cn: str) -> bool:
        """Thu hồi certificate."""
        return self.ra.process_revocation(subject_cn)

    def lookup(self, subject_cn: str) -> Optional[x509.Certificate]:
        """Tra cứu certificate trong repository."""
        return self.repository.get_certificate(subject_cn)


# =============================================================================
#  Utility Functions — Hàm tiện ích
# =============================================================================

def create_csr(cn: str, org: str, private_key,
               country: str = "VN") -> x509.CertificateSigningRequest:
    """
    Tạo Certificate Signing Request (CSR).

    End Entity tạo CSR rồi gửi cho RA.
    CSR được ký bởi private key → chứng minh sở hữu.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )

    return csr


def verify_certificate_chain(cert_chain_pems: List[str],
                              trusted_root_pem: str,
                              crl_pems: Optional[List[str]] = None) -> Tuple[bool, str]:
    """
    Validate certificate chain: leaf → intermediate → root.

    Args:
        cert_chain_pems: [end_entity_pem, intermediate_pem, root_pem]
        trusted_root_pem: PEM của trusted Root CA (pre-installed)
        crl_pems: Danh sách CRL PEM để kiểm tra revocation

    Returns:
        (is_valid, message)
    """
    if len(cert_chain_pems) < 2:
        return False, "Certificate chain phải có ít nhất 2 certificate"

    # Load tất cả cert
    certs = []
    for pem in cert_chain_pems:
        certs.append(x509.load_pem_x509_certificate(pem.encode("utf-8")))

    trusted_root = x509.load_pem_x509_certificate(trusted_root_pem.encode("utf-8"))

    # Load CRLs
    crls = []
    if crl_pems:
        for crl_pem in crl_pems:
            crls.append(x509.load_pem_x509_crl(crl_pem.encode("utf-8")))

    now = datetime.utcnow()

    # === Bước 1: Kiểm tra Root cert khớp với trusted root ===
    chain_root = certs[-1]
    if chain_root.public_bytes(serialization.Encoding.PEM) != trusted_root.public_bytes(serialization.Encoding.PEM):
        return False, "Root CA trong chain không khớp với trusted root"

    # === Bước 2: Validate từng cặp cert trong chain ===
    for i in range(len(certs) - 1):
        child_cert = certs[i]
        parent_cert = certs[i + 1]

        # 2a. Kiểm tra issuer/subject khớp
        if child_cert.issuer != parent_cert.subject:
            return False, f"Chain bị đứt: cert[{i}].issuer != cert[{i+1}].subject"

        # 2b. Kiểm tra thời hạn
        if now < child_cert.not_valid_before:
            return False, f"Certificate [{i}] chưa có hiệu lực"
        if now > child_cert.not_valid_after:
            return False, f"Certificate [{i}] đã hết hạn"

        # 2c. Verify chữ ký: parent ký child
        try:
            parent_cert.public_key().verify(
                child_cert.signature,
                child_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child_cert.signature_hash_algorithm,
            )
        except (InvalidSignature, Exception) as e:
            return False, f"Chữ ký cert[{i}] không hợp lệ: {e}"

        # 2d. Kiểm tra CRL (revocation check)
        for crl in crls:
            if crl.issuer == parent_cert.subject:
                revoked = crl.get_revoked_certificate_by_serial_number(
                    child_cert.serial_number
                )
                if revoked is not None:
                    return False, f"Certificate [{i}] đã bị thu hồi (trong CRL)"

    # === Bước 3: Verify self-signed root ===
    try:
        trusted_root.public_key().verify(
            trusted_root.signature,
            trusted_root.tbs_certificate_bytes,
            padding.PKCS1v15(),
            trusted_root.signature_hash_algorithm,
        )
    except (InvalidSignature, Exception) as e:
        return False, f"Root CA self-signature không hợp lệ: {e}"

    return True, "Certificate chain hợp lệ ✓"


def check_revocation(cert_pem: str, crl_pems: List[str]) -> Tuple[bool, str]:
    """
    Kiểm tra certificate có bị thu hồi không.

    Returns:
        (is_revoked, message)
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
    for crl_pem in crl_pems:
        crl = x509.load_pem_x509_crl(crl_pem.encode("utf-8"))
        revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked is not None:
            return True, f"Certificate đã bị thu hồi vào {revoked.revocation_date.isoformat()}"
    return False, "Certificate chưa bị thu hồi"


def get_cert_info(cert: x509.Certificate) -> Dict[str, Any]:
    """In thông tin chi tiết của X.509 certificate."""
    info = {
        "Version": f"v{cert.version.value + 1}",
        "Serial Number": format(cert.serial_number, "x"),
        "Issuer": _dn_to_str(cert.issuer),
        "Subject": _dn_to_str(cert.subject),
        "Not Valid Before": cert.not_valid_before.isoformat(),
        "Not Valid After": cert.not_valid_after.isoformat(),
        "Public Key Algorithm": cert.public_key().__class__.__name__,
        "Signature Algorithm": cert.signature_algorithm_oid._name,
    }

    # Extensions
    extensions = {}
    for ext in cert.extensions:
        extensions[ext.oid._name] = {
            "critical": ext.critical,
            "value": str(ext.value),
        }
    info["Extensions"] = extensions

    return info


def print_cert_info(cert: x509.Certificate, title: str = "Certificate Info"):
    """In đẹp thông tin certificate ra console."""
    info = get_cert_info(cert)
    print(f"\n{'─' * 60}")
    print(f"  📜 {title}")
    print(f"{'─' * 60}")
    for key, value in info.items():
        if key == "Extensions":
            print(f"  Extensions:")
            for ext_name, ext_data in value.items():
                crit = "CRITICAL" if ext_data["critical"] else "non-critical"
                print(f"    • {ext_name} [{crit}]: {ext_data['value']}")
        else:
            print(f"  {key}: {value}")
    print(f"{'─' * 60}\n")


def serialize_cert_to_pem(cert: x509.Certificate) -> str:
    """Serialize certificate sang PEM string."""
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def load_cert_from_pem(pem_data: str) -> x509.Certificate:
    """Load certificate từ PEM string."""
    return x509.load_pem_x509_certificate(pem_data.encode("utf-8"))


def serialize_csr_to_pem(csr: x509.CertificateSigningRequest) -> str:
    """Serialize CSR sang PEM string."""
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def load_csr_from_pem(pem_data: str) -> x509.CertificateSigningRequest:
    """Load CSR từ PEM string."""
    return x509.load_pem_x509_csr(pem_data.encode("utf-8"))


# =============================================================================
#  Internal helpers
# =============================================================================

def _get_cn(name: x509.Name) -> str:
    """Lấy Common Name từ X.509 Name."""
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        return "Unknown"


def _dn_to_str(name: x509.Name) -> str:
    """Chuyển Distinguished Name sang string đẹp."""
    parts = []
    for attr in name:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts)


def _verify_csr_signature(csr: x509.CertificateSigningRequest,
                           raise_on_fail: bool = True) -> bool:
    """Verify CSR signature (chứng minh sở hữu private key)."""
    if not csr.is_signature_valid:
        if raise_on_fail:
            raise ValueError("CSR signature không hợp lệ!")
        return False
    return True


def _save_private_key(key, path: str):
    """Lưu private key ra file PEM."""
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(path, 0o600)


def _save_certificate(cert: x509.Certificate, path: str):
    """Lưu certificate ra file PEM."""
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_cert_from_pem_file(path: str) -> x509.Certificate:
    """Load certificate từ file PEM."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


# =============================================================================
#  Backward Compatibility — Giữ API cũ cho code chưa migrate
# =============================================================================

class CertificateAuthority:
    """
    Wrapper cho backward compatibility.
    Delegate sang PKISystem.
    """

    def __init__(self, data_dir: str = "pki"):
        self.pki = PKISystem(data_dir)
        self.cert_repository: Dict[str, Dict] = {}
        self.crl: set = set()
        self._refresh_repo()

    def _refresh_repo(self):
        """Sync repository vào dict cho backward compat."""
        self.cert_repository = {}
        for entry in self.pki.repository.list_certificates():
            self.cert_repository[entry["subject"]] = entry

    def get_public_key_pem(self) -> str:
        return self.pki.root_ca.get_cert_pem()

    def issue_certificate(self, subject: str, public_key_pem: str) -> Dict:
        """Cấp certificate (backward compat — tạo CSR nội bộ)."""
        # Load public key to create a temporary key pair for CSR
        # In new flow, client should send CSR directly
        pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

        # Tạo cert thông qua PKI system (bypass CSR for backward compat)
        now = datetime.utcnow()
        cert_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IAM Security System"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(cert_subject)
            .issuer_name(self.pki.intermediate_ca.certificate.subject)
            .public_key(pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(pub_key),
                critical=False,
            )
        )
        cert = builder.sign(self.pki.intermediate_ca.private_key, hashes.SHA256())
        self.pki.repository.store_certificate(cert, "client")
        self._refresh_repo()

        # Return dict for backward compat
        return {
            "serial_number": format(cert.serial_number, "x"),
            "issuer": _get_cn(cert.issuer),
            "subject": subject,
            "public_key": public_key_pem,
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_to": cert.not_valid_after_utc.isoformat(),
            "cert_pem": serialize_cert_to_pem(cert),
            "chain_pems": self.pki.get_cert_chain_pems(cert),
            "crls_pem": self.pki.get_all_crls_pem(),
        }

    def get_certificate(self, subject: str) -> Optional[Dict]:
        cert = self.pki.lookup(subject)
        if cert is None:
            return None
        return {
            "serial_number": format(cert.serial_number, "x"),
            "issuer": _get_cn(cert.issuer),
            "subject": _get_cn(cert.subject),
            "public_key": cert.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8"),
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_to": cert.not_valid_after.isoformat(),
            "cert_pem": serialize_cert_to_pem(cert),
            "chain_pems": self.pki.get_cert_chain_pems(cert),
            "crls_pem": self.pki.get_all_crls_pem(),
        }

    def revoke_certificate(self, serial_number: str) -> None:
        self.pki.intermediate_ca.revoke_certificate(int(serial_number, 16))


def verify_certificate(cert: Dict, ca_public_key_pem: str,
                       expected_subject: str = None, crl: set = None) -> bool:
    """
    Backward-compatible verify function.
    Sử dụng X.509 chain validation thay vì custom JSON.
    """
    try:
        chain_pems = cert.get("chain_pems")
        crls_pem = cert.get("crls_pem")

        if chain_pems:
            # New X.509 flow: validate full chain
            # ca_public_key_pem ở đây thực chất là root_ca_cert_pem
            is_valid, msg = verify_certificate_chain(
                chain_pems, ca_public_key_pem,
                crl_pems=crls_pem
            )
            if not is_valid:
                print(f"[VERIFY] ❌ {msg}")
                return False

            # Check expected subject
            leaf_cert = x509.load_pem_x509_certificate(chain_pems[0].encode("utf-8"))
            if expected_subject and _get_cn(leaf_cert.subject) != expected_subject:
                print(f"[VERIFY] ❌ Subject mismatch: expected={expected_subject}, got={_get_cn(leaf_cert.subject)}")
                return False

            print(f"[VERIFY] ✓ Certificate chain hợp lệ cho: {_get_cn(leaf_cert.subject)}")
            return True
        else:
            # Fallback: old JSON cert
            print("[VERIFY] ⚠ Legacy cert format, skipping chain validation")
            return True

    except Exception as e:
        print(f"[VERIFY] ❌ Verification failed: {e}")
        return False


def extract_public_key(cert: Dict) -> Any:
    """Trích xuất Public Key Object từ cert dict."""
    # Try new flow first
    chain_pems = cert.get("chain_pems")
    if chain_pems:
        leaf_cert = x509.load_pem_x509_certificate(chain_pems[0].encode("utf-8"))
        return leaf_cert.public_key()

    # Fallback to old flow
    public_key_pem = cert.get("public_key")
    if not public_key_pem:
        raise ValueError("No public key in certificate")
    return serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
