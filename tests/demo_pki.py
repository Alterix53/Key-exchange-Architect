#!/usr/bin/env python3
"""
Demo PKI — Minh họa Section 14.4 (X.509 Certificates) + 14.5 (Public-Key Infrastructure)
==========================================================================================

Chạy: python demo_pki.py

Demo này chạy standalone (không cần server/client) để minh họa:
  1. Tạo PKI Hierarchy: Root CA → Intermediate CA
  2. Registration + Certification: CSR → RA → CA → Certificate
  3. X.509 v3 Certificate chi tiết (extensions, fields)
  4. Certificate Chain Validation
  5. Certificate Revocation (CRL)
  6. Certificate Renewal (Key Pair Update)
"""

import os
import shutil
import sys

# Thêm project root vào path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.hazmat.primitives.asymmetric import rsa
from src.public_key_distribution import (
    PKISystem, create_csr, verify_certificate_chain,
    check_revocation, print_cert_info, serialize_cert_to_pem,
    get_cert_info, _get_cn,
)


def safe_input(prompt=""):
    """input() wrapper that skips when stdin is not a terminal."""
    try:
        if sys.stdin.isatty():
            input(prompt)
    except EOFError:
        pass


def separator(title: str):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def main():
    # Clean up old demo data
    demo_dir = "demo_pki_data"
    if os.path.exists(demo_dir):
        shutil.rmtree(demo_dir)

    # =========================================================================
    #  PHẦN 1: TẠO PKI HIERARCHY (Section 14.5)
    # =========================================================================
    separator("PHẦN 1: TẠO PKI HIERARCHY (Section 14.5)")
    print("""
    PKI (Public Key Infrastructure) bao gồm:
      • Root CA         — CA gốc, tự ký certificate của mình
      • Intermediate CA — CA trung gian, được Root CA ký
      • RA              — Registration Authority, xác minh CSR
      • Repository      — Kho lưu trữ certificate
    
    Cấu trúc:
      Root CA (self-signed)
        └── Intermediate CA (signed by Root CA)
              ├── Server cert (signed by Intermediate CA)
              ├── Client A cert
              └── Client B cert
    """)

    pki = PKISystem(data_dir=demo_dir)

    print("\n--- Root CA Certificate ---")
    print_cert_info(pki.root_ca.certificate, "Root CA Certificate (Self-Signed)")

    print("\n--- Intermediate CA Certificate ---")
    print_cert_info(pki.intermediate_ca.certificate, "Intermediate CA Certificate (Signed by Root)")

    safe_input("\n>>> Nhấn Enter để tiếp tục...\n")

    # =========================================================================
    #  PHẦN 2: CSR + REGISTRATION + CERTIFICATION (Section 14.5)
    # =========================================================================
    separator("PHẦN 2: ĐĂNG KÝ & CẤP CERTIFICATE (Section 14.5 — PKIX Functions)")
    print("""
    Quy trình cấp certificate (PKIX Management Functions):
    
    1. End Entity sinh RSA key pair
    2. End Entity tạo CSR (Certificate Signing Request)
       → CSR được ký bởi private key → chứng minh sở hữu
    3. Gửi CSR cho RA (Registration Authority)
    4. RA xác minh:
       a) CSR signature hợp lệ
       b) Subject name hợp lệ
       c) Không trùng cert đã cấp
    5. RA chuyển CSR cho Intermediate CA
    6. Intermediate CA ký → tạo X.509 v3 certificate
    7. Certificate được lưu vào Repository
    """)

    # --- Client Alice ---
    print("─" * 50)
    print("  Đăng ký cho Client: Alice")
    print("─" * 50)

    alice_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    alice_csr = create_csr("Alice", "IAM Security System", alice_private_key)
    print(f"[Alice] Đã tạo CSR (signed bởi private key)")
    print(f"[Alice] CSR Subject: {_get_cn(alice_csr.subject)}")
    print(f"[Alice] CSR Signature Valid: {alice_csr.is_signature_valid}")

    alice_cert = pki.issue_cert_from_csr(alice_csr, is_server=False)
    print_cert_info(alice_cert, "Alice's Certificate (X.509 v3)")

    # --- Client Bob ---
    print("─" * 50)
    print("  Đăng ký cho Client: Bob")
    print("─" * 50)

    bob_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    bob_csr = create_csr("Bob", "IAM Security System", bob_private_key)
    print(f"[Bob] Đã tạo CSR")

    bob_cert = pki.issue_cert_from_csr(bob_csr, is_server=False)
    print_cert_info(bob_cert, "Bob's Certificate (X.509 v3)")

    # --- Server ---
    print("─" * 50)
    print("  Đăng ký cho Server")
    print("─" * 50)

    server_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    server_csr = create_csr("relay-server", "IAM Security System", server_private_key)
    server_cert = pki.issue_cert_from_csr(server_csr, is_server=True)
    print_cert_info(server_cert, "Server Certificate (ExtendedKeyUsage: SERVER_AUTH)")

    safe_input("\n>>> Nhấn Enter để tiếp tục...\n")

    # =========================================================================
    #  PHẦN 3: X.509 v3 CERTIFICATE CHI TIẾT (Section 14.4)
    # =========================================================================
    separator("PHẦN 3: CẤU TRÚC X.509 v3 CERTIFICATE (Section 14.4)")
    print("""
    Cấu trúc X.509 v3 Certificate bao gồm:
    
    ┌───────────────────────────────────────┐
    │  Version:             v3              │
    │  Serial Number:       (unique)        │
    │  Signature Algorithm: SHA256WithRSA   │
    │  Issuer:              CA's DN         │
    │  Validity:                            │
    │    Not Before:        (timestamp)     │
    │    Not After:         (timestamp)     │
    │  Subject:             Entity's DN     │
    │  Subject Public Key Info:             │
    │    Algorithm:         RSA             │
    │    Public Key:        (key data)      │
    │  Extensions (v3):                     │
    │    • BasicConstraints                 │
    │    • KeyUsage                         │
    │    • ExtendedKeyUsage                 │
    │    • SubjectKeyIdentifier             │
    │    • AuthorityKeyIdentifier           │
    │    • SubjectAlternativeName           │
    │  Signature:           (CA's signature)│
    └───────────────────────────────────────┘
    """)

    print("Chi tiết Alice's Certificate:")
    info = get_cert_info(alice_cert)
    for key, value in info.items():
        if key == "Extensions":
            print(f"\n  📋 X.509 v3 Extensions:")
            for ext_name, ext_data in value.items():
                crit = "🔴 CRITICAL" if ext_data["critical"] else "🟢 non-critical"
                print(f"    ├─ {ext_name} [{crit}]")
                print(f"    │  Value: {ext_data['value']}")
        else:
            print(f"  {key}: {value}")

    print(f"\n  Giải thích Extensions:")
    print(f"    • BasicConstraints(ca=False)    → Đây KHÔNG phải CA, là end-entity cert")
    print(f"    • KeyUsage(digitalSignature,    → Được dùng cho ký số và mã hóa khóa")
    print(f"      keyEncipherment)")
    print(f"    • ExtendedKeyUsage(CLIENT_AUTH)  → Chỉ dùng cho xác thực client")
    print(f"    • SubjectKeyIdentifier          → ID unique cho public key")
    print(f"    • AuthorityKeyIdentifier        → ID của CA đã ký cert này")
    print(f"    • SubjectAlternativeName        → Tên thay thế (DNS name)")

    safe_input("\n>>> Nhấn Enter để tiếp tục...\n")

    # =========================================================================
    #  PHẦN 4: CERTIFICATE CHAIN VALIDATION (Section 14.4)
    # =========================================================================
    separator("PHẦN 4: CERTIFICATE CHAIN VALIDATION (Section 14.4)")
    print("""
    Certificate chain validation — xác minh chuỗi chứng chỉ:
    
    Alice's Cert ──verify──→ Intermediate CA ──verify──→ Root CA (trusted)
       │                         │                          │
       │ issuer = IntermCA       │ issuer = Root CA          │ self-signed
       │ signed by IntermCA      │ signed by Root CA         │ TRUSTED ROOT
       
    Quy trình:
    1. Kiểm tra Root CA khớp với trusted root (pre-installed)
    2. Verify chữ ký từng cặp: child.signature verified by parent.publicKey
    3. Kiểm tra thời hạn (not_before, not_after)
    4. Kiểm tra CRL (revocation)
    """)

    # Lấy chain
    alice_chain = pki.get_cert_chain_pems(alice_cert)
    root_ca_pem = pki.root_ca.get_cert_pem()
    crls_pem = pki.get_all_crls_pem()

    print(f"Certificate chain cho Alice ({len(alice_chain)} certs):")
    for i, pem in enumerate(alice_chain):
        cert = load_cert_from_pem_str(pem)
        level = ["📄 End-Entity (Alice)", "📂 Intermediate CA", "🏛️  Root CA"][i]
        print(f"  [{i}] {level}: {_get_cn(cert.subject)} — signed by {_get_cn(cert.issuer)}")

    print(f"\n--- Validating chain... ---")
    is_valid, msg = verify_certificate_chain(alice_chain, root_ca_pem, crls_pem)
    print(f"  Kết quả: {'✅ ' + msg if is_valid else '❌ ' + msg}")

    # Test với wrong root
    print(f"\n--- Test với Root CA giả (phải fail) ---")
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    from cryptography import x509 as x509_mod
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone
    from cryptography.hazmat.primitives import hashes as h
    fake_root = (
        x509_mod.CertificateBuilder()
        .subject_name(x509_mod.Name([x509_mod.NameAttribute(NameOID.COMMON_NAME, "Fake CA")]))
        .issuer_name(x509_mod.Name([x509_mod.NameAttribute(NameOID.COMMON_NAME, "Fake CA")]))
        .public_key(fake_key.public_key())
        .serial_number(x509_mod.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(fake_key, h.SHA256())
    )
    fake_root_pem = fake_root.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    is_valid, msg = verify_certificate_chain(alice_chain, fake_root_pem, crls_pem)
    print(f"  Kết quả: {'✅ ' + msg if is_valid else '❌ ' + msg}")
    assert not is_valid, "Should have failed with fake root!"
    print(f"  → Đúng! Không thể giả mạo Root CA.")

    safe_input("\n>>> Nhấn Enter để tiếp tục...\n")

    # =========================================================================
    #  PHẦN 5: CERTIFICATE REVOCATION / CRL (Section 14.5)
    # =========================================================================
    separator("PHẦN 5: CERTIFICATE REVOCATION — CRL (Section 14.5)")
    print("""
    Khi private key bị lộ hoặc certificate cần thu hồi:
    
    1. End Entity gửi Revocation Request → RA
    2. RA xác minh → CA thêm serial number vào CRL
    3. CA ký CRL mới → publish
    4. Mọi người kiểm tra CRL trước khi trust cert
    
    CRL = Certificate Revocation List (danh sách cert đã bị thu hồi)
    """)

    # Verify Bob trước khi thu hồi
    bob_chain = pki.get_cert_chain_pems(bob_cert)
    print("--- Verify Bob TRƯỚC khi thu hồi ---")
    is_valid, msg = verify_certificate_chain(bob_chain, root_ca_pem, crls_pem)
    print(f"  Kết quả: {'✅ ' + msg if is_valid else '❌ ' + msg}")

    # Kiểm tra CRL
    is_revoked, rev_msg = check_revocation(bob_chain[0], crls_pem)
    print(f"  CRL check: {'⚠️ ' + rev_msg if is_revoked else '✅ ' + rev_msg}")

    # Thu hồi Bob
    print(f"\n--- THU HỒI certificate của Bob ---")
    pki.revoke("Bob")

    # Lấy CRL mới
    crls_pem_updated = pki.get_all_crls_pem()

    # Verify Bob SAU khi thu hồi
    print(f"\n--- Verify Bob SAU khi thu hồi ---")
    is_valid, msg = verify_certificate_chain(bob_chain, root_ca_pem, crls_pem_updated)
    print(f"  Chain validation: {'✅ ' + msg if is_valid else '❌ ' + msg}")

    is_revoked, rev_msg = check_revocation(bob_chain[0], crls_pem_updated)
    print(f"  CRL check: {'⚠️ ' + rev_msg if is_revoked else '✅ ' + rev_msg}")
    print(f"  → Bob's certificate đã bị thu hồi, không thể trust nữa!")

    safe_input("\n>>> Nhấn Enter để tiếp tục...\n")

    # =========================================================================
    #  PHẦN 6: CERTIFICATE RENEWAL / KEY PAIR UPDATE (Section 14.5)
    # =========================================================================
    separator("PHẦN 6: CERTIFICATE RENEWAL — Key Pair Update (Section 14.5)")
    print("""
    Khi certificate sắp hết hạn hoặc cần key pair mới:
    
    1. End Entity sinh key pair MỚI
    2. Tạo CSR mới
    3. RA thu hồi cert CŨ
    4. RA chuyển CSR mới → CA cấp cert mới
    
    Đây là "Key Pair Update" trong PKIX Management Functions.
    """)

    print("--- Alice xin gia hạn certificate ---")
    print(f"  Serial cũ: {format(alice_cert.serial_number, 'x')[:16]}...")

    # Alice tạo key pair mới
    alice_new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alice_new_csr = create_csr("Alice", "IAM Security System", alice_new_key)

    # RA xử lý renewal
    alice_new_cert = pki.ra.process_renewal(alice_new_csr, validity_days=730)
    print(f"  Serial mới: {format(alice_new_cert.serial_number, 'x')[:16]}...")

    # Verify cert mới
    alice_new_chain = pki.get_cert_chain_pems(alice_new_cert)
    crls_final = pki.get_all_crls_pem()
    is_valid, msg = verify_certificate_chain(alice_new_chain, root_ca_pem, crls_final)
    print(f"  Verify cert mới: {'✅ ' + msg if is_valid else '❌ ' + msg}")

    # Verify cert cũ (phải fail vì đã bị thu hồi)
    is_revoked, rev_msg = check_revocation(
        serialize_cert_to_pem(alice_cert), crls_final
    )
    print(f"  Cert cũ bị thu hồi: {'✅ Đúng — ' + rev_msg if is_revoked else '❌ Sai'}")

    print_cert_info(alice_new_cert, "Alice's NEW Certificate (sau renewal)")

    safe_input("\n>>> Nhấn Enter để tiếp tục...\n")

    # =========================================================================
    #  PHẦN 7: CERTIFICATE REPOSITORY — TRA CỨU (Section 14.5)
    # =========================================================================
    separator("PHẦN 7: CERTIFICATE REPOSITORY (Section 14.5)")
    print("""
    Repository lưu trữ tất cả certificate đã cấp.
    Cho phép tra cứu theo subject name.
    """)

    print("--- Danh sách certificate trong Repository ---")
    for entry in pki.repository.list_certificates():
        print(f"  📜 Subject: {entry['subject']}")
        print(f"     Issuer:  {entry['issuer']}")
        print(f"     Serial:  {entry['serial'][:16]}...")
        print(f"     Expires: {entry['not_after']}")
        print(f"     Label:   {entry['label']}")
        print()

    # Tra cứu
    print("--- Tra cứu certificate của Alice ---")
    alice_lookup = pki.lookup("Alice")
    if alice_lookup:
        print(f"  ✓ Tìm thấy: CN={_get_cn(alice_lookup.subject)}")
    else:
        print(f"  ❌ Không tìm thấy")

    print("--- Tra cứu certificate của Bob (đã thu hồi → đã xóa khỏi repo) ---")
    bob_lookup = pki.lookup("Bob")
    if bob_lookup:
        print(f"  Tìm thấy: CN={_get_cn(bob_lookup.subject)}")
    else:
        print(f"  ✓ Không tìm thấy (đã bị thu hồi và xóa khỏi repository)")

    # =========================================================================
    #  TỔNG KẾT
    # =========================================================================
    separator("TỔNG KẾT")
    print("""
    ĐÃ MINH HỌA:
    
    ┌─────────────────────────────────────────────────────────────────────┐
    │  Section 14.4 — X.509 Certificates                                │
    │  ✅ X.509 v3 certificate structure (version, serial, validity...) │
    │  ✅ X.509 v3 Extensions (BasicConstraints, KeyUsage, EKU, SKI,   │
    │     AKI, SAN)                                                     │
    │  ✅ Certificate chain: Root CA → Intermediate CA → End-entity     │
    │  ✅ Certificate chain validation (signature, expiry, CRL)         │
    ├─────────────────────────────────────────────────────────────────────┤
    │  Section 14.5 — Public-Key Infrastructure                         │
    │  ✅ CA (Certificate Authority): Root CA + Intermediate CA         │
    │  ✅ RA (Registration Authority): verify CSR trước khi cấp cert   │
    │  ✅ Certificate Repository: lưu trữ + tra cứu certificate        │
    │  ✅ Registration: CSR flow (client chứng minh sở hữu private key)│
    │  ✅ Initialization: Client nhận Root CA cert (trust anchor)       │
    │  ✅ Certification: RA → CA → issue certificate                   │
    │  ✅ Key Pair Update: renewal (thu hồi cũ + cấp mới)             │
    │  ✅ Revocation: CRL persistent, revocation check                  │
    └─────────────────────────────────────────────────────────────────────┘
    """)

    # Clean up
    print(f"(Demo data saved to: {demo_dir}/)")
    print("Done! 🎉")


def load_cert_from_pem_str(pem: str):
    """Helper: load cert từ PEM string."""
    from cryptography.x509 import load_pem_x509_certificate
    return load_pem_x509_certificate(pem.encode("utf-8"))


# Need this import for the fake root test
from cryptography.hazmat.primitives import serialization


if __name__ == "__main__":
    main()
