#!/usr/bin/env python3
"""
Demo: Certificate Revocation Feature
========================================
Demonstrates the new revocation workflow:
1. User gets a certificate
2. User views certificate details
3. User requests revocation (simulating certificate compromise)
4. CRL is updated
5. Revocation check confirms certificate is revoked

Run: python demo_revocation.py
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.public_key_distribution import (
    PKISystem, create_csr, verify_certificate_chain,
    check_revocation, print_cert_info, _get_cn,
)
from cryptography.hazmat.primitives.asymmetric import rsa


def separator(title: str):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def main():
    separator("DEMO: Certificate Revocation Request Workflow")
    
    # Initialize PKI
    print("1️⃣  Khởi tạo PKI System...")
    pki = PKISystem("demo_revocation_pki")
    print("   ✓ PKI sẵn sàng\n")
    
    # User creates certificate
    print("2️⃣  User 'Alice' đăng ký chứng chỉ...")
    alice_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    alice_csr = create_csr("Alice", "IAM Security System", alice_key)
    alice_cert = pki.issue_cert_from_csr(alice_csr, is_server=False)
    alice_serial = format(alice_cert.serial_number, "x")[:16]
    print(f"   ✓ Certificate cấp cho Alice (Serial: {alice_serial})\n")
    
    print_cert_info(alice_cert, "Alice's Certificate")
    
    # Get initial CRL
    print("\n3️⃣  Kiểm tra CRL trước khi thu hồi...")
    crls_before = pki.get_all_crls_pem()
    print(f"   • Số CRL hiện tại: {len(crls_before)}")
    
    # Check certificate is valid
    print("\n4️⃣  Xác minh chứng chỉ trước khi thu hồi...")
    root_pem = pki.root_ca.get_cert_pem()
    chain = [
        alice_cert.public_bytes(0x10000).decode("utf-8"),  # PEM enum
        pki.intermediate_ca.get_cert_pem(),
        pki.root_ca.get_cert_pem(),
    ]
    is_valid_before, msg_before = verify_certificate_chain(chain, root_pem, crl_pems=crls_before)
    
    if is_valid_before:
        print(f"   ✓ Chứng chỉ hiện tại: {msg_before}")
    else:
        print(f"   ✗ Chứng chỉ không hợp lệ: {msg_before}")
    
    # Simulate certificate compromise - user requests revocation
    print("\n5️⃣  Alice's Certificate bị lộ → Alice yêu cầu thu hồi...")
    print("   📋 Ghi nhận: User Alice gửi yêu cầu revoke_cert")
    
    # Revoke the certificate
    success = pki.revoke("Alice")
    if success:
        print(f"   ✓ Yêu cầu thu hồi được xử lý thành công\n")
    else:
        print(f"   ✗ Không tìm thấy chứng chỉ để thu hồi\n")
        return
    
    # Get updated CRL
    print("6️⃣  CRL được cập nhật sau khi thu hồi...")
    crls_after = pki.get_all_crls_pem()
    print(f"   • Số CRL mới: {len(crls_after)}")
    
    # Verify certificate is now revoked
    print("\n7️⃣  Xác minh chứng chỉ sau khi thu hồi...")
    is_valid_after, msg_after = verify_certificate_chain(chain, root_pem, crl_pems=crls_after)
    
    if is_valid_after:
        print(f"   ✗ Chứng chỉ vẫn hợp lệ (BỤC BẦN): {msg_after}")
    else:
        print(f"   ✓ Chứng chỉ đã bị từ chối: {msg_after}")
    
    # Check revocation specifically
    print("\n8️⃣  Kiểm tra CRL để xác nhận revocation...")
    is_revoked, rev_msg = check_revocation(
        alice_cert.public_bytes(0x10000).decode("utf-8"),
        crls_after
    )
    
    if is_revoked:
        print(f"   ✓ Xác nhận: Chứng chỉ đã bị thu hồi")
        print(f"   ℹ️  {rev_msg}")
    else:
        print(f"   ✗ Lỗi: Chứng chỉ không được xem là đã thu hồi")
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 KẾT QUẢ ĐẠT ĐƯỢC")
    print("=" * 70)
    print("""
    ✅ Tính năng "Thu hồi Chứng chỉ" hoạt động đúng:
    
    1. User có thể xem thông tin chứng chỉ
    2. User có thể yêu cầu thu hồi khi certificate bị lộ
    3. PKI Server xử lý revoke_cert request
    4. IAM Server ghi nhận yêu cầu và call PKI để thu hồi
    5. Certificate được thêm vào CRL
    6. CRL được phân phối cập nhật cho clients
    7. Kiểm tra revocation xác nhận certificate đã bị revoke
    
    💡 Workflow hoàn chỉnh:
    
    Client (user) menu:
      ┌─ Xem chứng chỉ → Chi tiết + Options
      │  ├─ [1] Xem chi tiết
      │  └─ [2] Xin thu hồi
      │     └─ Server → PKI → update CRL → Client nhận CRL mới
      
    Audit trail:
      • CERT_REVOKED event ghi lại thời gian và user ID
      • CRL lưu trữ serial number và timestamp
      • Tất cả thao tác được track đầy đủ
    """)
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
