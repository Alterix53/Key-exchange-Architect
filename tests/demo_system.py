"""
Demo - Demonstration of IAM System with Key Management
Minh họa cách sử dụng hệ thống
"""

from src.key_management import KeyStore
from src.identity_management import (
    IdentityManagementSystem, Role, Permission
)
from src.secure_transmission import SecureTransmissionChannel, SecureMessage
from src.audit_logging import AuditLogger, AuditEventType


def print_section(title: str):
    """Hiển thị tiêu đề phần"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def demo_key_management():
    """Demo quản lý khóa"""
    print_section("1. KEY MANAGEMENT - QUẢN LÝ KHÓA")
    
    # Tạo KeyStore
    key_store = KeyStore("demo_keys")
    
    print("📋 A. Sinh khóa đối xứng (AES-256)")
    print("-" * 40)
    
    # Sinh khóa dữ liệu
    data_key_id = key_store.generate_symmetric_key(
        "data_encryption_key_1",
        "alice",
        "Data Encryption"
    )
    print(f"✓ Khóa dữ liệu được sinh: {data_key_id}")
    
    # Sinh khóa giao tiếp
    comm_key_id = key_store.generate_symmetric_key(
        "communication_key_1",
        "alice",
        "Secure Communication"
    )
    print(f"✓ Khóa giao tiếp được sinh: {comm_key_id}")
    
    print("\n📋 B. Sinh cặp khóa bất đối xứng (RSA-2048)")
    print("-" * 40)
    
    rsa_key_id, rsa_pub_id = key_store.generate_asymmetric_key_pair(
        "rsa_signing_key_1",
        "alice",
        "Message Signing"
    )
    print(f"✓ Khóa riêng RSA: {rsa_key_id}")
    print(f"✓ Khóa công khai RSA: {rsa_pub_id}")
    
    print("\n📋 C. Liệt kê khóa của người dùng")
    print("-" * 40)
    keys = key_store.list_keys("alice")
    for key_meta in keys:
        print(f"  • {key_meta['key_id']}: {key_meta['algorithm']} "
              f"({key_meta['key_size']} bits)")
    
    print("\n📋 D. Xoay vòng khóa (Key Rotation)")
    print("-" * 40)
    new_key_id = key_store.rotate_key(data_key_id)
    print(f"✓ Khóa cũ: {data_key_id} (đánh dấu không hoạt động)")
    print(f"✓ Khóa mới: {new_key_id} (phiên bản 2)")
    
    print("\n📋 E. Thu hồi khóa (Key Revocation)")
    print("-" * 40)
    key_store.revoke_key(comm_key_id)
    print(f"✓ Khóa {comm_key_id} đã được thu hồi")
    
    return key_store, data_key_id, rsa_key_id, rsa_pub_id


def demo_identity_management():
    """Demo quản lý danh tính"""
    print_section("2. IDENTITY MANAGEMENT - QUẢN LÝ DANH TÍNH")
    
    iam = IdentityManagementSystem("demo_identity")
    
    print("📋 A. Tạo người dùng")
    print("-" * 40)
    
    # Tạo người dùng admin
    admin = iam.create_user(
        username="admin",
        email="admin@company.com",
        password="AdminSecure@123",
        roles=[Role.ADMIN]
    )
    print(f"✓ Admin được tạo: {admin.username} ({admin.user_id})")
    
    # Tạo người dùng quản lý
    manager = iam.create_user(
        username="manager",
        email="manager@company.com",
        password="ManagerPass@123",
        roles=[Role.MANAGER]
    )
    print(f"✓ Manager được tạo: {manager.username} ({manager.user_id})")
    
    # Tạo người dùng bình thường
    user = iam.create_user(
        username="alice",
        email="alice@company.com",
        password="AlicePass@123",
        roles=[Role.USER]
    )
    print(f"✓ User được tạo: {user.username} ({user.user_id})")
    
    print("\n📋 B. Xác thực người dùng")
    print("-" * 40)
    
    # Xác thực thành công
    session = iam.authenticate_user("alice", "AlicePass@123", "192.168.1.100")
    if session:
        print(f"✓ Đăng nhập thành công!")
        print(f"  Session ID: {session.session_id}")
        print(f"  IP: {session.ip_address}")
    
    # Xác thực thất bại
    session_fail = iam.authenticate_user("alice", "WrongPassword", "192.168.1.100")
    if not session_fail:
        print(f"✗ Đăng nhập thất bại (mật khẩu sai)")
    
    print("\n📋 C. Kiểm soát truy cập dựa trên vai trò (RBAC)")
    print("-" * 40)
    
    # Kiểm tra quyền
    admin_perms = iam.get_user_permissions(admin.user_id)
    print(f"✓ Admin có {len(admin_perms)} quyền")
    print(f"  Có thể: tạo khóa? {Permission('keys', 'create') in admin_perms}")
    print(f"  Có thể: xóa khóa? {Permission('keys', 'delete') in admin_perms}")
    
    user_perms = iam.get_user_permissions(user.user_id)
    print(f"✓ User có {len(user_perms)} quyền")
    print(f"  Có thể: đọc khóa? {Permission('keys', 'read') in user_perms}")
    print(f"  Có thể: xóa khóa? {Permission('keys', 'delete') in user_perms}")
    
    print("\n📋 D. Multi-Factor Authentication (MFA)")
    print("-" * 40)
    
    mfa_secret = iam.enable_mfa(user.user_id)
    print(f"✓ MFA được bật cho user")
    print(f"  Mã bí mật: {mfa_secret[:20]}...")
    print(f"  MFA kích hoạt: {user.mfa_enabled}")
    
    # Xác minh MFA
    if iam.verify_mfa(user.user_id, mfa_secret[:6]):
        print(f"✓ Xác minh MFA thành công")
    
    print("\n📋 E. Xem danh sách người dùng")
    print("-" * 40)
    users = iam.list_users()
    for u in users:
        print(f"  • {u['username']:15} ({u['user_id'][:8]}...) - Vai trò: {u['roles']}")
    
    return iam, admin, manager, user


def demo_secure_transmission(key_store, iam, data_key_id, admin, user, rsa_key_id):
    """Demo truyền dữ liệu an toàn"""
    print_section("3. SECURE TRANSMISSION - TRUYỀN DỮ LIỆU AN TOÀN")
    
    channel = SecureTransmissionChannel()
    
    print("📋 A. Mã hóa/Giải mã với AES-256-GCM")
    print("-" * 40)
    
    # Lấy khóa
    encryption_key = key_store.get_symmetric_key(data_key_id)
    if encryption_key is None:
        print(f"✗ Không thể lấy khóa đối xứng cho {data_key_id}. Bỏ qua phần Secure Transmission.")
        return channel
    
    # Tạo thông điệp
    message = SecureMessage(
        sender_id=admin.user_id,
        recipient_id=user.user_id,
        content="Dữ liệu bí mật: Database credentials - user:admin password:secret123"
    )
    
    # Mã hóa
    nonce, ciphertext, tag = channel.encrypt_aes_256_gcm(
        message.content,
        encryption_key,
        f"{message.sender_id}:{message.recipient_id}"
    )
    
    print(f"✓ Thông điệp gốc: {message.content[:50]}...")
    print(f"✓ Mã hóa hoàn tất (AES-256-GCM)")
    print(f"  Ciphertext: {ciphertext[:50]}...")
    
    # Giải mã
    decrypted = channel.decrypt_aes_256_gcm(
        nonce, ciphertext, tag, encryption_key,
        f"{message.sender_id}:{message.recipient_id}"
    )
    
    print(f"✓ Giải mã thành công: {decrypted[:50]}...")
    
    print("\n📋 B. Chữ ký số (Digital Signature) - RSA")
    print("-" * 40)
    
    # Lấy khóa riêng
    private_key = key_store.get_private_key(rsa_key_id)
    public_key = key_store.get_public_key(rsa_key_id)
    if private_key is None or public_key is None:
        print(f"✗ Không thể tải cặp khóa RSA cho {rsa_key_id}. Bỏ qua phần chữ ký số.")
        return channel
    
    message_to_sign = "Xác nhận hợp đồng số 2024-001"
    
    # Ký thông điệp
    signature = channel.sign_message(message_to_sign, private_key)
    print(f"✓ Thông điệp: {message_to_sign}")
    print(f"✓ Chữ ký được tạo: {signature[:50]}...")
    
    # Xác minh chữ ký
    is_valid = channel.verify_signature(message_to_sign, signature, public_key)
    print(f"✓ Xác minh chữ ký: {'Hợp lệ ✓' if is_valid else 'Không hợp lệ ✗'}")
    
    # Thử thay đổi thông điệp
    tampered_message = "Xác nhận hợp đồng số 2024-999"
    is_valid_tampered = channel.verify_signature(tampered_message, signature, public_key)
    print(f"✓ Xác minh thông điệp bị thay đổi: {'Hợp lệ ✓' if is_valid_tampered else 'Không hợp lệ ✗'}")
    
    print("\n📋 C. HMAC - Kiểm tra tính toàn vẹn")
    print("-" * 40)
    
    hmac_key = key_store.get_symmetric_key(data_key_id)
    if hmac_key is None:
        print(f"✗ Không thể lấy khóa HMAC cho {data_key_id}. Bỏ qua phần HMAC.")
        return channel

    message_text = "Dữ liệu quan trọng"
    
    # Tạo HMAC
    hmac_value = channel.generate_hmac(message_text, hmac_key)
    print(f"✓ Thông điệp: {message_text}")
    print(f"  HMAC: {hmac_value}")
    
    # Xác minh HMAC
    is_integrity_ok = channel.verify_hmac(message_text, hmac_value, hmac_key)
    print(f"✓ Xác minh toàn vẹn: {'OK ✓' if is_integrity_ok else 'Lỗi ✗'}")
    
    print("\n📋 D. Truyền thông điệp được bảo vệ")
    print("-" * 40)
    
    # Gửi thông điệp an toàn
    secure_msg = SecureMessage(
        sender_id=admin.user_id,
        recipient_id=user.user_id,
        content="Mã OTP của bạn là: 123456"
    )
    
    encrypted_transmission = channel.send_secure_message(
        secure_msg,
        encryption_key,
        use_gcm=True
    )
    
    print(f"✓ Thông điệp được gửi an toàn")
    print(f"  Message ID: {encrypted_transmission['message_id']}")
    print(f"  Thuật toán: {encrypted_transmission['algorithm']}")
    print(f"  Người gửi: {encrypted_transmission['sender_id'][:8]}...")
    print(f"  Người nhận: {encrypted_transmission['recipient_id'][:8]}...")
    
    # Nhận và giải mã
    received_content = channel.receive_secure_message(
        encrypted_transmission,
        encryption_key
    )
    if received_content is None:
        print("✗ Giải mã thất bại, nội dung nhận được là None")
    else:
        print(f"✓ Thông điệp được giải mã: {received_content}")
    
    return channel


def demo_audit_logging(iam, key_store):
    """Demo ghi lại kiểm tra"""
    print_section("4. AUDIT LOGGING - GHI LẠI KIỂM TRA")
    
    audit = AuditLogger("demo_audit")
    
    print("📋 A. Ghi lại sự kiện")
    print("-" * 40)
    
    # Ghi lại đăng nhập
    audit.log_event(
        AuditEventType.USER_LOGIN,
        user_id="alice_123",
        resource="sessions",
        action="login",
        result="success",
        details={"session_duration_minutes": 60},
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0"
    )
    print("✓ Sự kiện đăng nhập được ghi")
    
    # Ghi lại tạo khóa
    audit.log_event(
        AuditEventType.KEY_GENERATED,
        user_id="alice_123",
        resource="keys",
        action="generate",
        result="success",
        details={"algorithm": "AES-256", "key_id": "key_001"},
        ip_address="192.168.1.100"
    )
    print("✓ Sự kiện sinh khóa được ghi")
    
    # Ghi lại cấp quyền
    audit.log_event(
        AuditEventType.PERMISSION_GRANTED,
        user_id="alice_123",
        resource="keys",
        action="read",
        result="success",
        details={"key_id": "key_001"}
    )
    print("✓ Sự kiện cấp quyền được ghi")
    
    # Ghi lại lỗi
    audit.log_event(
        AuditEventType.PERMISSION_DENIED,
        user_id="attacker_456",
        resource="keys",
        action="delete",
        result="failed",
        details={"reason": "insufficient_permissions"},
        ip_address="203.0.113.45"
    )
    print("✓ Sự kiện từ chối được ghi")
    
    print("\n📋 B. Truy vấn bản ghi kiểm tra")
    print("-" * 40)
    
    # Lấy bản ghi của người dùng
    user_logs = audit.get_logs_by_user("alice_123")
    print(f"✓ Bản ghi của alice_123: {len(user_logs)} sự kiện")
    for log in user_logs:
        print(f"  • {log['event_type']:30} - {log['result']}")
    
    # Lấy bản ghi của loại sự kiện
    key_logs = audit.get_logs_by_event_type(AuditEventType.KEY_GENERATED)
    print(f"\n✓ Bản ghi sinh khóa: {len(key_logs)} sự kiện")
    
    print("\n📋 C. Phát hiện hoạt động đáng nghi")
    print("-" * 40)
    
    # Ghi lại nhiều lần đăng nhập thất bại
    for i in range(4):
        audit.log_event(
            AuditEventType.USER_FAILED_LOGIN,
            user_id="suspicious_user",
            resource="sessions",
            action="login",
            result="failed",
            details={"attempt": i + 1},
            ip_address="203.0.113.99"
        )
    
    # Phát hiện hoạt động đáng nghi
    suspicious = audit.detect_suspicious_activity("suspicious_user")
    print(f"✓ Phát hiện hoạt động đáng nghi: {len(suspicious)} sự kiện")
    print(f"  → 4 lần đăng nhập thất bại trong 5 phút")
    
    print("\n📋 D. Báo cáo truy cập")
    print("-" * 40)
    
    report = audit.generate_access_report("alice_123")
    print(f"Báo cáo truy cập cho alice_123:")
    print(f"  • Tổng đăng nhập: {report['total_logins']}")
    print(f"  • Đăng nhập thất bại: {report['failed_logins']}")
    print(f"  • Khóa được truy cập: {report['keys_accessed']}")
    print(f"  • Quyền bị từ chối: {report['permissions_denied']}")
    
    print("\n📋 E. Xuất bản ghi")
    print("-" * 40)
    
    export_path = audit.export_logs(format="json")
    print(f"✓ Bản ghi đã được xuất: {export_path}")
    
    return audit


def main():
    """Chạy demo"""
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*10 + "IAM SYSTEM - KEY MANAGEMENT DEMONSTRATION" + " "*7 + "║")
    print("║" + " "*15 + "Hệ thống quản lý danh tính và khóa" + " "*11 + "║")
    print("╚" + "="*58 + "╝")
    
    # Demo 1: Key Management
    key_store, data_key_id, rsa_key_id, rsa_pub_id = demo_key_management()
    
    # Demo 2: Identity Management
    iam, admin, manager, user = demo_identity_management()
    
    # Demo 3: Secure Transmission
    channel = demo_secure_transmission(key_store, iam, data_key_id, admin, user, rsa_key_id)
    
    # Demo 4: Audit Logging
    audit = demo_audit_logging(iam, key_store)
    
    # Summary
    print_section("TỔNG HỢP HỆ THỐNG")
    
    print("📊 Thống kê:")
    print(f"  • Người dùng: {len(iam.users)}")
    print(f"  • Khóa: {len(key_store.keys_metadata)}")
    print(f"  • Sự kiện kiểm tra: {len(audit.current_logs)}")
    
    print("\n🎯 Các tính năng được minh họa:")
    print("  ✓ Sinh và quản lý khóa (đối xứng & bất đối xứng)")
    print("  ✓ Xoay vòng khóa (Key Rotation)")
    print("  ✓ Thu hồi khóa (Key Revocation)")
    print("  ✓ Quản lý danh tính người dùng")
    print("  ✓ Xác thực (Authentication)")
    print("  ✓ Phân quyền (Authorization / RBAC)")
    print("  ✓ Xác thực đa yếu tố (MFA)")
    print("  ✓ Mã hóa đối xứng (AES-256)")
    print("  ✓ Mã hóa bất đối xứng (RSA)")
    print("  ✓ Chữ ký số (Digital Signature)")
    print("  ✓ HMAC - Kiểm tra tính toàn vẹn")
    print("  ✓ Ghi lại kiểm tra (Audit Logging)")
    print("  ✓ Phát hiện hoạt động đáng nghi (Anomaly Detection)")
    
    print("\n✅ Demo hoàn tất!\n")


if __name__ == "__main__":
    main()
