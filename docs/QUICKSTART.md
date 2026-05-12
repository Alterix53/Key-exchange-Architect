QUICK START - IAM System with Key Management

================================================================================
1. CÀI ĐẶT & CẤU HÌNH
================================================================================

Bước 1: Cài đặt dependencies
───────────────────────────

    pip install -r requirements.txt

Bước 2: Kiểm tra cài đặt
───────────────────────

    python -c "from cryptography.hazmat.primitives import hashes; print('✓ cryptography OK')"


================================================================================
2. CHẠY DEMONSTRATION
================================================================================

Chạy demo đầy đủ:
─────────────────

    cd IAM_Key_Management_System
    python demo_system.py

Kết quả:
    ✓ Sinh khóa dối xứng (AES-256)
    ✓ Sinh cặp khóa bất đối xứng (RSA-2048)
    ✓ Xoay vòng khóa
    ✓ Tạo người dùng
    ✓ Xác thực
    ✓ Phân quyền (RBAC)
    ✓ Mã hóa & giải mã
    ✓ Chữ ký số
    ✓ Ghi lại kiểm tra
    ✓ Phát hiện hoạt động đáng nghi


================================================================================
3. CHẠY UNIT TESTS
================================================================================

Chạy tất cả tests:
──────────────────

    cd tests
    python -m unittest test_system.py -v

Chạy test cụ thể:
─────────────────

    python -m unittest test_system.TestKeyManagement -v
    python -m unittest test_system.TestIdentityManagement -v
    python -m unittest test_system.TestSecureTransmission -v
    python -m unittest test_system.TestAuditLogging -v


================================================================================
4. SỬ DỤNG CÓ BẢN
================================================================================

4.1 Nhập thư viện
─────────────────

    from src.key_management import KeyStore
    from src.identity_management import IdentityManagementSystem, Role, Permission
    from src.secure_transmission import SecureTransmissionChannel, SecureMessage
    from src.audit_logging import AuditLogger, AuditEventType


4.2 Khởi tạo hệ thống
──────────────────────

    # Tạo Key Store
    key_store = KeyStore("my_keys")
    
    # Tạo hệ thống quản lý danh tính
    iam = IdentityManagementSystem("my_identity")
    
    # Tạo kênh truyền an toàn
    channel = SecureTransmissionChannel()
    
    # Tạo logger kiểm tra
    audit = AuditLogger("my_audit")


4.3 Làm việc với khóa
───────────────────

    # Sinh khóa dối xứng
    key_id = key_store.generate_symmetric_key(
        key_id="encryption_key_1",
        owner="alice",
        purpose="Data Encryption",
        algorithm="AES-256"
    )
    
    # Lấy khóa để sử dụng
    key = key_store.get_symmetric_key(key_id)
    
    # Sinh cặp khóa RSA
    rsa_key_id, rsa_pub_id = key_store.generate_asymmetric_key_pair(
        key_id="signing_key_1",
        owner="alice",
        purpose="Message Signing"
    )
    
    # Xoay vòng khóa
    new_key_id = key_store.rotate_key(key_id)
    
    # Liệt kê khóa của người dùng
    keys = key_store.list_keys(owner="alice")
    for key in keys:
        print(f"- {key['key_id']}: {key['algorithm']}")


4.4 Quản lý người dùng
──────────────────────

    # Tạo người dùng
    admin = iam.create_user(
        username="admin",
        email="admin@company.com",
        password="AdminSecure@123",
        roles=[Role.ADMIN]
    )
    
    user = iam.create_user(
        username="alice",
        email="alice@company.com",
        password="AlicePass@123",
        roles=[Role.USER]
    )
    
    # Xác thực người dùng
    session = iam.authenticate_user(
        username="alice",
        password="AlicePass@123",
        ip_address="192.168.1.100"
    )
    
    if session:
        print(f"✓ Đăng nhập thành công: {session.session_id}")
    else:
        print("✗ Đăng nhập thất bại")
    
    # Kiểm tra quyền
    permission = Permission("keys", "read")
    if iam.check_permission(user.user_id, permission):
        print("✓ User được phép đọc khóa")
    else:
        print("✗ User không được phép")
    
    # Bật MFA
    mfa_secret = iam.enable_mfa(user.user_id)
    print(f"MFA Secret: {mfa_secret}")


4.5 Mã hóa & Giải mã
────────────────────

    # Mã hóa với AES-256-GCM
    plaintext = "Secret message"
    key = b'\x00' * 32  # 256-bit key
    
    nonce, ciphertext, tag = channel.encrypt_aes_256_gcm(plaintext, key)
    
    # Giải mã
    decrypted = channel.decrypt_aes_256_gcm(nonce, ciphertext, tag, key)
    print(f"Decrypted: {decrypted}")


4.6 Chữ ký số
──────────────

    # Lấy khóa riêng
    private_key = key_store.get_private_key(rsa_key_id)
    public_key = key_store.get_public_key(rsa_key_id)
    
    # Ký thông điệp
    message = "Hợp đồng số 2024-001"
    signature = channel.sign_message(message, private_key)
    
    # Xác minh chữ ký
    is_valid = channel.verify_signature(message, signature, public_key)
    print(f"Signature valid: {is_valid}")


4.7 Truyền thông điệp an toàn
──────────────────────────────

    # Tạo thông điệp
    message = SecureMessage(
        sender_id=admin.user_id,
        recipient_id=user.user_id,
        content="Thông tin nhạy cảm"
    )
    
    # Mã hóa & gửi
    key = key_store.get_symmetric_key(key_id)
    encrypted_msg = channel.send_secure_message(message, key, use_gcm=True)
    
    # Nhận & giải mã
    plaintext = channel.receive_secure_message(encrypted_msg, key)
    print(f"Nhận được: {plaintext}")


4.8 Ghi lại hoạt động
──────────────────────

    # Ghi sự kiện
    audit.log_event(
        event_type=AuditEventType.USER_LOGIN,
        user_id=user.user_id,
        resource="sessions",
        action="login",
        result="success",
        ip_address="192.168.1.100"
    )
    
    # Lấy bản ghi của người dùng
    logs = audit.get_logs_by_user(user.user_id)
    for log in logs:
        print(f"{log['timestamp']} - {log['event_type']}: {log['result']}")
    
    # Phát hiện hoạt động đáng nghi
    suspicious = audit.detect_suspicious_activity(user.user_id)
    if suspicious:
        print(f"⚠️  Phát hiện {len(suspicious)} sự kiện đáng nghi")


================================================================================
9. TERMINAL RELAY CHAT (SERVER + 2 CLIENT)
================================================================================

Luồng chạy:
──────────

1) Chạy server trước

        python server.py --host 127.0.0.1 --port 5000

2) Mở terminal thứ hai cho client A

        python client.py --name A --host 127.0.0.1 --port 5000

3) Mở terminal thứ ba cho client B

        python client.py --name B --host 127.0.0.1 --port 5000

4) Tại terminal client A nhập tin nhắn

Kết quả cần thấy:
───────────────

- Client gửi
    [STATUS] Đã nhận Certificate từ Server: {...}
    [INPUT] Tin nhắn ban đầu: {nội dung gốc}
    [ENCRYPT] Tin nhắn sau khi mã hóa: {nonce/ciphertext/tag dạng Base64}

- Server
    [LOG] Đang chuyển tiếp tin nhắn mã hóa từ Client A sang Client B.

- Client nhận
    [RECEIVED] Tin nhắn mã hóa nhận được: {nonce/ciphertext/tag dạng Base64}
    [DECRYPT] Tin nhắn sau khi giải mã: {nội dung gốc}

Ghi chú:
────────

- Server hiện chỉ hỗ trợ đúng 2 client kết nối cùng lúc.
- Nhập "exit" hoặc "quit" ở client để thoát.


================================================================================
5. VÍ DỤ HOÀN CHỈNH
================================================================================

VÍ DỤ: Gửi thông điệp bí mật từ Admin đến User
───────────────────────────────────────────────

    # 1. Khởi tạo hệ thống
    key_store = KeyStore("example_keys")
    iam = IdentityManagementSystem("example_identity")
    channel = SecureTransmissionChannel()
    audit = AuditLogger("example_audit")
    
    # 2. Tạo người dùng
    admin = iam.create_user("admin", "admin@co.com", "Admin@123", [Role.ADMIN])
    alice = iam.create_user("alice", "alice@co.com", "Alice@123", [Role.USER])
    
    # 3. Xác thực
    admin_session = iam.authenticate_user("admin", "Admin@123")
    alice_session = iam.authenticate_user("alice", "Alice@123")
    
    # 4. Sinh khóa
    comm_key_id = key_store.generate_symmetric_key(
        "shared_comm_key",
        "admin",
        "Communication"
    )
    comm_key = key_store.get_symmetric_key(comm_key_id)
    
    # 5. Gửi thông điệp
    message = SecureMessage(
        sender_id=admin.user_id,
        recipient_id=alice.user_id,
        content="Mật khẩu tạm thời: TempPass@2024"
    )
    
    encrypted = channel.send_secure_message(message, comm_key)
    
    # 6. Ghi lại
    audit.log_event(
        AuditEventType.MESSAGE_SENT,
        admin.user_id,
        "messages",
        "send",
        "success",
        {"recipient": alice.user_id}
    )
    
    # 7. Alice nhận & giải mã
    decrypted = channel.receive_secure_message(encrypted, comm_key)
    print(f"Alice nhận: {decrypted}")
    
    # 8. Ghi lại nhận
    audit.log_event(
        AuditEventType.MESSAGE_RECEIVED,
        alice.user_id,
        "messages",
        "receive",
        "success",
        {"sender": admin.user_id}
    )
    
    # 9. Báo cáo
    admin_report = audit.generate_access_report(admin.user_id)
    alice_report = audit.generate_access_report(alice.user_id)
    
    print(f"\n--- Admin Report ---")
    print(f"Logins: {admin_report['total_logins']}")
    print(f"Keys accessed: {admin_report['keys_accessed']}")
    
    print(f"\n--- Alice Report ---")
    print(f"Logins: {alice_report['total_logins']}")
    print(f"Messages received: {alice_report.get('messages_received', 0)}")


================================================================================
6. STRUCTURE DẠO HÀM DỮ LIỆU
================================================================================

Sau khi chạy demo, bạn sẽ thấy:

demo_keys/
  ├── master.key           # Master Key được bảo vệ
  ├── *.key               # Symmetric keys (encrypted)
  ├── *.meta              # Metadata (JSON)
  └── *_public.pem        # Public keys

demo_identity/
  ├── alice.json          # User alice
  ├── admin.json          # User admin
  └── ...

demo_audit/
  ├── 2024-01-XX_audit.jsonl   # Audit logs (append-only)
  └── export_*.json            # Exported logs


================================================================================
7. TROUBLESHOOTING
================================================================================

Q: "ModuleNotFoundError: No module named 'cryptography'"
A: Cài đặt: pip install cryptography

Q: "KeyError: 'key_id not found'"
A: Kiểm tra key_id đã tồn tại hay chưa

Q: "Decryption failed"
A: Kiểm tra key sử dụng để mã hóa/giải mã có giống nhau không

Q: "Session expired"
A: Login lại hoặc tăng session timeout

Q: "Permission denied"
A: Kiểm tra vai trò của người dùng có đủ quyền không


================================================================================
8. THAM KHẢO THÊM
================================================================================

- Đọc docs/README.md để hiểu chi tiết các module
- Đọc docs/ARCHITECTURE.md để xem flow & cấu trúc
- Xem demo_system.py để tìm ví dụ sử dụng
- Chạy tests để hiểu cách kiểm tra

================================================================================
