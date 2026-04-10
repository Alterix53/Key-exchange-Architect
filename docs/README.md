IAM System - Key Management and Distribution Documentation

================================================================================
1. GIỚI THIỆU HỆ THỐNG
================================================================================

Hệ thống này là một giải pháp toàn diện cho phép:

1.1 Key Management (Quản lý Khóa)
    ✓ Sinh khóa an toàn (đối xứng & bất đối xứng)
    ✓ Lưu trữ khóa được mã hóa
    ✓ Xoay vòng khóa định kỳ
    ✓ Thu hồi khóa (Key Revocation)
    ✓ Quản lý vòng đời khóa

1.2 Identity Management (Quản lý Danh tính)
    ✓ Quản lý người dùng
    ✓ Xác thực (Authentication)
    ✓ Phân quyền truy cập (Authorization)
    ✓ Kiểm soát truy cập dựa trên vai trò (RBAC)
    ✓ Xác thực đa yếu tố (MFA)

1.3 Secure Transmission (Truyền dữ liệu an toàn)
    ✓ Mã hóa AES-256 (CBC & GCM)
    ✓ Mã hóa RSA-OAEP
    ✓ Chữ ký số (Digital Signature)
    ✓ HMAC - Kiểm tra tính toàn vẹn
    ✓ Truyền thông điệp được bảo vệ

1.4 Audit & Compliance
    ✓ Ghi lại tất cả hoạt động
    ✓ Phát hiện hoạt động đáng nghi
    ✓ Báo cáo truy cập & tuân thủ
    ✓ Xuất bản ghi


================================================================================
2. CẤU TRÚC HỆ THỐNG
================================================================================

IAM_Key_Management_System/
├── src/
│   ├── key_management.py          # Quản lý khóa
│   ├── identity_management.py     # Quản lý danh tính
│   ├── secure_transmission.py     # Truyền dữ liệu an toàn
│   ├── audit_logging.py           # Ghi lại kiểm tra
│   └── __init__.py                # Tích hợp hệ thống
├── tests/
│   └── test_system.py             # Các bài kiểm tra
├── docs/
│   ├── README.md                  # Tài liệu
│   └── ARCHITECTURE.md            # Kiến trúc hệ thống
├── demo_system.py                 # Demonstration
└── requirements.txt               # Các phụ thuộc


================================================================================
3. KEY MANAGEMENT
================================================================================

3.1 Cấp bậc Khóa

    ┌─────────────────────────┐
    │    Master Key (KMS)     │ ← Lưu trữ an toàn nhất
    └────────────┬────────────┘
                 │
    ┌────────────┴────────────┐
    │                         │
    ▼                         ▼
┌─────────────┐        ┌──────────────┐
│  Data Key   │        │  Comm Key    │ ← Mã hóa dữ liệu
└─────────────┘        └──────────────┘
    │                         │
    ▼                         ▼
 DATA                    MESSAGES


3.2 Sinh Khóa

    a) Khóa đối xứng (Symmetric Keys)
       - AES-128: 128 bits
       - AES-256: 256 bits
       - Dùng cho: mã hóa dữ liệu, giao tiếp
    
    b) Khóa bất đối xứng (Asymmetric Keys)
       - RSA-2048, RSA-4096
       - Có cặp: Public Key (công khai), Private Key (riêng)
       - Dùng cho: chữ ký số, mã hóa key exchange

3.3 Lưu trữ Khóa

    Tất cả khóa đều được:
    - Mã hóa bằng Master Key
    - Lưu trữ với quyền cao (0o600)
    - Ghi lại metadata (sinh, hết hạn, người chủ sở hữu)

3.4 Xoay vòng Khóa

    Quy trình:
    1. Sinh khóa mới (version++)
    2. Đánh dấu khóa cũ không hoạt động
    3. Khóa cũ giữ lại để giải mã dữ liệu cũ
    4. Mã hóa dữ liệu mới bằng khóa mới

3.5 Thu hồi Khóa

    Khi một khóa bị phát hiện bị lộ:
    - Đánh dấu is_active = false
    - Không thể dùng cho hoạt động mới
    - Giữ lại để dò tìm tài liệu được mã hóa với khóa này


================================================================================
4. IDENTITY MANAGEMENT
================================================================================

4.1 Quản lý Người dùng

    User Attributes:
    - user_id: ID duy nhất
    - username: Tên đăng nhập
    - email: Địa chỉ email
    - roles: Danh sách vai trò
    - groups: Danh sách nhóm
    - attributes: Thông tin bổ sung tùy chỉnh
    - mfa_enabled: Trạng thái MFA
    - is_active: Người dùng còn hoạt động?

4.2 Xác thực (Authentication)

    Quy trình:
    1. Người dùng nhập username + password
    2. Xác minh password (PBKDF2 - 100,000 iterations)
    3. Tạo Session với token bí mật
    4. Nếu MFA bật: yêu cầu xác minh MFA
    5. Cập nhật last_login

    Password Hashing:
    - Dùng PBKDF2 với SHA-256
    - Salt 16 bytes ngẫu nhiên
    - 100,000 lần iteration

4.3 Phân quyền (Authorization) - RBAC

    Các Vai trò:
    ├── ADMIN
    │   └── Tất cả quyền
    ├── MANAGER
    │   ├── Quản lý người dùng (đọc/cập nhật)
    │   ├── Xoay vòng khóa
    │   └── Xem audit logs
    ├── USER
    │   ├── Đọc khóa công cộng
    │   └── Xem audit log của mình
    └── GUEST
        └── Đọc khóa công khai

    Quyền:
    - Format: {resource}:{action}
    - Ví dụ: keys:create, users:read, audit:read

4.4 Xác thực Đa yếu tố (MFA)

    Bước 1: Bật MFA
    - Sinh mã bí mật (TOTP seed)
    - Người dùng scan QR code
    
    Bước 2: Xác minh MFA
    - Người dùng nhập 6 chữ số từ ứng dụng
    - So sánh với mã bí mật
    - Giới hạn 5 lần thử

4.5 Quản lý Phiên (Session Management)

    Session Attributes:
    - session_id: Token phiên
    - user_id: ID người dùng
    - created_at: Thời gian tạo
    - expires_at: Thời gian hết hạn (mặc định 60 phút)
    - is_active: Phiên còn hoạt động?
    - ip_address: Địa chỉ IP
    - mfa_verified: Đã xác minh MFA?


================================================================================
5. SECURE TRANSMISSION
================================================================================

5.1 Mã hóa Đối xứng

    a) AES-256-CBC (Cipher Block Chaining)
    
       Từng bước:
       1. Sinh IV (Initialization Vector) 16 bytes ngẫu nhiên
       2. Padding (PKCS7) nếu cần
       3. Mã hóa: plaintext → ciphertext
       4. Gửi: IV || ciphertext
    
       Ưu điểm: Nhanh, hiệu quả
       Nhược điểm: Không xác thực
    
    b) AES-256-GCM (Galois/Counter Mode)
    
       Từng bước:
       1. Sinh nonce 12 bytes ngẫu nhiên
       2. Mã hóa & xác thực: plaintext → ciphertext + tag
       3. Gửi: nonce || ciphertext || tag
    
       Ưu điểm: Vừa mã hóa vừa xác thực
       Nhược điểm: Phức tạp hơn

5.2 Mã hóa Bất đối xứng

    RSA-OAEP (Optimal Asymmetric Encryption Padding)
    
    Mã hóa:
    1. Lấy khóa công khai của người nhận
    2. Mã hóa: plaintext → ciphertext
    3. Gửi: ciphertext
    
    Giải mã:
    1. Dùng khóa riêng để giải mã
    2. plaintext = decrypt(ciphertext, private_key)
    
    Dùng cho: Truyền khóa đối xứng (key exchange)

5.3 Chữ ký Số (Digital Signature)

    RSA-PSS (Probabilistic Signature Scheme)
    
    Ký (Sign):
    1. Tính hash: H = SHA256(message)
    2. Ký: signature = sign(H, private_key)
    3. Gửi: message || signature
    
    Xác minh (Verify):
    1. Nhận message || signature
    2. Tính H = SHA256(message)
    3. Kiểm tra: verify(signature, H, public_key)
    
    Tính chất:
    - Chứng thực: Người ký không thể phủ nhận
    - Toàn vẹn: Phát hiện nếu message bị sửa

5.4 HMAC (Hash-based Message Authentication Code)

    HMAC-SHA256
    
    Tạo:
    1. HMAC = SHA256(key || message || key)
    2. Gửi: message || HMAC
    
    Xác minh:
    1. Tính HMAC mới = SHA256(key || message || key)
    2. So sánh: HMAC_mới == HMAC_nhận
    
    Dùng cho: Kiểm tra toàn vẹn dữ liệu


================================================================================
6. AUDIT & LOGGING
================================================================================

6.1 Các Loại Sự kiện

    Người dùng:
    - user_created, user_login, user_logout
    - user_failed_login, user_updated, user_deactivated
    
    Khóa:
    - key_generated, key_rotated, key_accessed
    - key_revoked, key_deleted
    
    Quyền:
    - permission_granted, permission_denied, permission_revoked
    
    Thông điệp:
    - message_sent, message_received, message_decryption_failed
    
    MFA:
    - mfa_enabled, mfa_verification_success, mfa_verification_failed
    
    Hệ thống:
    - system_error, suspicious_activity

6.2 Bản Ghi

    Mỗi bản ghi chứa:
    - log_id: ID duy nhất
    - timestamp: Thời điểm
    - event_type: Loại sự kiện
    - user_id: Người thực hiện
    - resource: Tài nguyên (users, keys, messages)
    - action: Hành động (create, read, update, delete)
    - result: Kết quả (success, failed)
    - details: Dữ liệu bổ sung
    - ip_address: Địa chỉ IP
    - user_agent: Thông tin trình duyệt

6.3 Phát hiện Hoạt động Đáng nghi

    Tiêu chí:
    1. Nhiều lần đăng nhập thất bại (≥3 lần/5 phút)
    2. Đăng nhập từ nhiều IP khác nhau (≥2 IP/5 phút)
    3. Truy cập từ múi giờ khác (0-30 phút)

6.4 Báo cáo

    Báo cáo truy cập:
    - Tổng lần đăng nhập
    - Lần đăng nhập thất bại
    - Khóa được truy cập
    - Quyền bị từ chối
    - Lần đăng nhập gần nhất

    Xuất bản ghi:
    - JSON format
    - CSV format (cho Excel/Analytics)


================================================================================
7. SỬ DỤNG HỆ THỐNG
================================================================================

7.1 Cài đặt

    pip install -r requirements.txt

7.2 Khởi tạo

    from src import IAMSystem
    
    iam_system = IAMSystem(base_path="iam_data")
    admin_id = iam_system.initialize_admin_user()

7.3 Tạo người dùng

    user = iam_system.identity_mgmt.create_user(
        username="alice",
        email="alice@company.com",
        password="SecurePass@123",
        roles=[Role.USER]
    )

7.4 Xác thực

    session = iam_system.identity_mgmt.authenticate_user(
        username="alice",
        password="SecurePass@123",
        ip_address="192.168.1.100"
    )

7.5 Sinh khóa

    key_id = iam_system.key_store.generate_symmetric_key(
        key_id="data_key_1",
        owner="alice",
        purpose="Data Encryption",
        algorithm="AES-256"
    )

7.6 Mã hóa & Gửi thông điệp

    key = iam_system.key_store.get_symmetric_key(key_id)
    
    encrypted_msg = iam_system.send_encrypted_message(
        sender_id=admin_id,
        recipient_id=user.user_id,
        message_content="Secret data",
        encryption_key=key
    )

7.7 Nhận & Giải mã thông điệp

    plaintext = iam_system.receive_encrypted_message(
        recipient_id=user.user_id,
        encrypted_message=encrypted_msg,
        decryption_key=key
    )

7.8 Xem Audit Logs

    logs = iam_system.audit_logger.get_logs_by_user(user.user_id)
    
    for log in logs:
        print(f"{log['timestamp']} - {log['event_type']}: {log['result']}")


================================================================================
8. BẢO MẬT BEST PRACTICES
================================================================================

8.1 Lưu trữ Khóa

    ❏ Khóa Master được lưu riêng (chmod 0o600)
    ❏ Tất cả khóa sử use được mã hóa trước khi lưu
    ❏ Không bao giờ log khóa thực (chỉ log key_id)
    ❏ Định kỳ xoay vòng khóa (≥ 90 ngày)

8.2 Mật khẩu

    ❏ Hash với PBKDF2, SHA-256, 100K iterations
    ❏ Salt 16 bytes per user
    ❏ Mật khẩu ≥ 12 ký tự
    ❏ Yêu cầu gồm: hoa, thường, số, ký tự đặc biệt

8.3 Phiên

    ❏ Token phiên ≥ 32 bytes entropy
    ❏ Session timeout: 30-60 phút
    ❏ Bind to IP address
    ❏ Secure Cookies (HTTPS only, HttpOnly, Secure flags)

8.4 Truyền dữ liệu

    ❏ Luôn dùng TLS 1.2+ (HTTPS)
    ❏ Perfect Forward Secrecy (PFS)
    ❏ Cipher suites mạnh (AES-256-GCM, ChaCha20)
    ❏ Xác minh certificate

8.5 Xác thực

    ❏ Bắt buộc MFA cho admin/manager
    ❏ 2FA/TOTP cho nhạy cảm
    ❏ Thông báo đăng nhập bất thường
    ❏ Account lockout sau 5 lần thất bại

8.6 Kiểm toán

    ❏ Tất cả hành động được log
    ❏ Log được bảo vệ (append-only)
    ❏ Giữ lại log ≥ 1 năm
    ❏ Kiểm tra log định kỳ (hàng tuần)
    ❏ Alert hoạt động bất thường trong 5 phút


================================================================================
9. KIẾN TRÚC BẢNG DỮ LIỆU
================================================================================

users/ (Identity Storage)
├── {user_id}.json
└── Chứa: user_id, username, email, password_hash, roles, created_at, ...

keys/ (Key Storage)
├── master.key              # Master key (encrypted)
├── {key_id}.key           # Symmetric key (encrypted)
├── {key_id}.meta          # Key metadata (JSON)
├── {key_id}_private.pem   # RSA private key (encrypted)
├── {key_id}_public.pem    # RSA public key
└── ...

audit/ (Audit Storage)
├── YYYY-MM-DD_audit.jsonl # Một event per line
├── export_*.json          # Exported logs
└── ...


================================================================================
10. TROUBLESHOOTING
================================================================================

Vấn đề: Key not found
Giải pháp: Kiểm tra key_id có chính xác, khóa chưa bị xóa

Vấn đề: Decryption failed
Giải pháp: Verify Master Key đúng, ciphertext chưa bị hỏng

Vấn đề: Session expired
Giải pháp: Tăng session_timeout, hoặc logout & login lại

Vấn đề: MFA verification fails
Giải pháp: Kiểm tra thời gian server/client đồng bộ

Vấn đề: Too many failed attempts
Giải pháp: Account bị lockout tạm thời, thử lại sau


================================================================================
11. TÀI LIỆU THAM KHẢO
================================================================================

NIST Publications:
- NIST SP 800-57: Recommendation for Key Management
- NIST SP 800-63: Digital Identity Guidelines
- NIST SP 800-53: Security and Privacy Controls

Tiêu chuẩn mã hóa:
- FIPS 180-4: SHA Hash Algorithms
- FIPS 186-4: Digital Signature Standard
- RFC 2898: PBKDF2

Mã hóa:
- FIPS 197: Advanced Encryption Standard (AES)
- RFC 3394: AES Key Wrap Algorithm
- RFC 3610: AES-CCM

Xác thực:
- RFC 2104: HMAC
- RFC 4226: HOTP
- RFC 6238: TOTP

================================================================================
