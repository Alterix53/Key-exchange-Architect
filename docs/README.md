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
    - Lưu trữ với quyền cao (0o600) // 4 + 2 -> quyền chỉ đọc và viết của admin
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

    Certificate / PKI:
    - cert_csr_received, cert_issued, cert_revoked
    - cert_verified, cert_verification_failed
    - cert_chain_validated, cert_chain_validation_failed
    - crl_updated, cert_renewed
    
    Hệ thống:
    - system_error, suspicious_activity

6.2 Bản Ghi

    Mỗi bản ghi chứa:
    - log_id: ID duy nhất
    - timestamp: Thời điểm
    - event_type: Loại sự kiện
    - user_id: Người thực hiện
    - resource: Tài nguyên (users, keys, messages, pki)
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
7. PUBLIC KEY INFRASTRUCTURE — PKI (Section 14.5)
================================================================================

7.1 Tổng quan PKI

    PKI là hệ thống quản lý vòng đời certificate — từ đăng ký, cấp phát,
    sử dụng, gia hạn, cho đến thu hồi — với các vai trò rõ ràng.

    Thành phần:

    ┌──────────────────────────────────────────────────────────┐
    │                        PKI                               │
    │                                                          │
    │  ┌────────────┐   ┌──────────┐   ┌────────────────────┐ │
    │  │ End Entity │──→│    RA    │──→│        CA          │ │
    │  │  (Client)  │   │(Registra-│   │  (Certificate      │ │
    │  │            │   │  tion    │   │   Authority)       │ │
    │  └────────────┘   │Authority)│   └────────┬───────────┘ │
    │                   └──────────┘            │             │
    │                                  ┌────────▼───────────┐ │
    │                                  │    Repository      │ │
    │                                  │  (Kho lưu certs    │ │
    │                                  │   + CRL)           │ │
    │                                  └────────────────────┘ │
    └──────────────────────────────────────────────────────────┘

7.2 Certificate Authority (CA)

    Hệ thống sử dụng 2 tầng CA:

    a) Root CA (RootCA class)
       - RSA-4096, self-signed certificate
       - Thời hạn: 10 năm
       - BasicConstraints: ca=True, path_length=1
       - KeyUsage: keyCertSign, crlSign, digitalSignature
       - Nhiệm vụ: Chỉ ký certificate cho Intermediate CA
       - Quản lý CRL riêng (root_ca.crl)

    b) Intermediate CA (IntermediateCA class)
       - RSA-3072, certificate được Root CA ký
       - Thời hạn: 5 năm
       - BasicConstraints: ca=True, path_length=0
       - Nhiệm vụ: Cấp end-entity certificate cho client/server
       - Quản lý CRL riêng (intermediate_ca.crl)

    Tại sao cần 2 tầng?
       - Root CA private key cực kỳ quan trọng → nên để offline
       - Intermediate CA hoạt động hàng ngày
       - Nếu Intermediate CA bị lộ → chỉ cần thu hồi nó,
         Root CA vẫn an toàn

7.3 Registration Authority (RA)

    RA là cơ quan xác minh danh tính TRƯỚC KHI CA cấp certificate.

    Quy trình xử lý CSR:
    1. Nhận CSR từ End Entity
    2. Kiểm tra CSR signature hợp lệ (chứng minh sở hữu private key)
    3. Kiểm tra subject name hợp lệ (không rỗng)
    4. Kiểm tra trùng lặp (nếu đã có cert → thu hồi cũ, cấp mới)
    5. Chuyển CSR cho Intermediate CA cấp cert
    6. Lưu certificate vào Repository

7.4 Certificate Repository

    Kho lưu trữ tập trung cho tất cả certificate đã cấp.

    Chức năng:
    - Lưu certificate ra file .pem
    - Index bằng JSON (cert_index.json)
    - Tra cứu theo subject Common Name
    - Liệt kê tất cả certificate active

7.5 PKIX Management Functions

    a) Registration (Đăng ký)
       - End Entity sinh RSA key pair
       - Tạo CSR (Certificate Signing Request) — ký bởi private key
       - Gửi CSR cho RA

    b) Initialization (Khởi tạo)
       - Client nhận Root CA cert làm trust anchor
       - Lưu local tại data/root_ca_cert.pem

    c) Certification (Cấp phát)
       - RA verify CSR → chuyển cho Intermediate CA
       - CA ký → tạo X.509 v3 certificate
       - Lưu vào Repository

    d) Key Pair Update (Gia hạn)
       - End Entity sinh key pair MỚI
       - Tạo CSR mới → gửi cho RA
       - RA thu hồi cert CŨ + cấp cert mới

    e) Revocation (Thu hồi)
       - End Entity yêu cầu thu hồi
       - CA thêm serial number vào CRL
       - CRL được ký lại và publish

7.6 Certificate Revocation List (CRL)

    CRL là danh sách certificate đã bị thu hồi.

    Đặc điểm:
    - X.509 CRL chuẩn (không phải custom format)
    - Ký bởi CA (Root CA hoặc Intermediate CA)
    - Persistent: lưu ra file .crl
    - Cập nhật mỗi khi có certificate bị thu hồi
    - Client kiểm tra CRL trước khi trust cert


================================================================================
8. X.509 v3 CERTIFICATES (Section 14.4)
================================================================================

8.1 Cấu trúc Certificate

    ┌─────────────────────────────────────────┐
    │  Version:              v3               │
    │  Serial Number:        (unique random)  │
    │  Signature Algorithm:  SHA256WithRSA    │
    │  Issuer:               CA's DN          │
    │  Validity:                              │
    │    Not Before:         (timestamp)      │
    │    Not After:          (timestamp)      │
    │  Subject:              Entity's DN      │
    │  Subject Public Key Info:               │
    │    Algorithm:          RSA              │
    │    Public Key:         (key data)       │
    │  Extensions (v3):                       │
    │    • BasicConstraints                   │
    │    • KeyUsage                           │
    │    • ExtendedKeyUsage                   │
    │    • SubjectKeyIdentifier               │
    │    • AuthorityKeyIdentifier             │
    │    • SubjectAlternativeName             │
    │  Signature:            (CA's signature) │
    └─────────────────────────────────────────┘

8.2 X.509 v3 Extensions

    a) BasicConstraints [CRITICAL]
       - CA cert:     ca=True, path_length=1 hoặc 0
       - End-entity:  ca=False
       → Phân biệt CA certificate và end-entity certificate

    b) KeyUsage [CRITICAL]
       - CA cert:     keyCertSign, crlSign, digitalSignature
       - End-entity:  digitalSignature, keyEncipherment
       → Giới hạn cách sử dụng certificate

    c) ExtendedKeyUsage [non-critical]
       - Server cert: serverAuth (OID: 1.3.6.1.5.5.7.3.1)
       - Client cert: clientAuth (OID: 1.3.6.1.5.5.7.3.2)
       → Phân biệt mục đích sử dụng

    d) SubjectKeyIdentifier [non-critical]
       - Hash(public_key) → ID unique cho public key
       → Giúp xác định certificate nhanh

    e) AuthorityKeyIdentifier [non-critical]
       - Hash(issuer_public_key) → ID của CA đã ký
       → Giúp xây dựng certificate chain

    f) SubjectAlternativeName [non-critical]
       - DNS name hoặc IP address thay thế
       → Cho phép 1 cert dùng cho nhiều domain

8.3 Certificate Chain Validation

    Quy trình validate chain [leaf, intermediate, root]:

    Bước 1: Root cert trong chain == trusted root (pre-installed)?
            Nếu khác → REJECT (Root CA bị giả mạo)

    Bước 2: Với mỗi cặp (child, parent) trong chain:
            a) child.issuer == parent.subject?
               → Chain liên tục không bị đứt
            b) parent.publicKey.verify(child.signature)?
               → Chữ ký hợp lệ
            c) child.not_before <= now <= child.not_after?
               → Certificate chưa hết hạn
            d) child.serial KHÔNG có trong CRL?
               → Certificate chưa bị thu hồi

    Bước 3: Verify root cert self-signature
            → Root CA tự ký cho chính mình

    Nếu tất cả pass → Certificate chain hợp lệ ✓


================================================================================
9. SỬ DỤNG HỆ THỐNG
================================================================================

9.1 Cài đặt

    pip install -r requirements.txt

9.2 Chạy Server + Client

    Terminal 1: python server.py --host 127.0.0.1 --port 5000
    Terminal 2: python client.py --name Alice --host 127.0.0.1 --port 5000
    Terminal 3: python client.py --name Bob --host 127.0.0.1 --port 5000

9.3 Demo PKI Standalone

    python demo_pki.py

    Demo minh họa:
    1. Tạo PKI hierarchy (Root CA → Intermediate CA)
    2. CSR → RA → CA → Certificate
    3. X.509 v3 certificate chi tiết
    4. Certificate chain validation
    5. Certificate revocation + CRL
    6. Certificate renewal
    7. Certificate Repository lookup

9.4 Khởi tạo IAM System (API)

    from src import IAMSystem
    
    iam_system = IAMSystem(base_path="iam_data")
    admin_id = iam_system.initialize_admin_user()

9.5 Tạo người dùng

    user = iam_system.identity_mgmt.create_user(
        username="alice",
        email="alice@company.com",
        password="SecurePass@123",
        roles=[Role.USER]
    )

9.6 Mã hóa & Gửi thông điệp

    key = iam_system.key_store.get_symmetric_key(key_id)
    
    encrypted_msg = iam_system.send_encrypted_message(
        sender_id=admin_id,
        recipient_id=user.user_id,
        message_content="Secret data",
        encryption_key=key
    )


================================================================================
10. BẢO MẬT
================================================================================

10.1 PKI

    ❏ Root CA RSA-4096, Intermediate CA RSA-3072
    ❏ Certificate chain validation trước khi trust
    ❏ CRL check trước khi accept peer certificate
    ❏ Mutual authentication (client verify server, server verify CSR)
    ❏ CSR signed by private key (chứng minh sở hữu)
    ❏ Root CA cert pinning

10.2 Lưu trữ Khóa

    ❏ Khóa Master được lưu riêng (chmod 0o600)
    ❏ Tất cả khóa được mã hóa trước khi lưu
    ❏ Không bao giờ log khóa thực (chỉ log key_id)
    ❏ Định kỳ xoay vòng khóa (≥ 90 ngày)

10.3 Mật khẩu

    ❏ Hash với PBKDF2, SHA-256, 100K iterations
    ❏ Salt 16 bytes per user
    ❏ Mật khẩu ≥ 12 ký tự

10.4 Truyền dữ liệu

    ❏ End-to-End Encryption: AES-256-GCM
    ❏ Key Exchange: RSA-OAEP
    ❏ Session key 256-bit (os.urandom)


================================================================================
11. CẤU TRÚC THƯ MỤC
================================================================================

Key-exchange-Architect/
├── server.py                          # Relay server + PKI
├── client.py                          # Client + CSR + chain validation
├── demo_pki.py                        # Demo standalone PKI (14.4 + 14.5)
├── demo_system.py                     # Demo hệ thống tổng
├── requirements.txt
├── src/
│   ├── __init__.py                    # IAMSystem integration
│   ├── public_key_distribution.py     # ★ PKI module (14.4 + 14.5)
│   ├── key_management.py              # Key lifecycle
│   ├── identity_management.py         # IAM + RBAC
│   ├── secure_transmission.py         # Crypto primitives
│   └── audit_logging.py              # Audit logging
├── tests/
│   └── test_system.py
├── docs/
│   ├── README.md                      # Tài liệu (file này)
│   ├── ARCHITECTURE.md                # Kiến trúc
│   └── USE_CASES_AND_PRACTICES.md
└── data/                              # Auto-generated khi chạy
    ├── root_ca_cert.pem               # Root CA certificate
    ├── root_ca_private.pem            # Root CA private key
    ├── root_ca.crl                    # Root CA CRL
    ├── intermediate_ca_cert.pem       # Intermediate CA certificate
    ├── intermediate_ca_private.pem    # Intermediate CA private key
    ├── intermediate_ca.crl            # Intermediate CA CRL
    ├── server_cert.pem                # Server certificate
    ├── server_private.pem             # Server private key
    ├── cert_index.json                # Certificate index
    └── certificates/                  # Issued certificates
        ├── Alice_xxxx.pem
        └── Bob_xxxx.pem


================================================================================
12. TÀI LIỆU THAM KHẢO
================================================================================

Textbook:
- William Stallings, "Cryptography and Network Security"
  Chapter 14: Key Management and Distribution
  Section 14.4: X.509 Certificates
  Section 14.5: Public-Key Infrastructure

NIST Publications:
- NIST SP 800-57: Recommendation for Key Management
- NIST SP 800-63: Digital Identity Guidelines

Standards:
- RFC 5280: Internet X.509 PKI Certificate and CRL Profile
- RFC 2986: PKCS #10 — Certificate Signing Request
- RFC 6960: X.509 Online Certificate Status Protocol (OCSP)

Cryptography:
- FIPS 197: Advanced Encryption Standard (AES)
- RFC 2898: PBKDF2

================================================================================

