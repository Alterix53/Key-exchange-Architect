USE CASES & BEST PRACTICES

================================================================================
1. USE CASES
================================================================================

USE CASE 1: Bảo vệ dữ liệu nhạy cảm
───────────────────────────────────

Scenario:
  • Công ty cần bảo vệ hồ sơ nhân viên (lương, địa chỉ, ...)
  • Chỉ HR Manager có thể truy cập
  • Tất cả truy cập phải được ghi lại

Solution:
  1. Sử dụng AES-256-GCM mã hóa dữ liệu tại rest
  2. Master Key được lưu riêng biệt
  3. Key rotation định kỳ (quarterly)
  4. RBAC: Chỉ Role.MANAGER + HR group có permission
  5. Audit logs tất cả access attempts


USE CASE 2: Xác thực an toàn cho ứng dụng web
───────────────────────────────────────────

Scenario:
  • Ứng dụng web với 1000+ người dùng
  • Cần bảo vệ khỏi credential stuffing attacks
  • Cần phát hiện đăng nhập bất thường

Solution:
  1. PBKDF2 hash + salt cho mật khẩu
  2. MFA bắt buộc cho admin/sensitive operations
  3. Session timeout 30 phút
  4. IP binding: mỗi session bind to specific IP
  5. Failed login detection: >3 lần = lockout 15 phút
  6. Geographic anomaly: Đăng nhập từ 2 địa điểm khác nhau trong 5 phút


USE CASE 3: Secure API Communication
─────────────────────────────────────

Scenario:
  • 2 microservices cần giao tiếp an toàn
  • Dữ liệu sensitive (API keys, PII)
  • Cần chứng thực (authentication) + toàn vẹn (integrity)

Solution:
  1. RSA key exchange để negotiate shared key
  2. AES-256-GCM cho message encryption
  3. HMAC cho message integrity
  4. Digital signatures cho non-repudiation
  5. Session-based communication
  
  Flow:
    Service A                          Service B
    ─────────                          ─────────
    
    1. Generate ephemeral key
    2. RSA(ephemeral_key, ServiceB_pub) ──────→
    
                                        3. Decrypt ephemeral key
                                        4. Now share ephemeral key
    
    5. AES(message, ephemeral_key) ──────→
    
                                        6. Decrypt message
                                        7. Verify HMAC
    
    8. ← AES(response, ephemeral_key)


USE CASE 4: Compliance & Audit
──────────────────────────────

Scenario:
  • Công ty cần tuân thủ GDPR/CCPA/PCI-DSS
  • Cần chứng minh ai đã truy cập dữ liệu nào & khi nào
  • Cần detect & respond to suspicious activity

Solution:
  1. Ghi lại tất cả hoạt động (audit log)
  2. Append-only log structure (không thể sửa lịch sử)
  3. Export logs định kỳ để off-site storage
  4. Automated alerts untuk anomalies
  5. Compliance reports (hàng tuần/tháng)
  6. Long-term retention (≥ 3 năm)
  
  Monitored Events:
    • User login/logout
    • Permission grants/denials
    • Key generation/rotation/revocation
    • Data access attempts
    • System errors


USE CASE 5: Key Lifecycle Management
────────────────────────────────────

Scenario:
  • Công ty có hàng ngàn khóa
  • Khóa phải được rotate định kỳ
  • Cần track vòng đời mỗi khóa

Solution:
  1. Automatic key rotation (90 ngày)
  2. Version tracking: key_v1, key_v2, ...
  3. Staggered rotation: không rotate tất cả cùng lúc
  4. Archive old keys: để giải mã dữ liệu cũ
  5. Key destruction policy: xóa sau 7 năm
  
  Timeline:
    Day 1:     Generate key_v1
    Day 88:    Alert: key needs rotation
    Day 90:    Generate key_v2, mark key_v1 inactive
    Day 91-810: Keep key_v1 for decryption
    Day 810:   Secure destroy key_v1


USE CASE 6: Disaster Recovery
──────────────────────────────

Scenario:
  • Primary data center bị lỗi
  • Cần khôi phục khóa & user data
  • RTO: 1 giờ, RPO: 15 phút

Solution:
  1. Key backup được mã hóa & lưu ở off-site
  2. User data replication (active-passive)
  3. Audit log replication
  4. Automated failover to secondary site
  5. Regular DR drills (hàng quý)
  
  Backup Process:
    Primary KMS ─→ Export encrypted keys ─→ Secure transport ─→ Backup vault
                   (weekly)
    
  Recovery Process:
    Disaster ─→ Detect (5 min) ─→ Failover (10 min) ─→ Restore keys (20 min)


================================================================================
2. BEST PRACTICES
================================================================================

2.1 Key Management Best Practices
─────────────────────────────────

✓ DO:
  • Sinh khóa với entropy cao (cryptographically secure random)
  • Lưu Master Key riêng biệt (hardware HSM khi có thể)
  • Rotate keys định kỳ (ít nhất mỗi năm, tốt hơn là 90 ngày)
  • Sử dụng key versioning & tagging
  • Backup keys encrypted & off-site
  • Monitor key usage & access logs
  • Implement separation of duties
  • Use different keys for different purposes

✗ DON'T:
  • Sinh khóa từ passwords (dùng random generators)
  • Lưu khóa trong source code
  • Lưu khóa không mã hóa
  • Reuse keys across different systems
  • Log khóa (chỉ log key usage/access)
  • Cho nhiều người có quyền backup key
  • Rotate khóa cùng lúc (stagger rotation)
  • Xóa khóa ngay (giữ để giải mã dữ liệu cũ)


2.2 Identity & Access Best Practices
────────────────────────────────────

✓ DO:
  • Enforce strong password policy
  • Implement MFA cho tất cả users (admin/sensitive)
  • Use PBKDF2/Argon2 cho password hashing
  • Implement session timeout
  • Bind session to IP address
  • Log tất cả authentication attempts
  • Monitor failed login patterns
  • Implement account lockout
  • Use RBAC + attribute-based access control
  • Regular access reviews & recertification
  • Implement principle of least privilege
  • Deactivate unused accounts

✗ DON'T:
  • Store passwords in plaintext
  • Use weak hashing (MD5, SHA1)
  • Allow password reuse
  • Share accounts between users
  • Disable MFA
  • Create permanent admin accounts
  • Use default credentials in production
  • Have session timeouts > 8 hours
  • Implement access without revision/approval
  • Skip access reviews


2.3 Secure Transmission Best Practices
──────────────────────────────────────

✓ DO:
  • Always encrypt sensitive data in transit (TLS 1.2+)
  • Use strong cipher suites (AES-GCM, ChaCha20)
  • Implement perfect forward secrecy (PFS)
  • Verify certificates (pinning for critical)
  • Use digital signatures untuk non-repudiation
  • Implement HMAC/GCM tags untuk integrity
  • Use AEAD modes (GCM, ChaCha20-Poly1305)
  • Generate random nonces/IVs
  • Implement key agreement untuk session keys
  • Log message exchanges (with_PII redaction)

✗ DON'T:
  • Send sensitive data over HTTP
  • Use weak TLS versions (< 1.2)
  • Use weak cipher suites
  • Disable certificate validation
  • Use predictable nonces/IVs
  • Reuse keys across different purposes
  • Implement custom crypto
  • Ignore certificate expiry warnings
  • Mix critical & non-critical data in same channel
  • Log plaintext messages


2.4 Audit & Compliance Best Practices
────────────────────────────────────

✓ DO:
  • Log tất cả security-relevant events
  • Use append-only log structure
  • Include timestamps server-side
  • Log source IP & user agent
  • Include context (what, who, when, where, why)
  • Backup logs regularly (off-site)
  • Retain logs ≥ 1 năm (better: 3-7 năm)
  • Monitor logs for unusual patterns
  • Alert pada suspicious activity
  • Regular log reviews (hàng tuần)
  • Implement log integrity checks (HMAC/signatures)
  • Encrypt logs at rest & in transit
  • Implement log rotation & archival

✗ DON'T:
  • Skip logging for "less important" operations
  • Log passwords or sensitive data
  • Store logs locally only
  • Delete logs prematurely
  • Rely only on human review
  • Missing alert mechanisms
  • Store logs with write permissions
  • Use weak log integrity checks
  • Mix logs from different systems without correlation
  • Forget to anonymize PII from logs


2.5 Development & Testing Best Practices
────────────────────────────────────────

✓ DO:
  • Use well-tested crypto libraries (cryptography, OpenSSL)
  • Use different keys for dev/staging/prod
  • Test error handling (key not found, expired keys)
  • Test key rotation flows
  • Test access control policies
  • Implement security unit tests
  • Security code review untuk crypto code
  • Use static analysis tools (bandit, semgrep)
  • Penetration test regularly
  • OWASP Top 10 assessment

✗ DON'T:
  • Commit real keys/credentials to git
  • Use production data in development
  • Implement custom cryptography
  • Skip security testing
  • Use hardcoded secrets
  • Disable security features in dev
  • Share dev keys with production keys
  • Forget environment-specific config
  • Use insecure random generators
  • Ignore security warnings


================================================================================
3. SECURITY CHECKLIST
================================================================================

Before Production Deployment:
─────────────────────────────

Key Management:
  □ Master Key securely stored (HSM or encrypted)
  □ Key generation uses secure randomness
  □ Key rotation policy documented & tested
  □ Key backup process tested & verified
  □ Old keys retained for decryption
  □ All keys properly versioned
  □ Key access logged

Identity Management:
  □ Password policy enforced (length, complexity)
  □ PBKDF2/Argon2 hashing with salt
  □ MFA enabled for administrative accounts
  □ Session timeout configured (30-60 min)
  □ Session binding to IP/device
  □ Account lockout after failed attempts
  □ Unused accounts deactivated
  □ RBAC policies implemented & tested

Secure Transmission:
  □ All sensitive data encrypted in transit (TLS 1.2+)
  □ Strong cipher suites configured
  □ Certificate validation enabled
  □ Perfect forward secrecy enabled
  □ AEAD modes used (not CBC without auth)
  □ Digital signatures implemented (if needed)
  □ No hardcoded cryptographic constants

Audit & Logging:
  □ All security events logged
  □ Logs encrypted at rest
  □ Logs backed up off-site
  □ Retention policy ≥ 1 year
  □ Monitoring & alerting configured
  □ False positive rates acceptable
  □ Log integrity checks implemented

Operations:
  □ Key rotation schedule established
  □ Backup/disaster recovery tested
  □ Incident response plan documented
  □ Security team trained
  □ Vendor security assessments completed
  □ Compliance requirements identified


================================================================================
4. THREAT MODELS
================================================================================

Threat 1: Key Compromise
────────────────────────

Attack: Attacker gains access to Master Key
Impact: All encrypted data can be decrypted
Mitigation:
  ✓ Use hardware HSM untuk Master Key
  ✓ Implement key escrow (split key among 3+ parties)
  ✓ Detect unusual key access patterns
  ✓ Rotate keys upon suspected compromise
  ✓ Maintain offline backup of keys
  Detection:
  - Monitor Master Key access logs
  - Alert upon unusual access patterns
  - Regular key integrity checks


Threat 2: Credential Stuffing
──────────────────────────────

Attack: Attacker uses leaked credentials from other services
Impact: Account takeover, data breach
Mitigation:
  ✓ Implement MFA (defeats credential stuffing)
  ✓ Account lockout after N failed attempts
  ✓ Password not in compromised lists (Have I Been Pwned)
  ✓ Alert user upon unusual behavior
  ✓ Force password change upon compromise notice
  Detection:
  - Monitor failed login patterns
  - Alert > 5 failed attempts/hour
  - Monitor for geographic anomalies


Threat 3: Man-in-the-Middle (MITM)
──────────────────────────────────

Attack: Attacker intercepts communication
Impact: Data disclosure, modification
Mitigation:
  ✓ Use TLS 1.2+ for all communication
  ✓ Certificate pinning for critical connections
  ✓ Verify certificate authenticity
  ✓ Use AEAD modes (GCM) for integrity
  ✓ Implement message signing
  Detection:
  - Monitor certificate warnings
  - Alert upon signature verification failures
  - Monitor unusual communication patterns


Threat 4: Insider Threat
────────────────────────

Attack: Malicious/disgruntled employee misuses access
Impact: Data theft, sabotage
Mitigation:
  ✓ Principle of least privilege
  ✓ Separation of duties (no one person = full access)
  ✓ Comprehensive audit logging
  ✓ Anomaly detection on data access
  ✓ Access reviews & recertification
  ✓ Off-boarding process (revoke access)
  Detection:
  - Unusual data volume access
  - Unusual hours/locations
  - Unusual file types downloaded
  - Failed access attempts to restricted resources


Threat 5: Cryptanalysis / Brute Force
─────────────────────────────────────

Attack: Attacker attempts computational attack on encryption
Impact: Plaintext recovery (if successful)
Mitigation:
  ✓ Use proven, well-vetted algorithms (AES-256, RSA-2048)
  ✓ Use sufficient key sizes (256+ bits for symmetric)
  ✓ Use random nonces/IVs (not predictable)
  ✓ Use modern modes (GCM, not ECB or CBC without auth)
  ✓ Monitor for unusual decryption failures
  Detection:
  - Monitor decryption error rates
  - Alert upon high fail rates (possible attack)


================================================================================
5. PERFORMANCE CONSIDERATIONS
================================================================================

Optimization:
──────────────

Key Caching:
  ✓ Cache decrypted keys in memory (secured)
  ✓ TTL-based expiry (prevent stale data)
  ✓ Monitor cache hit rates
  Example: Cache AES keys for 5 minutes

Batch Operations:
  ✓ Process multiple messages in batch
  ✓ Reduces overhead
  ✓ Better CPU cache utilization
  Example: Process 100 messages at once vs 1 at a time

Async Processing:
  ✓ Offload heavy crypto operations (signing, key generation)
  ✓ Use task queues (Celery, RQ)
  ✓ Return result via callback

Hardware Acceleration:
  ✓ Use AES-NI (hardware AES) when available
  ✓ Use AVX for faster crypto operations
  Example: cryptography library auto-detects & uses these


Performance Metrics:
────────────────────

Expected Performance (on modern CPU):
  • AES-256 encryption: 1-2 GB/sec (with AES-NI)
  • HMAC-SHA256: 500-800 MB/sec
  • RSA-2048 sign/verify: 1-2 ms per operation
  • PBKDF2 (100K iterations): 100-200 ms per hash

Monitoring:
  □ Track crypto operation latency
  □ Monitor CPU utilization
  □ Alert upon performance degradation
  □ Regular performance testing


================================================================================
