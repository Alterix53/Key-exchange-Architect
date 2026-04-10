ARCHITECTURE - IAM System Architecture

================================================================================
SYSTEM OVERVIEW
================================================================================

┌─────────────────────────────────────────────────────────────────────────┐
│                         IAM SYSTEM ARCHITECTURE                         │
└─────────────────────────────────────────────────────────────────────────┘

                              ┌──────────────┐
                              │    Users     │
                              └──────┬───────┘
                                     │
        ┌────────────────────────────┼────────────────────────────┐
        ▼                            ▼                            ▼
    ┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
    │  Key Management │      │   Identity Mgmt │      │ Secure Transmit │
    │                 │      │                 │      │                 │
    │ • Symmetric Keys│      │ • Users         │      │ • AES-256       │
    │ • Asymmetric    │      │ • Auth          │      │ • RSA           │
    │ • Rotation      │      │ • Authorization │      │ • Signatures    │
    │ • Storage       │      │ • RBAC          │      │ • HMAC          │
    └────────┬────────┘      └────────┬────────┘      └────────┬────────┘
             │                        │                        │
             └────────────────────────┼────────────────────────┘
                                      │
                                      ▼
                          ┌───────────────────────┐
                          │  Audit & Logging      │
                          │                       │
                          │ • Event Logging       │
                          │ • Compliance          │
                          │ • Anomaly Detection   │
                          │ • Reporting           │
                          └───────────────────────┘


================================================================================
1. KEY MANAGEMENT SYSTEM (KMS)
================================================================================

                    Master Key Hierarchy
                           │
        ┌──────────────────┴──────────────────┐
        │                                     │
        ▼                                     ▼
   ┌─────────────┐                   ┌──────────────┐
   │  User Keys  │                   │  System Keys │
   │             │                   │              │
   │ • Sym KEK  │                   │ • Auth Key   │
   │ • Asym KEK │                   │ • Encryp Key │
   └─────────────┘                   └──────────────┘
        │                                     │
        ├─────────────────────┬───────────────┤
        ▼                     ▼               ▼
   Data Key            Comm Key          Session Key
   (AES-256)           (AES-256)          (Random)


   Key Lifecycle:
   ───────────────

   GENERATION          DISTRIBUTION        USAGE           ROTATION        RETIREMENT
   ──────────          ────────────        ─────           ────────        ──────────
      │                    │                  │                │               │
      └──→ [Random]    ┌───┴──────┐          └──→ Encrypt   └──→ [NewKey]  └──→ Archive
          [PKIX]  ─────┤Secure    ├──→ Store         Decrypt        Rehash      Store
                       │Delivery  │
                       └──────────┘


   Storage Structure:
   ──────────────────

   keys/
   ├── master.key (chmod 0o600)           ← Master Key (Encrypted)
   │
   ├── data_key_v1.key                    ← Symmetric Key (Encrypted with Master)
   ├── data_key_v1.meta                   ← Metadata (JSON)
   │
   ├── rsa_signing_v1_private.pem         ← RSA Private (Encrypted with Master)
   ├── rsa_signing_v1_public.pem          ← RSA Public (Plain)
   ├── rsa_signing_v1.meta                ← Metadata
   │
   └── ...


================================================================================
2. IDENTITY & ACCESS MANAGEMENT (IAM)
================================================================================

   User Authentication Flow:
   ─────────────────────────

        ┌─────────────┐
        │    User     │
        └──────┬──────┘
               │ 1. username + password
               ▼
        ┌─────────────────────────────┐
        │  1. Hash password (PBKDF2)  │
        │  2. Verify hash             │
        └──────┬──────────────────────┘
               │
          ┌────┴─────┐
          ▼          ▼
       [+] OK    [-] FAIL
          │          │
          ▼          ▼
       2FA?      Log Failed
          │      Return None
       ┌──┴──┐
       ▼     ▼
       No   Yes
       │      │
       ▼      ▼
     Create  Ping MFA
     Session  (TOTP)
     │        │
     │    Verify
     │        │
     │    ┌───┴────┐
     │    ▼        ▼
     │   [+]      [-]
     │    │       │
     └────┼───────┘
          ▼
     Return Session


   Authorization Flow (RBAC):
   ──────────────────────────

   User ──┐
          │ Has roles?: [ADMIN, USER, MANAGER]
          ▼
   Role ──┬──> Permissions: Set of (resource, action)
          │
          ├─ ADMIN: ✓ keys:create, ✓ keys:delete, ✓ users:*
          ├─ USER:  ✓ keys:read, ✗ keys:delete
          └─ MANAGER: ✓ keys:rotate, ✓ users:read

   Check Permission(user_id, resource, action):
   1. Get user by user_id
   2. Get roles from user
   3. Collect permissions from all roles
   4. Check if (resource, action) in permissions


   Session Management:
   ──────────────────

   Session State Machine:
   
            ┌────────┐
            │ Active │ ◄──────┐
            └───┬────┘        │
                │      Refresh
                │ expires_at
                │ > now
                ▼
           ┌─────────┐
           │ Expired │ ───────────┐
           └─────────┘            │
                                  │ Logout
                               ┌──┴───┐
                               ▼      ▼
                            │ Inactive │
                            └──────────┘


================================================================================
3. SECURE TRANSMISSION LAYER
================================================================================

   Message Encryption/Decryption:
   ──────────────────────────────

   SENDER                           RECEIVER
   ──────                           ────────
   
   Message ───┐
              │
              ├─→ Get Key
              │
              ├─→ AES-256-GCM
              │   ├─ Random Nonce
              │   ├─ Encrypt + Authenticate
              │   └─ Generate Auth Tag
              │
              ├─→ Create Packet
              │   ├─ Nonce (12 bytes)
              │   ├─ Ciphertext
              │   ├─ Tag (16 bytes)
              │   └─ Associated Data
              │
              └─→ Send ─────────────────────→ Receive
                                              │
                                              ├─→ Get Key
                                              │
                                              ├─→ AES-256-GCM
                                              │   ├─ Extract Nonce
                                              │   ├─ Verify Tag
                                              │   └─ Decrypt
                                              │
                                              ├─→ Verify Integrity
                                              │
                                              └─→ Plaintext


   Digital Signature Process:
   ─────────────────────────

   SIGNER                          VERIFIER
   ──────                          ────────
   
   Message
      │
      ├─→ SHA256(Message)
      │    │
      │    └─→ Hash
      │
      ├─→ RSA Sign(Hash, PrivKey)
      │    │
      │    └─→ Signature
      │
      │Send: Message + Signature
             ───────────────────→ Receive
                                  │
                                  ├─→ SHA256(Message)
                                  │
                                  ├─→ RSA Verify(Sig, Hash, PubKey)
                                  │    │
                                  │    ├─→ Valid? YES ✓
                                  │    └─→ Valid? NO  ✗


================================================================================
4. AUDIT & LOGGING SYSTEM
================================================================================

   Event Flow:
   ───────────

   Action                Log Event              Persist
   ──────                ─────────              ───────
   
   • Login    ──────┬──→ USER_LOGIN      ──┬──→ Disk
   • Create   ──────┼──→ USER_CREATED    ──┤   (JSONL)
   • Generate ──────┼──→ KEY_GENERATED   ──┤
   • Rotate   ──────┼──→ KEY_ROTATED     ──┤
   • Deny     ──────┼──→ PERMISSION_DENIED ──┤
   • Revoke   ──────┴──→ KEY_REVOKED     ──┴──→ Memory


   Audit Storage:
   ──────────────

   audit/
   ├── 2024-01-15_audit.jsonl    # One event per line
   ├── 2024-01-16_audit.jsonl
   ├── 2024-01-17_audit.jsonl
   │
   └── exports/
       ├── export_20240117_120000.json  # Full export
       └── export_20240117_120000.csv   # CSV export


   Anomaly Detection:
   ──────────────────

   Monitor:
   1. Failed Logins ≥ 3 in 5 min → Alert
   2. Multiple IPs in 5 min → Alert
   3. Permission Denied ≥ 5 in session → Alert
   4. Key Access abnormal pattern → Alert
   5. Off-hours access → Alert


================================================================================
5. DATA FLOW DIAGRAM
================================================================================

   User Registration:
   ──────────────────

   User Input
      │
      • username
      • email
      • password
      │
      ▼
   Create User
      │
      ├─ Generate user_id (random)
      ├─ Hash password (PBKDF2 + salt)
      ├─ Store in Identity DB
      │
      ▼
   Audit Log
      └─ USER_CREATED event


   Authentication:
   ──────────────

   User Input
      │
      • username
      • password
      │
      ▼
   Authenticate
      │
      ├─ Find user by username
      ├─ Verify password
      ├─ Check is_active
      │
      ▼
   ┌──────────┐
   │ Valid?   │
   └──┬───┬──┘
      │   │
      ▼   ▼
    YES   NO
      │   │
      │   └─→ Log: USER_FAILED_LOGIN
      │       Return None
      │
      ▼
   Create Session
      │
      ├─ Generate session_id
      ├─ Set expires_at
      ├─ Check MFA: mfa_enabled?
      │
      ▼
   Return Session ──→ User


   Secure Message Send:
   ────────────────────

   User Input
      │
      • recipient_id
      • message
      │
      ▼
   Permission Check
      │
      ├─ User has keys:read?
      │
      └─→ NO → Log PERMISSION_DENIED, Return Error
      
   Get Key
      │
      ├─ Get encryption key from keystore
      │
      ▼
   Encrypt
      │
      ├─ Generate nonce
      ├─ AES-256-GCM encrypt
      ├─ Generate auth tag
      │
      ▼
   Create Secure Message Packet
      │
      ├─ message_id
      ├─ sender_id
      ├─ recipient_id
      ├─ nonce
      ├─ ciphertext
      ├─ tag
      │
      ▼
   Persist
      │
      ├─ In-memory message log
      ├─ Audit: MESSAGE_SENT
      │
      ▼
   Return encrypted message


================================================================================
6. SECURITY LAYERS
================================================================================

   Layer 1: Storage Security
   ─────────────────────────
   
   All Keys → Encrypted with Master Key
   Master Key → 256-bit random entropy
   Files → chmod 0o600 (read/write owner only)
   

   Layer 2: Access Control
   ───────────────────────
   
   Authentication → PBKDF2 + salt
   Authorization → RBAC with fine-grained permissions
   Session → Timeout + IP binding
   MFA → TOTP (Time-based One-Time Password)
   

   Layer 3: Data Protection
   ────────────────────────
   
   At Rest → AES-256-CBC or AES-256-GCM
   In Transit → TLS 1.2+ (HTTPS)
   Integrity → HMAC-SHA256 or GCM tag
   

   Layer 4: Non-Repudiation
   ────────────────────────
   
   Digital Signatures → RSA-PSS
   Audit Trail → Append-only logs
   Timestamps → Server-generated


   Layer 5: Detection
   ──────────────────
   
   Anomaly Detection → Failed attempts, unusual patterns
   Real-time Alerting → Immediate notification
   Forensics → Full audit trail for investigation


================================================================================
7. DEPLOYMENT ARCHITECTURE
================================================================================

   Single Node:
   ────────────

   ┌─────────────────────────────────────┐
   │         Server Machine              │
   │                                     │
   │  ┌─────────────────────────────┐   │
   │  │    IAM Application          │   │
   │  │                             │   │
   │  │  ├─ Key Management          │   │
   │  │  ├─ Identity Management     │   │
   │  │  ├─ Secure Transmission     │   │
   │  │  └─ Audit Logging           │   │
   │  │                             │   │
   │  └──────────┬──────────────────┘   │
   │             │                      │
   │  ┌──────────┴──────────────────┐   │
   │  │   Local File Storage         │   │
   │  │   (keys/, identity/, audit/) │   │
   │  │   chmod 0o600 (secure)       │   │
   │  └──────────────────────────────┘   │
   │                                     │
   └─────────────────────────────────────┘


   Multi-Node (HA):
   ────────────────

   Master Server                    Replica Server
   ──────────────                   ──────────────
   
   ┌──────────────────┐           ┌──────────────────┐
   │  IAM Application │ ──Sync─→  │  IAM Application │
   └──────────────────┘           └──────────────────┘
          │                               │
          ▼                               ▼
   ┌──────────────────┐           ┌──────────────────┐
   │ Key storage (RW) │           │ Key storage (RO) │
   │ identity (RW)    │ ──Repl──→ │ identity (RO)    │
   │ audit (RW)       │           │ audit (RO)       │
   └──────────────────┘           └──────────────────┘


================================================================================
8. API ENDPOINTS (Conceptual)
================================================================================

   Key Management:
   ───────────────
   POST   /api/keys/generate         - Generate key
   POST   /api/keys/rotate           - Rotate key
   POST   /api/keys/revoke           - Revoke key
   GET    /api/keys/{key_id}         - Get key metadata
   GET    /api/keys                  - List keys


   Identity Management:
   ────────────────────
   POST   /api/users                 - Create user
   GET    /api/users/{user_id}       - Get user
   POST   /api/users/{user_id}/roles - Update roles
   GET    /api/auth/login            - Login
   POST   /api/auth/logout           - Logout
   POST   /api/mfa/enable            - Enable MFA


   Secure Transmission:
   ────────────────────
   POST   /api/messages/send         - Send encrypted message
   GET    /api/messages/{msg_id}     - Get message
   POST   /api/messages/decrypt      - Decrypt message


   Audit:
   ──────
   GET    /api/audit/logs            - Get audit logs
   GET    /api/audit/logs/{user_id}  - User logs
   GET    /api/audit/anomalies       - Anomalies


================================================================================
