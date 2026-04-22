# Key Exchange Architect — Hệ thống quản lý khóa và phân phối

Hệ thống minh họa **Chapter 14: Key Management and Distribution**, tập trung vào:
- **Section 14.4** — X.509 Certificates
- **Section 14.5** — Public-Key Infrastructure (PKI)

## Kiến trúc PKI

```
┌──────────────────────────────────────────────────────────┐
│                    Root CA (RSA-4096)                     │
│             Self-signed X.509 v3 Certificate             │
│          BasicConstraints(ca=True, path_length=1)        │
│          KeyUsage(keyCertSign, crlSign)                   │
└────────────────────────┬─────────────────────────────────┘
                         │ signs
┌────────────────────────▼─────────────────────────────────┐
│              Intermediate CA (RSA-3072)                   │
│           Signed by Root CA                               │
│          BasicConstraints(ca=True, path_length=0)         │
│          KeyUsage(keyCertSign, crlSign)                    │
└──────────┬──────────────────────┬────────────────────────┘
           │ signs                │ signs
┌──────────▼──────────┐  ┌───────▼──────────────┐
│  Server Certificate │  │  Client Certificates │
│  EKU: serverAuth    │  │  EKU: clientAuth     │
│  KeyUsage:          │  │  KeyUsage:           │
│   digitalSignature  │  │   digitalSignature   │
│   keyEncipherment   │  │   keyEncipherment    │
└─────────────────────┘  └──────────────────────┘

┌──────────────────────┐  ┌─────────────────────┐
│  Registration        │  │  Certificate        │
│  Authority (RA)      │  │  Repository         │
│  • Verify CSR        │  │  • Store certs      │
│  • Check identity    │  │  • Lookup by CN     │
│  • Forward to CA     │  │  • Persistent JSON  │
└──────────────────────┘  └─────────────────────┘
```

## Khởi chạy

### Cài đặt

```bash
pip install -r requirements.txt
```

### Chạy Server + Client (Demo live)

**Terminal 1 — Server:**
```bash
python server.py --host 127.0.0.1 --port 5000
```

Server sẽ:
1. Tạo PKI hierarchy (Root CA → Intermediate CA)
2. Cấp Server Certificate qua RA
3. Lắng nghe kết nối client

**Terminal 2 — Client A:**
```bash
python client.py --name Alice --host 127.0.0.1 --port 5000
```

**Terminal 3 — Client B:**
```bash
python client.py --name Bob --host 127.0.0.1 --port 5000
```

### Handshake Flow

```
Client A                   Server (PKI)                   Client B
  │                            │                              │
  │── hello {CSR} ──────────→  │                              │
  │                            │  RA verify CSR               │
  │                            │  Intermediate CA issue cert  │
  │  ←── welcome {             │                              │
  │    client_cert_chain,      │                              │
  │    server_cert_chain       │                              │
  │  } ────────────────────────│                              │
  │                            │                              │
  │  verify server cert chain  │                              │
  │  (mutual authentication)   │                              │
  │                            │  ←── hello {CSR} ────────── │
  │                            │  RA verify → issue cert      │
  │                            │  ──→ welcome {chains} ─────→ │
  │                            │                              │
  │  ←── peer_joined ─────────│───── peer_joined ──────────→ │
  │                            │                              │
  │── cert_request(Bob) ─────→│                              │
  │  ←── cert_response {      │                              │
  │    Bob_cert_chain          │                              │
  │  } ───────────────────────│                              │
  │                            │                              │
  │  validate Bob's chain      │                              │
  │  check CRL                 │                              │
  │  extract Bob's public key  │                              │
  │  encrypt AES-256 key       │                              │
  │  with Bob's RSA public key │                              │
  │── relay_session_key ──────→│───── relay_session_key ────→ │
  │                            │                       decrypt│
  │                            │                              │
  │ ════════ AES-256-GCM encrypted chat ════════════════════ │
```

### Client Commands

| Command | Mô tả |
|---|---|
| `<tin nhắn>` | Gửi tin nhắn mã hóa AES-256-GCM |
| `list_users` | Xem danh sách users trong PKI Repository |
| `get_crl` | Lấy CRL (Certificate Revocation List) mới nhất |
| `quit` / `exit` | Thoát |

### Chạy Demo Standalone

```bash
python demo_pki.py
```

Demo minh họa toàn bộ PKI lifecycle mà không cần mở server/client:
1. Tạo PKI hierarchy
2. CSR → RA → CA → Certificate
3. X.509 v3 certificate structure + extensions
4. Certificate chain validation
5. Certificate revocation + CRL
6. Certificate renewal (Key Pair Update)
7. Certificate Repository lookup

---

## Cấu trúc thư mục

```
Key-exchange-Architect/
├── server.py                          # Relay server + PKI
├── client.py                          # Client + CSR + chain validation
├── demo_pki.py                        # Demo standalone PKI
├── demo_system.py                     # Demo hệ thống tổng
├── requirements.txt                   # Dependencies
├── src/
│   ├── __init__.py                    # IAMSystem integration
│   ├── public_key_distribution.py     # ★ PKI module (14.4 + 14.5)
│   ├── key_management.py              # Key lifecycle management
│   ├── identity_management.py         # IAM + RBAC
│   ├── secure_transmission.py         # AES-GCM/CBC, RSA-OAEP, HMAC
│   └── audit_logging.py              # Audit logging
├── tests/
│   └── test_system.py
├── docs/
│   ├── README.md                      # Tài liệu chi tiết
│   ├── ARCHITECTURE.md                # Kiến trúc hệ thống
│   └── USE_CASES_AND_PRACTICES.md     # Use cases
└── data/                              # (auto-generated)
    ├── root_ca_cert.pem
    ├── root_ca_private.pem
    ├── root_ca.crl
    ├── intermediate_ca_cert.pem
    ├── intermediate_ca_private.pem
    ├── intermediate_ca.crl
    ├── server_cert.pem
    ├── cert_index.json
    └── certificates/
        ├── Alice_xxxxx.pem
        └── Bob_xxxxx.pem
```

## Mapping với sách (Chapter 14)

### Section 14.4 — X.509 Certificates

| Concept | Implementation |
|---|---|
| X.509 v3 certificate format | `cryptography.x509` — Version, Serial, Issuer DN, Subject DN, Validity, Public Key |
| BasicConstraints | `ca=True/False`, `path_length` phân biệt CA vs end-entity |
| KeyUsage | `digitalSignature`, `keyCertSign`, `crlSign`, `keyEncipherment` |
| ExtendedKeyUsage | `serverAuth` cho server, `clientAuth` cho client |
| SubjectKeyIdentifier | Hash của public key — ID unique cho cert |
| AuthorityKeyIdentifier | ID của CA đã ký cert |
| SubjectAlternativeName | DNS name cho cert |
| Certificate Chain | Root CA → Intermediate CA → End-entity |
| Chain Validation | Verify signature + expiry + issuer match + CRL check |

### Section 14.5 — Public-Key Infrastructure

| PKIX Function | Implementation |
|---|---|
| **Registration** | Client tạo CSR (signed by private key) → gửi cho RA |
| **Initialization** | Client pin Root CA cert làm trust anchor |
| **Certification** | RA verify CSR → Intermediate CA sign → issue cert |
| **Key Pair Update** | `process_renewal()` — thu hồi cert cũ + cấp cert mới |
| **Revocation** | `revoke_certificate()` → thêm vào CRL persistent |
| **CA** | `RootCA` (self-signed, RSA-4096) + `IntermediateCA` (RSA-3072) |
| **RA** | `RegistrationAuthority` — verify CSR signature + identity |
| **Repository** | `CertificateRepository` — persistent cert storage + lookup |
| **CRL** | X.509 CRL chuẩn, ký bởi CA, persist ra file `.crl` |

## Bảo mật

- **Mutual Authentication**: Client verify server cert chain, server verify client CSR
- **End-to-End Encryption**: AES-256-GCM session key, distributed via RSA-OAEP
- **Certificate Pinning**: Client pin Root CA cert locally
- **Revocation Check**: Client check CRL trước khi trust peer cert
- **Audit Logging**: Tất cả PKI operations được ghi log (CSR, issue, revoke)

## Dependencies

```
cryptography>=41.0.0
```