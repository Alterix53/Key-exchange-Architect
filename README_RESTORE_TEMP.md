# Key Exchange Architect ΓÇö Hß╗ç thß╗æng quß║ún l├╜ kh├│a v├á ph├ón phß╗æi

Hß╗ç thß╗æng minh hß╗ìa **Chapter 14: Key Management and Distribution**, tß║¡p trung v├áo:
- **Section 14.4** ΓÇö X.509 Certificates
- **Section 14.5** ΓÇö Public-Key Infrastructure (PKI)

## Kiß║┐n tr├║c PKI

```
ΓöîΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÉ
Γöé                    Root CA (RSA-4096)                     Γöé
Γöé             Self-signed X.509 v3 Certificate             Γöé
Γöé          BasicConstraints(ca=True, path_length=1)        Γöé
Γöé          KeyUsage(keyCertSign, crlSign)                   Γöé
ΓööΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓö¼ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÿ
                         Γöé signs
ΓöîΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓû╝ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÉ
Γöé              Intermediate CA (RSA-3072)                   Γöé
Γöé           Signed by Root CA                               Γöé
Γöé          BasicConstraints(ca=True, path_length=0)         Γöé
Γöé          KeyUsage(keyCertSign, crlSign)                    Γöé
ΓööΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓö¼ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓö¼ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÿ
           Γöé signs                Γöé signs
ΓöîΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓû╝ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÉ  ΓöîΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓû╝ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÉ
Γöé  Server Certificate Γöé  Γöé  Client Certificates Γöé
Γöé  EKU: serverAuth    Γöé  Γöé  EKU: clientAuth     Γöé
Γöé  KeyUsage:          Γöé  Γöé  KeyUsage:           Γöé
Γöé   digitalSignature  Γöé  Γöé   digitalSignature   Γöé
Γöé   keyEncipherment   Γöé  Γöé   keyEncipherment    Γöé
ΓööΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÿ  ΓööΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÿ

ΓöîΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÉ  ΓöîΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÉ
Γöé  Registration        Γöé  Γöé  Certificate        Γöé
Γöé  Authority (RA)      Γöé  Γöé  Repository         Γöé
Γöé  ΓÇó Verify CSR        Γöé  Γöé  ΓÇó Store certs      Γöé
Γöé  ΓÇó Check identity    Γöé  Γöé  ΓÇó Lookup by CN     Γöé
Γöé  ΓÇó Forward to CA     Γöé  Γöé  ΓÇó Persistent JSON  Γöé
ΓööΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÿ  ΓööΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÿ
```

## Khß╗ƒi chß║íy

### C├ái ─æß║╖t

```bash
pip install -r requirements.txt
```

### Chß║íy Server + Client (Demo live)

**Terminal 1 ΓÇö Server:**
```bash
python server.py --host 127.0.0.1 --port 5000
```

Server sß║╜:
1. Tß║ío PKI hierarchy (Root CA ΓåÆ Intermediate CA)
2. Cß║Ñp Server Certificate qua RA
3. Lß║»ng nghe kß║┐t nß╗æi client

**Terminal 2 ΓÇö Client A:**
```bash
python client.py --name Alice --host 127.0.0.1 --port 5000
```

**Terminal 3 ΓÇö Client B:**
```bash
python client.py --name Bob --host 127.0.0.1 --port 5000
```

### Handshake Flow

```
Client A                   Server (PKI)                   Client B
  Γöé                            Γöé                              Γöé
  ΓöéΓöÇΓöÇ hello {CSR} ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓåÆ  Γöé                              Γöé
  Γöé                            Γöé  RA verify CSR               Γöé
  Γöé                            Γöé  Intermediate CA issue cert  Γöé
  Γöé  ΓåÉΓöÇΓöÇ welcome {             Γöé                              Γöé
  Γöé    client_cert_chain,      Γöé                              Γöé
  Γöé    server_cert_chain       Γöé                              Γöé
  Γöé  } ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöé                              Γöé
  Γöé                            Γöé                              Γöé
  Γöé  verify server cert chain  Γöé                              Γöé
  Γöé  (mutual authentication)   Γöé                              Γöé
  Γöé                            Γöé  ΓåÉΓöÇΓöÇ hello {CSR} ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ Γöé
  Γöé                            Γöé  RA verify ΓåÆ issue cert      Γöé
  Γöé                            Γöé  ΓöÇΓöÇΓåÆ welcome {chains} ΓöÇΓöÇΓöÇΓöÇΓöÇΓåÆ Γöé
  Γöé                            Γöé                              Γöé
  Γöé  ΓåÉΓöÇΓöÇ peer_joined ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöéΓöÇΓöÇΓöÇΓöÇΓöÇ peer_joined ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓåÆ Γöé
  Γöé                            Γöé                              Γöé
  ΓöéΓöÇΓöÇ cert_request(Bob) ΓöÇΓöÇΓöÇΓöÇΓöÇΓåÆΓöé                              Γöé
  Γöé  ΓåÉΓöÇΓöÇ cert_response {      Γöé                              Γöé
  Γöé    Bob_cert_chain          Γöé                              Γöé
  Γöé  } ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöé                              Γöé
  Γöé                            Γöé                              Γöé
  Γöé  validate Bob's chain      Γöé                              Γöé
  Γöé  check CRL                 Γöé                              Γöé
  Γöé  extract Bob's public key  Γöé                              Γöé
  Γöé  encrypt AES-256 key       Γöé                              Γöé
  Γöé  with Bob's RSA public key Γöé                              Γöé
  ΓöéΓöÇΓöÇ relay_session_key ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓåÆΓöéΓöÇΓöÇΓöÇΓöÇΓöÇ relay_session_key ΓöÇΓöÇΓöÇΓöÇΓåÆ Γöé
  Γöé                            Γöé                       decryptΓöé
  Γöé                            Γöé                              Γöé
  Γöé ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ AES-256-GCM encrypted chat ΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉΓòÉ Γöé
```

### Client Commands

| Command | M├┤ tß║ú |
|---|---|
| `<tin nhß║»n>` | Gß╗¡i tin nhß║»n m├ú h├│a AES-256-GCM |
| `list_users` | Xem danh s├ích users trong PKI Repository |
| `get_crl` | Lß║Ñy CRL (Certificate Revocation List) mß╗¢i nhß║Ñt |
| `quit` / `exit` | Tho├ít |

### Chß║íy Demo Standalone

```bash
python demo_pki.py
```

Demo minh hß╗ìa to├án bß╗Ö PKI lifecycle m├á kh├┤ng cß║ºn mß╗ƒ server/client:
1. Tß║ío PKI hierarchy
2. CSR ΓåÆ RA ΓåÆ CA ΓåÆ Certificate
3. X.509 v3 certificate structure + extensions
4. Certificate chain validation
5. Certificate revocation + CRL
6. Certificate renewal (Key Pair Update)
7. Certificate Repository lookup

---

## Cß║Ñu tr├║c th╞░ mß╗Ñc

```
Key-exchange-Architect/
Γö£ΓöÇΓöÇ server.py                          # Relay server + PKI
Γö£ΓöÇΓöÇ client.py                          # Client + CSR + chain validation
Γö£ΓöÇΓöÇ demo_pki.py                        # Demo standalone PKI
Γö£ΓöÇΓöÇ demo_system.py                     # Demo hß╗ç thß╗æng tß╗òng
Γö£ΓöÇΓöÇ requirements.txt                   # Dependencies
Γö£ΓöÇΓöÇ src/
Γöé   Γö£ΓöÇΓöÇ __init__.py                    # IAMSystem integration
Γöé   Γö£ΓöÇΓöÇ public_key_distribution.py     # Γÿà PKI module (14.4 + 14.5)
Γöé   Γö£ΓöÇΓöÇ key_management.py              # Key lifecycle management
Γöé   Γö£ΓöÇΓöÇ identity_management.py         # IAM + RBAC
Γöé   Γö£ΓöÇΓöÇ secure_transmission.py         # AES-GCM/CBC, RSA-OAEP, HMAC
Γöé   ΓööΓöÇΓöÇ audit_logging.py              # Audit logging
Γö£ΓöÇΓöÇ tests/
Γöé   ΓööΓöÇΓöÇ test_system.py
Γö£ΓöÇΓöÇ docs/
Γöé   Γö£ΓöÇΓöÇ README.md                      # T├ái liß╗çu chi tiß║┐t
Γöé   Γö£ΓöÇΓöÇ ARCHITECTURE.md                # Kiß║┐n tr├║c hß╗ç thß╗æng
Γöé   ΓööΓöÇΓöÇ USE_CASES_AND_PRACTICES.md     # Use cases
ΓööΓöÇΓöÇ data/                              # (auto-generated)
    Γö£ΓöÇΓöÇ root_ca_cert.pem
    Γö£ΓöÇΓöÇ root_ca_private.pem
    Γö£ΓöÇΓöÇ root_ca.crl
    Γö£ΓöÇΓöÇ intermediate_ca_cert.pem
    Γö£ΓöÇΓöÇ intermediate_ca_private.pem
    Γö£ΓöÇΓöÇ intermediate_ca.crl
    Γö£ΓöÇΓöÇ server_cert.pem
    Γö£ΓöÇΓöÇ cert_index.json
    ΓööΓöÇΓöÇ certificates/
        Γö£ΓöÇΓöÇ Alice_xxxxx.pem
        ΓööΓöÇΓöÇ Bob_xxxxx.pem
```

## Mapping vß╗¢i s├ích (Chapter 14)

### Section 14.4 ΓÇö X.509 Certificates

| Concept | Implementation |
|---|---|
| X.509 v3 certificate format | `cryptography.x509` ΓÇö Version, Serial, Issuer DN, Subject DN, Validity, Public Key |
| BasicConstraints | `ca=True/False`, `path_length` ph├ón biß╗çt CA vs end-entity |
| KeyUsage | `digitalSignature`, `keyCertSign`, `crlSign`, `keyEncipherment` |
| ExtendedKeyUsage | `serverAuth` cho server, `clientAuth` cho client |
| SubjectKeyIdentifier | Hash cß╗ºa public key ΓÇö ID unique cho cert |
| AuthorityKeyIdentifier | ID cß╗ºa CA ─æ├ú k├╜ cert |
| SubjectAlternativeName | DNS name cho cert |
| Certificate Chain | Root CA ΓåÆ Intermediate CA ΓåÆ End-entity |
| Chain Validation | Verify signature + expiry + issuer match + CRL check |

### Section 14.5 ΓÇö Public-Key Infrastructure

| PKIX Function | Implementation |
|---|---|
| **Registration** | Client tß║ío CSR (signed by private key) ΓåÆ gß╗¡i cho RA |
| **Initialization** | Client pin Root CA cert l├ám trust anchor |
| **Certification** | RA verify CSR ΓåÆ Intermediate CA sign ΓåÆ issue cert |
| **Key Pair Update** | `process_renewal()` ΓÇö thu hß╗ôi cert c┼⌐ + cß║Ñp cert mß╗¢i |
| **Revocation** | `revoke_certificate()` ΓåÆ th├¬m v├áo CRL persistent |
| **CA** | `RootCA` (self-signed, RSA-4096) + `IntermediateCA` (RSA-3072) |
| **RA** | `RegistrationAuthority` ΓÇö verify CSR signature + identity |
| **Repository** | `CertificateRepository` ΓÇö persistent cert storage + lookup |
| **CRL** | X.509 CRL chuß║⌐n, k├╜ bß╗ƒi CA, persist ra file `.crl` |

## Bß║úo mß║¡t

- **Mutual Authentication**: Client verify server cert chain, server verify client CSR
- **End-to-End Encryption**: AES-256-GCM session key, distributed via RSA-OAEP
- **Certificate Pinning**: Client pin Root CA cert locally
- **Revocation Check**: Client check CRL tr╞░ß╗¢c khi trust peer cert
- **Audit Logging**: Tß║Ñt cß║ú PKI operations ─æ╞░ß╗úc ghi log (CSR, issue, revoke)

## Dependencies

```
cryptography>=41.0.0
```
