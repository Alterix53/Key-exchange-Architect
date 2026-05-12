# PROJECT INDEX - IAM Key Management System

## 1) Muc tieu project

Project mo phong he thong IAM + Key Management + PKI, gom:
- Quan ly khoa (tao, luu, rotate, revoke)
- Quan ly danh tinh (user, authn, authz, RBAC, MFA)
- Truyen thong an toan (AES/RSA/HMAC/chu ky)
- Audit logging va bao cao
- Public Key Infrastructure (Root CA, Intermediate CA, RA, CRL)

## 2) Entry points chinh

- `server.py`: Relay server + quy trinh PKI cap cert cho client.
- `client.py`: Client chat, tao CSR, xac thuc certificate chain.
- `demo_pki.py`: Demo lifecycle PKI standalone.
- `demo_system.py`: Demo tong hop IAM + Key Management + Secure Transmission.
- `init_demo_env.py`: Khoi tao du lieu/demo environment.

## 3) Cau truc thu muc

```text
IAM_Key_Management_System/
|- src/
|  |- __init__.py
|  |- key_management.py
|  |- identity_management.py
|  |- secure_transmission.py
|  |- audit_logging.py
|  |- public_key_distribution.py
|  `- db/
|     |- __init__.py
|     |- config.py
|     |- db_connection.py
|     `- db_initializer.py
|- tests/
|  `- test_system.py
|- docs/
|  |- README.md
|  |- ARCHITECTURE.md
|  |- USE_CASES_AND_PRACTICES.md
|  `- Latest_update_18.4.md
|- data/                    # du lieu sinh ra khi chay
|- demo_identity/           # du lieu demo
|- demo_keys/               # du lieu demo
|- demo_audit/              # du lieu demo
|- README.md
|- QUICKSTART.md
|- README_DEMO.md
|- SYSTEM_SUMMARY.md
|- PROJECT_INDEX.md
|- requirements.txt
`- init_db.sql
```

## 4) Index theo module (`src/`)

### `src/key_management.py`
- Quan ly vong doi khoa: generate, retrieve, rotate, revoke, list.
- Ho tro khoa doi xung va bat doi xung.

### `src/identity_management.py`
- Quan ly user/session.
- Authentication, RBAC authorization, MFA workflow.

### `src/secure_transmission.py`
- Primitive crypto va secure messaging flow.
- AES CBC/GCM, RSA OAEP, signature, HMAC.

### `src/audit_logging.py`
- Ghi nhat ky su kien bao mat va truy cap.
- Truy van log, phat hien hanh vi bat thuong, xuat bao cao.

### `src/public_key_distribution.py`
- Thanh phan PKI:
  - Root CA / Intermediate CA
  - Registration Authority (RA)
  - Certificate Repository
  - Revocation (CRL) va chain validation

### `src/db/`
- `config.py`: Cau hinh ket noi DB.
- `db_connection.py`: Tao/quan ly ket noi database.
- `db_initializer.py`: Khoi tao schema ban dau.

## 5) Testing

- `tests/test_system.py`: Unit tests cho cac module chinh.
- Chay test:
  - `python -m unittest tests/test_system.py -v`

## 6) Tai lieu can doc theo thu tu

1. `README.md` - Tong quan va cach chay nhanh.
2. `QUICKSTART.md` - Cac buoc setup/chay.
3. `README_DEMO.md` - Huong dan demo.
4. `docs/ARCHITECTURE.md` - Kien truc chi tiet.
5. `docs/USE_CASES_AND_PRACTICES.md` - Use case va best practices.

## 7) Dependencies va run commands

- Dependency chinh: `cryptography>=41.0.0`
- Cai dat:
  - `pip install -r requirements.txt`
- Run server/client:
  - `python server.py --host 127.0.0.1 --port 5000`
  - `python client.py --name Alice --host 127.0.0.1 --port 5000`

## 8) Ghi chu

- Day la project huong hoc thuat/thu nghiem.
- Thu muc `data/` va cac thu muc `demo_*` co the thay doi theo lan chay.
