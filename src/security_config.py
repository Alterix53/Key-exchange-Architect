"""
Security Configuration Module
Quản lý chế độ bảo mật (demo vs secure) và cung cấp passphrase
cho việc mã hóa private key / master key tại rest.
"""

import os
import secrets
import hashlib
from dotenv import load_dotenv

load_dotenv()

_SECURE_MODE_VALUES = {"true", "1", "yes", "secure", "production"}


def is_secure_mode() -> bool:
    return os.getenv("IAM_SECURITY_MODE", "demo").lower() in _SECURE_MODE_VALUES


def get_pki_key_passphrase() -> bytes | None:
    """Passphrase dùng để mã hóa CA / server private key trên disk.

    - Secure mode: bắt buộc phải có env ``IAM_PKI_PASSPHRASE``, raise nếu thiếu.
    - Demo mode: trả về giá trị mặc định (không bảo mật) hoặc None nếu env không đặt,
      cho phép hệ thống chạy demo dễ dàng.
    """
    raw = os.getenv("IAM_PKI_PASSPHRASE", "")
    if raw:
        return raw.encode("utf-8")

    if is_secure_mode():
        raise RuntimeError(
            "IAM_SECURITY_MODE=secure nhưng thiếu IAM_PKI_PASSPHRASE. "
            "Cần đặt biến môi trường IAM_PKI_PASSPHRASE chứa passphrase "
            "để mã hóa private key trên disk."
        )
    return None


def get_master_key_passphrase() -> bytes | None:
    """Passphrase dùng để bọc (wrap) master key trước khi lưu DB.

    - Secure mode: bắt buộc ``IAM_MASTER_KEY_PASSPHRASE``.
    - Demo mode: trả về None → master key lưu plaintext (chấp nhận cho demo).
    """
    raw = os.getenv("IAM_MASTER_KEY_PASSPHRASE", "")
    if raw:
        return raw.encode("utf-8")

    if is_secure_mode():
        raise RuntimeError(
            "IAM_SECURITY_MODE=secure nhưng thiếu IAM_MASTER_KEY_PASSPHRASE. "
            "Cần đặt biến môi trường để bọc master key trong DB."
        )
    return None


def wrap_master_key(master_key: bytes) -> bytes:
    """Bọc master key bằng AES-256-GCM dưới passphrase-derived key.
    Trả về master_key nguyên gốc nếu không có passphrase (demo mode).
    """
    passphrase = get_master_key_passphrase()
    if passphrase is None:
        return master_key

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac("sha256", passphrase, salt, 100_000)
    aesgcm = AESGCM(derived)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, master_key, associated_data=b"master_key_wrap")
    return b"WRAP1" + salt + nonce + ct


def unwrap_master_key(wrapped: bytes) -> bytes:
    """Giải bọc master key. Nếu dữ liệu không có header WRAP1, trả về nguyên
    (backward-compat với master key plaintext cũ)."""
    if not wrapped.startswith(b"WRAP1"):
        passphrase = get_master_key_passphrase()
        if passphrase is not None:
            raise RuntimeError(
                "Master key trong DB đang ở dạng plaintext nhưng "
                "IAM_MASTER_KEY_PASSPHRASE đã được đặt. Cần migrate master key "
                "sang dạng wrapped trước khi chạy ở chế độ secure."
            )
        return wrapped

    passphrase = get_master_key_passphrase()
    if passphrase is None:
        raise RuntimeError(
            "Master key đã được wrap nhưng thiếu IAM_MASTER_KEY_PASSPHRASE "
            "để giải mã."
        )

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = wrapped[5:21]
    nonce = wrapped[21:33]
    ct = wrapped[33:]
    derived = hashlib.pbkdf2_hmac("sha256", passphrase, salt, 100_000)
    aesgcm = AESGCM(derived)
    return aesgcm.decrypt(nonce, ct, associated_data=b"master_key_wrap")
