# -*- coding: utf-8 -*-
"""
Script tao tai khoan admin mot lan duy nhat.
Chay: python create_admin.py
"""

import sys
import os
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Đảm bảo import được các module trong src/
sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
load_dotenv()

from src.identity_management import IdentityManagementSystem, Role

ADMIN_USERNAME = "admin"
ADMIN_EMAIL    = "admin@gmail.com"
ADMIN_PASSWORD = "admin123"

def main():
    print("=== Tạo tài khoản Admin ===")

    try:
        iam = IdentityManagementSystem()
    except Exception as e:
        print(f"[ERROR] Không kết nối được SQL Server: {e}")
        sys.exit(1)

    # Tìm admin hiện tại nếu có
    existing = None
    for user in iam.users.values():
        if user.username == ADMIN_USERNAME:
            existing = user
            break

    if existing:
        # Cập nhật lại email, password (re-hash đúng format salt$hash), roles
        existing.email         = ADMIN_EMAIL
        existing.password_hash = iam.hash_password(ADMIN_PASSWORD)
        existing.roles         = [Role.ADMIN]
        existing.is_active     = True
        iam._save_user(existing)
        print(f"[OK] Da cap nhat tai khoan admin (user_id={existing.user_id})")
        user = existing
    else:
        user = iam.create_user(
            username=ADMIN_USERNAME,
            email=ADMIN_EMAIL,
            password=ADMIN_PASSWORD,
            roles=[Role.ADMIN],
        )
        print(f"[OK] Da tao tai khoan admin moi!")

    print(f"     user_id  : {user.user_id}")
    print(f"     username : {user.username}")
    print(f"     email    : {user.email}")
    print(f"     roles    : {[r.value for r in user.roles]}")
    print(f"     password : da duoc hash bang PBKDF2-HMAC-SHA256 (100 000 iterations)")

    # Xac nhan verify password hoat dong dung
    ok = iam.verify_password(ADMIN_PASSWORD, user.password_hash)
    print(f"     verify   : {'PASS' if ok else 'FAIL'}")

if __name__ == "__main__":
    main()
