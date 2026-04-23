"""
Init Demo Environment
Script dọn dẹp và khởi tạo môi trường Demo từ đầu
"""

import os
import shutil
import sys

# Thêm src vào PYTHONPATH
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.identity_management import IdentityManagementSystem, Role
from src.key_management import KeyStore
from src.public_key_distribution import CertificateAuthority
from src.audit_logging import AuditLogger, AuditEventType


def clean_environment():
    """Xóa các thư mục data cũ để làm lại từ đầu"""
    print("🧹 Đang dọn dẹp môi trường cũ...")
    try:
        from src.db import get_working_connection_string
        import pyodbc

        conn_str = get_working_connection_string()
        conn = pyodbc.connect(conn_str, autocommit=True)
        cursor = conn.cursor()
        # Xóa sạch dữ liệu các bảng theo thứ tự tránh lỗi khóa ngoại
        cursor.execute("DELETE FROM AuditLogs")
        cursor.execute("DELETE FROM KeysData")
        cursor.execute("DELETE FROM KeysMetadata")
        cursor.execute("DELETE FROM Users")
        conn.close()
        print("  - Đã xóa dữ liệu trong SQL Server (IAM_KMS_DB)")
    except Exception as e:
        print(f"  - Lỗi khi dọn dẹp SQL Server: {e}")
    
    dirs_to_clean = ["demo_identity", "demo_keys", "demo_audit", "data", "pki"]
    for d in dirs_to_clean:
        if os.path.exists(d):
            shutil.rmtree(d)
            print(f"  - Xóa {d}/")
        os.makedirs(d, exist_ok=True)
    print("  ✓ Hoàn tất làm sạch.")


def setup_demo_environment():
    print("\n🚀 Bắt đầu khởi tạo dữ liệu mẫu hệ thống IAM MS (Backend: sqlserver)...")

    from src.db import get_working_connection_string
    from src.storage_backend import SqlServerUserStorage, SqlServerKeyStorage, SqlServerAuditStorage

    conn_str = get_working_connection_string()
    user_storage = SqlServerUserStorage(conn_str)
    key_storage = SqlServerKeyStorage(conn_str)
    audit_storage = SqlServerAuditStorage(conn_str)
    
    iam = IdentityManagementSystem("demo_identity", storage=user_storage)
    key_store = KeyStore("demo_keys", storage=key_storage)
    audit = AuditLogger("demo_audit", storage=audit_storage)

    # 1. Khởi tạo Admin
    print("\n1️⃣  Đang tạo tài khoản Admin...")
    admin = iam.create_user("admin", "admin@company.com", "Admin@123", [Role.ADMIN])
    print(f"  ✓ User admin created! (ID: {admin.user_id})")
    audit.log_event(AuditEventType.USER_CREATED, "system", "users", "create", details={"username": "admin"})

    # 2. Khởi tạo User thường (Alice)
    print("\n2️⃣  Đang tạo tài khoản User (Alice)...")
    alice = iam.create_user("alice", "alice@company.com", "Alice@123", [Role.USER])
    print(f"  ✓ User alice created! (ID: {alice.user_id})")
    audit.log_event(AuditEventType.USER_CREATED, "system", "users", "create", details={"username": "alice"})

    # 3. Tạo certificate authority (CA)
    print("\n3️⃣  Đang khởi tạo Hệ thống PKI / CA...")
    ca = CertificateAuthority(data_dir="pki")
    print("  ✓ Root/Intermediate CA artifacts đã được sinh trong pki/")
    print("    - pki/root/private/root.key")
    print("    - pki/root/certs/root.crt")
    print("    - pki/intermediate/private/intermediate.key")
    print("    - pki/intermediate/certs/intermediate.crt")
    audit.log_event(AuditEventType.KEY_GENERATED, "system", "pki", "init_ca")

    # 4. Sinh khóa đối xứng mấu (Mocking)
    print("\n4️⃣  Sinh khóa dữ liệu (AES-256) mặc định cho Alice...")
    aes_key_id = key_store.generate_symmetric_key(f"aes_{alice.user_id}_default", alice.user_id, "File Encryption", "AES-256")
    print(f"  ✓ Tạo khóa đối xứng thành công (ID: {aes_key_id})")
    audit.log_event(AuditEventType.KEY_GENERATED, alice.user_id, "keys", "generate", details={"algo": "AES-256"})

    print("\n=======================================================")
    print("🎉 KHỞI TẠO HOÀN TẤT 🎉")
    print("=======================================================")
    print("Môi trường đã sẵn sàng!")
    print("Tài khoản để đăng nhập:")
    print("  - Quản trị viên : admin / Admin@123")
    print("  - Người dùng    : alice / Alice@123")
    print("\nBước tiếp theo:")
    print("  1. Chạy 'python server.py' ở một terminal")
    print("  2. Chạy 'python client.py' ở các terminal khác")
    print("=======================================================")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Clean and initialize IAM DB")
    parser.parse_args()

    clean_environment()
    setup_demo_environment()
