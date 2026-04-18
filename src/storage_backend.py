"""
Storage Backend Abstraction Layer
Cung cấp interface trừu tượng để hoán đổi storage backend (JSON File ↔ SQL Server).

Kiến trúc Repository Pattern:
    BusinessLogic (IdentityManagementSystem, KeyStore, AuditLogger)
        │
        ▼  gọi qua interface
    StorageBackend (ABC)
        ├── JsonFile*Storage   ← Hiện tại (demo, file system)
        └── SqlServer*Storage  ← Tương lai (production, SQL Server)
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional
import json
import os
import secrets


# ============================================================
#  Abstract Base Classes — Định nghĩa Interface
# ============================================================

class UserStorage(ABC):
    """Interface cho lưu trữ dữ liệu người dùng"""

    @abstractmethod
    def save_user(self, user_dict: Dict) -> None:
        """Lưu/Cập nhật thông tin người dùng (upsert)"""
        pass

    @abstractmethod
    def load_all_users(self) -> List[Dict]:
        """Tải tất cả người dùng, trả về danh sách dict"""
        pass

    @abstractmethod
    def delete_user(self, user_id: str) -> None:
        """Xóa người dùng theo user_id"""
        pass


class KeyStorage(ABC):
    """Interface cho lưu trữ khóa mã hóa"""

    @abstractmethod
    def load_or_create_master_key(self) -> bytes:
        """Tải Master Key nếu tồn tại, nếu chưa thì sinh mới và lưu"""
        pass

    @abstractmethod
    def save_key_bytes(self, key_id: str, data: bytes) -> None:
        """Lưu khóa đối xứng (đã mã hóa bằng master key)"""
        pass

    @abstractmethod
    def load_key_bytes(self, key_id: str) -> Optional[bytes]:
        """Tải khóa đối xứng (đã mã hóa), trả về None nếu không tồn tại"""
        pass

    @abstractmethod
    def save_private_key_bytes(self, key_id: str, data: bytes) -> None:
        """Lưu khóa riêng RSA (đã mã hóa bằng master key)"""
        pass

    @abstractmethod
    def load_private_key_bytes(self, key_id: str) -> Optional[bytes]:
        """Tải khóa riêng RSA (đã mã hóa), trả về None nếu không tồn tại"""
        pass

    @abstractmethod
    def save_public_key_bytes(self, key_id: str, data: bytes) -> None:
        """Lưu khóa công khai RSA (plaintext PEM)"""
        pass

    @abstractmethod
    def load_public_key_bytes(self, key_id: str) -> Optional[bytes]:
        """Tải khóa công khai RSA, trả về None nếu không tồn tại"""
        pass

    @abstractmethod
    def save_metadata(self, key_id: str, metadata_dict: Dict) -> None:
        """Lưu metadata của khóa"""
        pass

    @abstractmethod
    def load_metadata(self, key_id: str) -> Optional[Dict]:
        """Tải metadata của khóa, trả về None nếu không tồn tại"""
        pass

    @abstractmethod
    def list_key_ids(self) -> List[str]:
        """Liệt kê tất cả key IDs có metadata"""
        pass


class AuditStorage(ABC):
    """Interface cho lưu trữ audit log"""

    @abstractmethod
    def save_log(self, log_dict: Dict) -> None:
        """Lưu (append) một bản ghi audit"""
        pass

    @abstractmethod
    def load_all_logs(self) -> List[Dict]:
        """Tải tất cả bản ghi audit"""
        pass

    @abstractmethod
    def export_logs(self, logs: List[Dict], fmt: str, output_file: str) -> str:
        """Xuất bản ghi ra file, trả về đường dẫn file đã xuất"""
        pass


# ============================================================
#  JSON File Implementations — Dùng cho Demo (file system)
# ============================================================

class JsonFileUserStorage(UserStorage):
    """Lưu trữ người dùng bằng JSON file — mỗi user một file riêng"""

    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)

    def save_user(self, user_dict: Dict) -> None:
        user_path = os.path.join(self.storage_path, f"{user_dict['user_id']}.json")
        with open(user_path, 'w', encoding='utf-8') as f:
            json.dump(user_dict, f, indent=2, ensure_ascii=False)

    def load_all_users(self) -> List[Dict]:
        users = []
        for filename in os.listdir(self.storage_path):
            if filename.endswith('.json'):
                user_path = os.path.join(self.storage_path, filename)
                with open(user_path, 'r', encoding='utf-8') as f:
                    users.append(json.load(f))
        return users

    def delete_user(self, user_id: str) -> None:
        user_path = os.path.join(self.storage_path, f"{user_id}.json")
        if os.path.exists(user_path):
            os.remove(user_path)


class JsonFileKeyStorage(KeyStorage):
    """Lưu trữ khóa bằng file — .key, .meta, .pem"""

    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)

    def load_or_create_master_key(self) -> bytes:
        master_key_path = os.path.join(self.storage_path, "master.key")
        if os.path.exists(master_key_path):
            with open(master_key_path, 'rb') as f:
                return f.read()
        else:
            master_key = secrets.token_bytes(32)  # 256-bit key
            with open(master_key_path, 'wb') as f:
                f.write(master_key)
            try:
                os.chmod(master_key_path, 0o600)
            except OSError:
                pass  # Windows không hỗ trợ đầy đủ Unix permissions
            return master_key

    def save_key_bytes(self, key_id: str, data: bytes) -> None:
        key_path = os.path.join(self.storage_path, f"{key_id}.key")
        with open(key_path, 'wb') as f:
            f.write(data)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass

    def load_key_bytes(self, key_id: str) -> Optional[bytes]:
        key_path = os.path.join(self.storage_path, f"{key_id}.key")
        if not os.path.exists(key_path):
            return None
        with open(key_path, 'rb') as f:
            return f.read()

    def save_private_key_bytes(self, key_id: str, data: bytes) -> None:
        key_path = os.path.join(self.storage_path, f"{key_id}_private.pem")
        with open(key_path, 'wb') as f:
            f.write(data)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass

    def load_private_key_bytes(self, key_id: str) -> Optional[bytes]:
        key_path = os.path.join(self.storage_path, f"{key_id}_private.pem")
        if not os.path.exists(key_path):
            return None
        with open(key_path, 'rb') as f:
            return f.read()

    def save_public_key_bytes(self, key_id: str, data: bytes) -> None:
        key_path = os.path.join(self.storage_path, f"{key_id}_public.pem")
        with open(key_path, 'wb') as f:
            f.write(data)

    def load_public_key_bytes(self, key_id: str) -> Optional[bytes]:
        key_path = os.path.join(self.storage_path, f"{key_id}_public.pem")
        if not os.path.exists(key_path):
            return None
        with open(key_path, 'rb') as f:
            return f.read()

    def save_metadata(self, key_id: str, metadata_dict: Dict) -> None:
        metadata_path = os.path.join(self.storage_path, f"{key_id}.meta")
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata_dict, f, indent=2)

    def load_metadata(self, key_id: str) -> Optional[Dict]:
        metadata_path = os.path.join(self.storage_path, f"{key_id}.meta")
        if not os.path.exists(metadata_path):
            return None
        with open(metadata_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def list_key_ids(self) -> List[str]:
        ids = []
        for filename in os.listdir(self.storage_path):
            if filename.endswith('.meta'):
                ids.append(filename.replace('.meta', ''))
        return ids


class JsonFileAuditStorage(AuditStorage):
    """Lưu trữ audit log bằng JSONL file — mỗi ngày một file"""

    def __init__(self, log_path: str):
        self.log_path = log_path
        os.makedirs(log_path, exist_ok=True)

    def save_log(self, log_dict: Dict) -> None:
        timestamp = log_dict.get('timestamp', '')
        date_str = timestamp[:10]  # YYYY-MM-DD
        log_file = os.path.join(self.log_path, f"{date_str}_audit.jsonl")
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_dict, ensure_ascii=False) + '\n')

    def load_all_logs(self) -> List[Dict]:
        logs = []
        for filename in sorted(os.listdir(self.log_path)):
            if filename.endswith('_audit.jsonl'):
                log_file = os.path.join(self.log_path, filename)
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.strip():
                            logs.append(json.loads(line))
        return logs

    def export_logs(self, logs: List[Dict], fmt: str, output_file: str) -> str:
        if fmt == "json":
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, default=str, ensure_ascii=False)
        elif fmt == "csv":
            import csv
            output_file = output_file.replace('.json', '.csv')
            if logs:
                keys = logs[0].keys()
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(logs)
        return output_file


# ============================================================
#  SQL Server Stub — Placeholder cho tương lai
#  Cài đặt: pip install pyodbc
#  Kết nối: SQL Server Management Studio (SSMS)
# ============================================================

class SqlServerUserStorage(UserStorage):
    """
    [STUB] Lưu trữ người dùng bằng SQL Server.

    Yêu cầu:
        - pip install pyodbc
        - SQL Server instance đang chạy
        - Table 'users' đã được tạo (xem schema bên dưới)

    Schema:
        CREATE TABLE users (
            user_id        NVARCHAR(50)   PRIMARY KEY,
            username       NVARCHAR(100)  NOT NULL UNIQUE,
            email          NVARCHAR(200)  NOT NULL,
            password_hash  NVARCHAR(500)  NOT NULL,
            roles          NVARCHAR(500)  NOT NULL,  -- JSON array: '["admin","user"]'
            is_active      BIT            NOT NULL DEFAULT 1,
            mfa_enabled    BIT            NOT NULL DEFAULT 0,
            groups_json    NVARCHAR(MAX)  NULL,      -- JSON array
            attributes_json NVARCHAR(MAX) NULL,      -- JSON object
            created_at     DATETIME2      NOT NULL DEFAULT GETDATE(),
            last_login     DATETIME2      NULL
        );
    """

    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        # import pyodbc
        # self.conn = pyodbc.connect(connection_string)
        raise NotImplementedError(
            "SqlServerUserStorage chưa được triển khai. "
            "Cần cài đặt pyodbc và cấu hình SQL Server connection string."
        )

    def save_user(self, user_dict: Dict) -> None:
        raise NotImplementedError

    def load_all_users(self) -> List[Dict]:
        raise NotImplementedError

    def delete_user(self, user_id: str) -> None:
        raise NotImplementedError


class SqlServerKeyStorage(KeyStorage):
    """
    [STUB] Lưu trữ khóa bằng SQL Server.

    Schema:
        CREATE TABLE keys_metadata (
            key_id          NVARCHAR(200)  PRIMARY KEY,
            owner           NVARCHAR(50)   NOT NULL,
            algorithm       NVARCHAR(50)   NOT NULL,
            key_size        INT            NOT NULL,
            purpose         NVARCHAR(200)  NULL,
            is_active       BIT            NOT NULL DEFAULT 1,
            version         INT            NOT NULL DEFAULT 1,
            private_key_password_protected BIT NOT NULL DEFAULT 0,
            created_at      DATETIME2      NOT NULL DEFAULT GETDATE(),
            expires_at      DATETIME2      NOT NULL,
            last_rotated    DATETIME2      NOT NULL
        );

        CREATE TABLE keys_data (
            key_id          NVARCHAR(200)  PRIMARY KEY,
            key_type        NVARCHAR(20)   NOT NULL,  -- 'symmetric', 'private', 'public'
            key_data        VARBINARY(MAX) NOT NULL,   -- Encrypted key bytes
            FOREIGN KEY (key_id) REFERENCES keys_metadata(key_id)
        );

        -- Master key nên được lưu trong SQL Server bằng
        -- Transparent Data Encryption (TDE) hoặc Always Encrypted.
    """

    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        raise NotImplementedError(
            "SqlServerKeyStorage chưa được triển khai."
        )

    def load_or_create_master_key(self) -> bytes:
        raise NotImplementedError

    def save_key_bytes(self, key_id: str, data: bytes) -> None:
        raise NotImplementedError

    def load_key_bytes(self, key_id: str) -> Optional[bytes]:
        raise NotImplementedError

    def save_private_key_bytes(self, key_id: str, data: bytes) -> None:
        raise NotImplementedError

    def load_private_key_bytes(self, key_id: str) -> Optional[bytes]:
        raise NotImplementedError

    def save_public_key_bytes(self, key_id: str, data: bytes) -> None:
        raise NotImplementedError

    def load_public_key_bytes(self, key_id: str) -> Optional[bytes]:
        raise NotImplementedError

    def save_metadata(self, key_id: str, metadata_dict: Dict) -> None:
        raise NotImplementedError

    def load_metadata(self, key_id: str) -> Optional[Dict]:
        raise NotImplementedError

    def list_key_ids(self) -> List[str]:
        raise NotImplementedError


class SqlServerAuditStorage(AuditStorage):
    """
    [STUB] Lưu trữ audit log bằng SQL Server.

    Schema:
        CREATE TABLE audit_logs (
            log_id         NVARCHAR(50)   PRIMARY KEY,
            timestamp      DATETIME2      NOT NULL DEFAULT GETDATE(),
            event_type     NVARCHAR(50)   NOT NULL,
            user_id        NVARCHAR(50)   NOT NULL,
            resource       NVARCHAR(100)  NOT NULL,
            action         NVARCHAR(100)  NOT NULL,
            result         NVARCHAR(20)   NOT NULL DEFAULT 'success',
            details_json   NVARCHAR(MAX)  NULL,     -- JSON object
            ip_address     NVARCHAR(45)   NULL,
            user_agent     NVARCHAR(500)  NULL,

            INDEX IX_audit_user_id  (user_id),
            INDEX IX_audit_event    (event_type),
            INDEX IX_audit_timestamp (timestamp)
        );
    """

    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        raise NotImplementedError(
            "SqlServerAuditStorage chưa được triển khai."
        )

    def save_log(self, log_dict: Dict) -> None:
        raise NotImplementedError

    def load_all_logs(self) -> List[Dict]:
        raise NotImplementedError

    def export_logs(self, logs: List[Dict], fmt: str, output_file: str) -> str:
        raise NotImplementedError
