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
        import pyodbc
        try:
            conn = pyodbc.connect(connection_string)
            conn.close()
        except pyodbc.Error as e:
            raise RuntimeError(f"Cannot connect to SQL Server: {e}")

    def save_user(self, user_dict: Dict) -> None:
        import pyodbc
        conn = pyodbc.connect(self.connection_string, autocommit=True)
        cursor = conn.cursor()
        
        roles_json = json.dumps(user_dict.get('roles', ['user']))
        last_login = user_dict.get('last_login')
        if last_login == "": last_login = None
        
        cursor.execute("SELECT 1 FROM Users WHERE user_id = ?", user_dict['user_id'])
        exists = cursor.fetchone()
        
        if exists:
            cursor.execute('''
                UPDATE Users SET 
                    username = ?, email = ?, password_hash = ?, roles = ?, 
                    mfa_secret = ?, mfa_enabled = ?, status = ?, last_login = ?
                WHERE user_id = ?
            ''', (
                user_dict['username'], user_dict['email'], user_dict['password_hash'], 
                roles_json, user_dict.get('mfa_secret'), user_dict.get('mfa_enabled', False), 
                user_dict.get('status', 'active'), last_login, user_dict['user_id']
            ))
        else:
            cursor.execute('''
                INSERT INTO Users (user_id, username, email, password_hash, roles, mfa_secret, mfa_enabled, status, created_at, last_login)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_dict['user_id'], user_dict['username'], user_dict['email'], user_dict['password_hash'], 
                roles_json, user_dict.get('mfa_secret'), user_dict.get('mfa_enabled', False), 
                user_dict.get('status', 'active'), user_dict.get('created_at'), last_login
            ))
        conn.close()

    def load_all_users(self) -> List[Dict]:
        import pyodbc
        conn = pyodbc.connect(self.connection_string)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, username, email, password_hash, roles, mfa_secret, mfa_enabled, status, created_at, last_login FROM Users")
        
        users = []
        for row in cursor.fetchall():
            user_dict = {
                'user_id': row.user_id,
                'username': row.username,
                'email': row.email,
                'password_hash': row.password_hash,
                'roles': json.loads(row.roles),
                'mfa_secret': row.mfa_secret,
                'mfa_enabled': bool(row.mfa_enabled),
                'status': row.status,
                'created_at': row.created_at.isoformat() if row.created_at else None,
                'last_login': row.last_login.isoformat() if row.last_login else None
            }
            users.append(user_dict)
        conn.close()
        return users

    def delete_user(self, user_id: str) -> None:
        import pyodbc
        conn = pyodbc.connect(self.connection_string, autocommit=True)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Users WHERE user_id = ?", user_id)
        conn.close()


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

    def load_or_create_master_key(self) -> bytes:
        import pyodbc
        import secrets
        conn = pyodbc.connect(self.connection_string, autocommit=True)
        cursor = conn.cursor()
        cursor.execute("SELECT key_payload FROM KeysData WHERE key_id = 'master_key' AND key_type = 'master'")
        row = cursor.fetchone()
        if row:
            master_key = row.key_payload
        else:
            master_key = secrets.token_bytes(32)
            cursor.execute("INSERT INTO KeysData (key_id, key_type, key_payload) VALUES ('master_key', 'master', ?)", master_key)
        conn.close()
        return master_key

    def save_key_bytes(self, key_id: str, data: bytes) -> None:
        self._upsert_key_data(key_id, 'symmetric', data)

    def load_key_bytes(self, key_id: str) -> Optional[bytes]:
        return self._load_key_data(key_id, 'symmetric')

    def save_private_key_bytes(self, key_id: str, data: bytes) -> None:
        self._upsert_key_data(key_id, 'private', data)

    def load_private_key_bytes(self, key_id: str) -> Optional[bytes]:
        return self._load_key_data(key_id, 'private')

    def save_public_key_bytes(self, key_id: str, data: bytes) -> None:
        self._upsert_key_data(key_id, 'public', data)

    def load_public_key_bytes(self, key_id: str) -> Optional[bytes]:
        return self._load_key_data(key_id, 'public')
        
    def _upsert_key_data(self, key_id: str, key_type: str, data: bytes) -> None:
        import pyodbc
        conn = pyodbc.connect(self.connection_string, autocommit=True)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM KeysData WHERE key_id = ? AND key_type = ?", (key_id, key_type))
        exists = cursor.fetchone()
        if exists:
            cursor.execute("UPDATE KeysData SET key_payload = ? WHERE key_id = ? AND key_type = ?", (data, key_id, key_type))
        else:
            cursor.execute("INSERT INTO KeysData (key_id, key_type, key_payload) VALUES (?, ?, ?)", (key_id, key_type, data))
        conn.close()
        
    def _load_key_data(self, key_id: str, key_type: str) -> Optional[bytes]:
        import pyodbc
        conn = pyodbc.connect(self.connection_string)
        cursor = conn.cursor()
        cursor.execute("SELECT key_payload FROM KeysData WHERE key_id = ? AND key_type = ?", (key_id, key_type))
        row = cursor.fetchone()
        conn.close()
        if row: return row.key_payload
        return None

    def save_metadata(self, key_id: str, metadata_dict: Dict) -> None:
        import pyodbc
        conn = pyodbc.connect(self.connection_string, autocommit=True)
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM KeysMetadata WHERE key_id = ?", key_id)
        exists = cursor.fetchone()
        
        last_rot = metadata_dict.get('last_rotated')
        expires = metadata_dict.get('expires_at')
        if last_rot == "": last_rot = None
        if expires == "": expires = None
        
        if exists:
            cursor.execute('''
                UPDATE KeysMetadata SET
                    owner_id = ?, algorithm = ?, key_size = ?, purpose = ?,
                    is_active = ?, version = ?, expires_at = ?, last_rotated = ?
                WHERE key_id = ?
            ''', (
                metadata_dict.get('owner', metadata_dict.get('owner_id', 'system')), 
                metadata_dict.get('algorithm', 'AES-256'), metadata_dict.get('key_size', 256), 
                metadata_dict.get('purpose'), metadata_dict.get('is_active', True), 
                metadata_dict.get('version', 1), expires, last_rot, key_id
            ))
        else:
            cursor.execute('''
                INSERT INTO KeysMetadata (key_id, owner_id, algorithm, key_size, purpose, is_active, version, creation_date, expires_at, last_rotated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                key_id, metadata_dict.get('owner', metadata_dict.get('owner_id', 'system')), metadata_dict.get('algorithm', 'AES-256'), 
                metadata_dict.get('key_size', 256), metadata_dict.get('purpose'), 
                metadata_dict.get('is_active', True), metadata_dict.get('version', 1), 
                metadata_dict.get('created_at'), expires, last_rot
            ))
        conn.close()

    def load_metadata(self, key_id: str) -> Optional[Dict]:
        import pyodbc
        conn = pyodbc.connect(self.connection_string)
        cursor = conn.cursor()
        cursor.execute("SELECT key_id, owner_id, algorithm, key_size, purpose, is_active, version, creation_date, expires_at, last_rotated FROM KeysMetadata WHERE key_id = ?", key_id)
        row = cursor.fetchone()
        conn.close()
        if not row: return None
        
        return {
            'key_id': row.key_id,
            'owner': row.owner_id,
            'owner_id': row.owner_id,
            'algorithm': row.algorithm,
            'key_size': row.key_size,
            'purpose': row.purpose,
            'is_active': bool(row.is_active),
            'version': row.version,
            'creation_date': row.creation_date.isoformat() if row.creation_date else None,
            'expires_at': row.expires_at.isoformat() if row.expires_at else None,
            'last_rotated': row.last_rotated.isoformat() if row.last_rotated else None
        }

    def list_key_ids(self) -> List[str]:
        import pyodbc
        conn = pyodbc.connect(self.connection_string)
        cursor = conn.cursor()
        cursor.execute("SELECT key_id FROM KeysMetadata")
        ids = [row.key_id for row in cursor.fetchall()]
        conn.close()
        return ids


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

    def save_log(self, log_dict: Dict) -> None:
        import pyodbc
        conn = pyodbc.connect(self.connection_string, autocommit=True)
        cursor = conn.cursor()
        
        details_json = None
        if 'details' in log_dict and log_dict['details']:
            details_json = json.dumps(log_dict['details'])
            
        cursor.execute('''
            INSERT INTO AuditLogs (event_id, timestamp, event_type, user_id, resource, action, result, details_json, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_dict.get('log_id', secrets.token_hex(8)), log_dict.get('timestamp'), 
            log_dict.get('event_type'), log_dict.get('user_id'), log_dict.get('resource'), 
            log_dict.get('action'), log_dict.get('result', 'success'), details_json, 
            log_dict.get('ip_address'), log_dict.get('user_agent')
        ))
        conn.close()

    def load_all_logs(self) -> List[Dict]:
        import pyodbc
        conn = pyodbc.connect(self.connection_string)
        cursor = conn.cursor()
        cursor.execute("SELECT event_id, timestamp, event_type, user_id, resource, action, result, details_json, ip_address, user_agent FROM AuditLogs ORDER BY timestamp ASC")
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'log_id': row.event_id,
                'event_id': row.event_id,
                'timestamp': row.timestamp.isoformat() if row.timestamp else None,
                'event_type': row.event_type,
                'user_id': row.user_id,
                'resource': row.resource,
                'action': row.action,
                'result': row.result,
                'details': json.loads(row.details_json) if row.details_json else {},
                'ip_address': row.ip_address,
                'user_agent': row.user_agent
            })
        conn.close()
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
