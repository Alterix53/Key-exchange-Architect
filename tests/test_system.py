"""
Tests for Key Management System
"""

import unittest
import os
import shutil
from src.key_management import KeyStore, KeyMetadata
from src.identity_management import IdentityManagementSystem, Role, Permission
from src.secure_transmission import SecureTransmissionChannel
from src.audit_logging import AuditLogger, AuditEventType


class TestKeyManagement(unittest.TestCase):
    """Test Key Management"""
    
    def setUp(self):
        self.test_path = "test_keys"
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        self.key_store = KeyStore(self.test_path)
    
    def tearDown(self):
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
    
    def test_generate_symmetric_key(self):
        """Test sinh khóa đối xứng"""
        key_id = self.key_store.generate_symmetric_key(
            "test_key",
            "alice",
            "Test Purpose"
        )
        self.assertIsNotNone(key_id)
        self.assertIn(key_id, self.key_store.keys_metadata)
    
    def test_generate_asymmetric_key_pair(self):
        """Test sinh cặp khóa bất đối xứng"""
        key_id, pub_id = self.key_store.generate_asymmetric_key_pair(
            "test_rsa",
            "alice",
            "Signing"
        )
        self.assertIsNotNone(key_id)
        self.assertIsNotNone(pub_id)
    
    def test_key_rotation(self):
        """Test xoay vòng khóa"""
        key_id = self.key_store.generate_symmetric_key(
            "rotate_test",
            "alice",
            "Test"
        )
        new_key_id = self.key_store.rotate_key(key_id)
        self.assertNotEqual(key_id, new_key_id)
    
    def test_key_revocation(self):
        """Test thu hồi khóa"""
        key_id = self.key_store.generate_symmetric_key(
            "revoke_test",
            "alice",
            "Test"
        )
        self.key_store.revoke_key(key_id)
        self.assertFalse(self.key_store.keys_metadata[key_id].is_active)

    def test_rotate_key_missing_metadata(self):
        """Test xoay vòng khóa khi metadata thiếu"""
        with self.assertRaises(ValueError):
            self.key_store.rotate_key("missing_key")

    def test_revoke_key_missing_metadata(self):
        """Test thu hồi khóa khi metadata thiếu"""
        with self.assertRaises(ValueError):
            self.key_store.revoke_key("missing_key")


class TestIdentityManagement(unittest.TestCase):
    """Test Identity Management"""
    
    def setUp(self):
        self.test_path = "test_identity"
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        self.iam = IdentityManagementSystem(self.test_path)
    
    def tearDown(self):
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
    
    def test_create_user(self):
        """Test tạo người dùng"""
        user = self.iam.create_user(
            "testuser",
            "test@example.com",
            "password123",
            [Role.USER]
        )
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "testuser")
    
    def test_authenticate_user(self):
        """Test xác thực người dùng"""
        self.iam.create_user("alice", "alice@example.com", "password123")
        session = self.iam.authenticate_user("alice", "password123")
        self.assertIsNotNone(session)
    
    def test_failed_authentication(self):
        """Test xác thực thất bại"""
        self.iam.create_user("alice", "alice@example.com", "password123")
        session = self.iam.authenticate_user("alice", "wrongpassword")
        self.assertIsNone(session)

    def test_verify_password_with_empty_hash(self):
        """Test xác minh mật khẩu với hash rỗng"""
        self.assertFalse(self.iam.verify_password("password123", ""))
        self.assertFalse(self.iam.verify_password("password123", None))
    
    def test_rbac_permissions(self):
        """Test RBAC quyền"""
        admin = self.iam.create_user(
            "admin",
            "admin@example.com",
            "admin123",
            [Role.ADMIN]
        )
        user = self.iam.create_user(
            "user",
            "user@example.com",
            "user123",
            [Role.USER]
        )
        
        # Admin có thể xóa khóa
        admin_perm = Permission("keys", "delete")
        self.assertTrue(self.iam.check_permission(admin.user_id, admin_perm))
        
        # User không thể xóa khóa
        self.assertFalse(self.iam.check_permission(user.user_id, admin_perm))


class TestSecureTransmission(unittest.TestCase):
    """Test Secure Transmission"""
    
    def setUp(self):
        self.channel = SecureTransmissionChannel()
        self.key = os.urandom(32)  # AES-256 key
    
    def test_aes_256_cbc_encryption(self):
        """Test mã hóa AES-256-CBC"""
        plaintext = "Secret message"
        iv, ciphertext = self.channel.encrypt_aes_256_cbc(plaintext, self.key)
        
        decrypted = self.channel.decrypt_aes_256_cbc(iv, ciphertext, self.key)
        self.assertEqual(plaintext, decrypted)
    
    def test_aes_256_gcm_encryption(self):
        """Test mã hóa AES-256-GCM"""
        plaintext = "Secret message"
        nonce, ciphertext, tag = self.channel.encrypt_aes_256_gcm(
            plaintext, self.key
        )
        
        decrypted = self.channel.decrypt_aes_256_gcm(
            nonce, ciphertext, tag, self.key
        )
        self.assertEqual(plaintext, decrypted)
    
    def test_hmac_generation(self):
        """Test tạo HMAC"""
        message = "Important data"
        hmac_value = self.channel.generate_hmac(message, self.key)
        
        is_valid = self.channel.verify_hmac(message, hmac_value, self.key)
        self.assertTrue(is_valid)
    
    def test_hmac_tampering_detection(self):
        """Test phát hiện sửa đổi HMAC"""
        message = "Important data"
        hmac_value = self.channel.generate_hmac(message, self.key)
        
        tampered = "Modified data"
        is_valid = self.channel.verify_hmac(tampered, hmac_value, self.key)
        self.assertFalse(is_valid)


class TestAuditLogging(unittest.TestCase):
    """Test Audit Logging"""
    
    def setUp(self):
        self.test_path = "test_audit"
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        self.audit = AuditLogger(self.test_path)
    
    def tearDown(self):
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
    
    def test_log_event(self):
        """Test ghi sự kiện"""
        self.audit.log_event(
            AuditEventType.USER_LOGIN,
            "user123",
            "sessions",
            "login",
            "success"
        )
        logs = self.audit.get_logs_by_user("user123")
        self.assertEqual(len(logs), 1)
    
    def test_get_logs_by_event_type(self):
        """Test lấy bản ghi theo loại sự kiện"""
        self.audit.log_event(
            AuditEventType.KEY_GENERATED,
            "user123",
            "keys",
            "generate",
            "success"
        )
        logs = self.audit.get_logs_by_event_type(AuditEventType.KEY_GENERATED)
        self.assertGreater(len(logs), 0)
    
    def test_suspicious_activity_detection(self):
        """Test phát hiện hoạt động đáng nghi"""
        # Tạo 3 lần đăng nhập thất bại
        for _ in range(3):
            self.audit.log_event(
                AuditEventType.USER_FAILED_LOGIN,
                "suspect_user",
                "sessions",
                "login",
                "failed"
            )
        
        suspicious = self.audit.detect_suspicious_activity("suspect_user")
        self.assertGreater(len(suspicious), 0)

    def test_generate_access_report_without_login(self):
        """Test báo cáo truy cập khi không có sự kiện đăng nhập"""
        self.audit.log_event(
            AuditEventType.PERMISSION_DENIED,
            "user_no_login",
            "keys",
            "delete",
            "failed"
        )

        report = self.audit.generate_access_report("user_no_login")
        self.assertEqual(report["last_login"], None)
        self.assertEqual(report["permissions_denied"], 1)


if __name__ == '__main__':
    unittest.main()
