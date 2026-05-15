"""
Tests for Key Management System
"""

import unittest
import os
import shutil
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidKey
from src.key_management import KeyStore, KeyMetadata
from src.identity_management import IdentityManagementSystem, Role, Permission
from src.secure_transmission import SecureTransmissionChannel
from src.audit_logging import AuditLogger, AuditEventType
from src.storage_backend import MemoryAuditStorage
from src.public_key_distribution import CertificateAuthority, verify_certificate, extract_public_key


logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s %(name)s - %(message)s"
)
logger = logging.getLogger("tests.test_system")


class LoggedTestCase(unittest.TestCase):
    """Base test case with start/end logs for each test."""

    def setUp(self):
        logger.info("START %s.%s", self.__class__.__name__, self._testMethodName)

    def tearDown(self):
        logger.info("END   %s.%s", self.__class__.__name__, self._testMethodName)


class TestKeyManagement(LoggedTestCase):
    """Test Key Management"""
    
    def setUp(self):
        super().setUp()
        self.test_path = "test_keys"
        logger.info("Preparing key test storage at %s", self.test_path)
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        self.key_store = KeyStore(self.test_path)
    
    def tearDown(self):
        logger.info("Cleaning key test storage at %s", self.test_path)
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        super().tearDown()
    
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

    def test_generate_password_protected_rsa_private_key(self):
        """Test private key RSA được bảo vệ bằng password"""
        key_id, _ = self.key_store.generate_asymmetric_key_pair(
            "test_rsa_pwd",
            "alice",
            "Signing",
            private_key_password="StrongPass@123"
        )

        private_key = self.key_store.get_private_key(
            key_id,
            private_key_password="StrongPass@123"
        )
        self.assertIsNotNone(private_key)

    def test_get_private_key_with_wrong_password(self):
        """Test không thể mở private key khi password sai"""
        key_id, _ = self.key_store.generate_asymmetric_key_pair(
            "test_rsa_wrong_pwd",
            "alice",
            "Signing",
            private_key_password="RightPass@123"
        )

        with self.assertRaises((TypeError, ValueError, InvalidKey)):
            self.key_store.get_private_key(
                key_id,
                private_key_password="WrongPass@123"
            )
    
    def test_key_rotation(self):
        """Test xoay vòng khóa"""
        key_id = self.key_store.generate_symmetric_key(
            "rotate_test",
            "alice",
            "Test"
        )
        new_key_id = self.key_store.rotate_key(key_id)
        self.assertNotEqual(key_id, new_key_id)

    def test_rotate_password_protected_rsa_requires_password(self):
        """Test rotate RSA có password protection phải yêu cầu password"""
        key_id, _ = self.key_store.generate_asymmetric_key_pair(
            "rotate_rsa_pwd",
            "alice",
            "Signing",
            private_key_password="RotatePass@123"
        )

        with self.assertRaises(ValueError):
            self.key_store.rotate_key(key_id)

    def test_rotate_password_protected_rsa_with_password(self):
        """Test rotate RSA có password protection khi cung cấp password đúng"""
        key_id, _ = self.key_store.generate_asymmetric_key_pair(
            "rotate_rsa_pwd_ok",
            "alice",
            "Signing",
            private_key_password="RotatePass@123"
        )

        new_key_id = self.key_store.rotate_key(
            key_id,
            private_key_password="RotatePass@123"
        )
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


class TestIdentityManagement(LoggedTestCase):
    """Test Identity Management"""
    
    def setUp(self):
        super().setUp()
        self.test_path = "test_identity"
        logger.info("Preparing identity test storage at %s", self.test_path)
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        self.iam = IdentityManagementSystem(self.test_path)
    
    def tearDown(self):
        logger.info("Cleaning identity test storage at %s", self.test_path)
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        super().tearDown()
    
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


class TestSecureTransmission(LoggedTestCase):
    """Test Secure Transmission"""
    
    def setUp(self):
        super().setUp()
        self.channel = SecureTransmissionChannel()
        self.key = os.urandom(32)  # AES-256 key
        logger.info("Generated ephemeral AES-256 test key")
    
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


class TestMutualAuthentication(LoggedTestCase):
    """Test mutual authentication client-server"""

    def setUp(self):
        super().setUp()
        self.test_path = "test_mutual_auth"
        logger.info("Preparing mutual auth test storage at %s", self.test_path)
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        self.ca = CertificateAuthority(self.test_path)
        self.channel = SecureTransmissionChannel()

    def tearDown(self):
        logger.info("Cleaning mutual auth test storage at %s", self.test_path)
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        super().tearDown()

    def test_server_proof_of_possession(self):
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_pub_pem = server_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        server_cert = self.ca.issue_certificate("IAM-Server", server_pub_pem)

        server_nonce = "server-nonce-123"
        server_signature = self.channel.sign_message(f"{server_nonce}|IAM-Server", server_key)

        self.assertTrue(
            verify_certificate(server_cert, self.ca.get_public_key_pem(), expected_subject="IAM-Server")
        )
        server_public_key = extract_public_key(server_cert)
        self.assertTrue(
            self.channel.verify_signature(f"{server_nonce}|IAM-Server", server_signature, server_public_key)
        )

    def test_client_proof_of_possession(self):
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client_pub_pem = client_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        client_cert = self.ca.issue_certificate("alice", client_pub_pem)

        server_nonce = "server-nonce-456"
        client_nonce = "client-nonce-789"
        client_signature = self.channel.sign_message(
            f"{server_nonce}|{client_nonce}|alice",
            client_key
        )

        self.assertTrue(
            verify_certificate(client_cert, self.ca.get_public_key_pem(), expected_subject="alice")
        )
        client_public_key = extract_public_key(client_cert)
        self.assertTrue(
            self.channel.verify_signature(
                f"{server_nonce}|{client_nonce}|alice",
                client_signature,
                client_public_key
            )
        )


class TestAuditLogging(LoggedTestCase):
    """Test Audit Logging"""

    def setUp(self):
        super().setUp()
        self.audit = AuditLogger("test_audit", storage=MemoryAuditStorage())

    def tearDown(self):
        super().tearDown()
    
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


class TestSecurityConfig(LoggedTestCase):
    """Test security_config module (Phase 1 — secret protection)."""

    def test_wrap_unwrap_roundtrip(self):
        """wrap_master_key + unwrap_master_key produce original key."""
        os.environ["IAM_MASTER_KEY_PASSPHRASE"] = "test-passphrase-42"
        try:
            from src.security_config import wrap_master_key, unwrap_master_key
            original = os.urandom(32)
            wrapped = wrap_master_key(original)
            self.assertTrue(wrapped.startswith(b"WRAP1"))
            self.assertNotEqual(wrapped, original)
            recovered = unwrap_master_key(wrapped)
            self.assertEqual(original, recovered)
        finally:
            os.environ.pop("IAM_MASTER_KEY_PASSPHRASE", None)

    def test_unwrap_plaintext_passthrough_demo_mode(self):
        """In demo mode (no passphrase), unwrap returns raw bytes unchanged."""
        os.environ.pop("IAM_MASTER_KEY_PASSPHRASE", None)
        os.environ["IAM_SECURITY_MODE"] = "demo"
        try:
            from src.security_config import unwrap_master_key
            raw = os.urandom(32)
            self.assertEqual(unwrap_master_key(raw), raw)
        finally:
            os.environ.pop("IAM_SECURITY_MODE", None)

    def test_secure_mode_requires_passphrase(self):
        """Secure mode raises when IAM_MASTER_KEY_PASSPHRASE is missing."""
        os.environ["IAM_SECURITY_MODE"] = "secure"
        os.environ.pop("IAM_MASTER_KEY_PASSPHRASE", None)
        try:
            from src.security_config import get_master_key_passphrase
            with self.assertRaises(RuntimeError):
                get_master_key_passphrase()
        finally:
            os.environ.pop("IAM_SECURITY_MODE", None)


class TestUserStatusConsistency(LoggedTestCase):
    """Test Phase 2 — user status/MFA persistence consistency."""

    def setUp(self):
        super().setUp()
        self.test_path = "test_user_consistency"
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        self.iam = IdentityManagementSystem(self.test_path)

    def tearDown(self):
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        super().tearDown()

    def test_to_dict_includes_status_field(self):
        """User.to_dict() emits 'status' mapped from is_active."""
        user = self.iam.create_user("statususer", "s@e.com", "pass123")
        d = user.to_dict()
        self.assertEqual(d['status'], 'active')
        self.assertTrue(d['is_active'])

    def test_deactivate_sets_status_inactive(self):
        """After deactivate, to_dict returns status='inactive'."""
        user = self.iam.create_user("deactuser", "d@e.com", "pass123")
        self.iam.deactivate_user(user.user_id)
        d = self.iam.users[user.user_id].to_dict()
        self.assertEqual(d['status'], 'inactive')
        self.assertFalse(d['is_active'])

    def test_deactivated_user_cannot_login(self):
        user = self.iam.create_user("noauth", "n@e.com", "pass123")
        self.iam.deactivate_user(user.user_id)
        session = self.iam.authenticate_user("noauth", "pass123")
        self.assertIsNone(session)

    def test_enable_mfa_persists_secret(self):
        """enable_mfa stores mfa_secret on User object."""
        user = self.iam.create_user("mfauser", "m@e.com", "pass123")
        secret = self.iam.enable_mfa(user.user_id)
        self.assertIsNotNone(secret)
        self.assertEqual(user.mfa_secret, secret)
        self.assertTrue(user.mfa_enabled)


class TestKeyLifecycleGuard(LoggedTestCase):
    """Test Phase 3 — revoked/expired key access denied."""

    def setUp(self):
        super().setUp()
        self.test_path = "test_key_lifecycle"
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        self.key_store = KeyStore(self.test_path)

    def tearDown(self):
        if os.path.exists(self.test_path):
            shutil.rmtree(self.test_path)
        super().tearDown()

    def test_revoked_symmetric_key_access_denied(self):
        """After revoke, get_symmetric_key should raise ValueError."""
        key_id = self.key_store.generate_symmetric_key(
            "revoke_guard_test", "alice", "Test"
        )
        self.key_store.revoke_key(key_id)
        with self.assertRaises(ValueError) as ctx:
            self.key_store.get_symmetric_key(key_id)
        self.assertIn("thu hồi", str(ctx.exception).lower().replace("đã bị ", ""))

    def test_revoked_private_key_access_denied(self):
        """After revoke, get_private_key should raise ValueError."""
        key_id, _, _ = self.key_store.generate_asymmetric_key_pair(
            "revoke_rsa_guard", "alice", "Test"
        )
        self.key_store.revoke_key(key_id)
        with self.assertRaises(ValueError):
            self.key_store.get_private_key(key_id)

    def test_rotate_persists_old_key_inactive(self):
        """After rotate, old key's is_active is persisted to storage."""
        key_id = self.key_store.generate_symmetric_key(
            "rotate_persist_test", "alice", "Test"
        )
        new_key_id = self.key_store.rotate_key(key_id)
        meta = self.key_store.storage.load_metadata(key_id)
        self.assertFalse(meta['is_active'])
        new_key = self.key_store.get_symmetric_key(new_key_id)
        self.assertIsNotNone(new_key)


if __name__ == '__main__':
    unittest.main()
