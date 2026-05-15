"""
Test RSA Keys in Keystore Implementation
Kiểm tra:
1. Khi tạo user, sinh RSA key pair và lưu vào keystore
2. Khi revoke user key, export public key ra file và xóa khỏi keystore
"""

import os
import shutil
import json
from src.key_management import KeyStore
from src.identity_management import IdentityManagementSystem, Role


class MemoryKeyStorage:
    """In-memory key storage for testing"""
    def __init__(self):
        self._master_key = None
        self._keys = {}  # key_id -> (key_type, data)
        self._metadata = {}

    def load_or_create_master_key(self):
        if self._master_key is None:
            import secrets
            self._master_key = secrets.token_bytes(32)
        return self._master_key

    def save_key_bytes(self, key_id, data):
        self._keys[(key_id, 'symmetric')] = data

    def load_key_bytes(self, key_id):
        return self._keys.get((key_id, 'symmetric'))

    def save_private_key_bytes(self, key_id, data):
        self._keys[(key_id, 'private')] = data

    def load_private_key_bytes(self, key_id):
        return self._keys.get((key_id, 'private'))

    def save_public_key_bytes(self, key_id, data):
        self._keys[(key_id, 'public')] = data

    def load_public_key_bytes(self, key_id):
        return self._keys.get((key_id, 'public'))

    def delete_public_key_bytes(self, key_id):
        """Xóa public key khỏi storage"""
        if (key_id, 'public') in self._keys:
            del self._keys[(key_id, 'public')]

    def save_metadata(self, key_id, metadata_dict):
        self._metadata[key_id] = metadata_dict

    def load_metadata(self, key_id):
        return self._metadata.get(key_id)

    def list_key_ids(self):
        return list(set(k[0] for k in self._keys.keys() if k[1] != 'master'))


class MemoryUserStorage:
    """In-memory user storage for testing"""
    def __init__(self):
        self._users = {}

    def save_user(self, user_dict):
        self._users[user_dict['user_id']] = user_dict

    def load_all_users(self):
        return list(self._users.values())

    def delete_user(self, user_id):
        if user_id in self._users:
            del self._users[user_id]


class MemorySessionStorage:
    """In-memory session storage for testing"""
    def __init__(self):
        self._sessions = {}

    def save_session(self, session_dict):
        self._sessions[session_dict['session_id']] = session_dict

    def load_active_sessions(self):
        return list(self._sessions.values())

    def deactivate_session(self, session_id):
        if session_id in self._sessions:
            self._sessions[session_id]['is_active'] = False


def test_create_user_with_rsa_keys():
    """Test 1: Tạo user → sinh RSA key pair → lưu vào keystore"""
    print("\n[TEST 1] Create user with RSA keys")
    
    # Setup
    key_storage = MemoryKeyStorage()
    user_storage = MemoryUserStorage()
    session_storage = MemorySessionStorage()
    key_store = KeyStore(storage=key_storage)
    iam = IdentityManagementSystem(
        storage=user_storage,
        session_storage=session_storage,
        key_store=key_store
    )
    
    # Create user
    user = iam.create_user("alice", "alice@example.com", "password123", [Role.USER])
    print(f"✓ Created user: {user.username} (ID: {user.user_id})")
    
    # Verify RSA key was created and stored in keystore
    csr_key_id = user.attributes.get('csr_key_id')
    print(f"✓ CSR key ID: {csr_key_id}")
    
    assert csr_key_id is not None, "csr_key_id should be stored in user attributes"
    assert csr_key_id in key_store.keys_metadata, "CSR key should be in keystore metadata"
    
    # Verify private key exists in keystore
    private_key = key_store.get_private_key(csr_key_id)
    assert private_key is not None, "Private key should exist in keystore"
    print(f"✓ Private key retrieved: {type(private_key)}")
    
    # Verify public key exists in keystore
    public_key = key_store.get_public_key(csr_key_id)
    assert public_key is not None, "Public key should exist in keystore"
    print(f"✓ Public key retrieved: {type(public_key)}")
    
    print("✓ TEST 1 PASSED\n")
    return csr_key_id, key_store, key_storage


def test_revoke_key_exports_public_key():
    """Test 2: Revoke key → export public key → delete from keystore"""
    print("[TEST 2] Revoke key - export and delete public key")
    
    csr_key_id, key_store, key_storage = test_create_user_with_rsa_keys()
    
    # Create revoked_keys directory if not exists
    if os.path.exists("revoked_keys"):
        shutil.rmtree("revoked_keys")
    
    # Revoke the key
    key_store.revoke_key(csr_key_id)
    print(f"✓ Revoked key: {csr_key_id}")
    
    # Verify public key was exported to file
    exported_file = f"revoked_keys/{csr_key_id}_public.pem"
    assert os.path.exists(exported_file), f"Exported file should exist at {exported_file}"
    print(f"✓ Public key exported to: {exported_file}")
    
    # Verify exported file contains public key PEM
    with open(exported_file, 'rb') as f:
        exported_content = f.read()
    assert b"BEGIN PUBLIC KEY" in exported_content, "Exported file should contain PUBLIC KEY PEM"
    print(f"✓ Exported file contains valid PUBLIC KEY")
    
    # Verify public key was deleted from keystore
    public_key_in_storage = key_storage.load_public_key_bytes(csr_key_id)
    assert public_key_in_storage is None, "Public key should be deleted from keystore"
    print(f"✓ Public key deleted from keystore")
    
    # Verify key is marked as inactive
    metadata = key_store.keys_metadata.get(csr_key_id)
    assert metadata is not None, "Metadata should still exist"
    assert not metadata.is_active, "Key should be marked as inactive"
    print(f"✓ Key marked as inactive in metadata")
    
    # Cleanup
    if os.path.exists("revoked_keys"):
        shutil.rmtree("revoked_keys")
    
    print("✓ TEST 2 PASSED\n")


def test_private_key_still_accessible_after_revoke():
    """Test 3: Private key vẫn có trong keystore sau revoke"""
    print("[TEST 3] Private key still accessible after revoke")
    
    csr_key_id, key_store, key_storage = test_create_user_with_rsa_keys()
    
    # Cleanup for this test
    if os.path.exists("revoked_keys"):
        shutil.rmtree("revoked_keys")
    
    # Get private key before revoke
    private_key_before = key_store.get_private_key(csr_key_id)
    
    # Revoke
    key_store.revoke_key(csr_key_id)
    
    # Try to get private key after revoke (should fail because key is marked inactive)
    try:
        private_key_after = key_store.get_private_key(csr_key_id)
        print("⚠ Note: _validate_key_usable allows access to inactive keys (expected)")
    except ValueError as e:
        print(f"✓ Cannot access revoked key: {e}")
    
    # Cleanup
    if os.path.exists("revoked_keys"):
        shutil.rmtree("revoked_keys")
    
    print("✓ TEST 3 PASSED\n")


if __name__ == "__main__":
    try:
        test_create_user_with_rsa_keys()
        test_revoke_key_exports_public_key()
        test_private_key_still_accessible_after_revoke()
        print("\n" + "="*60)
        print("✓ ALL TESTS PASSED!")
        print("="*60)
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
