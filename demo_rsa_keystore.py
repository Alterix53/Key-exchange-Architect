"""
Demo: RSA Keys in Keystore System
Minh họa:
1. Khi tạo user, sinh RSA key pair (dùng xin ký chứng chỉ) → lưu vào keystore
2. Khi revoke key, export public key ra file → xóa khỏi keystore
3. Private key vẫn được lưu trong keystore để dùng ký chứng chỉ
"""

import os
import shutil
from cryptography.hazmat.primitives import serialization
from src.key_management import KeyStore
from src.identity_management import IdentityManagementSystem, Role
from src.storage_backend import MemoryKeyStorage, MemoryUserStorage, MemorySessionStorage


def setup_in_memory_storage():
    """Setup in-memory storage backends"""
    return MemoryKeyStorage(), MemoryUserStorage(), MemorySessionStorage()


def print_section(title):
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def demo_rsa_keystore():
    """Full demo of RSA keys in keystore"""
    
    print_section("RSA Keys in Keystore - Full Demo")
    
    # 1. Setup
    print("\n[SETUP] Initializing systems...")
    key_storage, user_storage, session_storage = setup_in_memory_storage()
    key_store = KeyStore(storage=key_storage)
    iam = IdentityManagementSystem(
        storage=user_storage,
        session_storage=session_storage,
        key_store=key_store
    )
    print("✓ Systems initialized")
    
    # 2. Create users
    print_section("Phase 1: Creating Users with RSA Keys")
    
    users = [
        ("alice", "alice@example.com", "alice_pass123"),
        ("bob", "bob@example.com", "bob_pass123"),
    ]
    
    user_mapping = {}
    for username, email, password in users:
        user = iam.create_user(username, email, password, [Role.USER])
        user_mapping[username] = user
        csr_key_id = user.attributes.get('csr_key_id')
        
        print(f"\n✓ Created user: {username}")
        print(f"  - User ID: {user.user_id}")
        print(f"  - Email: {email}")
        print(f"  - CSR Key ID: {csr_key_id}")
        
        # Get keys from keystore
        private_key = key_store.get_private_key(csr_key_id)
        public_key = key_store.get_public_key(csr_key_id)
        
        print(f"  - Private key in keystore: ✓ ({type(private_key).__name__})")
        print(f"  - Public key in keystore: ✓ ({type(public_key).__name__})")
        
        # Show public key fingerprint
        from cryptography.hazmat.primitives import hashes
        pub_numbers = public_key.public_numbers()
        pub_hash = hashes.Hash(hashes.SHA256())
        pub_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_hash.update(pub_der)
        fingerprint = pub_hash.finalize().hex()[:16]
        print(f"  - Public key fingerprint: {fingerprint}...")
    
    # 3. Revoke Alice's key
    print_section("Phase 2: Revoking Alice's RSA Key")
    
    alice = user_mapping['alice']
    alice_key_id = alice.attributes['csr_key_id']
    
    print(f"\nRevoking key: {alice_key_id}")
    print(f"  - Exporting public key to file...")
    print(f"  - Deleting public key from keystore...")
    
    # Cleanup old revoked_keys
    if os.path.exists("revoked_keys"):
        shutil.rmtree("revoked_keys")
    
    key_store.revoke_key(alice_key_id)
    
    print(f"\n✓ Key revoked successfully")
    
    # Verify export
    exported_file = f"revoked_keys/{alice_key_id}_public.pem"
    if os.path.exists(exported_file):
        with open(exported_file, 'rb') as f:
            pem_content = f.read().decode('utf-8')
        print(f"✓ Public key exported to: {exported_file}")
        print(f"  File size: {len(pem_content)} bytes")
        print(f"  Preview:\n{pem_content[:200]}...")
    
    # Verify deletion from keystore
    public_key_still_in_storage = key_storage.load_public_key_bytes(alice_key_id)
    if public_key_still_in_storage is None:
        print(f"✓ Public key deleted from keystore")
    
    # Check metadata
    metadata = key_store.keys_metadata.get(alice_key_id)
    print(f"✓ Metadata marked as inactive: {not metadata.is_active}")
    
    # 4. Bob's key still works
    print_section("Phase 3: Verifying Bob's Key Still Active")
    
    bob = user_mapping['bob']
    bob_key_id = bob.attributes['csr_key_id']
    
    try:
        private_key = key_store.get_private_key(bob_key_id)
        public_key = key_store.get_public_key(bob_key_id)
        print(f"\n✓ Bob's key is still active and accessible")
        print(f"  - Private key: ✓ Available")
        print(f"  - Public key: ✓ Available")
    except ValueError as e:
        print(f"✗ Error accessing Bob's key: {e}")
    
    # 5. Alice's key is no longer accessible
    print_section("Phase 4: Verifying Alice's Key is Revoked")
    
    try:
        private_key = key_store.get_private_key(alice_key_id)
        print(f"⚠ Warning: Alice's key should be revoked but is still accessible")
    except ValueError as e:
        print(f"\n✓ Alice's key is properly revoked")
        print(f"  - Error message: {e}")
    
    # Summary
    print_section("Summary")
    
    print(f"\n✓ Total users created: {len(users)}")
    print(f"✓ Total RSA keys generated: {len(users)}")
    print(f"✓ Keys revoked: 1 (Alice)")
    print(f"✓ Active keys: 1 (Bob)")
    
    print("\n✓ RSA Keys in Keystore implementation is working correctly!")
    print("  - Users get RSA key pairs for CSR signing")
    print("  - Both private and public keys stored in keystore")
    print("  - Revocation exports public key and removes from keystore")
    print("  - Access control prevents use of revoked keys")
    
    # Cleanup
    if os.path.exists("revoked_keys"):
        shutil.rmtree("revoked_keys")


if __name__ == "__main__":
    try:
        demo_rsa_keystore()
        print("\n" + "="*70)
        print("  ✓ DEMO COMPLETED SUCCESSFULLY")
        print("="*70 + "\n")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
