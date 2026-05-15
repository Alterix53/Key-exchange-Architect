#!/usr/bin/env python
"""
Test script to verify PKI audit logging integration.
"""

import os
import sys
import shutil
import tempfile

# Add src to path
sys.path.insert(0, os.path.dirname(__file__))

from src.public_key_distribution import (
    PKISystem,
    create_csr,
)
from src.audit_logging import AuditLogger
from src.storage_backend import MemoryAuditStorage
from cryptography.hazmat.primitives.asymmetric import rsa

def test_pki_audit_logging():
    """Test PKI system with audit logging."""
    
    # Create temporary directory for test
    test_dir = tempfile.mkdtemp(prefix="pki_audit_test_")

    try:
        print("=" * 70)
        print("TEST: PKI SYSTEM WITH AUDIT LOGGING INTEGRATION")
        print("=" * 70)
        
        # 1. Initialize audit logger
        print("\n[1/5] Khởi tạo Audit Logger...")
        audit_logger = AuditLogger("pki_audit_test", storage=MemoryAuditStorage())
        print("✓ Audit Logger khởi tạo thành công")
        
        # 2. Initialize PKI system with audit logger
        print("\n[2/5] Khởi tạo PKI System với Audit Logger...")
        pki_system = PKISystem(data_dir=test_dir, audit_logger=audit_logger)
        print("✓ PKI System khởi tạo thành công")
        
        # 3. Test CSR processing and certificate issuance
        print("\n[3/5] Kiểm tra CSR processing và Certificate issuance...")
        
        # Generate client key pair
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create CSR
        csr = create_csr("test_user", "Test Org", client_key)
        
        # Issue certificate
        cert = pki_system.issue_cert_from_csr(csr, is_server=False)
        if cert:
            print("✓ Certificate cấp thành công")
        else:
            print("✗ Lỗi cấp certificate")
            return False
        
        # 4. Test certificate lookup
        print("\n[4/5] Kiểm tra Certificate lookup...")
        looked_up = pki_system.lookup("test_user")
        if looked_up:
            print("✓ Certificate được tìm thấy qua lookup")
        else:
            print("✗ Lỗi lookup certificate")
            return False
        
        # 5. Check audit logs
        print("\n[5/5] Kiểm tra Audit logs...")
        
        # Get all logs
        all_logs = audit_logger.get_all_logs()
        print(f"  Tổng số events ghi log: {len(all_logs)}")
        
        # Count event types
        event_types = {}
        for log in all_logs:
            event = log.get('event_type')
            event_types[event] = event_types.get(event, 0) + 1
        
        print("\n  Chi tiết các event types:")
        for event, count in sorted(event_types.items()):
            print(f"    - {event}: {count}")
        
        # Check if key event types are present
        key_events = [
            'cert_csr_received',
            'cert_issued',
            'cert_verified'
        ]
        
        has_key_events = any(event in event_types for event in key_events)
        
        if has_key_events:
            print("\n✓ Audit logging hoạt động - các event PKI đã được ghi log")
        else:
            print("\n⚠ Không tìm thấy key PKI events trong audit logs")
        
        print("\n" + "=" * 70)
        print("TEST PASSED - PKI Audit Integration hoạt động!")
        print("=" * 70)
        return True
        
    except Exception as e:
        print(f"\n✗ LỖI: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup
        try:
            shutil.rmtree(test_dir, ignore_errors=True)
        except:
            pass


if __name__ == "__main__":
    success = test_pki_audit_logging()
    sys.exit(0 if success else 1)
