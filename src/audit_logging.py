"""
Audit and Logging Module
Ghi lại tất cả hoạt động để kiểm tra an toàn
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from enum import Enum


class AuditEventType(Enum):
    """Các loại sự kiện kiểm tra"""
    # Người dùng
    USER_CREATED = "user_created"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_FAILED_LOGIN = "user_failed_login"
    USER_UPDATED = "user_updated"
    USER_DEACTIVATED = "user_deactivated"
    
    # Khóa
    KEY_GENERATED = "key_generated"
    KEY_ROTATED = "key_rotated"
    KEY_ACCESSED = "key_accessed"
    KEY_REVOKED = "key_revoked"
    KEY_DELETED = "key_deleted"
    
    # Quyền truy cập
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    PERMISSION_REVOKED = "permission_revoked"
    
    # Truyền dữ liệu
    MESSAGE_SENT = "message_sent"
    MESSAGE_RECEIVED = "message_received"
    MESSAGE_DECRYPTION_FAILED = "message_decryption_failed"
    
    # MFA
    MFA_ENABLED = "mfa_enabled"
    MFA_VERIFICATION_SUCCESS = "mfa_verification_success"
    MFA_VERIFICATION_FAILED = "mfa_verification_failed"
    
    # Certificate / PKI
    CERT_CSR_RECEIVED = "cert_csr_received"
    CERT_ISSUED = "cert_issued"
    CERT_REVOKED = "cert_revoked"
    CERT_VERIFIED = "cert_verified"
    CERT_VERIFICATION_FAILED = "cert_verification_failed"
    CERT_CHAIN_VALIDATED = "cert_chain_validated"
    CERT_CHAIN_VALIDATION_FAILED = "cert_chain_validation_failed"
    CRL_UPDATED = "crl_updated"
    CERT_RENEWED = "cert_renewed"
    
    # Hệ thống
    SYSTEM_ERROR = "system_error"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class AuditLog:
    """Bản ghi kiểm tra"""
    def __init__(self, event_type: AuditEventType, user_id: str,
                 resource: str, action: str, result: str = "success",
                 details: Optional[Dict] = None):
        self.log_id = self._generate_log_id()
        self.timestamp = datetime.now()
        self.event_type = event_type
        self.user_id = user_id
        self.resource = resource
        self.action = action
        self.result = result
        self.details = details or {}
        self.ip_address: Optional[str] = None
        self.user_agent: Optional[str] = None
    
    def _generate_log_id(self) -> str:
        """Sinh ID bản ghi"""
        import secrets
        return secrets.token_hex(16)
    
    def to_dict(self):
        return {
            'log_id': self.log_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'user_id': self.user_id,
            'resource': self.resource,
            'action': self.action,
            'result': self.result,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent
        }


class AuditLogger:
    """Ghi lại kiểm tra"""
    def __init__(self, log_path: str = "audit_logs"):
        self.log_path = log_path
        os.makedirs(log_path, exist_ok=True)
        self.current_logs: List[AuditLog] = []
        self._load_logs()
    
    def log_event(self, event_type: AuditEventType, user_id: str,
                  resource: str, action: str, result: str = "success",
                  details: Optional[Dict] = None, ip_address: Optional[str] = None,
                  user_agent: Optional[str] = None) -> AuditLog:
        """Ghi sự kiện"""
        log = AuditLog(event_type, user_id, resource, action, result, details)
        log.ip_address = ip_address
        log.user_agent = user_agent
        
        self.current_logs.append(log)
        self._save_log(log)
        
        return log
    
    def _save_log(self, log: AuditLog):
        """Lưu bản ghi"""
        # Lưu theo ngày
        date_str = log.timestamp.strftime("%Y-%m-%d")
        log_file = os.path.join(self.log_path, f"{date_str}_audit.jsonl")
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(log.to_dict()) + '\n')
    
    def _load_logs(self):
        """Tải bản ghi từ file"""
        for filename in os.listdir(self.log_path):
            if filename.endswith('_audit.jsonl'):
                log_file = os.path.join(self.log_path, filename)
                with open(log_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            log = AuditLog(
                                AuditEventType(data['event_type']),
                                data['user_id'],
                                data['resource'],
                                data['action'],
                                data['result'],
                                data.get('details')
                            )
                            log.log_id = data['log_id']
                            log.ip_address = data['ip_address']
                            log.user_agent = data['user_agent']
                            self.current_logs.append(log)
    
    def get_logs_by_user(self, user_id: str,
                        limit: int = 100) -> List[Dict]:
        """Lấy bản ghi theo người dùng"""
        logs = [log for log in self.current_logs if log.user_id == user_id]
        return [log.to_dict() for log in logs[-limit:]]
    
    def get_logs_by_event_type(self, event_type: AuditEventType,
                              limit: int = 100) -> List[Dict]:
        """Lấy bản ghi theo loại sự kiện"""
        logs = [log for log in self.current_logs if log.event_type == event_type]
        return [log.to_dict() for log in logs[-limit:]]
    
    def get_logs_by_resource(self, resource: str,
                            limit: int = 100) -> List[Dict]:
        """Lấy bản ghi theo tài nguyên"""
        logs = [log for log in self.current_logs if log.resource == resource]
        return [log.to_dict() for log in logs[-limit:]]
    
    def get_failed_access_attempts(self, limit: int = 50) -> List[Dict]:
        """Lấy những lần truy cập thất bại"""
        logs = [log for log in self.current_logs
                if log.result == "failed" and "permission" in log.event_type.value]
        return [log.to_dict() for log in logs[-limit:]]
    
    def detect_suspicious_activity(self, user_id: str,
                                   time_window_minutes: int = 5) -> List[Dict]:
        """Phát hiện hoạt động đáng nghi"""
        from datetime import timedelta
        
        threshold_time = datetime.now() - timedelta(minutes=time_window_minutes)
        
        # Tìm các nỗ lực đăng nhập thất bại
        failed_logins = [
            log for log in self.current_logs
            if log.user_id == user_id
            and log.event_type == AuditEventType.USER_FAILED_LOGIN
            and log.timestamp > threshold_time
        ]
        
        suspicious_logs = []
        
        # Nếu có nhiều lần đăng nhập thất bại
        if len(failed_logins) >= 3:
            suspicious_logs.extend([log.to_dict() for log in failed_logins])
        
        # Tìm các truy cập từ IP khác nhau trong thời gian ngắn
        recent_logins = [
            log for log in self.current_logs
            if log.user_id == user_id
            and log.event_type == AuditEventType.USER_LOGIN
            and log.timestamp > threshold_time
        ]
        
        ip_addresses = set(log.ip_address for log in recent_logins if log.ip_address)
        if len(ip_addresses) > 1:
            suspicious_logs.extend([log.to_dict() for log in recent_logins])
        
        return suspicious_logs
    
    def generate_access_report(self, user_id: str) -> Dict:
        """Tạo báo cáo truy cập"""
        user_logs = [log for log in self.current_logs if log.user_id == user_id]
        login_timestamps = [
            log.timestamp for log in user_logs
            if log.event_type == AuditEventType.USER_LOGIN
        ]
        last_login_ts = max(login_timestamps, default=None)
        
        total_logins = len([log for log in user_logs 
                           if log.event_type == AuditEventType.USER_LOGIN])
        failed_logins = len([log for log in user_logs
                            if log.event_type == AuditEventType.USER_FAILED_LOGIN])
        keys_accessed = len([log for log in user_logs
                            if log.event_type == AuditEventType.KEY_ACCESSED])
        permissions_denied = len([log for log in user_logs
                                 if log.event_type == AuditEventType.PERMISSION_DENIED])
        
        return {
            'user_id': user_id,
            'total_logins': total_logins,
            'failed_logins': failed_logins,
            'keys_accessed': keys_accessed,
            'permissions_denied': permissions_denied,
            'last_login': last_login_ts.isoformat() if last_login_ts else None,
            'report_generated_at': datetime.now().isoformat()
        }
    
    def export_logs(self, format: str = "json", output_file: Optional[str] = None) -> str:
        """Xuất bản ghi"""
        if output_file is None:
            output_file = os.path.join(self.log_path,
                                      f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        if format == "json":
            logs_data = [log.to_dict() for log in self.current_logs]
            with open(output_file, 'w') as f:
                json.dump(logs_data, f, indent=2, default=str)
        elif format == "csv":
            import csv
            output_file = output_file.replace('.json', '.csv')
            if self.current_logs:
                keys = self.current_logs[0].to_dict().keys()
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows([log.to_dict() for log in self.current_logs])
        
        return output_file
    
    def get_all_logs(self, limit: int = 1000) -> List[Dict]:
        """Lấy tất cả bản ghi"""
        return [log.to_dict() for log in self.current_logs[-limit:]]
