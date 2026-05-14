"""
PKI Microservice Server
========================
Chạy như một tiến trình độc lập, lắng nghe trên TCP port 5005.
Bọc PKISystem bên trong và xử lý các request qua JSON protocol.

Giao thức:
    Client gửi 1 dòng JSON kết thúc bằng '\\n':
        { "action": "...", "data": {...} }

    Server trả về 1 dòng JSON kết thúc bằng '\\n':
        { "status": "ok"|"error", "result": ... }

Actions:
    - issue_cert:  { "csr_pem": "...", "is_server": false }  → cert PEM
    - lookup:      { "user_id": "..." }                      → cert PEM | null
    - get_chain:   { "cert_pem": "..." }                     → [pem, ...]
    - get_crls:    {}                                        → [pem, ...]
"""

import json
import os
import socket
import sys
import threading
import argparse
from datetime import datetime

# Ensure startup banners and status messages don't crash on non-UTF-8 consoles.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Đảm bảo import được module src
sys.path.insert(0, os.path.dirname(__file__))

from src.public_key_distribution import (
    PKISystem,
    load_csr_from_pem,
    load_cert_from_pem,
    serialize_cert_to_pem,
)
from src.audit_logging import AuditLogger, AuditEventType


class PKIServer:
    """
    TCP Server bọc PKISystem, xử lý JSON-RPC đơn giản qua socket.
    Mỗi client kết nối → nhận 1 request → trả 1 response → đóng kết nối.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 5005, data_dir: str = "pki", audit_logger: AuditLogger = None):
        self.host = host
        self.port = port
        self.audit_logger = audit_logger

        # Khởi tạo hệ thống PKI thực sự bên trong tiến trình này
        print("=" * 60)
        print("  PKI MICROSERVICE — Khởi tạo")
        print("=" * 60)
        self.pki = PKISystem(data_dir=data_dir, audit_logger=audit_logger)
        print(f"[PKI Server] PKI System sẵn sàng (data_dir={data_dir})")
        if audit_logger:
            print(f"[PKI Server] Audit logging: ENABLED")

    # ------------------------------------------------------------------
    #   Xử lý từng action
    # ------------------------------------------------------------------

    def _handle_issue_cert(self, data: dict) -> dict:
        """Action: issue_cert — Nhận CSR (PEM), trả Certificate (PEM)."""
        csr_pem = data.get("csr_pem")
        is_server = data.get("is_server", False)

        if not csr_pem:
            return {"status": "error", "message": "Thiếu csr_pem"}

        try:
            csr = load_csr_from_pem(csr_pem)
            cert = self.pki.issue_cert_from_csr(csr, is_server=is_server)
            if cert is None:
                if self.audit_logger:
                    try:
                        self.audit_logger.log_event(
                            AuditEventType.CERT_VERIFICATION_FAILED,
                            "system",
                            "pki",
                            "issue_cert",
                            "failed",
                            details={"reason": "PKI rejected CSR"}
                        )
                    except Exception as e:
                        print(f"[PKI Server] ⚠ Lỗi ghi audit log: {e}")
                return {"status": "error", "message": "PKI từ chối cấp chứng chỉ từ CSR"}
            cert_pem = serialize_cert_to_pem(cert)
            print(f"[PKI Server] ✓ Đã cấp certificate (is_server={is_server})")
            return {"status": "ok", "result": cert_pem}
        except Exception as e:
            print(f"[PKI Server] ✗ Lỗi issue_cert: {e}")
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        AuditEventType.SYSTEM_ERROR,
                        "system",
                        "pki",
                        "issue_cert",
                        "failed",
                        details={"error": str(e)}
                    )
                except Exception as log_err:
                    print(f"[PKI Server] ⚠ Lỗi ghi audit log: {log_err}")
            return {"status": "error", "message": str(e)}

    def _handle_lookup(self, data: dict) -> dict:
        """Action: lookup — Tra cứu certificate theo user_id (subject CN)."""
        user_id = data.get("user_id")
        if not user_id:
            return {"status": "error", "message": "Thiếu user_id"}

        cert = self.pki.lookup(user_id)
        if cert is None:
            print(f"[PKI Server] ℹ lookup('{user_id}') → không tìm thấy")
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        AuditEventType.CERT_VERIFIED,
                        user_id,
                        "pki",
                        "lookup",
                        "failed",
                        details={"reason": "Certificate not found"}
                    )
                except Exception as e:
                    print(f"[PKI Server] ⚠ Lỗi ghi audit log: {e}")
            return {"status": "ok", "result": None}

        cert_pem = serialize_cert_to_pem(cert)
        print(f"[PKI Server] ✓ lookup('{user_id}') → tìm thấy certificate")
        if self.audit_logger:
            try:
                self.audit_logger.log_event(
                    AuditEventType.CERT_VERIFIED,
                    user_id,
                    "pki",
                    "lookup",
                    "success",
                    details={"subject_cn": user_id}
                )
            except Exception as e:
                print(f"[PKI Server] ⚠ Lỗi ghi audit log: {e}")
        return {"status": "ok", "result": cert_pem}

    def _handle_get_chain(self, data: dict) -> dict:
        """Action: get_chain — Trả về certificate chain dạng mảng PEM."""
        cert_pem = data.get("cert_pem")
        if not cert_pem:
            return {"status": "error", "message": "Thiếu cert_pem"}

        try:
            cert = load_cert_from_pem(cert_pem)
            chain = self.pki.get_cert_chain_pems(cert)
            print(f"[PKI Server] ✓ get_chain → {len(chain)} certificates")
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        AuditEventType.CERT_CHAIN_VALIDATED,
                        "system",
                        "pki",
                        "get_chain",
                        "success",
                        details={"chain_length": len(chain)}
                    )
                except Exception as e:
                    print(f"[PKI Server] ⚠ Lỗi ghi audit log: {e}")
            return {"status": "ok", "result": chain}
        except Exception as e:
            print(f"[PKI Server] ✗ Lỗi get_chain: {e}")
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        AuditEventType.SYSTEM_ERROR,
                        "system",
                        "pki",
                        "get_chain",
                        "failed",
                        details={"error": str(e)}
                    )
                except Exception as log_err:
                    print(f"[PKI Server] ⚠ Lỗi ghi audit log: {log_err}")
            return {"status": "error", "message": str(e)}

    def _handle_get_crls(self, data: dict) -> dict:
        """Action: get_crls — Trả về tất cả CRL dạng mảng PEM."""
        try:
            crls = self.pki.get_all_crls_pem()
            print(f"[PKI Server] ✓ get_crls → {len(crls)} CRLs")
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        AuditEventType.CRL_UPDATED,
                        "system",
                        "pki",
                        "get_crls",
                        "success",
                        details={"crl_count": len(crls)}
                    )
                except Exception as e:
                    print(f"[PKI Server] ⚠ Lỗi ghi audit log: {e}")
            return {"status": "ok", "result": crls}
        except Exception as e:
            print(f"[PKI Server] ✗ Lỗi get_crls: {e}")
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        AuditEventType.SYSTEM_ERROR,
                        "system",
                        "pki",
                        "get_crls",
                        "failed",
                        details={"error": str(e)}
                    )
                except Exception as log_err:
                    print(f"[PKI Server] ⚠ Lỗi ghi audit log: {log_err}")
            return {"status": "error", "message": str(e)}

    def _handle_revoke_cert(self, data: dict) -> dict:
        """Action: revoke_cert — Thu hồi certificate theo subject CN."""
        subject_cn = data.get("subject_cn")
        if not subject_cn:
            return {"status": "error", "message": "Thiếu subject_cn"}

        try:
            success = self.pki.revoke(subject_cn)
            if not success:
                print(f"[PKI Server] ℹ revoke('{subject_cn}') → không tìm thấy certificate")
                if self.audit_logger:
                    try:
                        self.audit_logger.log_event(
                            AuditEventType.CERT_REVOKED,
                            subject_cn,
                            "pki",
                            "revoke_cert",
                            "failed",
                            details={"reason": "Certificate not found"}
                        )
                    except Exception as e:
                        print(f"[PKI Server] ⚠ Lỗi ghi audit log: {e}")
                return {"status": "error", "message": f"Certificate cho '{subject_cn}' không tồn tại"}

            print(f"[PKI Server] ✓ revoke('{subject_cn}') → thành công")
            crls = self.pki.get_all_crls_pem()
            
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        AuditEventType.CERT_REVOKED,
                        subject_cn,
                        "pki",
                        "revoke_cert",
                        "success",
                        details={"subject_cn": subject_cn, "crl_count": len(crls)}
                    )
                except Exception as e:
                    print(f"[PKI Server] ⚠ Lỗi ghi audit log: {e}")
            
            return {"status": "ok", "result": {"message": f"Certificate '{subject_cn}' đã được thu hồi", "crls": crls}}
        except Exception as e:
            print(f"[PKI Server] ✗ Lỗi revoke_cert: {e}")
            if self.audit_logger:
                try:
                    self.audit_logger.log_event(
                        AuditEventType.SYSTEM_ERROR,
                        subject_cn or "unknown",
                        "pki",
                        "revoke_cert",
                        "failed",
                        details={"error": str(e)}
                    )
                except Exception as log_err:
                    print(f"[PKI Server] ⚠ Lỗi ghi audit log: {log_err}")
            return {"status": "error", "message": str(e)}

    # ------------------------------------------------------------------
    #   Router — Phân phối action
    # ------------------------------------------------------------------

    _ACTION_MAP = {
        "issue_cert": "_handle_issue_cert",
        "lookup": "_handle_lookup",
        "get_chain": "_handle_get_chain",
        "get_crls": "_handle_get_crls",
        "revoke_cert": "_handle_revoke_cert",
    }

    def _dispatch(self, payload: dict) -> dict:
        """Phân phối request tới handler tương ứng."""
        action = payload.get("action")
        data = payload.get("data", {})

        handler_name = self._ACTION_MAP.get(action)
        if not handler_name:
            return {"status": "error", "message": f"Unknown action: {action}"}

        handler = getattr(self, handler_name)
        return handler(data)

    # ------------------------------------------------------------------
    #   Socket Server Loop
    # ------------------------------------------------------------------

    def _handle_connection(self, conn: socket.socket, addr: tuple):
        """Xử lý 1 kết nối từ PKIClient."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n[PKI Server {timestamp}] ← Kết nối mới từ {addr[0]}:{addr[1]}")

        try:
            reader = conn.makefile("r", encoding="utf-8")
            raw_line = reader.readline()
            if not raw_line:
                return

            payload = json.loads(raw_line.strip())
            action = payload.get("action", "?")
            print(f"[PKI Server {timestamp}] ← Action: {action} | Data keys: {list(payload.get('data', {}).keys())}")

            response = self._dispatch(payload)

            response_line = json.dumps(response, ensure_ascii=False) + "\n"
            conn.sendall(response_line.encode("utf-8"))

            status_icon = "✓" if response.get("status") == "ok" else "✗"
            print(f"[PKI Server {timestamp}] → Trả về: {status_icon} status={response.get('status')}")

        except json.JSONDecodeError as e:
            err = {"status": "error", "message": f"JSON không hợp lệ: {e}"}
            conn.sendall((json.dumps(err) + "\n").encode("utf-8"))
            print(f"[PKI Server] ✗ JSON decode error: {e}")
        except Exception as e:
            print(f"[PKI Server] ✗ Lỗi xử lý kết nối {addr}: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def start(self):
        """Bắt đầu lắng nghe kết nối TCP."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(10)

        print()
        print("=" * 60)
        print(f"  PKI MICROSERVICE đang lắng nghe tại {self.host}:{self.port}")
        print("  Nhấn Ctrl+C để dừng.")
        print("=" * 60)
        print()

        while True:
            conn, addr = server_sock.accept()
            thread = threading.Thread(
                target=self._handle_connection,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()


# ==================================================================
#  Entry Point
# ==================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PKI Microservice Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5005, help="Port to bind (default: 5005)")
    parser.add_argument("--data-dir", default="pki", help="PKI data directory (default: pki)")
    parser.add_argument("--disable-audit", action="store_true", help="Disable audit logging (default: enabled)")
    args = parser.parse_args()

    audit_logger = None
    if not args.disable_audit:
        try:
            audit_logger = AuditLogger()
            print("[PKI Server] ✓ Audit logging: ENABLED (tự động)")
        except Exception as e:
            print(f"[PKI Server] ⚠ Không thể khởi tạo audit logger: {e}")
            print("[PKI Server] Tiếp tục mà không có audit logging.")
    else:
        print("[PKI Server] Audit logging: DISABLED")

    server = PKIServer(host=args.host, port=args.port, data_dir=args.data_dir, audit_logger=audit_logger)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[PKI Server] Đang dừng PKI Microservice...")
        sys.exit(0)
