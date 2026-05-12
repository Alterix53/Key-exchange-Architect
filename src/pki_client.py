"""
PKI Client — Duck-typing thay thế PKISystem
=============================================
Class này có các method giống hệt PKISystem nhưng bên trong
gửi JSON request qua TCP socket tới PKI Microservice (pki_server.py).

Mục đích:
    - server.py chỉ cần đổi 1 dòng: `self.pki = PKIClient()` thay vì `PKISystem()`
    - Toàn bộ logic mã hóa / giải mã KHÔNG thay đổi (Duck-typing)
    - Nếu PKI Server không chạy → raise Exception timeout (demo lỗi kết nối)
"""

import json
import socket
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization


# Timeout mặc định khi kết nối tới PKI Server (giây)
PKI_CONNECT_TIMEOUT = 3


class PKIClient:
    """
    Drop-in replacement cho PKISystem.
    Giao tiếp với pki_server.py qua TCP socket trên localhost:5005.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 5005):
        self.host = host
        self.port = port
        print(f"[PKI Client] Khởi tạo — target PKI Server: {host}:{port}")

        # Thử kết nối lần đầu để kiểm tra PKI Server có chạy không
        try:
            self._call("get_crls", {})
            print(f"[PKI Client] ✓ Đã kết nối thành công tới PKI Server ({host}:{port})")
        except Exception as e:
            print(f"[PKI Client] ⚠ Không thể kết nối PKI Server lúc khởi tạo: {e}")
            print(f"[PKI Client] ⚠ Các thao tác PKI sẽ thất bại cho đến khi PKI Server được bật.")

    # ------------------------------------------------------------------
    #   Giao tiếp Socket cơ bản
    # ------------------------------------------------------------------

    def _call(self, action: str, data: dict) -> dict:
        """
        Gửi 1 JSON request tới PKI Server, nhận 1 JSON response.
        Mỗi lần gọi mở 1 kết nối TCP mới (short-lived connection).

        Raises:
            Exception nếu không kết nối được hoặc timeout.
        """
        payload = {"action": action, "data": data}
        payload_line = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PKI_CONNECT_TIMEOUT)
            sock.connect((self.host, self.port))
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            raise Exception(
                f"Không thể kết nối PKI Server ({self.host}:{self.port}) — Timeout {PKI_CONNECT_TIMEOUT}s. "
                f"Hãy đảm bảo pki_server.py đang chạy. Lỗi gốc: {e}"
            )

        try:
            sock.sendall(payload_line)

            # Đọc response (1 dòng JSON)
            reader = sock.makefile("r", encoding="utf-8")
            raw_line = reader.readline()
            if not raw_line:
                raise Exception("PKI Server đóng kết nối mà không trả response")

            response = json.loads(raw_line.strip())

            if response.get("status") == "error":
                raise Exception(f"PKI Server trả lỗi: {response.get('message', 'Unknown')}")

            return response
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    #   Duck-typing methods — API giống hệt PKISystem
    # ------------------------------------------------------------------

    def issue_cert_from_csr(
        self,
        csr: x509.CertificateSigningRequest,
        is_server: bool = False,
    ) -> Optional[x509.Certificate]:
        """
        Gửi CSR tới PKI Server để cấp certificate.
        Returns: x509.Certificate hoặc None.
        """
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        response = self._call("issue_cert", {
            "csr_pem": csr_pem,
            "is_server": is_server,
        })

        cert_pem = response.get("result")
        if cert_pem is None:
            return None

        return x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

    def lookup(self, subject_cn: str) -> Optional[x509.Certificate]:
        """
        Tra cứu certificate theo subject CN (user_id).
        Returns: x509.Certificate hoặc None.
        """
        response = self._call("lookup", {"user_id": subject_cn})

        cert_pem = response.get("result")
        if cert_pem is None:
            return None

        return x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

    def get_cert_chain_pems(self, end_entity_cert: x509.Certificate) -> List[str]:
        """
        Lấy certificate chain dạng PEM strings.
        Returns: [end_entity_pem, intermediate_pem, root_pem]
        """
        cert_pem = end_entity_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

        response = self._call("get_chain", {"cert_pem": cert_pem})
        return response.get("result", [])

    def get_all_crls_pem(self) -> List[str]:
        """
        Lấy tất cả CRL dạng PEM.
        Returns: [root_crl_pem, intermediate_crl_pem]
        """
        response = self._call("get_crls", {})
        return response.get("result", [])
