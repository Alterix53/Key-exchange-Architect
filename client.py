"""
Terminal client for encrypted relay chat.
"""

import argparse
import base64
import json
import socket
import threading
from datetime import datetime
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.secure_transmission import SecureTransmissionChannel


def send_json(sock: socket.socket, payload: Dict[str, Any]) -> None:
    data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    sock.sendall(data)


class RelayClient:
    def __init__(self, client_id: str, host: str, port: int):
        self.client_id = client_id
        self.host = host
        self.port = port
        self.channel = SecureTransmissionChannel()

        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        self.sock: Optional[socket.socket] = None
        self.reader = None
        self.running = True
        self.session_key: Optional[bytes] = None
        self._send_lock = threading.Lock()

    def _public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def _recv_json(self) -> Optional[Dict[str, Any]]:
        if isinstance(self.reader, type(None)):
            return None
        line = self.reader.readline()
        if not line:
            return None
        return json.loads(line)

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.reader = self.sock.makefile("r", encoding="utf-8")

        send_json(
            self.sock,
            {
                "type": "hello",
                "client_id": self.client_id,
                "public_key": self._public_key_pem(),
            },
        )

        while self.session_key is None:
            packet = self._recv_json()
            if packet is None:
                raise ConnectionError("Server closed connection during handshake")

            packet_type = packet.get("type")
            if packet_type == "error":
                raise RuntimeError(packet.get("message", "Server error"))

            if packet_type == "cert":
                cert = packet.get("certificate", {})
                print(f"[STATUS] Đã nhận Certificate từ Server: {json.dumps(cert, ensure_ascii=False)}")
                continue

            if packet_type == "session_key":
                encrypted_key = packet.get("encrypted_key", "")
                key_b64 = self.channel.decrypt_rsa_oaep(encrypted_key, self.private_key)
                self.session_key = base64.b64decode(key_b64)
                print("[STATUS] Session key đã được thiết lập thành công.")

    def _receive_loop(self) -> None:
        while self.running:
            try:
                packet = self._recv_json()
                if packet is None:
                    print("[STATUS] Kết nối bị đóng bởi Server.")
                    self.running = False
                    break

                if packet.get("type") != "relay":
                    continue

                encrypted_view = {
                    "nonce": packet.get("nonce", ""),
                    "ciphertext": packet.get("ciphertext", ""),
                    "tag": packet.get("tag", ""),
                }
                print(f"[RECEIVED] Tin nhắn mã hóa nhận được: {json.dumps(encrypted_view, ensure_ascii=False)}")

                session_key = self.session_key
                if session_key is None:
                    print("[STATUS] Chưa có session key để giải mã.")
                    self.running = False
                    break

                plaintext = self.channel.decrypt_aes_256_gcm(
                    packet.get("nonce", ""),
                    packet.get("ciphertext", ""),
                    packet.get("tag", ""),
                    session_key,
                    packet.get("associated_data", ""),
                )
                print(f"[DECRYPT] Tin nhắn sau khi giải mã: {plaintext}")
            except Exception as exc:
                print(f"[STATUS] Lỗi nhận/giải mã: {exc}")
                self.running = False
                break

    def _send_chat(self, plaintext: str) -> None:
        if not self.session_key:
            raise RuntimeError("Session key chưa sẵn sàng")

        associated_data = f"{self.client_id}:relay"
        nonce, ciphertext, tag = self.channel.encrypt_aes_256_gcm(
            plaintext,
            self.session_key,
            associated_data,
        )

        print(f"[INPUT] Tin nhắn ban đầu: {plaintext}")
        print(f"[ENCRYPT] Tin nhắn sau khi mã hóa: {json.dumps({'nonce': nonce, 'ciphertext': ciphertext, 'tag': tag}, ensure_ascii=False)}")

        payload = {
            "type": "chat",
            "sender_id": self.client_id,
            "algorithm": "AES-256-GCM",
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag,
            "associated_data": associated_data,
            "timestamp": datetime.now().isoformat(),
        }
        if self.sock is None:
            raise RuntimeError("Socket chưa được khởi tạo")
        with self._send_lock:
            send_json(self.sock, payload)

    def run(self) -> None:
        self.connect()

        receiver = threading.Thread(target=self._receive_loop, daemon=True)
        receiver.start()

        while self.running:
            try:
                message = input("")
            except EOFError:
                break
            except KeyboardInterrupt:
                break

            if not message.strip():
                continue
            if message.strip().lower() in {"quit", "exit"}:
                self.running = False
                break

            self._send_chat(message)

        self.running = False
        try:
            if self.sock is not None:
                self.sock.close()
        except Exception:
            pass
        try:
            if self.reader is not None:
                self.reader.close()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypted terminal client")
    parser.add_argument("--name", required=True, help="Client ID")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=5000, help="Server port")
    args = parser.parse_args()

    client = RelayClient(client_id=args.name, host=args.host, port=args.port)
    client.run()


if __name__ == "__main__":
    main()
