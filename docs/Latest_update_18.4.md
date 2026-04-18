# 🚀 Hoàn thành nâng cấp IAM End-to-End Demo

Hệ thống đã được nâng cấp thành công từ một script chat relay đơn giản thành một kiến trúc **API Backend + Interactive CLI Client** hoàn chỉnh, tích hợp 100% các tính năng bảo mật (Identity, Key Management, PKI, Audit, Secure Transmission).

## 1. Các thành phần đã triển khai
1. **`init_demo_env.py`**:
   - Dọn dẹp (`demo_*` và `data/`)
   - Seed tự động: cặp khóa Root CA, Master Key, admin, alice, khóa AES mẫu.
2. **`server.py` (API Backend)**:
   - Kiến trúc Route - Middleware JSON over TCP.
   - Quản lý Session ID thay vì dựa trên Network socket blind-trust.
   - Role-Based Access Control (RBAC) trên từng route (`keys:read`, `audit:read`, ...).
3. **`client.py` (Interactive Interface)**:
   - Không còn prompt "hello" thô kệch, hiển thị **Login/Register Menu**.
   - Hỗ trợ màu ANSI (`OKGREEN`, `FAIL`, `WARNING`) cho giao diện terminal cực đẹp.
   - Menu số động: Quản trị/User nhìn thấy Data riêng biệt.
4. **`README_DEMO.md`**:
   - Hướng dẫn step-by-step cho quá trình mở nhiều terminal tương tác chéo (Admin <-> Alice).

## 2. Kiến trúc Refactoring Lưu trữ (Repository Pattern)
Cùng với đó, tất cả logic lưu trữ đã được chuyển sang `src/storage_backend.py`:
- Cung cấp `UserStorage`, `KeyStorage`, `AuditStorage` Interface.
- Hệ thống vẫn đang chạy bằng Data files (`JsonFile*Storage`) nhưng **đã sẵn sàng Code cho SQL Server**. Khi cần chuyển sang SQL Server Management Studio, bạn chỉ cần sử dụng các class STUB `SqlServerUserStorage` đã có sẵn Schema.

## 3. Cách chạy Demo ngay lập tức:

> [!TIP]
> **Bước 1**: Mở Terminal 1 và chạy lệnh thiết lập dữ liệu mẫu:
> ```bash
> python init_demo_env.py
> ```
> 
> **Bước 2**: Khởi động máy chủ:
> ```bash
> python server.py
> ```
> 
> **Bước 3**: Mở Terminal 2 và trải nghiệm:
> ```bash
> python client.py
> ```
> *(Sử dụng tài khoản `admin`/`Admin@123` hoặc `alice`/`Alice@123`)*

## 4. Kiểm chứng hệ thống
Bạn có thể tự tay Sign up một user mới tên `bob` ngay trên `client.py` và sau đó bảo `alice` "chat" trực tiếp với `bob`.
Toàn bộ session keys RSA và dữ liệu message AES-GCM đều sẽ được hiển thị ngay trên log của máy client. Đồng thời, Admin có thể kiểm tra thao tác của cả Bob và Alice trên Audit Log Menu.
