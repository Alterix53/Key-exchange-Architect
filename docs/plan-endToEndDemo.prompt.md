## Plan: Kịch bản và Tích hợp Kiến trúc Demo Toàn diện

Kế hoạch này sẽ chuyển đổi mô hình Message Relay hiện tại bằng cách tích hợp trực tiếp các module core (Identity, KMS, Audit) vào giao diện dòng lệnh. Server sẽ đóng vai trò như một API Backend, Client sẽ đóng vai trò như một App người dùng tương tác với hệ thống thay vì chỉ chat.

**Steps**
1. **Khởi tạo Dữ liệu & Môi trường**: Tạo script `init_demo_env.py` để làm sạch và seed dữ liệu mẫu vào `demo_identity/`, `demo_keys/`, `demo_audit/`. Sinh Master Key, thiết lập CA, khởi tạo 2 tài khoản mẫu (VD: `admin` với role ADMIN, và `alice` với role USER).
2. **Nâng cấp Backend (`server.py`)**: 
   - Khởi tạo `IdentityManagementSystem`, `KeyStore` và `AuditLogger` ngay khi server chạy.
   - Thêm các API/JSON Handler mới để xử lý: Xác thực đăng nhập (Login/MFA), Xin cấp chứng chỉ số, Sinh khóa (Key Generate), Phân quyền, và Truy vấn Log.
   - *Tính phụ thuộc*: Mọi logic xử lý endpoint mới đều phải kiểm tra Token/Session và gọi qua `AuditLogger`.
3. **Nâng cấp Client CLI (`client.py`)**: 
   - Chặn kết nối tự động ban đầu. Yêu cầu nhập username và password.
   - Thêm luồng chờ lệnh (Slash Commands) ở dạng console. Ví dụ:
     - `/login <user> <pass>`
     - `/cert` (Xem chi tiết chứng chỉ CA cấp phát).
     - `/key gen <name> <type>` và `/key get <name>`.
     - `/audit` (Lệnh truy vấn log).
4. **Soạn thảo Kịch bản Demo Thực tế (`README_DEMO.md`)**: Mô phỏng kịch bản step-by-step để bạn thực hiện khi chấm điểm, minh họa thành công các khía cạnh bảo mật như MFA (nếu bật), RBAC (truy cập trái phép), Rotation, và Audit.

**Relevant files**
- `server.py` — Sửa đổi vòng lặp TCP hiện tại, thêm bộ định tuyến JSON cho các lệnh nghiệp vụ quản lý (gọi tới `src/`).
- `client.py` — Thêm cơ chế xác thực đầu vào, quản lý Session/Token tạm thời, và bộ phân tích cú pháp lệnh (command parser) từ bàn phím.
- `init_demo_env.py` (Mới) — Script chạy lần đầu để setup hệ thống (User, Keys, CA).
- `README_DEMO.md` (Mới) — File markdown liệt kê từng lệnh gõ khi bắt đầu chạy demo.

**Verification**
1. Chạy `init_demo_env.py` tạo cơ sở dữ liệu file thành công. Khởi chạy `server.py`.
2. Đầu cuối 1 mở `client.py`: Đăng nhập bằng `alice`. Thử gọi `/key gen` và `/key list` thành công.
3. Người dùng `alice` thử gọi truy vấn `/audit` (Phân quyền: Hệ thống phải từ chối - Access Denied).
4. Đầu cuối 2 mở `client.py`: Đăng nhập bằng quyền quản trị `admin`. Tiến hành chat mã hóa AES-GCM với Alice (mô phỏng E2E).
5. Người dùng `admin` gõ `/audit` và trích xuất thành công nội dung log từ file `.jsonl` trong thư mục `demo_audit/`, trên log phản ánh rõ sự kiện Alice vừa bị từ chối truy cập 1 phút trước.

**Decisions**
- Vẫn giữ nguyên kiến trúc Terminal-UI (CLI), không cần thiết kế giao diện Web cồng kềnh cho buổi Demo.
- Tận dụng 100% các file có sẵn trong `src/` (Identity, Key, Audit, PKI).
- Lưu trữ vẫn sử dụng file system (`demo_*`) để chứng minh dễ dàng (có thể mở file jsonl hoặc meta cho người chấm xem trực tiếp).