"""
Công cụ tự động cấu hình Database SQL Server.
Tự động kết nối, tạo CSDL IAM_KMS_DB và các bảng nếu chưa có.
Sử dụng Windows Authentication.
"""

import pyodbc
import os
import sys

DEFAULT_SERVER = "localhost" # Hoặc tên server/instance (Vd: localhost\SQLEXPRESS)

def get_connection_string(database="master", server=DEFAULT_SERVER):
    # Sử dụng ODBC Driver 17 for SQL Server hoặc ODBC Driver 18
    # Có thể điều chỉnh Driver thành tuỳ dòng máy, ví dụ 'SQL Server' là driver legacy có sẵn.
    # Thêm TrustServerCertificate=yes để skip SSL
    return (
        f"Driver={{ODBC Driver 17 for SQL Server}};"
        f"Server={server};"
        f"Database={database};"
        f"Trusted_Connection=yes;"
        f"TrustServerCertificate=yes;"
    )

def setup_database(server=DEFAULT_SERVER):
    print(f"🔄 Đang kết nối tới SQL Server: {server} ...")
    try:
        # Bắt đầu kết nối master để tạo DB
        conn_master = pyodbc.connect(get_connection_string("master", server), autocommit=True)
        cursor_master = conn_master.cursor()
        
        # Kiểm tra Database
        cursor_master.execute("SELECT name FROM sys.databases WHERE name = 'IAM_KMS_DB'")
        if not cursor_master.fetchone():
            print("📦 Đang khởi tạo CSDL IAM_KMS_DB...")
            cursor_master.execute("CREATE DATABASE IAM_KMS_DB")
        else:
            print("✅ CSDL IAM_KMS_DB đã tồn tại.")
        
        conn_master.close()
        
    except pyodbc.Error as e:
        print(f"❌ LỖI KẾT NỐI: Không thể kết nối hoặc khởi tạo CSDL. Hãy kiểm tra lại SQL Server đang chạy và bạn có cài ODBC Driver 17.\nChi tiết: {str(e)}")
        sys.exit(1)

    print("🔄 Đang triển khai bảng (Schema) vào IAM_KMS_DB...")
    try:
        # Đọc nội dung file init_db.sql
        sql_script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'init_db.sql')
        with open(sql_script_path, 'r', encoding='utf-8') as f:
            sql_script = f.read()

        # pyodbc không kham nổi lệnh 'GO' nên phải tách kịch bản ra
        commands = [cmd.strip() for cmd in sql_script.split('GO') if cmd.strip()]

        conn_db = pyodbc.connect(get_connection_string("IAM_KMS_DB", server), autocommit=True)
        cursor_db = conn_db.cursor()

        for command in commands:
            if command:
                try:
                    cursor_db.execute(command)
                except pyodbc.Error as inner_e:
                    # Bỏ qua những lỗi USE DATABASE không tương thích trong script chạy trực tiếp
                    if "USE [IAM_KMS_DB]" not in command and "CREATE DATABASE" not in command:
                        print(f"⚠️ Cảnh báo chạy lệnh: {inner_e}")

        conn_db.close()
        print("🎉 Khởi tạo các bảng SQL Server thành công!")

    except FileNotFoundError:
        print(f"❌ LỖI File init_db.sql không tìm thấy tại: {sql_script_path}")
        sys.exit(1)
    except pyodbc.Error as e:
        print(f"❌ LỖI KHI TẠO BẢNG: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        setup_database(sys.argv[1])
    else:
        setup_database()
