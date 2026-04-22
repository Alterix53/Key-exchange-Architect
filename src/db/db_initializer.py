import pyodbc
import os
import sys
from .db_connection import get_working_connection_string
from .config import DBConfig

def setup_database():
    server = DBConfig.SERVER
    db_name = DBConfig.DATABASE
    print(f"🔄 Đang tìm Driver và kết nối tới SQL Server: {server} ...")
    try:
        conn_str_master = get_working_connection_string("master")
        conn_master = pyodbc.connect(conn_str_master, autocommit=True)
        cursor_master = conn_master.cursor()
        
        # Check Database
        cursor_master.execute(f"SELECT name FROM sys.databases WHERE name = '{db_name}'")
        if not cursor_master.fetchone():
            print(f"📦 Đang khởi tạo CSDL {db_name}...")
            cursor_master.execute(f"CREATE DATABASE {db_name}")
        else:
            print(f"✅ CSDL {db_name} đã tồn tại.")
            
        conn_master.close()
        
    except Exception as e:
        print(f"❌ LỖI KẾT NỐI KHỞI TẠO DB: {str(e)}")
        sys.exit(1)
        
    print(f"🔄 Đang triển khai bảng (Schema) vào {db_name}...")
    try:
        # File init_db.sql in the root directory
        sql_script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'init_db.sql')
        with open(sql_script_path, 'r', encoding='utf-8') as f:
            sql_script = f.read()

        commands = [cmd.strip() for cmd in sql_script.split('GO') if cmd.strip()]

        conn_str_db = get_working_connection_string(db_name)
        conn_db = pyodbc.connect(conn_str_db, autocommit=True)
        cursor_db = conn_db.cursor()

        for command in commands:
            if command:
                try:
                    cursor_db.execute(command)
                except pyodbc.Error as inner_e:
                    # Ignore USE database errors as we connect directly to the target DB
                    if f"USE [{db_name}]" not in command and "CREATE DATABASE" not in command:
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
    setup_database()
