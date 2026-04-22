import pyodbc
import time
from .config import DBConfig

def get_working_connection_string(database=None, max_retries=3, retry_delay=2):
    """
    Tự động thử các Driver và lấy connection string phù hợp.
    Sẽ thử kết nối đến master trước để xác định Driver hợp lệ.
    """
    db_name = database or DBConfig.DATABASE
    last_error = None

    for driver in DBConfig.DRIVERS:
        # Build test connection string for 'master'
        test_conn_parts = [
            f"Driver={{{driver}}}",
            f"Server={DBConfig.SERVER}",
            f"Database=master",
            "TrustServerCertificate=yes"
        ]
        if DBConfig.USE_WINDOWS_AUTH:
            test_conn_parts.append("Trusted_Connection=yes")
        else:
            test_conn_parts.append(f"UID={DBConfig.USERNAME}")
            test_conn_parts.append(f"PWD={DBConfig.PASSWORD}")
        
        test_conn_str = ";".join(test_conn_parts)

        driver_works = False
        for attempt in range(max_retries):
            try:
                # Test short connection
                conn = pyodbc.connect(test_conn_str, timeout=5)
                conn.close()
                driver_works = True
                break
            except pyodbc.Error as e:
                last_error = e
                # Check if it's "driver not found" error
                err_msg = str(e)
                if "IM020" in err_msg or "IM002" in err_msg or "Data source name not found" in err_msg:
                    # Skip retrying this driver
                    break
                print(f"⚠️ [Attempt {attempt+1}/{max_retries}] Driver '{driver}' could not connect to server: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    
        if driver_works:
            # Construct actual target string
            target_conn_parts = [
                f"Driver={{{driver}}}",
                f"Server={DBConfig.SERVER}",
                f"Database={db_name}",
                "TrustServerCertificate=yes"
            ]
            if DBConfig.USE_WINDOWS_AUTH:
                target_conn_parts.append("Trusted_Connection=yes")
            else:
                target_conn_parts.append(f"UID={DBConfig.USERNAME}")
                target_conn_parts.append(f"PWD={DBConfig.PASSWORD}")
                
            return ";".join(target_conn_parts)
            
    raise ConnectionError(f"❌ Could not connect to SQL Server. Last error: {last_error}")

def get_connection(database=None):
    """Lấy object connection (nếu cần thiết)"""
    conn_str = get_working_connection_string(database)
    return pyodbc.connect(conn_str, autocommit=True)
