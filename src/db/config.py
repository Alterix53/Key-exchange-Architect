import os
from dotenv import load_dotenv

load_dotenv()

class DBConfig:
    # Server and name
    SERVER = os.getenv("DB_SERVER", "localhost")
    DATABASE = os.getenv("DB_NAME", "IAM_KMS_DB")
    
    # Auth
    USE_WINDOWS_AUTH = os.getenv("DB_USE_WINDOWS_AUTH", "True").lower() in ("true", "1", "yes", "t")
    USERNAME = os.getenv("DB_USER", "")
    PASSWORD = os.getenv("DB_PASSWORD", "")
    
    # Fallback drivers
    DRIVERS = [
        "ODBC Driver 18 for SQL Server",
        "ODBC Driver 17 for SQL Server",
        "ODBC Driver 13 for SQL Server",
        "SQL Server"
    ]
