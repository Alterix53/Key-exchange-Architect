-- Script khởi tạo cấu trúc CSDL IAM Key Management cho SQL Server
-- Script có thể chạy nhiều lần an toàn (Idempotent)

IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'IAM_KMS_DB')
BEGIN
    CREATE DATABASE IAM_KMS_DB;
END
GO

USE IAM_KMS_DB;
GO

----------------------------------------------------------------------
-- 1. Identity Management (Bảng Người dùng)
----------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'Users')
BEGIN
    CREATE TABLE Users (
        user_id        VARCHAR(50)    NOT NULL PRIMARY KEY,
        username       NVARCHAR(100)  NOT NULL UNIQUE,
        email          NVARCHAR(200)  NOT NULL,
        password_hash  VARCHAR(256)   NOT NULL,
        roles          NVARCHAR(MAX)  NOT NULL DEFAULT '["user"]',
        mfa_secret     VARCHAR(100)   NULL,
        mfa_enabled    BIT            NOT NULL DEFAULT 0,
        status         VARCHAR(20)    NOT NULL DEFAULT 'active',
        created_at     DATETIME2      NOT NULL DEFAULT GETDATE(),
        last_login     DATETIME2      NULL
    );

    CREATE INDEX IX_Users_Username ON Users(username);
END
GO

----------------------------------------------------------------------
-- 2. Key Management System
----------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'KeysMetadata')
BEGIN
    CREATE TABLE KeysMetadata (
        key_id         VARCHAR(100)   NOT NULL PRIMARY KEY,
        owner_id       VARCHAR(50)    NOT NULL,
        algorithm      VARCHAR(50)    NOT NULL,
        key_size       INT            NOT NULL,
        purpose        NVARCHAR(200)  NULL,
        is_active      BIT            NOT NULL DEFAULT 1,
        version        INT            NOT NULL DEFAULT 1,
        creation_date  DATETIME2      NOT NULL DEFAULT GETDATE(),
        expires_at     DATETIME2      NULL,
        last_rotated   DATETIME2      NULL,
        
        CONSTRAINT FK_KeysMetadata_Users FOREIGN KEY (owner_id) 
            REFERENCES Users(user_id) ON DELETE CASCADE
    );

    CREATE INDEX IX_KeysMetadata_Owner ON KeysMetadata(owner_id);
END
GO

IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'KeysData')
BEGIN
    CREATE TABLE KeysData (
        key_id         VARCHAR(100)   NOT NULL,
        key_type       VARCHAR(20)    NOT NULL,  -- 'symmetric', 'private', 'public', 'master'
        key_payload    VARBINARY(MAX) NOT NULL,  
        
        CONSTRAINT PK_KeysData PRIMARY KEY (key_id, key_type)
    );
END
GO

----------------------------------------------------------------------
-- 3. Ghi lại nhật ký kiểm toán (Audit Logs)
----------------------------------------------------------------------
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'AuditLogs')
BEGIN
    CREATE TABLE AuditLogs (
        event_id       VARCHAR(50)    NOT NULL PRIMARY KEY,
        timestamp      DATETIME2      NOT NULL DEFAULT GETDATE(),
        event_type     VARCHAR(50)    NOT NULL,
        user_id        VARCHAR(50)    NOT NULL,
        resource       VARCHAR(100)   NOT NULL,
        action         VARCHAR(100)   NOT NULL,
        result         VARCHAR(20)    NOT NULL DEFAULT 'success',
        details_json   NVARCHAR(MAX)  NULL,     
        ip_address     VARCHAR(45)    NULL,
        user_agent     NVARCHAR(500)  NULL
    );

    CREATE INDEX IX_AuditLogs_UserId ON AuditLogs(user_id);
    CREATE INDEX IX_AuditLogs_EventType ON AuditLogs(event_type);
    CREATE NONCLUSTERED INDEX IX_AuditLogs_Timestamp ON AuditLogs(timestamp DESC);
END
GO
