-- TechVault Solutions Database Schema
-- Intentionally includes some security weaknesses for testing

-- Users table (password hashes stored, some with weak algorithms)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    department VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    api_key VARCHAR(64)
);

-- Customer data
CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    company_name VARCHAR(255) NOT NULL,
    contact_name VARCHAR(255),
    contact_email VARCHAR(255),
    phone VARCHAR(50),
    plan_tier VARCHAR(50) DEFAULT 'basic',
    monthly_revenue DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Files metadata (for file upload feature)
CREATE TABLE IF NOT EXISTS files (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    filename VARCHAR(255) NOT NULL,
    original_name VARCHAR(255),
    file_size BIGINT,
    mime_type VARCHAR(100),
    upload_path VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    key_hash VARCHAR(64) NOT NULL,
    key_prefix VARCHAR(8) NOT NULL,
    description VARCHAR(255),
    permissions TEXT DEFAULT 'read',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP
);

-- Audit log (intentionally incomplete - vulnerability)
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action VARCHAR(100),
    resource VARCHAR(255),
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Backup schedule (contains sensitive info - vulnerability)
CREATE TABLE IF NOT EXISTS backup_config (
    id SERIAL PRIMARY KEY,
    backup_type VARCHAR(50),
    s3_bucket VARCHAR(255),
    aws_access_key VARCHAR(100),
    aws_secret_key VARCHAR(100),
    schedule VARCHAR(50),
    last_run TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

-- Session tokens
CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- Comments (for XSS testing)
CREATE TABLE IF NOT EXISTS comments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    content TEXT NOT NULL,
    page VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
