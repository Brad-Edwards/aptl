-- Gaming API Database Schema

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME,
  is_premium BOOLEAN DEFAULT 0,
  account_value INTEGER DEFAULT 0,
  email_verified BOOLEAN DEFAULT 0,
  email_change_date DATETIME,
  password_change_date DATETIME,
  recovery_attempts INTEGER DEFAULT 0
);

-- Characters and game data
CREATE TABLE IF NOT EXISTS characters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name VARCHAR(50) NOT NULL,
  level INTEGER DEFAULT 1,
  class VARCHAR(20) NOT NULL,
  gold INTEGER DEFAULT 100,
  experience INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_played DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS player_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  character_id INTEGER,
  session_id VARCHAR(255) NOT NULL,
  login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
  logout_time DATETIME,
  actions_count INTEGER DEFAULT 0,
  locations_visited INTEGER DEFAULT 0,
  ip_address VARCHAR(45),
  user_agent TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS login_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  username VARCHAR(50),
  ip_address VARCHAR(45) NOT NULL,
  user_agent TEXT,
  login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
  success BOOLEAN NOT NULL,
  failure_reason VARCHAR(100),
  geo_location VARCHAR(10),
  device_fingerprint VARCHAR(100),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Chat channels
CREATE TABLE IF NOT EXISTS chat_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(50) NOT NULL,
  type VARCHAR(20) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create default chat channels
INSERT OR IGNORE INTO chat_channels (id, name, type) VALUES 
  (1, 'Global', 'global'),
  (2, 'Trade', 'trade'),
  (3, 'Guild', 'guild');

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_characters_user_id ON characters(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON player_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON player_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id);
CREATE INDEX IF NOT EXISTS idx_login_history_ip ON login_history(ip_address);