const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

class DatabaseManager {
  constructor(logger) {
    this.logger = logger;
    this.dataDir = path.join(__dirname, 'data');
    this.dbPath = path.join(this.dataDir, 'gaming.db');
    
    // Ensure data directory exists
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, (err) => {
        if (err) {
          this.logger.error('Database connection failed', { error: err.message, dbPath: this.dbPath });
          reject(err);
        } else {
          this.logger.info('Connected to SQLite database', { dbPath: this.dbPath });
          resolve(this.db);
        }
      });
    });
  }

  async initializeSchema() {
    const schema = `
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

      CREATE TABLE IF NOT EXISTS inventory_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        character_id INTEGER NOT NULL,
        item_id VARCHAR(50) NOT NULL,
        item_name VARCHAR(100) NOT NULL,
        quantity INTEGER DEFAULT 1,
        item_value INTEGER DEFAULT 0,
        equipped BOOLEAN DEFAULT 0,
        acquired_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE
      );

      -- Trading and marketplace
      CREATE TABLE IF NOT EXISTS marketplace_listings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seller_id INTEGER NOT NULL,
        character_id INTEGER NOT NULL,
        item_id VARCHAR(50) NOT NULL,
        item_name VARCHAR(100) NOT NULL,
        price INTEGER NOT NULL,
        quantity INTEGER DEFAULT 1,
        listed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        sold_at DATETIME,
        buyer_id INTEGER,
        FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE,
        FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS trade_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user INTEGER NOT NULL,
        to_user INTEGER NOT NULL,
        from_character INTEGER,
        to_character INTEGER,
        item_id VARCHAR(50),
        item_name VARCHAR(100),
        gold_amount INTEGER DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        trade_type VARCHAR(20) NOT NULL, -- 'direct', 'marketplace', 'gift'
        status VARCHAR(20) DEFAULT 'completed', -- 'pending', 'completed', 'cancelled'
        FOREIGN KEY (from_user) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (to_user) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (from_character) REFERENCES characters(id) ON DELETE SET NULL,
        FOREIGN KEY (to_character) REFERENCES characters(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS player_friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL,
        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'accepted', 'blocked'
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, friend_id)
      );

      -- Chat and social
      CREATE TABLE IF NOT EXISTS chat_channels (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name VARCHAR(50) NOT NULL,
        type VARCHAR(20) NOT NULL, -- 'global', 'guild', 'trade', 'private'
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        channel_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        character_id INTEGER,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS private_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user INTEGER NOT NULL,
        to_user INTEGER NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        read_at DATETIME,
        FOREIGN KEY (from_user) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (to_user) REFERENCES users(id) ON DELETE CASCADE
      );

      -- Behavioral tracking
      CREATE TABLE IF NOT EXISTS user_preferences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        setting_key VARCHAR(100) NOT NULL,
        setting_value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, setting_key)
      );

      CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT,
        login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        success BOOLEAN NOT NULL,
        failure_reason VARCHAR(100),
        geo_location VARCHAR(10),
        device_fingerprint VARCHAR(100),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      -- Game world activities
      CREATE TABLE IF NOT EXISTS game_activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        character_id INTEGER NOT NULL,
        session_id VARCHAR(255) NOT NULL,
        activity_type VARCHAR(50) NOT NULL, -- 'combat', 'quest', 'trade', 'chat', 'move'
        activity_data TEXT, -- JSON data for specific activity
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE
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
      CREATE INDEX IF NOT EXISTS idx_inventory_character_id ON inventory_items(character_id);
      CREATE INDEX IF NOT EXISTS idx_marketplace_seller_id ON marketplace_listings(seller_id);
      CREATE INDEX IF NOT EXISTS idx_trades_from_user ON trade_history(from_user);
      CREATE INDEX IF NOT EXISTS idx_trades_to_user ON trade_history(to_user);
      CREATE INDEX IF NOT EXISTS idx_friends_user_id ON player_friends(user_id);
      CREATE INDEX IF NOT EXISTS idx_chat_messages_channel ON chat_messages(channel_id);
      CREATE INDEX IF NOT EXISTS idx_chat_messages_timestamp ON chat_messages(timestamp);
      CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id);
      CREATE INDEX IF NOT EXISTS idx_login_history_ip ON login_history(ip_address);
      CREATE INDEX IF NOT EXISTS idx_activities_user_character ON game_activities(user_id, character_id);
    `;

    return new Promise((resolve, reject) => {
      this.db.exec(schema, (err) => {
        if (err) {
          this.logger.error('Failed to initialize database schema', { error: err.message });
          reject(err);
        } else {
          this.logger.info('Database schema initialized successfully');
          resolve();
        }
      });
    });
  }

  getDatabase() {
    return this.db;
  }

  close() {
    return new Promise((resolve, reject) => {
      if (this.db) {
        this.db.close((err) => {
          if (err) {
            this.logger.error('Error closing database', { error: err.message });
            reject(err);
          } else {
            this.logger.info('Database connection closed');
            resolve();
          }
        });
      } else {
        resolve();
      }
    });
  }
}

module.exports = DatabaseManager;