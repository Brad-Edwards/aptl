-- Create account status lookup table
CREATE TABLE account_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status TEXT NOT NULL UNIQUE,
    description TEXT
);

-- Create users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    account_value INTEGER DEFAULT 0,
    account_status_id INTEGER NOT NULL,
    email_last_changed DATETIME,
    FOREIGN KEY (account_status_id) REFERENCES account_status(id)
);

-- Create characters table
CREATE TABLE characters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    level INTEGER DEFAULT 1,
    class TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create items table
CREATE TABLE items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    rarity TEXT NOT NULL,
    gold_value INTEGER NOT NULL
);

-- Create character inventory junction table
CREATE TABLE character_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    character_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    quantity INTEGER DEFAULT 1,
    FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
    UNIQUE(character_id, item_id)
);

-- Create game locations table
CREATE TABLE game_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

-- Create sessions table
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    logout_time DATETIME,
    ip_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create login history table
CREATE TABLE login_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT 1,
    geo_location TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create player movement table
CREATE TABLE player_movement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    character_id INTEGER,
    session_id INTEGER NOT NULL,
    location_id INTEGER NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE SET NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (location_id) REFERENCES game_locations(id) ON DELETE CASCADE
);

-- Create transactions table
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_character_id INTEGER,
    to_character_id INTEGER,
    item_id INTEGER NOT NULL,
    quantity INTEGER DEFAULT 1,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    transaction_type TEXT NOT NULL,
    FOREIGN KEY (from_character_id) REFERENCES characters(id) ON DELETE SET NULL,
    FOREIGN KEY (to_character_id) REFERENCES characters(id) ON DELETE SET NULL,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE
);

-- Create marketplace activity table
CREATE TABLE marketplace_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    character_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    item_id INTEGER,
    transaction_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE SET NULL,
    FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE SET NULL
);

-- Create messages table
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create settings changes table
CREATE TABLE settings_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    change_type TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_characters_user_id ON characters(user_id);
CREATE INDEX idx_character_inventory_character_id ON character_inventory(character_id);
CREATE INDEX idx_character_inventory_item_id ON character_inventory(item_id);
CREATE INDEX idx_login_history_user_id ON login_history(user_id);
CREATE INDEX idx_login_history_ip_address ON login_history(ip_address);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_player_movement_user_id ON player_movement(user_id);
CREATE INDEX idx_player_movement_session_id ON player_movement(session_id);
CREATE INDEX idx_transactions_from_character ON transactions(from_character_id);
CREATE INDEX idx_transactions_to_character ON transactions(to_character_id);
CREATE INDEX idx_marketplace_activity_user_id ON marketplace_activity(user_id);
CREATE INDEX idx_marketplace_activity_character_id ON marketplace_activity(character_id);
CREATE INDEX idx_messages_from_user ON messages(from_user_id);
CREATE INDEX idx_messages_to_user ON messages(to_user_id);
CREATE INDEX idx_settings_changes_user_id ON settings_changes(user_id);

