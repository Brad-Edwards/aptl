-- Complete Gaming Schema for Gaming API CTF Data Generation
-- Combines base schema with enhanced tables for realistic player activity tracking

-- Base tables from original schema
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
  total_playtime_hours INTEGER DEFAULT 0,
  last_ip_address VARCHAR(45),
  preferred_language VARCHAR(10) DEFAULT 'en-US',
  timezone VARCHAR(50) DEFAULT 'UTC'
);

CREATE TABLE IF NOT EXISTS characters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name VARCHAR(50) NOT NULL,
  level INTEGER DEFAULT 1,
  class VARCHAR(20) NOT NULL,
  gold INTEGER DEFAULT 0,
  experience INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_played DATETIME DEFAULT CURRENT_TIMESTAMP,
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
  username VARCHAR(50) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  user_agent TEXT,
  login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
  success BOOLEAN DEFAULT 1,
  failure_reason VARCHAR(50),
  geo_location VARCHAR(100),
  device_fingerprint VARCHAR(255),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS chat_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(50) NOT NULL UNIQUE,
  description TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Enhanced tables for realistic activity tracking
CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(100) NOT NULL,
  gold_value INTEGER NOT NULL,
  category_id INTEGER,
  rarity VARCHAR(20) DEFAULT 'common',
  item_type VARCHAR(50),
  level_requirement INTEGER DEFAULT 1,
  FOREIGN KEY (category_id) REFERENCES item_categories(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_username VARCHAR(50) NOT NULL,
  to_username VARCHAR(50) NOT NULL,
  item_name VARCHAR(100) NOT NULL,
  gold_value INTEGER NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gameplay_activities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  character_id INTEGER,
  session_id VARCHAR(255),
  activity_type VARCHAR(50) NOT NULL,
  location VARCHAR(100),
  duration_minutes INTEGER DEFAULT 0,
  experience_gained INTEGER DEFAULT 0,
  gold_earned INTEGER DEFAULT 0,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  details TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS marketplace_activities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  character_id INTEGER,
  session_id VARCHAR(255),
  action_type VARCHAR(50) NOT NULL,
  item_id INTEGER,
  item_name VARCHAR(100),
  price_viewed INTEGER,
  search_query VARCHAR(255),
  category VARCHAR(50),
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE SET NULL,
  FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS social_activities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  character_id INTEGER,
  session_id VARCHAR(255),
  activity_type VARCHAR(50) NOT NULL,
  channel_id INTEGER,
  channel_name VARCHAR(50),
  message_count INTEGER DEFAULT 1,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE SET NULL,
  FOREIGN KEY (channel_id) REFERENCES chat_channels(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS character_progression (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  character_id INTEGER NOT NULL,
  session_id VARCHAR(255),
  event_type VARCHAR(50) NOT NULL,
  old_level INTEGER,
  new_level INTEGER,
  experience_gained INTEGER DEFAULT 0,
  gold_change INTEGER DEFAULT 0,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  details TEXT,
  FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS character_inventory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  character_id INTEGER NOT NULL,
  item_id INTEGER NOT NULL,
  quantity INTEGER DEFAULT 1,
  acquired_date DATETIME DEFAULT CURRENT_TIMESTAMP,
  source VARCHAR(50),
  FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE,
  FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
  UNIQUE(character_id, item_id)
);

CREATE TABLE IF NOT EXISTS transaction_details (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  transaction_id INTEGER NOT NULL,
  from_character_id INTEGER,
  to_character_id INTEGER,
  item_id INTEGER NOT NULL,
  quantity INTEGER DEFAULT 1,
  unit_price INTEGER NOT NULL,
  transaction_type VARCHAR(50),
  FOREIGN KEY (from_character_id) REFERENCES characters(id) ON DELETE SET NULL,
  FOREIGN KEY (to_character_id) REFERENCES characters(id) ON DELETE SET NULL,
  FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS game_locations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(100) NOT NULL UNIQUE,
  type VARCHAR(50) NOT NULL,
  level_requirement INTEGER DEFAULT 1,
  description TEXT
);

CREATE TABLE IF NOT EXISTS item_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(50) NOT NULL UNIQUE,
  parent_id INTEGER,
  description TEXT,
  FOREIGN KEY (parent_id) REFERENCES item_categories(id) ON DELETE SET NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_gameplay_activities_user_session ON gameplay_activities(user_id, session_id);
CREATE INDEX IF NOT EXISTS idx_marketplace_activities_user ON marketplace_activities(user_id);
CREATE INDEX IF NOT EXISTS idx_marketplace_activities_item ON marketplace_activities(item_id);
CREATE INDEX IF NOT EXISTS idx_social_activities_user ON social_activities(user_id);
CREATE INDEX IF NOT EXISTS idx_character_progression_char ON character_progression(character_id);
CREATE INDEX IF NOT EXISTS idx_character_inventory_char ON character_inventory(character_id);
CREATE INDEX IF NOT EXISTS idx_transaction_details_from_char ON transaction_details(from_character_id);
CREATE INDEX IF NOT EXISTS idx_transaction_details_to_char ON transaction_details(to_character_id);

-- Pre-populate chat channels
INSERT OR IGNORE INTO chat_channels (id, name, description) VALUES 
(1, 'Global', 'General chat for all players'),
(2, 'Trade', 'Trading and marketplace discussions'),
(3, 'Guild', 'Guild member communications');

-- Pre-populate game locations
INSERT OR IGNORE INTO game_locations (name, type, level_requirement) VALUES 
('Town Square', 'town', 1),
('Marketplace', 'marketplace', 1),
('Newbie Dungeon', 'dungeon', 1),
('Forest Clearing', 'exploration', 3),
('PvP Arena', 'pvp_arena', 10),
('Guild Hall', 'guild_hall', 5),
('Advanced Dungeon', 'dungeon', 15),
('Raid Portal', 'raid', 25),
('Trading Post', 'marketplace', 5),
('Chat Lounge', 'social', 1);

-- Pre-populate item categories
INSERT OR IGNORE INTO item_categories (name, description) VALUES 
('Weapons', 'Combat weapons and tools'),
('Armor', 'Protective equipment'),
('Consumables', 'Potions, food, and temporary items'),
('Materials', 'Crafting and upgrade materials'),
('Accessories', 'Rings, amulets, and special items'),
('Quest Items', 'Special items for quests');

-- Pre-populate weapon subcategories  
INSERT OR IGNORE INTO item_categories (name, parent_id, description) 
SELECT 'Swords', id, 'Melee sword weapons' FROM item_categories WHERE name = 'Weapons';

INSERT OR IGNORE INTO item_categories (name, parent_id, description) 
SELECT 'Staves', id, 'Magical staves for casters' FROM item_categories WHERE name = 'Weapons';

INSERT OR IGNORE INTO item_categories (name, parent_id, description) 
SELECT 'Bows', id, 'Ranged bow weapons' FROM item_categories WHERE name = 'Weapons';