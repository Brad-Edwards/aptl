-- Enhanced Gaming Schema for Realistic Player Activity Tracking
-- These tables extend the existing schema to capture detailed player behavior

-- Gameplay activity tracking
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
  details TEXT, -- JSON for additional activity-specific data
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE SET NULL
);

-- Marketplace activity tracking  
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

-- Social/Chat activity tracking
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

-- Character progression tracking (levels, achievements, etc.)
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
  details TEXT, -- JSON for additional progression data
  FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE
);

-- Inventory tracking (what players own)
CREATE TABLE IF NOT EXISTS character_inventory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  character_id INTEGER NOT NULL,
  item_id INTEGER NOT NULL,
  quantity INTEGER DEFAULT 1,
  acquired_date DATETIME DEFAULT CURRENT_TIMESTAMP,
  source VARCHAR(50), -- 'quest_reward', 'marketplace_purchase', 'trade', 'drop'
  FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE,
  FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
  UNIQUE(character_id, item_id)
);

-- Enhanced transaction tracking (link to inventory changes)
CREATE TABLE IF NOT EXISTS transaction_details (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  transaction_id INTEGER NOT NULL,
  from_character_id INTEGER,
  to_character_id INTEGER,
  item_id INTEGER NOT NULL,
  quantity INTEGER DEFAULT 1,
  unit_price INTEGER NOT NULL,
  transaction_type VARCHAR(50), -- 'player_trade', 'marketplace_sale', 'gift'
  FOREIGN KEY (from_character_id) REFERENCES characters(id) ON DELETE SET NULL,
  FOREIGN KEY (to_character_id) REFERENCES characters(id) ON DELETE SET NULL,
  FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE
);

-- Game locations/areas for activity tracking
CREATE TABLE IF NOT EXISTS game_locations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(100) NOT NULL UNIQUE,
  type VARCHAR(50) NOT NULL, -- 'dungeon', 'marketplace', 'town', 'pvp_arena', 'guild_hall'
  level_requirement INTEGER DEFAULT 1,
  description TEXT
);

-- Item categories for better marketplace organization
CREATE TABLE IF NOT EXISTS item_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(50) NOT NULL UNIQUE,
  parent_id INTEGER, -- for nested categories
  description TEXT,
  FOREIGN KEY (parent_id) REFERENCES item_categories(id) ON DELETE SET NULL
);

-- Add category to items table (extend existing)
ALTER TABLE items ADD COLUMN category_id INTEGER REFERENCES item_categories(id);
ALTER TABLE items ADD COLUMN rarity VARCHAR(20) DEFAULT 'common'; -- 'common', 'rare', 'epic', 'legendary'
ALTER TABLE items ADD COLUMN item_type VARCHAR(50); -- 'weapon', 'armor', 'consumable', 'material'
ALTER TABLE items ADD COLUMN level_requirement INTEGER DEFAULT 1;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_gameplay_activities_user_session ON gameplay_activities(user_id, session_id);
CREATE INDEX IF NOT EXISTS idx_marketplace_activities_user ON marketplace_activities(user_id);
CREATE INDEX IF NOT EXISTS idx_marketplace_activities_item ON marketplace_activities(item_id);
CREATE INDEX IF NOT EXISTS idx_social_activities_user ON social_activities(user_id);
CREATE INDEX IF NOT EXISTS idx_character_progression_char ON character_progression(character_id);
CREATE INDEX IF NOT EXISTS idx_character_inventory_char ON character_inventory(character_id);
CREATE INDEX IF NOT EXISTS idx_transaction_details_from_char ON transaction_details(from_character_id);
CREATE INDEX IF NOT EXISTS idx_transaction_details_to_char ON transaction_details(to_character_id);

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