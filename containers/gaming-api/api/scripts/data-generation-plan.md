# Gaming API Data Generation Plan

## Analysis Summary

### Current Database Schema
The gaming API has a **normalized schema** with the following tables:

**Core User Data:**
- `users` - Basic user accounts (id, username, password_hash, email, created_at, last_login, is_premium, account_value, email_verified, etc.)
- `characters` - Game characters linked to users (id, user_id, name, level, class, gold, experience, created_at, last_played)

**Session & Activity Data:**
- `player_sessions` - Login/gameplay sessions (user_id, character_id, session_id, login_time, logout_time, actions_count, locations_visited, ip_address, user_agent)
- `login_history` - Authentication attempts (user_id, username, ip_address, user_agent, login_time, success, failure_reason, geo_location, device_fingerprint)

**Game Economy:**
- `items` - Game items (id, name, gold_value) 
- `transactions` - Item trades between users (from_username, to_username, item_name, gold_value, timestamp)

**Other:**
- `chat_channels` - Pre-populated (Global, Trade, Guild)
- `auth_events` - Appears to be duplicate of login_history

### Current State
- Database exists with proper schema
- 0 users, 0 characters, 4 player_sessions (likely test data)
- Auth API endpoints expect data in this structure

## Data Generation Requirements

### Target Volume (CTF Scenario)
- **150-300 users** for realistic but manageable dataset
- **1-3 characters per user** (some users have multiple characters)
- **500-1000 login attempts** (mix of success/failure for credential stuffing simulation)
- **200-500 player sessions** (realistic gameplay activity)
- **50-100 item transactions** (basic economy activity)
- **20-30 game items** (standard RPG items)

### Data Relationships & Constraints
1. **Users** → **Characters** (1:many, users can have multiple characters)
2. **Users** → **Player Sessions** (1:many, track login/gameplay sessions)  
3. **Users** → **Login History** (1:many, all auth attempts)
4. **Characters** → **Player Sessions** (1:many, sessions can be linked to specific characters)
5. **Users** → **Transactions** (many:many, users trade items with each other)
6. **Items** → **Transactions** (1:many, items are traded multiple times)

### Realistic Data Patterns
- **User Types**: New players, active players, dormant players, premium players
- **Character Distribution**: Warriors, Mages, Rogues, etc. with level progression
- **Login Patterns**: Active users login frequently, dormant users rarely
- **Session Durations**: Vary from short (5-30 min) to long (2-4 hours)
- **Item Economy**: Common items traded frequently, rare items traded rarely
- **Geographic Distribution**: Consistent IP ranges per user (simulated regions)

## Implementation Plan

### Phase 1: Project Setup ✅
- [x] Clean up broken previous attempt
- [x] Analyze existing schema and API requirements

### Phase 2: Core Architecture Design ✅
- [x] **2.1** Design clean, modular script architecture
- [x] **2.2** Create configuration system for data generation parameters  
- [x] **2.3** Set up database connection utilities
- [x] **2.4** Design data validation system

### Phase 3: Data Generators Implementation ✅
- [x] **3.1** User Generator (accounts, emails, passwords, account ages)
- [x] **3.2** Character Generator (names, classes, levels, linked to users)
- [x] **3.3** Item Generator (game items with realistic values)  
- [x] **3.4** Session Generator (login/logout sessions with realistic durations)
- [x] **3.5** Login History Generator (auth attempts with success/failure patterns)
- [x] **3.6** Transaction Generator (item trades between users)
- [x] **3.7** Activity Generator (gameplay, marketplace, social activities)

### Phase 4: Data Relationships & Validation ✅
- [x] **4.1** Implement referential integrity validation
- [x] **4.2** Create realistic relationship patterns (users → characters → sessions)
- [x] **4.3** Add data consistency checks (login dates, session durations, etc.)

### Phase 5: Database Integration ✅
- [x] **5.1** Create database insertion utilities for each table
- [x] **5.2** Implement transaction-safe bulk insertions
- [x] **5.3** Add progress logging and error handling
- [x] **5.4** Create main orchestration script

### Phase 6: Testing & Quality ✅
- [x] **6.1** Create comprehensive unit tests for each generator function
- [x] **6.2** Add integration tests for data relationships
- [x] **6.3** Implement data quality validation (realistic distributions, etc.)
- [x] **6.4** Performance testing for target data volumes

### Phase 7: Documentation & Maintenance
- [x] **7.1** Create usage documentation and examples
- [x] **7.2** Add configuration guides for different scenarios  
- [x] **7.3** Create troubleshooting guides

## Technical Architecture

### File Structure
```
api/scripts/
├── generate-data.js           # Main orchestration script
├── config/
│   ├── base-config.js         # Base configuration settings
│   └── ctf-config.js          # CTF-specific settings (150-300 users)
├── generators/
│   ├── user-generator.js      # User account generation
│   ├── character-generator.js # Character creation  
│   ├── session-generator.js   # Session/activity generation
│   ├── item-generator.js      # Game items
│   └── transaction-generator.js # Item trading
├── database/
│   ├── connection.js          # Database utilities
│   ├── inserters.js           # Bulk insertion functions
│   └── validators.js          # Data validation
└── utils/
    ├── date-helpers.js        # Date/time utilities
    ├── name-generators.js     # Character/username generation
    └── probability.js         # Weighted random distributions
```

### Design Principles
- **Modular**: Each generator is independent and testable
- **Configurable**: Easy to adjust for different scenarios (CTF vs full game)
- **Validated**: Comprehensive relationship and data quality validation
- **Fast**: Efficient bulk operations for target volumes
- **Maintainable**: Clear separation of concerns, no over-engineering

## Potential Schema Issues & Questions

### Discovered Issues
1. **auth_events table**: Seems redundant with login_history - should we use one or both?
2. **Foreign key constraints**: Some use user IDs, others use usernames - is this intentional?
3. **DateTime formats**: Mix of DATETIME and TEXT fields - need consistency

### Questions for Approval
1. **Item Categories**: Should we add an item_categories table for organized item types?
2. **Character Stats**: Should we add more character attributes (health, mana, stats)?
3. **Guild System**: Should we add tables for guilds/teams that characters can join?
4. **Inventory System**: Should we track what items each character owns?

## Success Criteria
- ✅ Generate 150-300 realistic user accounts
- ✅ Create 1-3 characters per user with appropriate level distribution
- ✅ Generate realistic login/session patterns for CTF scenario
- ✅ Create active item economy with trading history
- ✅ All data relationships properly maintained
- ✅ Database populated without errors or inconsistencies
- ✅ API can authenticate and serve all generated users
- ✅ Comprehensive test coverage for all generators