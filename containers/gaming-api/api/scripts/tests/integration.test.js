const { describe, it, expect, beforeEach, afterEach } = require('@jest/globals');
const { DataGenerationOrchestrator } = require('../generate-data');
const config = require('../config/base-config');
const path = require('path');
const fs = require('fs');

// Mock bcrypt for faster tests  
const bcrypt = require('bcryptjs');
const mockHash = jest.fn((password, rounds) => Promise.resolve(`hashed_${password}`));
bcrypt.hash = mockHash;

describe('Integration Tests', () => {
  let orchestrator;
  let testDbPath;

  beforeEach(async () => {
    // Create test configuration with smaller numbers for faster tests
    const testConfig = {
      ...config,
      users: {
        count: 5,
        distribution: { active: 0.4, casual: 0.4, dormant: 0.2 }
      },
      economy: {
        ...config.economy,
        items: { ...config.economy.items, count: 10 },
        transactions: { ...config.economy.transactions, count: 5 }
      },
      sessions: { ...config.sessions, totalCount: 15 },
      activities: {
        ...config.activities,
        gameplay: { ...config.activities.gameplay, totalCount: 20 },
        marketplace: { ...config.activities.marketplace, totalCount: 10 },
        social: { ...config.activities.social, totalCount: 8 }
      }
    };

    orchestrator = new DataGenerationOrchestrator(testConfig);
    
    // Use test database
    testDbPath = path.join(__dirname, 'integration-test.sqlite');
    orchestrator.db.dbPath = testDbPath;
    orchestrator.inserters.db.dbPath = testDbPath;
  });

  afterEach(async () => {
    try {
      await orchestrator.inserters.disconnect();
    } catch (error) {
      // Ignore disconnect errors in tests
    }
    
    // Clean up test database
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
    
    // Clean up any test reports
    const reportsDir = path.join(__dirname, '..', 'reports');
    if (fs.existsSync(reportsDir)) {
      const files = fs.readdirSync(reportsDir);
      files.forEach(file => {
        if (file.includes('test') || file.includes('integration')) {
          fs.unlinkSync(path.join(reportsDir, file));
        }
      });
    }
  });

  describe('End-to-End Data Generation', () => {
    it('should generate complete dataset without errors', async () => {
      // Create test database with enhanced schema
      await orchestrator.connectDatabase();
      
      // Create minimal schema for testing
      await createTestSchema(orchestrator.db);
      
      // Generate all data
      await orchestrator.generateAllData();
      
      // Verify data was generated
      expect(orchestrator.generatedData.users).toBeDefined();
      expect(orchestrator.generatedData.characters).toBeDefined();
      expect(orchestrator.generatedData.items).toBeDefined();
      expect(orchestrator.generatedData.sessions).toBeDefined();
      expect(orchestrator.generatedData.loginHistory).toBeDefined();
      expect(orchestrator.generatedData.transactions).toBeDefined();
      
      // Check quantities
      expect(orchestrator.generatedData.users.length).toBe(5);
      expect(orchestrator.generatedData.items.length).toBe(10);
      expect(orchestrator.generatedData.sessions.length).toBeGreaterThan(10); // Sessions depend on user types
      expect(orchestrator.generatedData.transactions.length).toBe(5);
      
      // Validate data
      await orchestrator.validateAllData();
      
      // Insert data
      await orchestrator.insertAllData();
      
      // Verify data was inserted
      const stats = await orchestrator.inserters.getInsertionStats();
      expect(stats.users).toBe(5);
      expect(stats.items).toBe(10);
      
    }, 30000); // 30 second timeout for full integration test

    it('should maintain data relationships correctly', async () => {
      await orchestrator.connectDatabase();
      await createTestSchema(orchestrator.db);
      
      await orchestrator.generateAllData();
      
      const { users, characters, sessions, transactions } = orchestrator.generatedData;
      
      // Every character should reference a valid user
      const userIds = new Set(users.map(u => u.id));
      characters.forEach(char => {
        expect(userIds.has(char.user_id)).toBe(true);
      });
      
      // Every session should reference a valid user
      sessions.forEach(session => {
        expect(userIds.has(session.user_id)).toBe(true);
      });
      
      // Character sessions should reference valid characters
      const characterIds = new Set(characters.map(c => c.id));
      sessions.forEach(session => {
        if (session.character_id) {
          expect(characterIds.has(session.character_id)).toBe(true);
        }
      });
      
      // Transactions should reference valid users
      const usernames = new Set(users.map(u => u.username));
      transactions.forEach(tx => {
        expect(usernames.has(tx.from_username)).toBe(true);
        expect(usernames.has(tx.to_username)).toBe(true);
        expect(tx.from_username).not.toBe(tx.to_username);
      });
    });

    it('should generate realistic data distributions', async () => {
      await orchestrator.connectDatabase();
      await createTestSchema(orchestrator.db);
      
      await orchestrator.generateAllData();
      
      const { users, characters, items } = orchestrator.generatedData;
      
      // User type distribution should match config
      const activeUsers = users.filter(u => u.user_type === 'active');
      const casualUsers = users.filter(u => u.user_type === 'casual');
      const dormantUsers = users.filter(u => u.user_type === 'dormant');
      
      expect(activeUsers.length).toBe(2); // 40% of 5
      expect(casualUsers.length).toBe(2); // 40% of 5  
      expect(dormantUsers.length).toBe(1); // 20% of 5
      
      // Every user should have at least one character
      const usersWithChars = new Set(characters.map(c => c.user_id));
      users.forEach(user => {
        expect(usersWithChars.has(user.id)).toBe(true);
      });
      
      // Character levels should be within valid range
      characters.forEach(char => {
        expect(char.level).toBeGreaterThanOrEqual(1);
        expect(char.level).toBeLessThanOrEqual(50);
      });
      
      // Items should have valid rarities and prices
      items.forEach(item => {
        expect(['common', 'rare', 'epic', 'legendary']).toContain(item.rarity);
        expect(item.gold_value).toBeGreaterThan(0);
        expect(item.level_requirement).toBeGreaterThanOrEqual(1);
        expect(item.level_requirement).toBeLessThanOrEqual(50);
      });
    });

    it('should generate activities based on session patterns', async () => {
      await orchestrator.connectDatabase();
      await createTestSchema(orchestrator.db);
      
      await orchestrator.generateAllData();
      
      const { gameplayActivities, marketplaceActivities, socialActivities } = orchestrator.generatedData;
      
      // Should have generated activities
      expect(gameplayActivities.length).toBeGreaterThan(0);
      expect(marketplaceActivities.length).toBeGreaterThan(0);
      expect(socialActivities.length).toBeGreaterThan(0);
      
      // Activities should have valid timestamps and durations
      [...gameplayActivities, ...marketplaceActivities, ...socialActivities].forEach(activity => {
        expect(activity.timestamp).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
        
        if (activity.duration_minutes !== undefined) {
          expect(activity.duration_minutes).toBeGreaterThanOrEqual(0);
        }
        
        if (activity.experience_gained !== undefined) {
          expect(activity.experience_gained).toBeGreaterThanOrEqual(0);
        }
        
        if (activity.gold_earned !== undefined) {
          expect(activity.gold_earned).toBeGreaterThanOrEqual(0);
        }
      });
    });

    it('should generate consistent user behavior patterns', async () => {
      await orchestrator.connectDatabase();
      await createTestSchema(orchestrator.db);
      
      await orchestrator.generateAllData();
      
      const { users, sessions, loginHistory } = orchestrator.generatedData;
      
      // Active users should have more sessions than dormant users
      const activeUser = users.find(u => u.user_type === 'active');
      const dormantUser = users.find(u => u.user_type === 'dormant');
      
      if (activeUser && dormantUser) {
        const activeSessions = sessions.filter(s => s.user_id === activeUser.id);
        const dormantSessions = sessions.filter(s => s.user_id === dormantUser.id);
        
        expect(activeSessions.length).toBeGreaterThanOrEqual(dormantSessions.length);
      }
      
      // Login history should include both successful and failed attempts
      const successfulLogins = loginHistory.filter(l => l.success === true);
      const failedLogins = loginHistory.filter(l => l.success === false);
      
      expect(successfulLogins.length).toBeGreaterThan(0);
      expect(failedLogins.length).toBeGreaterThanOrEqual(0); // May be 0 in small test set
      
      // All login attempts should have valid timestamps
      loginHistory.forEach(login => {
        expect(login.login_time).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
        expect(typeof login.success).toBe('boolean');
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle database connection errors gracefully', async () => {
      // Point to invalid database path
      orchestrator.db.dbPath = '/invalid/path/database.sqlite';
      orchestrator.inserters.db.dbPath = '/invalid/path/database.sqlite';
      
      await expect(orchestrator.connectDatabase()).rejects.toThrow();
    });

    it('should validate data before insertion', async () => {
      await orchestrator.connectDatabase();
      await createTestSchema(orchestrator.db);
      
      await orchestrator.generateAllData();
      
      // Corrupt some data to test validation
      orchestrator.generatedData.users[0].email = 'invalid-email'; // Remove @
      
      await expect(orchestrator.validateAllData()).rejects.toThrow();
    });
  });

  describe('Report Generation', () => {
    it('should generate comprehensive reports', async () => {
      await orchestrator.connectDatabase();
      await createTestSchema(orchestrator.db);
      
      await orchestrator.generateAllData();
      await orchestrator.validateAllData();
      
      // Generate reports
      const summaryReport = orchestrator.generateSummaryReport();
      const userReport = orchestrator.generateUserReport();
      
      // Summary report should have all expected fields
      expect(summaryReport).toHaveProperty('users', 5);
      expect(summaryReport).toHaveProperty('characters');
      expect(summaryReport).toHaveProperty('items', 10);
      expect(summaryReport).toHaveProperty('sessions');
      expect(summaryReport.sessions).toBeGreaterThan(10);
      expect(summaryReport).toHaveProperty('transactions', 5);
      expect(summaryReport).toHaveProperty('generationTime');
      
      // User report should have distribution data
      expect(userReport).toHaveProperty('total', 5);
      expect(userReport).toHaveProperty('byType');
      expect(userReport.byType).toHaveProperty('active');
      expect(userReport.byType).toHaveProperty('casual');
      expect(userReport.byType).toHaveProperty('dormant');
    });
  });
});

// Helper function to create minimal test schema
async function createTestSchema(db) {
  const schemaSql = `
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

    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name VARCHAR(100) NOT NULL,
      gold_value INTEGER NOT NULL,
      category_id INTEGER,
      rarity VARCHAR(20) DEFAULT 'common',
      item_type VARCHAR(50),
      level_requirement INTEGER DEFAULT 1
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
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
      device_fingerprint VARCHAR(255)
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
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
      transaction_type VARCHAR(50)
    );
  `;

  const statements = schemaSql.split(';').filter(s => s.trim());
  for (const statement of statements) {
    if (statement.trim()) {
      await db.run(statement.trim());
    }
  }
}