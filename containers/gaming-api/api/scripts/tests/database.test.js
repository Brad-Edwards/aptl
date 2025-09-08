const { describe, it, expect, beforeEach, afterEach } = require('@jest/globals');
const Database = require('../database/connection');
const DataInserters = require('../database/inserters');
const DataValidator = require('../database/validators');
const path = require('path');
const fs = require('fs');

describe('Database', () => {
  let db;
  const testDbPath = path.join(__dirname, 'test.sqlite');

  beforeEach(async () => {
    // Create a test database instance
    db = new Database();
    db.dbPath = testDbPath;
    await db.connect();
    
    // Create minimal test tables
    await db.run(`
      CREATE TABLE IF NOT EXISTS test_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(50) NOT NULL,
        email VARCHAR(100) NOT NULL
      )
    `);
  });

  afterEach(async () => {
    await db.disconnect();
    
    // Clean up test database
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  describe('connection', () => {
    it('should connect to database successfully', async () => {
      const newDb = new Database();
      newDb.dbPath = testDbPath + '2';
      
      await expect(newDb.connect()).resolves.not.toThrow();
      await newDb.disconnect();
      
      if (fs.existsSync(testDbPath + '2')) {
        fs.unlinkSync(testDbPath + '2');
      }
    });
  });

  describe('run', () => {
    it('should execute SQL commands successfully', async () => {
      const result = await db.run(
        'INSERT INTO test_users (username, email) VALUES (?, ?)',
        ['testuser', 'test@example.com']
      );
      
      expect(result).toHaveProperty('lastID');
      expect(result.lastID).toBeGreaterThan(0);
      expect(result).toHaveProperty('changes', 1);
    });
  });

  describe('get', () => {
    it('should retrieve single row', async () => {
      await db.run(
        'INSERT INTO test_users (username, email) VALUES (?, ?)',
        ['testuser', 'test@example.com']
      );
      
      const user = await db.get(
        'SELECT * FROM test_users WHERE username = ?',
        ['testuser']
      );
      
      expect(user).not.toBeNull();
      expect(user.username).toBe('testuser');
      expect(user.email).toBe('test@example.com');
    });

    it('should return undefined for non-existent row', async () => {
      const user = await db.get(
        'SELECT * FROM test_users WHERE username = ?',
        ['nonexistent']
      );
      
      expect(user).toBeUndefined();
    });
  });

  describe('all', () => {
    it('should retrieve multiple rows', async () => {
      await db.run(
        'INSERT INTO test_users (username, email) VALUES (?, ?)',
        ['user1', 'user1@example.com']
      );
      await db.run(
        'INSERT INTO test_users (username, email) VALUES (?, ?)',
        ['user2', 'user2@example.com']
      );
      
      const users = await db.all('SELECT * FROM test_users ORDER BY username');
      
      expect(users).toHaveLength(2);
      expect(users[0].username).toBe('user1');
      expect(users[1].username).toBe('user2');
    });

    it('should return empty array for no results', async () => {
      const users = await db.all('SELECT * FROM test_users');
      expect(users).toEqual([]);
    });
  });

  describe('bulkInsert', () => {
    it('should insert multiple records', async () => {
      const data = [
        ['user1', 'user1@example.com'],
        ['user2', 'user2@example.com'],
        ['user3', 'user3@example.com']
      ];
      
      const count = await db.bulkInsert(
        'test_users',
        ['username', 'email'],
        data
      );
      
      expect(count).toBe(3);
      
      const users = await db.all('SELECT * FROM test_users ORDER BY username');
      expect(users).toHaveLength(3);
    });

    it('should handle empty data gracefully', async () => {
      await expect(
        db.bulkInsert('test_users', ['username', 'email'], [])
      ).rejects.toThrow('No data provided');
    });
  });

  describe('transactions', () => {
    it('should handle successful transactions', async () => {
      await db.beginTransaction();
      
      await db.run(
        'INSERT INTO test_users (username, email) VALUES (?, ?)',
        ['user1', 'user1@example.com']
      );
      
      await db.commit();
      
      const users = await db.all('SELECT * FROM test_users');
      expect(users).toHaveLength(1);
    });

    it('should rollback failed transactions', async () => {
      await db.beginTransaction();
      
      await db.run(
        'INSERT INTO test_users (username, email) VALUES (?, ?)',
        ['user1', 'user1@example.com']
      );
      
      await db.rollback();
      
      const users = await db.all('SELECT * FROM test_users');
      expect(users).toHaveLength(0);
    });
  });

  describe('utility methods', () => {
    beforeEach(async () => {
      await db.run(
        'INSERT INTO test_users (username, email) VALUES (?, ?)',
        ['testuser', 'test@example.com']
      );
    });

    it('should check table existence', async () => {
      const exists = await db.tableExists('test_users');
      expect(exists).toBe(true);
      
      const notExists = await db.tableExists('nonexistent_table');
      expect(notExists).toBe(false);
    });

    it('should get table schema', async () => {
      const schema = await db.getTableSchema('test_users');
      expect(Array.isArray(schema)).toBe(true);
      expect(schema.length).toBeGreaterThan(0);
      
      const columnNames = schema.map(col => col.name);
      expect(columnNames).toContain('id');
      expect(columnNames).toContain('username');
      expect(columnNames).toContain('email');
    });

    it('should get row count', async () => {
      const count = await db.getRowCount('test_users');
      expect(count).toBe(1);
    });
  });
});

describe('DataInserters', () => {
  let inserters;
  let testDbPath;

  beforeEach(async () => {
    testDbPath = path.join(__dirname, 'inserters-test.sqlite');
    inserters = new DataInserters();
    inserters.db.dbPath = testDbPath;
    await inserters.connect();
    
    // Create minimal test schema
    await inserters.db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(50),
        password_hash VARCHAR(255),
        email VARCHAR(100),
        created_at TEXT,
        last_login TEXT,
        is_premium INTEGER,
        account_value INTEGER,
        email_verified INTEGER,
        total_playtime_hours INTEGER,
        last_ip_address VARCHAR(45),
        preferred_language VARCHAR(10),
        timezone VARCHAR(50)
      )
    `);
  });

  afterEach(async () => {
    await inserters.disconnect();
    
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  describe('insertUsers', () => {
    it('should insert users successfully', async () => {
      const users = [
        {
          username: 'testuser1',
          password_hash: 'hash1',
          email: 'user1@example.com',
          created_at: '2024-01-01 12:00:00',
          last_login: '2024-01-02 12:00:00',
          is_premium: true,
          account_value: 100,
          email_verified: true,
          total_playtime_hours: 50,
          last_ip_address: '192.168.1.1',
          preferred_language: 'en-US',
          timezone: 'UTC'
        },
        {
          username: 'testuser2',
          password_hash: 'hash2',
          email: 'user2@example.com',
          created_at: '2024-01-01 12:00:00',
          last_login: '2024-01-02 12:00:00',
          is_premium: false,
          account_value: 50,
          email_verified: false,
          total_playtime_hours: 25,
          last_ip_address: '192.168.1.2',
          preferred_language: 'en-US',
          timezone: 'UTC'
        }
      ];
      
      const count = await inserters.insertUsers(users);
      expect(count).toBe(2);
      
      const insertedUsers = await inserters.db.all('SELECT * FROM users ORDER BY username');
      expect(insertedUsers).toHaveLength(2);
      expect(insertedUsers[0].username).toBe('testuser1');
      expect(insertedUsers[1].username).toBe('testuser2');
    });
  });

  describe('getInsertionStats', () => {
    it('should return table row counts', async () => {
      // Insert test data
      await inserters.insertUsers([{
        username: 'testuser',
        password_hash: 'hash',
        email: 'test@example.com',
        created_at: '2024-01-01 12:00:00',
        last_login: '2024-01-02 12:00:00',
        is_premium: false,
        account_value: 0,
        email_verified: true,
        total_playtime_hours: 0,
        last_ip_address: '192.168.1.1',
        preferred_language: 'en-US',
        timezone: 'UTC'
      }]);
      
      const stats = await inserters.getInsertionStats();
      expect(stats.users).toBe(1);
      expect(stats.characters).toBe(0); // Table doesn't exist in minimal schema
    });
  });
});

describe('DataValidator', () => {
  describe('validateUser', () => {
    it('should pass validation for valid user', () => {
      const validUser = {
        username: 'testuser',
        password_hash: 'hashed_password',
        email: 'test@example.com',
        created_at: '2024-01-01T12:00:00Z',
        account_value: 100
      };
      
      const errors = DataValidator.validateUser(validUser);
      expect(errors).toHaveLength(0);
    });

    it('should detect invalid username', () => {
      const invalidUser = {
        username: 'ab', // Too short
        password_hash: 'hashed_password',
        email: 'test@example.com',
        created_at: '2024-01-01T12:00:00Z'
      };
      
      const errors = DataValidator.validateUser(invalidUser);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Username must be a string');
    });

    it('should detect invalid email', () => {
      const invalidUser = {
        username: 'testuser',
        password_hash: 'hashed_password',
        email: 'invalid-email', // No @
        created_at: '2024-01-01T12:00:00Z'
      };
      
      const errors = DataValidator.validateUser(invalidUser);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Valid email is required');
    });

    it('should detect missing password hash', () => {
      const invalidUser = {
        username: 'testuser',
        email: 'test@example.com',
        created_at: '2024-01-01T12:00:00Z'
      };
      
      const errors = DataValidator.validateUser(invalidUser);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Password hash is required');
    });
  });

  describe('validateCharacter', () => {
    it('should pass validation for valid character', () => {
      const validCharacter = {
        user_id: 1,
        name: 'TestCharacter',
        level: 25,
        class: 'Warrior',
        gold: 500,
        experience: 10000,
        created_at: '2024-01-01T12:00:00Z'
      };
      
      const errors = DataValidator.validateCharacter(validCharacter);
      expect(errors).toHaveLength(0);
    });

    it('should detect invalid level', () => {
      const invalidCharacter = {
        user_id: 1,
        name: 'TestCharacter',
        level: 100, // Too high
        class: 'Warrior',
        gold: 500,
        experience: 10000,
        created_at: '2024-01-01T12:00:00Z'
      };
      
      const errors = DataValidator.validateCharacter(invalidCharacter);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('level must be between 1 and 50');
    });

    it('should detect negative gold', () => {
      const invalidCharacter = {
        user_id: 1,
        name: 'TestCharacter',
        level: 25,
        class: 'Warrior',
        gold: -100, // Negative
        experience: 10000,
        created_at: '2024-01-01T12:00:00Z'
      };
      
      const errors = DataValidator.validateCharacter(invalidCharacter);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Gold and experience cannot be negative');
    });
  });

  describe('validateTransaction', () => {
    it('should pass validation for valid transaction', () => {
      const validTransaction = {
        from_username: 'user1',
        to_username: 'user2',
        item_name: 'Iron Sword',
        gold_value: 100,
        timestamp: '2024-01-01T12:00:00Z'
      };
      
      const errors = DataValidator.validateTransaction(validTransaction);
      expect(errors).toHaveLength(0);
    });

    it('should detect self-trading', () => {
      const invalidTransaction = {
        from_username: 'user1',
        to_username: 'user1', // Same user
        item_name: 'Iron Sword',
        gold_value: 100,
        timestamp: '2024-01-01T12:00:00Z'
      };
      
      const errors = DataValidator.validateTransaction(invalidTransaction);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Cannot trade with yourself');
    });

    it('should detect invalid gold value', () => {
      const invalidTransaction = {
        from_username: 'user1',
        to_username: 'user2',
        item_name: 'Iron Sword',
        gold_value: 0, // Invalid
        timestamp: '2024-01-01T12:00:00Z'
      };
      
      const errors = DataValidator.validateTransaction(invalidTransaction);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Gold value must be positive');
    });
  });

  describe('validateDataRelationships', () => {
    it('should detect invalid character user references', () => {
      const users = [{ id: 1, username: 'user1' }];
      const characters = [
        { id: 1, user_id: 1, name: 'char1' },
        { id: 2, user_id: 999, name: 'char2' } // Invalid user_id
      ];
      
      const errors = DataValidator.validateDataRelationships({ users, characters });
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Characters reference non-existent users');
    });

    it('should pass validation for valid relationships', () => {
      const users = [
        { id: 1, username: 'user1' },
        { id: 2, username: 'user2' }
      ];
      const characters = [
        { id: 1, user_id: 1, name: 'char1' },
        { id: 2, user_id: 2, name: 'char2' }
      ];
      
      const errors = DataValidator.validateDataRelationships({ users, characters });
      expect(errors).toHaveLength(0);
    });
  });

  describe('isValidDate', () => {
    it('should validate correct dates', () => {
      expect(DataValidator.isValidDate('2024-01-01T12:00:00Z')).toBe(true);
      expect(DataValidator.isValidDate('2024-12-31 23:59:59')).toBe(true);
    });

    it('should reject invalid dates', () => {
      expect(DataValidator.isValidDate('invalid-date')).toBe(false);
      expect(DataValidator.isValidDate('')).toBe(false);
      expect(DataValidator.isValidDate(null)).toBe(false);
      expect(DataValidator.isValidDate(undefined)).toBe(false);
    });
  });

  describe('validateAllData', () => {
    it('should validate complete data set', () => {
      const data = {
        users: [{
          id: 1,
          username: 'testuser',
          password_hash: 'hash',
          email: 'test@example.com',
          created_at: '2024-01-01T12:00:00Z'
        }],
        characters: [{
          id: 1,
          user_id: 1,
          name: 'TestChar',
          level: 25,
          class: 'Warrior',
          gold: 500,
          experience: 10000,
          created_at: '2024-01-02T12:00:00Z'
        }]
      };
      
      const result = DataValidator.validateAllData(data);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });
});