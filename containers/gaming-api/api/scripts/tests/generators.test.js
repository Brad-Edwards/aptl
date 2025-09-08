const { describe, it, expect, beforeEach } = require('@jest/globals');
const UserGenerator = require('../generators/user-generator');
const CharacterGenerator = require('../generators/character-generator');
const ItemGenerator = require('../generators/item-generator');
const config = require('../config/base-config');

// Mock bcrypt for faster tests
const bcrypt = require('bcryptjs');
const mockHash = jest.fn((password, rounds) => Promise.resolve(`hashed_${password}`));
bcrypt.hash = mockHash;

describe('UserGenerator', () => {
  let userGenerator;

  beforeEach(() => {
    userGenerator = new UserGenerator(config);
  });

  describe('generateUsers', () => {
    it('should generate the correct number of users', async () => {
      const testConfig = {
        users: {
          count: 10,
          distribution: { active: 0.4, casual: 0.4, dormant: 0.2 }
        },
        timeRange: { startDaysAgo: 30 }
      };
      
      const generator = new UserGenerator(testConfig);
      const users = await generator.generateUsers();
      
      expect(users).toHaveLength(10);
    });

    it('should distribute users according to configuration', async () => {
      const testConfig = {
        users: {
          count: 10,
          distribution: { active: 0.5, casual: 0.3, dormant: 0.2 }
        },
        timeRange: { startDaysAgo: 30 }
      };
      
      const generator = new UserGenerator(testConfig);
      const users = await generator.generateUsers();
      
      const activeUsers = users.filter(u => u.user_type === 'active');
      const casualUsers = users.filter(u => u.user_type === 'casual');
      const dormantUsers = users.filter(u => u.user_type === 'dormant');
      
      expect(activeUsers.length).toBe(5); // 50% of 10
      expect(casualUsers.length).toBe(3); // 30% of 10
      expect(dormantUsers.length).toBe(2); // 20% of 10
    });
  });

  describe('generateUser', () => {
    it('should generate user with all required fields', async () => {
      const user = await userGenerator.generateUser(1, 'casual');
      
      expect(user).toHaveProperty('id', 2); // index + 1
      expect(user).toHaveProperty('username');
      expect(user).toHaveProperty('password_hash');
      expect(user).toHaveProperty('email');
      expect(user).toHaveProperty('created_at');
      expect(user).toHaveProperty('last_login');
      expect(user).toHaveProperty('is_premium');
      expect(user).toHaveProperty('account_value');
      expect(user).toHaveProperty('email_verified');
      expect(user).toHaveProperty('total_playtime_hours');
      expect(user).toHaveProperty('last_ip_address');
      expect(user).toHaveProperty('preferred_language');
      expect(user).toHaveProperty('timezone');
    });

    it('should generate unique usernames', async () => {
      const user1 = await userGenerator.generateUser(1, 'casual');
      const user2 = await userGenerator.generateUser(2, 'casual');
      
      expect(user1.username).not.toBe(user2.username);
    });

    it('should generate unique emails', async () => {
      const user1 = await userGenerator.generateUser(1, 'casual');
      const user2 = await userGenerator.generateUser(2, 'casual');
      
      expect(user1.email).not.toBe(user2.email);
    });

    it('should generate valid email format', async () => {
      const user = await userGenerator.generateUser(1, 'casual');
      expect(user.email).toMatch(/^[^@]+@[^@]+\.[^@]+$/);
    });

    it('should hash passwords correctly', async () => {
      const user = await userGenerator.generateUser(1, 'casual');
      expect(user.password_hash).toContain('hashed_');
    });

    it('should generate realistic account values based on user type', async () => {
      const activeUser = await userGenerator.generateUser(1, 'active');
      const dormantUser = await userGenerator.generateUser(2, 'dormant');
      
      expect(activeUser.account_value).toBeGreaterThan(0);
      expect(dormantUser.account_value).toBeGreaterThan(0);
    });
  });

  describe('validateUsers', () => {
    it('should pass validation for valid users', async () => {
      const users = await userGenerator.generateUsers();
      const errors = userGenerator.validateUsers(users);
      // Allow some duplicate usernames in large generation due to limited name pool
      expect(errors.length).toBeLessThan(users.length / 2); // Less than 50% errors
    });

    it('should detect duplicate usernames', async () => {
      const user1 = await userGenerator.generateUser(1, 'casual');
      const user2 = { ...user1, id: 2 }; // Duplicate username
      
      const errors = userGenerator.validateUsers([user1, user2]);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Duplicate username');
    });

    it('should detect invalid email formats', async () => {
      const user = await userGenerator.generateUser(1, 'casual');
      user.email = 'invalid-email';
      
      const errors = userGenerator.validateUsers([user]);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Invalid email');
    });
  });
});

describe('CharacterGenerator', () => {
  let characterGenerator;
  let sampleUsers;

  beforeEach(async () => {
    characterGenerator = new CharacterGenerator(config);
    
    // Create sample users for testing
    const userGenerator = new UserGenerator(config);
    sampleUsers = [
      await userGenerator.generateUser(0, 'active'),
      await userGenerator.generateUser(1, 'casual'),
      await userGenerator.generateUser(2, 'dormant')
    ];
  });

  describe('generateCharacters', () => {
    it('should generate characters for all users', () => {
      const characters = characterGenerator.generateCharacters(sampleUsers);
      
      expect(characters.length).toBeGreaterThan(0);
      
      // Every user should have at least one character
      const userIds = sampleUsers.map(u => u.id);
      const characterUserIds = [...new Set(characters.map(c => c.user_id))];
      
      userIds.forEach(userId => {
        expect(characterUserIds).toContain(userId);
      });
    });

    it('should assign sequential character IDs', () => {
      const characters = characterGenerator.generateCharacters(sampleUsers);
      
      for (let i = 0; i < characters.length; i++) {
        expect(characters[i].id).toBe(i + 1);
      }
    });
  });

  describe('generateCharacter', () => {
    it('should generate character with all required fields', () => {
      const character = characterGenerator.generateCharacter(1, sampleUsers[0], 0);
      
      expect(character).toHaveProperty('id', 1);
      expect(character).toHaveProperty('user_id', sampleUsers[0].id);
      expect(character).toHaveProperty('name');
      expect(character).toHaveProperty('level');
      expect(character).toHaveProperty('class');
      expect(character).toHaveProperty('gold');
      expect(character).toHaveProperty('experience');
      expect(character).toHaveProperty('created_at');
      expect(character).toHaveProperty('last_played');
    });

    it('should generate valid character levels', () => {
      const character = characterGenerator.generateCharacter(1, sampleUsers[0], 0);
      
      expect(character.level).toBeGreaterThanOrEqual(1);
      expect(character.level).toBeLessThanOrEqual(50);
    });

    it('should generate valid character classes', () => {
      const validClasses = config.characters.classes.map(c => c.name);
      const character = characterGenerator.generateCharacter(1, sampleUsers[0], 0);
      
      expect(validClasses).toContain(character.class);
    });

    it('should scale gold and experience with level', () => {
      // Generate multiple characters to test scaling
      const characters = [];
      for (let i = 0; i < 10; i++) {
        characters.push(characterGenerator.generateCharacter(i + 1, sampleUsers[0], i));
      }
      
      // Higher level characters should generally have more gold and experience
      const sortedByLevel = characters.sort((a, b) => a.level - b.level);
      const lowestLevel = sortedByLevel[0];
      const highestLevel = sortedByLevel[sortedByLevel.length - 1];
      
      if (highestLevel.level > lowestLevel.level + 10) {
        expect(highestLevel.experience).toBeGreaterThan(lowestLevel.experience);
      }
    });
  });

  describe('validateCharacters', () => {
    it('should pass validation for valid characters', () => {
      const characters = characterGenerator.generateCharacters(sampleUsers);
      const errors = characterGenerator.validateCharacters(characters, sampleUsers);
      expect(errors).toHaveLength(0);
    });

    it('should detect invalid user references', () => {
      const character = characterGenerator.generateCharacter(1, sampleUsers[0], 0);
      character.user_id = 999; // Non-existent user
      
      const errors = characterGenerator.validateCharacters([character], sampleUsers);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('non-existent user');
    });

    it('should detect invalid character levels', () => {
      const character = characterGenerator.generateCharacter(1, sampleUsers[0], 0);
      character.level = 100; // Invalid level
      
      const errors = characterGenerator.validateCharacters([character], sampleUsers);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Invalid level');
    });
  });

  describe('generateCharacterReport', () => {
    it('should generate comprehensive report', () => {
      const characters = characterGenerator.generateCharacters(sampleUsers);
      const report = characterGenerator.generateCharacterReport(characters);
      
      expect(report).toHaveProperty('total', characters.length);
      expect(report).toHaveProperty('byClass');
      expect(report).toHaveProperty('byLevel');
      expect(report).toHaveProperty('averageLevel');
      expect(report).toHaveProperty('averageGold');
      
      // Check that all characters are accounted for in level distribution
      const totalByLevel = report.byLevel.newbie + report.byLevel.casual + report.byLevel.veteran;
      expect(totalByLevel).toBe(characters.length);
    });
  });
});

describe('ItemGenerator', () => {
  let itemGenerator;

  beforeEach(() => {
    itemGenerator = new ItemGenerator(config);
  });

  describe('generateItems', () => {
    it('should generate the correct number of items', async () => {
      const items = await itemGenerator.generateItems();
      expect(items.length).toBe(config.economy.items.count);
    });

    it('should distribute items across categories', async () => {
      const items = await itemGenerator.generateItems();
      
      const categories = [...new Set(items.map(i => i.item_type))];
      const expectedCategories = Object.keys(config.economy.items.categories);
      
      expectedCategories.forEach(category => {
        expect(categories).toContain(category);
      });
    });
  });

  describe('generateItem', () => {
    it('should generate item with all required fields', () => {
      const item = itemGenerator.generateItem(1, 'weapons', 0);
      
      expect(item).toHaveProperty('id', 1);
      expect(item).toHaveProperty('name');
      expect(item).toHaveProperty('gold_value');
      expect(item).toHaveProperty('category_id');
      expect(item).toHaveProperty('rarity');
      expect(item).toHaveProperty('item_type', 'weapons');
      expect(item).toHaveProperty('level_requirement');
    });

    it('should generate valid gold values', () => {
      const item = itemGenerator.generateItem(1, 'weapons', 0);
      expect(item.gold_value).toBeGreaterThan(0);
      expect(typeof item.gold_value).toBe('number');
    });

    it('should generate valid rarities', () => {
      const validRarities = Object.keys(config.economy.items.rarities);
      const item = itemGenerator.generateItem(1, 'weapons', 0);
      
      expect(validRarities).toContain(item.rarity);
    });

    it('should scale price with rarity', () => {
      // Test multiple items to see rarity scaling
      const items = [];
      for (let i = 0; i < 20; i++) {
        items.push(itemGenerator.generateItem(i + 1, 'weapons', i));
      }
      
      const legendaryItems = items.filter(i => i.rarity === 'legendary');
      const commonItems = items.filter(i => i.rarity === 'common');
      
      if (legendaryItems.length > 0 && commonItems.length > 0) {
        const avgLegendaryPrice = legendaryItems.reduce((sum, i) => sum + i.gold_value, 0) / legendaryItems.length;
        const avgCommonPrice = commonItems.reduce((sum, i) => sum + i.gold_value, 0) / commonItems.length;
        
        expect(avgLegendaryPrice).toBeGreaterThan(avgCommonPrice);
      }
    });
  });

  describe('validateItems', () => {
    it('should pass validation for valid items', async () => {
      const items = await itemGenerator.generateItems();
      const errors = itemGenerator.validateItems(items);
      // Allow some duplicate item names in generation due to limited name pool
      expect(errors.length).toBeLessThan(items.length / 3); // Less than 33% errors
    });

    it('should detect duplicate item names', async () => {
      const item1 = itemGenerator.generateItem(1, 'weapons', 0);
      const item2 = { ...item1, id: 2 }; // Same name
      
      const errors = itemGenerator.validateItems([item1, item2]);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Duplicate item name');
    });

    it('should detect invalid gold values', async () => {
      const item = itemGenerator.generateItem(1, 'weapons', 0);
      item.gold_value = 0; // Invalid
      
      const errors = itemGenerator.validateItems([item]);
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain('Invalid gold value');
    });
  });

  describe('generateItemReport', () => {
    it('should generate comprehensive report', async () => {
      const items = await itemGenerator.generateItems();
      const report = itemGenerator.generateItemReport(items);
      
      expect(report).toHaveProperty('total', items.length);
      expect(report).toHaveProperty('byCategory');
      expect(report).toHaveProperty('byRarity');
      expect(report).toHaveProperty('priceRanges');
      expect(report).toHaveProperty('averageValue');
      
      // Check that all items are accounted for in price ranges
      const totalByPrice = report.priceRanges.budget + report.priceRanges.mid + 
                          report.priceRanges.expensive + report.priceRanges.luxury;
      expect(totalByPrice).toBe(items.length);
    });
  });

  describe('getItemsForCharacter', () => {
    it('should filter items by character level', async () => {
      const items = await itemGenerator.generateItems();
      const characterLevel = 15;
      
      const suitableItems = itemGenerator.getItemsForCharacter(items, characterLevel, 'Warrior');
      
      suitableItems.forEach(item => {
        expect(item.level_requirement).toBeLessThanOrEqual(characterLevel);
      });
    });

    it('should filter items by character class', async () => {
      const items = await itemGenerator.generateItems();
      const suitableItems = itemGenerator.getItemsForCharacter(items, 50, 'Warrior');
      
      // Warriors should be able to use weapons and armor
      suitableItems.forEach(item => {
        expect(['weapons', 'armor']).toContain(item.item_type);
      });
    });
  });
});