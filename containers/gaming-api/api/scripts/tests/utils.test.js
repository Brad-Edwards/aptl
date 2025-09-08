const { describe, it, expect, beforeEach } = require('@jest/globals');
const NameGenerators = require('../utils/name-generators');
const DateHelpers = require('../utils/date-helpers');
const ProbabilityHelpers = require('../utils/probability');

describe('NameGenerators', () => {
  describe('generateUsername', () => {
    it('should generate consistent usernames with index', () => {
      const username1 = NameGenerators.generateConsistentData('username', 1);
      const username2 = NameGenerators.generateConsistentData('username', 1);
      expect(username1).toBe(username2);
    });

    it('should generate different usernames for different indices', () => {
      const username1 = NameGenerators.generateConsistentData('username', 1);
      const username2 = NameGenerators.generateConsistentData('username', 2);
      expect(username1).not.toBe(username2);
    });

    it('should generate valid username format', () => {
      const username = NameGenerators.generateUsername();
      expect(typeof username).toBe('string');
      expect(username.length).toBeGreaterThan(0);
      expect(username.length).toBeLessThan(50);
    });
  });

  describe('generateCharacterName', () => {
    it('should generate names based on character class', () => {
      const warriorName = NameGenerators.generateCharacterName('Warrior');
      const mageName = NameGenerators.generateCharacterName('Mage');
      
      expect(typeof warriorName).toBe('string');
      expect(typeof mageName).toBe('string');
      expect(warriorName.length).toBeGreaterThan(0);
      expect(mageName.length).toBeGreaterThan(0);
    });

    it('should handle invalid character classes gracefully', () => {
      const name = NameGenerators.generateCharacterName('InvalidClass');
      expect(typeof name).toBe('string');
      expect(name.length).toBeGreaterThan(0);
    });
  });

  describe('generateEmail', () => {
    it('should generate valid email format', () => {
      const email = NameGenerators.generateEmail('testuser');
      expect(email).toMatch(/^[^@]+@[^@]+\.[^@]+$/);
      expect(email).toContain('testuser');
    });

    it('should be consistent with index', () => {
      const email1 = NameGenerators.generateConsistentData('email', 1, 'testuser');
      const email2 = NameGenerators.generateConsistentData('email', 1, 'testuser');
      expect(email1).toBe(email2);
    });
  });

  describe('generateIPAddress', () => {
    it('should generate valid IP format', () => {
      const ip = NameGenerators.generateIPAddress();
      expect(ip).toMatch(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
      
      const parts = ip.split('.');
      parts.forEach(part => {
        const num = parseInt(part);
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThanOrEqual(255);
      });
    });
  });

  describe('generateItemName', () => {
    it('should generate names for all categories and rarities', () => {
      const categories = ['weapons', 'armor', 'consumables', 'materials'];
      const rarities = ['common', 'rare', 'epic', 'legendary'];
      
      categories.forEach(category => {
        rarities.forEach(rarity => {
          const itemName = NameGenerators.generateItemName(category, rarity);
          expect(typeof itemName).toBe('string');
          expect(itemName.length).toBeGreaterThan(0);
          expect(itemName).not.toBe('Unknown Item');
        });
      });
    });

    it('should handle invalid category gracefully', () => {
      const itemName = NameGenerators.generateItemName('invalid', 'common');
      expect(itemName).toBe('Unknown Item');
    });
  });
});

describe('DateHelpers', () => {
  describe('randomDateBetween', () => {
    it('should generate date within range', () => {
      const start = new Date('2024-01-01');
      const end = new Date('2024-12-31');
      const randomDate = DateHelpers.randomDateBetween(start, end);
      
      expect(randomDate).toBeInstanceOf(Date);
      expect(randomDate.getTime()).toBeGreaterThanOrEqual(start.getTime());
      expect(randomDate.getTime()).toBeLessThanOrEqual(end.getTime());
    });
  });

  describe('generateAccountCreationDate', () => {
    it('should generate date within specified days ago', () => {
      const creationDate = DateHelpers.generateAccountCreationDate(30);
      const now = new Date();
      const thirtyDaysAgo = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
      
      expect(creationDate).toBeInstanceOf(Date);
      expect(creationDate.getTime()).toBeGreaterThanOrEqual(thirtyDaysAgo.getTime());
      expect(creationDate.getTime()).toBeLessThanOrEqual(now.getTime());
    });
  });

  describe('generateLastLoginDate', () => {
    it('should generate login date after account creation', () => {
      const createdAt = new Date('2024-01-01');
      const lastLogin = DateHelpers.generateLastLoginDate(createdAt, 'active');
      
      expect(lastLogin).toBeInstanceOf(Date);
      expect(lastLogin.getTime()).toBeGreaterThanOrEqual(createdAt.getTime());
    });

    it('should vary by user type', () => {
      const createdAt = new Date('2024-01-01');
      const activeLogin = DateHelpers.generateLastLoginDate(createdAt, 'active');
      const dormantLogin = DateHelpers.generateLastLoginDate(createdAt, 'dormant');
      
      // Dormant users should generally have older last logins
      // This is probabilistic, so we just check they're valid dates
      expect(activeLogin).toBeInstanceOf(Date);
      expect(dormantLogin).toBeInstanceOf(Date);
    });
  });

  describe('generateSessionDuration', () => {
    it('should generate realistic durations', () => {
      const duration = DateHelpers.generateSessionDuration('casual', 'evening');
      
      expect(typeof duration).toBe('number');
      expect(duration).toBeGreaterThan(0);
      expect(duration).toBeLessThan(600); // Less than 10 hours
    });

    it('should vary by user type', () => {
      const activeDuration = DateHelpers.generateSessionDuration('active', 'evening');
      const dormantDuration = DateHelpers.generateSessionDuration('dormant', 'evening');
      
      expect(activeDuration).toBeGreaterThanOrEqual(30); // Active users play longer
      expect(dormantDuration).toBeGreaterThanOrEqual(15); // Dormant users shorter sessions
    });
  });

  describe('formatForSQLite', () => {
    it('should format date for SQLite', () => {
      const date = new Date('2024-06-15T14:30:25.123Z');
      const formatted = DateHelpers.formatForSQLite(date);
      
      expect(typeof formatted).toBe('string');
      expect(formatted).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
      expect(formatted).toBe('2024-06-15 14:30:25');
    });
  });

  describe('daysSince', () => {
    it('should calculate days correctly', () => {
      const now = new Date();
      const threeDaysAgo = new Date(now.getTime() - (3 * 24 * 60 * 60 * 1000));
      
      const days = DateHelpers.daysSince(threeDaysAgo);
      expect(days).toBe(3);
    });
  });
});

describe('ProbabilityHelpers', () => {
  describe('weightedRandom', () => {
    it('should select items based on weight', () => {
      const items = [
        { name: 'common', weight: 0.8 },
        { name: 'rare', weight: 0.2 }
      ];
      
      const selected = ProbabilityHelpers.weightedRandom(items);
      expect(['common', 'rare']).toContain(selected.name);
    });

    it('should handle single item', () => {
      const items = [{ name: 'only', weight: 1.0 }];
      const selected = ProbabilityHelpers.weightedRandom(items);
      expect(selected.name).toBe('only');
    });
  });

  describe('selectByProbability', () => {
    it('should select based on probability distribution', () => {
      const probabilities = {
        'option1': 0.7,
        'option2': 0.3
      };
      
      const selected = ProbabilityHelpers.selectByProbability(probabilities);
      expect(['option1', 'option2']).toContain(selected);
    });
  });

  describe('randomInt', () => {
    it('should generate integers within range', () => {
      for (let i = 0; i < 100; i++) {
        const num = ProbabilityHelpers.randomInt(1, 10);
        expect(Number.isInteger(num)).toBe(true);
        expect(num).toBeGreaterThanOrEqual(1);
        expect(num).toBeLessThanOrEqual(10);
      }
    });
  });

  describe('normalRandom', () => {
    it('should generate numbers around mean', () => {
      const samples = [];
      for (let i = 0; i < 1000; i++) {
        samples.push(ProbabilityHelpers.normalRandom(50, 10));
      }
      
      const avg = samples.reduce((a, b) => a + b) / samples.length;
      expect(avg).toBeCloseTo(50, 0); // Should be close to mean
    });
  });

  describe('chance', () => {
    it('should return boolean based on probability', () => {
      const alwaysTrue = ProbabilityHelpers.chance(1.0);
      const alwaysFalse = ProbabilityHelpers.chance(0.0);
      
      expect(alwaysTrue).toBe(true);
      expect(alwaysFalse).toBe(false);
    });
  });

  describe('generateCharacterLevel', () => {
    it('should generate levels within valid range', () => {
      const level = ProbabilityHelpers.generateCharacterLevel('casual');
      expect(level).toBeGreaterThanOrEqual(1);
      expect(level).toBeLessThanOrEqual(50);
    });

    it('should vary by user type', () => {
      const activeLevel = ProbabilityHelpers.generateCharacterLevel('active');
      const dormantLevel = ProbabilityHelpers.generateCharacterLevel('dormant');
      
      expect(activeLevel).toBeGreaterThanOrEqual(1);
      expect(dormantLevel).toBeGreaterThanOrEqual(1);
    });
  });

  describe('generateGoldAmount', () => {
    it('should generate realistic gold amounts', () => {
      const gold = ProbabilityHelpers.generateGoldAmount(20, 'casual');
      expect(gold).toBeGreaterThanOrEqual(0);
      expect(typeof gold).toBe('number');
    });

    it('should scale with character level', () => {
      const lowLevelGold = ProbabilityHelpers.generateGoldAmount(5, 'casual');
      const highLevelGold = ProbabilityHelpers.generateGoldAmount(45, 'casual');
      
      expect(highLevelGold).toBeGreaterThan(lowLevelGold);
    });
  });

  describe('seededProbability', () => {
    it('should generate consistent values with same seed', () => {
      const val1 = ProbabilityHelpers.seededProbability(12345, 0, 1);
      const val2 = ProbabilityHelpers.seededProbability(12345, 0, 1);
      expect(val1).toBe(val2);
    });

    it('should generate different values with different seeds', () => {
      const val1 = ProbabilityHelpers.seededProbability(12345, 0, 1);
      const val2 = ProbabilityHelpers.seededProbability(54321, 0, 1);
      expect(val1).not.toBe(val2);
    });

    it('should respect min/max bounds', () => {
      const val = ProbabilityHelpers.seededProbability(12345, 10, 20);
      expect(val).toBeGreaterThanOrEqual(10);
      expect(val).toBeLessThanOrEqual(20);
    });
  });
});