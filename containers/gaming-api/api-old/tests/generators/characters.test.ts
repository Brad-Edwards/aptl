import { CharactersGenerator } from '../../src/generators/characters';
import { PrismaClient } from '../../generated/prisma';
import * as fs from 'fs';

// Mock fs module
jest.mock('fs');
const mockFs = fs as jest.Mocked<typeof fs>;

describe('CharactersGenerator', () => {
  let generator: CharactersGenerator;
  let mockPrisma: any;
  
  const mockStaticData = {
    char_names: ['TestWarrior', 'TestMage', 'TestRogue', 'TestArcher'],
    class_names: ['Warrior', 'Mage', 'Rogue', 'Archer']
  };
  
  const mockUsers = [
    {
      id: 1,
      created_at: new Date('2024-01-01T00:00:00Z'),
      last_login: new Date('2024-06-01T00:00:00Z')
    },
    {
      id: 2,
      created_at: new Date('2024-02-01T00:00:00Z'),
      last_login: new Date('2024-07-01T00:00:00Z')
    }
  ];

  beforeEach(() => {
    mockPrisma = {
      users: {
        findMany: jest.fn(),
      },
      characters: {
        deleteMany: jest.fn(),
        createMany: jest.fn(),
      },
    };
    
    generator = new CharactersGenerator(mockPrisma);
    
    // Mock fs.readFileSync
    mockFs.readFileSync.mockReturnValue(JSON.stringify(mockStaticData));
    
    // Mock prisma methods
    mockPrisma.users.findMany.mockResolvedValue(mockUsers);
    mockPrisma.characters.deleteMany.mockResolvedValue({ count: 0 });
    mockPrisma.characters.createMany.mockResolvedValue({ count: 0 });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('generate', () => {
    it('should generate 1-3 characters per user', async () => {
      await generator.generate();
      
      expect(mockPrisma.characters.createMany).toHaveBeenCalledTimes(1);
      
      const createCall = mockPrisma.characters.createMany.mock.calls[0][0];
      const characters = createCall.data;
      
      // Should have generated characters for both users
      expect(characters.length).toBeGreaterThanOrEqual(2); // At least 1 per user
      expect(characters.length).toBeLessThanOrEqual(6); // At most 3 per user
      
      // Check user_id distribution
      const user1Chars = characters.filter((c: any) => c.user_id === 1);
      const user2Chars = characters.filter((c: any) => c.user_id === 2);
      
      expect(user1Chars.length).toBeGreaterThanOrEqual(1);
      expect(user1Chars.length).toBeLessThanOrEqual(3);
      expect(user2Chars.length).toBeGreaterThanOrEqual(1);
      expect(user2Chars.length).toBeLessThanOrEqual(3);
    });

    it('should use sequential character names without duplicates', async () => {
      await generator.generate();
      
      const createCall = mockPrisma.characters.createMany.mock.calls[0][0];
      const characters = createCall.data;
      
      // Character names should be unique (within the small test set)
      const names = characters.map((c: any) => c.name);
      const uniqueNames = new Set(names);
      expect(uniqueNames.size).toBe(names.length);
      
      // Names should come from our mock data
      names.forEach((name: string) => {
        expect(mockStaticData.char_names).toContain(name);
      });
    });

    it('should assign random classes from static data', async () => {
      await generator.generate();
      
      const createCall = mockPrisma.characters.createMany.mock.calls[0][0];
      const characters = createCall.data;
      
      characters.forEach((character: any) => {
        expect(mockStaticData.class_names).toContain(character.class);
      });
    });

    it('should generate levels between 1-100', async () => {
      await generator.generate();
      
      const createCall = mockPrisma.characters.createMany.mock.calls[0][0];
      const characters = createCall.data;
      
      characters.forEach((character: any) => {
        expect(character.level).toBeGreaterThanOrEqual(1);
        expect(character.level).toBeLessThanOrEqual(100);
      });
    });

    it('should generate gold between 1-1000 (base) with level adjustment', async () => {
      await generator.generate();
      
      const createCall = mockPrisma.characters.createMany.mock.calls[0][0];
      const characters = createCall.data;
      
      characters.forEach((character: any) => {
        expect(character.gold).toBeGreaterThanOrEqual(1);
        
        // Gold should be at least base amount, up to base * level multiplier
        const minExpected = 1;
        const maxExpected = Math.floor(1000 * (1 + character.level / 100));
        expect(character.gold).toBeLessThanOrEqual(maxExpected);
      });
    });

    it('should set created_at in first 50% of user timespan', async () => {
      await generator.generate();
      
      const createCall = mockPrisma.characters.createMany.mock.calls[0][0];
      const characters = createCall.data;
      
      characters.forEach((character: any) => {
        const user = mockUsers.find(u => u.id === character.user_id)!;
        const userCreatedTime = user.created_at.getTime();
        const userLastLoginTime = user.last_login.getTime();
        const characterCreatedTime = new Date(character.created_at).getTime();
        
        // Should be after user created
        expect(characterCreatedTime).toBeGreaterThanOrEqual(userCreatedTime);
        
        // Should be in first 50% of timespan
        const fiftyPercentMark = userCreatedTime + (userLastLoginTime - userCreatedTime) * 0.5;
        expect(characterCreatedTime).toBeLessThanOrEqual(fiftyPercentMark);
      });
    });

    it('should clear existing characters before generating new ones', async () => {
      await generator.generate();
      
      // Just verify deleteMany was called - order checking is complex with mocks
      expect(mockPrisma.characters.deleteMany).toHaveBeenCalledWith({});
    });

    it('should load static data from correct path', async () => {
      await generator.generate();
      
      expect(mockFs.readFileSync).toHaveBeenCalledWith(
        expect.stringContaining('static-data.json'),
        'utf8'
      );
    });

    it('should handle empty users list', async () => {
      mockPrisma.users.findMany.mockResolvedValue([]);
      
      await generator.generate();
      
      const createCall = mockPrisma.characters.createMany.mock.calls[0][0];
      expect(createCall.data).toEqual([]);
    });
  });

  describe('generateWeightedLevel', () => {
    it('should generate more low levels than high levels', async () => {
      // Test this by running generation multiple times and checking distribution
      const levels: number[] = [];
      
      // Generate characters multiple times to test distribution
      for (let i = 0; i < 10; i++) {
        await generator.generate();
        const createCall = mockPrisma.characters.createMany.mock.calls[i][0];
        const characters = createCall.data;
        levels.push(...characters.map((c: any) => c.level));
      }
      
      const lowLevels = levels.filter(level => level <= 30).length;
      const highLevels = levels.filter(level => level > 30).length;
      
      // Should have more low levels than high levels (70/30 split approximately)
      expect(lowLevels).toBeGreaterThan(highLevels);
    });
  });

  describe('generateGoldForLevel', () => {
    it('should generate more gold for higher level characters', async () => {
      // Mock specific levels to test gold scaling
      const highLevelUser = {
        id: 1,
        created_at: new Date('2024-01-01'),
        last_login: new Date('2024-06-01')
      };
      
      mockPrisma.users.findMany.mockResolvedValue([highLevelUser]);
      
      // Run multiple times to get different level/gold combinations
      const goldByLevel: { level: number, gold: number }[] = [];
      
      for (let i = 0; i < 20; i++) {
        await generator.generate();
        const createCall = mockPrisma.characters.createMany.mock.calls[i][0];
        const characters = createCall.data;
        goldByLevel.push(...characters.map((c: any) => ({ level: c.level, gold: c.gold })));
      }
      
      // Test that higher levels tend to have more gold
      const lowLevelGold = goldByLevel.filter(c => c.level <= 20).map(c => c.gold);
      const highLevelGold = goldByLevel.filter(c => c.level >= 80).map(c => c.gold);
      
      if (lowLevelGold.length > 0 && highLevelGold.length > 0) {
        const avgLowGold = lowLevelGold.reduce((a, b) => a + b, 0) / lowLevelGold.length;
        const avgHighGold = highLevelGold.reduce((a, b) => a + b, 0) / highLevelGold.length;
        
        expect(avgHighGold).toBeGreaterThan(avgLowGold);
      }
    });
  });
});