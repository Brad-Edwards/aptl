import { GameLocationsGenerator } from '../../src/generators/game-locations';
import { PrismaClient } from '../../generated/prisma';

describe('GameLocationsGenerator', () => {
  let generator: GameLocationsGenerator;
  let mockPrisma: jest.Mocked<PrismaClient>;

  beforeEach(() => {
    mockPrisma = new PrismaClient() as jest.Mocked<PrismaClient>;
    generator = new GameLocationsGenerator(mockPrisma);
  });

  describe('generate', () => {
    it('should clear existing data and insert new locations', async () => {
      await generator.generate();
      
      expect(mockPrisma.game_locations.deleteMany).toHaveBeenCalledWith({});
      expect(mockPrisma.game_locations.createMany).toHaveBeenCalledWith({
        data: expect.arrayContaining([
          expect.objectContaining({ name: 'Landing', type: 'hub', level_requirement: 1 }),
          expect.objectContaining({ name: 'Game', type: 'playground', level_requirement: 1 }),
          expect.objectContaining({ name: 'Chat', type: 'social', level_requirement: 1 }),
          expect.objectContaining({ name: 'Marketplace', type: 'commerce', level_requirement: 1 }),
          expect.objectContaining({ name: 'Settings', type: 'utility', level_requirement: 1 }),
        ]),
      });
    });

    it('should handle database errors gracefully', async () => {
      (mockPrisma.game_locations.deleteMany as jest.Mock).mockRejectedValue(new Error('Database error'));
      
      await expect(generator.generate()).rejects.toThrow('Database error');
    });
  });
});
