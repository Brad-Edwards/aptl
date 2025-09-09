import { ItemsGenerator } from '../../src/generators/items';
import { PrismaClient } from '../../generated/prisma';

describe('ItemsGenerator', () => {
  let generator: ItemsGenerator;
  let mockPrisma: jest.Mocked<PrismaClient>;

  beforeEach(() => {
    mockPrisma = new PrismaClient() as jest.Mocked<PrismaClient>;
    generator = new ItemsGenerator(mockPrisma);
  });

  describe('generate', () => {
    it('should clear existing data and insert new items with correct category mapping', async () => {
      await generator.generate();
      
      expect(mockPrisma.item_categories.findMany).toHaveBeenCalledWith({
        select: { id: true, name: true }
      });
      expect(mockPrisma.items.deleteMany).toHaveBeenCalledWith({});
      expect(mockPrisma.items.createMany).toHaveBeenCalledWith({
        data: expect.arrayContaining([
          expect.objectContaining({ name: 'Iron Sword', gold_value: 50, category_id: 1 }),
          expect.objectContaining({ name: 'Dragon Blade', gold_value: 1000, category_id: 1 }),
          expect.objectContaining({ name: 'Leather Armor', gold_value: 30, category_id: 2 }),
          expect.objectContaining({ name: 'Health Potion', gold_value: 10, category_id: 3 }),
        ]),
      });
    });

    it('should handle database errors gracefully', async () => {
      (mockPrisma.item_categories.findMany as jest.Mock).mockRejectedValue(new Error('Database error'));
      
      await expect(generator.generate()).rejects.toThrow('Database error');
    });
  });
});
