import { ItemCategoriesGenerator } from '../../src/generators/item-categories';
import { PrismaClient } from '../../generated/prisma';

describe('ItemCategoriesGenerator', () => {
  let generator: ItemCategoriesGenerator;
  let mockPrisma: jest.Mocked<PrismaClient>;

  beforeEach(() => {
    mockPrisma = new PrismaClient() as jest.Mocked<PrismaClient>;
    generator = new ItemCategoriesGenerator(mockPrisma);
  });

  describe('generate', () => {
    it('should clear existing data and insert new categories', async () => {
      await generator.generate();
      
      expect(mockPrisma.item_categories.deleteMany).toHaveBeenCalledWith({});
      expect(mockPrisma.item_categories.createMany).toHaveBeenCalledWith({
        data: [
          { name: 'Weapons', description: 'Combat weapons and tools', parent_id: null },
          { name: 'Armor', description: 'Protective gear and clothing', parent_id: null },
          { name: 'Consumables', description: 'Food, potions, and temporary items', parent_id: null },
          { name: 'Accessories', description: 'Rings, amulets, and jewelry', parent_id: null },
          { name: 'Materials', description: 'Crafting materials and components', parent_id: null },
          { name: 'Miscellaneous', description: 'Other items and curiosities', parent_id: null },
        ],
      });
    });

    it('should handle database errors gracefully', async () => {
      (mockPrisma.item_categories.deleteMany as jest.Mock).mockRejectedValue(new Error('Database error'));
      
      await expect(generator.generate()).rejects.toThrow('Database error');
    });
  });
});
