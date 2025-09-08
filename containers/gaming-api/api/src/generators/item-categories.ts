import { PrismaClient } from '../../generated/prisma';

export class ItemCategoriesGenerator {
  constructor(private prisma: PrismaClient) {}

  async generate(): Promise<void> {
    // Clear existing data
    await this.prisma.item_categories.deleteMany({});
    
    // Insert hardcoded categories
    await this.prisma.item_categories.createMany({
      data: [
        { name: 'Weapons', description: 'Combat weapons and tools', parent_id: null },
        { name: 'Armor', description: 'Protective gear and clothing', parent_id: null },
        { name: 'Consumables', description: 'Food, potions, and temporary items', parent_id: null },
        { name: 'Accessories', description: 'Rings, amulets, and jewelry', parent_id: null },
        { name: 'Materials', description: 'Crafting materials and components', parent_id: null },
        { name: 'Miscellaneous', description: 'Other items and curiosities', parent_id: null },
      ],
    });
  }
}
