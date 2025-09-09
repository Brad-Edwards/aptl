import { PrismaClient } from '../../generated/prisma';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class ItemsGenerator {
  constructor(private prisma: PrismaClient) {}

  async generate(): Promise<void> {
    // Load static data from JSON
    const staticDataPath = path.join(__dirname, '../../data/static-data.json');
    const staticData = JSON.parse(fs.readFileSync(staticDataPath, 'utf8'));
    
    // Get category name to ID mapping
    const categories = await this.prisma.item_categories.findMany({
      select: { id: true, name: true }
    });
    const categoryMap = new Map(categories.map(c => [c.name, c.id]));
    
    // Clear existing data
    await this.prisma.items.deleteMany({});
    
    // Map items with correct category IDs
    const itemsWithCategoryIds = staticData.items.map((item: any) => ({
      name: item.name,
      gold_value: item.gold_value,
      category_id: categoryMap.get(item.category),
      rarity: item.rarity,
      item_type: item.item_type,
      level_requirement: item.level_requirement,
    }));
    
    // Insert items with correct foreign keys
    await this.prisma.items.createMany({
      data: itemsWithCategoryIds,
    });
  }
}
