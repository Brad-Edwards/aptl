import { PrismaClient } from '../../generated/prisma';
import * as fs from 'fs';
import * as path from 'path';

export class ItemCategoriesGenerator {
  constructor(private prisma: PrismaClient) {}

  async generate(): Promise<void> {
    // Load static data from JSON
    const staticDataPath = path.join(__dirname, '../../data/static-data.json');
    const staticData = JSON.parse(fs.readFileSync(staticDataPath, 'utf8'));
    
    // Clear existing data
    await this.prisma.item_categories.deleteMany({});
    
    // Insert categories from JSON
    await this.prisma.item_categories.createMany({
      data: staticData.item_categories,
    });
  }
}
