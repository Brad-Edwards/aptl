import { PrismaClient } from '../../generated/prisma';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class GameLocationsGenerator {
  constructor(private prisma: PrismaClient) {}

  async generate(): Promise<void> {
    // Load static data from JSON
    const staticDataPath = path.join(__dirname, '../../data/static-data.json');
    const staticData = JSON.parse(fs.readFileSync(staticDataPath, 'utf8'));
    
    // Clear existing data
    await this.prisma.game_locations.deleteMany({});
    
    // Insert locations from JSON
    await this.prisma.game_locations.createMany({
      data: staticData.game_locations,
    });
  }
}
