import { PrismaClient } from '../../generated/prisma';
import * as fs from 'fs';
import * as path from 'path';

export class ChatChannelsGenerator {
  constructor(private prisma: PrismaClient) {}

  async generate(): Promise<void> {
    // Load static data from JSON
    const staticDataPath = path.join(__dirname, '../../data/static-data.json');
    const staticData = JSON.parse(fs.readFileSync(staticDataPath, 'utf8'));
    
    // Clear existing data
    await this.prisma.chat_channels.deleteMany({});
    
    // Insert channels from JSON
    await this.prisma.chat_channels.createMany({
      data: staticData.chat_channels,
    });
  }
}
