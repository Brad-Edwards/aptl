import { PrismaClient } from '../../generated/prisma';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class CharactersGenerator {
  private charNameIndex = 0;

  constructor(private prisma: PrismaClient) {}

  async generate(): Promise<void> {
    // Load static data
    const staticDataPath = path.join(__dirname, '../../data/static-data.json');
    const staticData = JSON.parse(fs.readFileSync(staticDataPath, 'utf8'));
    
    const charNames: string[] = staticData.char_names;
    const classNames: string[] = staticData.class_names;
    
    // Get all users
    const users = await this.prisma.users.findMany({
      select: { id: true, created_at: true, last_login: true }
    });
    
    // Clear existing characters
    await this.prisma.characters.deleteMany({});
    
    const characters = [];
    this.charNameIndex = 0;
    
    for (const user of users) {
      // Random 1-3 characters per user
      const numCharacters = Math.floor(Math.random() * 3) + 1;
      
      for (let i = 0; i < numCharacters; i++) {
        // Sequential character name (avoid duplicates)
        const charName = charNames[this.charNameIndex % charNames.length];
        this.charNameIndex++;
        
        // Random class
        const characterClass = classNames[Math.floor(Math.random() * classNames.length)];
        
        // Level: 1-100, weighted low (higher chance of low levels)
        const level = this.generateWeightedLevel();
        
        // Gold: 1-1000 with level adjustment
        const gold = this.generateGoldForLevel(level);
        
        // created_at: random time in first 50% between user created_at and last_login
        const createdAt = this.generateCharacterCreatedAt(user.created_at!, user.last_login!);
        
        characters.push({
          user_id: user.id,
          name: charName,
          class: characterClass,
          level: level,
          gold: gold,
          created_at: createdAt
        });
      }
    }
    
    // Insert all characters
    await this.prisma.characters.createMany({
      data: characters
    });
    
    console.log(`Generated ${characters.length} characters for ${users.length} users`);
  }
  
  private generateWeightedLevel(): number {
    // Weight towards lower levels - 70% chance of level 1-30, 30% chance of 31-100
    if (Math.random() < 0.7) {
      return Math.floor(Math.random() * 30) + 1; // 1-30
    } else {
      return Math.floor(Math.random() * 70) + 31; // 31-100
    }
  }
  
  private generateGoldForLevel(level: number): number {
    // Base gold: 1-1000, with level multiplier
    const baseGold = Math.floor(Math.random() * 1000) + 1;
    const levelMultiplier = 1 + (level / 100); // 1.01x to 2.0x based on level
    return Math.floor(baseGold * levelMultiplier);
  }
  
  private generateCharacterCreatedAt(userCreatedAt: Date, userLastLogin: Date): Date {
    const userCreatedTime = userCreatedAt.getTime();
    const userLastLoginTime = userLastLogin.getTime();
    
    // First 50% of time between account creation and last login
    const timeRange = (userLastLoginTime - userCreatedTime) * 0.5;
    const randomTime = userCreatedTime + Math.random() * timeRange;
    
    return new Date(randomTime);
  }
}