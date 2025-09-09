import { PrismaClient } from '../../generated/prisma';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface StaticUser {
  id: number;
  username: string;
  email: string;
  password_hash: string;
  user_type: string;
  created_at: string;
  last_login: string | null;
  is_premium: boolean;
  account_value: number;
  email_verified: boolean;
  total_playtime_hours: number;
  last_ip_address: string;
  preferred_language: string;
  timezone: string;
}

export class UsersGenerator {
  constructor(private prisma: PrismaClient) {}

  generatePasswordChangeDate(created_at: Date, last_login: Date | null): Date {
    if (!last_login) {
      // If no last login, password change is same as account creation
      return created_at;
    }
    
    // Generate random date between created_at and last_login (inclusive)
    const startTime = created_at.getTime();
    const endTime = last_login.getTime();
    const randomTime = startTime + Math.random() * (endTime - startTime);
    
    return new Date(randomTime);
  }

  generateSecurityQuestionsAnswered(): boolean {
    // 70% chance of having answered security questions (realistic for security analysis)
    return Math.random() < 0.7;
  }

  transformUserData(staticUser: StaticUser) {
    // Convert space-separated datetime to ISO format (replace space with T)
    const created_at = new Date(staticUser.created_at.replace(' ', 'T'));
    const last_login = staticUser.last_login ? new Date(staticUser.last_login.replace(' ', 'T')) : null;
    
    // Validate dates
    if (isNaN(created_at.getTime())) {
      throw new Error(`Invalid created_at date for user ${staticUser.username}: ${staticUser.created_at}`);
    }
    if (last_login && isNaN(last_login.getTime())) {
      throw new Error(`Invalid last_login date for user ${staticUser.username}: ${staticUser.last_login}`);
    }
    
    return {
      username: staticUser.username,
      email: staticUser.email,
      password_hash: staticUser.password_hash,
      created_at,
      last_login,
      is_premium: staticUser.is_premium,
      total_playtime_hours: staticUser.total_playtime_hours,
      preferred_language: staticUser.preferred_language,
      timezone: staticUser.timezone,
      last_password_change: this.generatePasswordChangeDate(created_at, last_login),
      security_questions_answered: this.generateSecurityQuestionsAnswered()
    };
  }

  async generate(): Promise<void> {
    // Load static user data from JSON
    const staticDataPath = path.join(__dirname, '../../data/static-data.json');
    const staticData = JSON.parse(fs.readFileSync(staticDataPath, 'utf8'));
    const staticUsers: StaticUser[] = staticData.users;
    
    // Clear existing data
    await this.prisma.users.deleteMany({});
    
    // Transform each user and prepare for database insertion
    const transformedUsers = staticUsers.map(user => this.transformUserData(user));
    
    // Insert transformed users
    await this.prisma.users.createMany({
      data: transformedUsers,
    });
  }
}
