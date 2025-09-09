import { UsersGenerator } from '../../src/generators/users';
import { PrismaClient } from '../../generated/prisma';

describe('UsersGenerator', () => {
  let generator: UsersGenerator;
  let mockPrisma: jest.Mocked<PrismaClient>;

  beforeEach(() => {
    mockPrisma = new PrismaClient() as jest.Mocked<PrismaClient>;
    generator = new UsersGenerator(mockPrisma);
  });

  describe('generatePasswordChangeDate', () => {
    it('should generate date between created_at and last_login', () => {
      const created_at = new Date('2024-01-01');
      const last_login = new Date('2024-12-31');
      
      const passwordChangeDate = generator.generatePasswordChangeDate(created_at, last_login);
      
      expect(passwordChangeDate).toBeInstanceOf(Date);
      expect(passwordChangeDate.getTime()).toBeGreaterThanOrEqual(created_at.getTime());
      expect(passwordChangeDate.getTime()).toBeLessThanOrEqual(last_login.getTime());
    });

    it('should handle same created_at and last_login dates', () => {
      const date = new Date('2024-06-15');
      const passwordChangeDate = generator.generatePasswordChangeDate(date, date);
      
      expect(passwordChangeDate.getTime()).toBe(date.getTime());
    });
  });

  describe('generateSecurityQuestionsAnswered', () => {
    it('should return boolean value', () => {
      const result = generator.generateSecurityQuestionsAnswered();
      
      expect(typeof result).toBe('boolean');
    });

    it('should generate different values across multiple calls', () => {
      const results = Array.from({ length: 10 }, () => 
        generator.generateSecurityQuestionsAnswered()
      );
      
      // Should have both true and false values
      expect(results).toContain(true);
      expect(results).toContain(false);
    });
  });

  describe('transformUserData', () => {
    it('should transform static user data to database format', () => {
      const staticUser = {
        id: 1,
        username: "TestUser",
        email: "test@example.com",
        password_hash: "$2b$10$dummy",
        user_type: "active",
        created_at: "2024-03-15 10:30:00",
        last_login: "2025-01-08 14:22:33",
        is_premium: true,
        account_value: 2500,
        email_verified: true,
        total_playtime_hours: 847,
        last_ip_address: "203.45.67.89",
        preferred_language: "en-US",
        timezone: "America/New_York"
      };

      const result = generator.transformUserData(staticUser);
      
      expect(result).toEqual({
        username: "TestUser",
        email: "test@example.com",
        password_hash: "$2b$10$dummy",
        created_at: new Date('2024-03-15T10:30:00'),
        last_login: new Date('2025-01-08T14:22:33'),
        is_premium: true,
        total_playtime_hours: 847,
        preferred_language: "en-US",
        timezone: "America/New_York",
        last_password_change: expect.any(Date),
        security_questions_answered: expect.any(Boolean)
      });
      
      // Verify password change date is within bounds
      expect(result.last_password_change.getTime()).toBeGreaterThanOrEqual(result.created_at.getTime());
      expect(result.last_password_change.getTime()).toBeLessThanOrEqual(result.last_login.getTime());
    });

    it('should handle null last_login', () => {
      const staticUser = {
        id: 1,
        username: "TestUser",
        email: "test@example.com",
        password_hash: "$2b$10$dummy",
        user_type: "dormant",
        created_at: "2024-03-15 10:30:00",
        last_login: null,
        is_premium: false,
        account_value: 100,
        email_verified: false,
        total_playtime_hours: 50,
        last_ip_address: "203.45.67.89",
        preferred_language: "en-US",
        timezone: "UTC"
      };

      const result = generator.transformUserData(staticUser);
      
      expect(result.last_login).toBeNull();
      expect(result.last_password_change.getTime()).toBeGreaterThanOrEqual(result.created_at.getTime());
    });
  });

  describe('generate', () => {
    it('should clear existing data and insert transformed users', async () => {
      await generator.generate();
      
      expect(mockPrisma.users.deleteMany).toHaveBeenCalledWith({});
      expect(mockPrisma.users.createMany).toHaveBeenCalledWith({
        data: expect.arrayContaining([
          expect.objectContaining({
            username: expect.any(String),
            email: expect.any(String),
            password_hash: expect.any(String),
            created_at: expect.any(Date),
            last_login: expect.any(Date),
            is_premium: expect.any(Boolean),
            total_playtime_hours: expect.any(Number),
            preferred_language: expect.any(String),
            timezone: expect.any(String),
            last_password_change: expect.any(Date),
            security_questions_answered: expect.any(Boolean)
          })
        ])
      });
    });

    it('should handle database errors gracefully', async () => {
      (mockPrisma.users.deleteMany as jest.Mock).mockRejectedValue(new Error('Database error'));
      
      await expect(generator.generate()).rejects.toThrow('Database error');
    });
  });
});
