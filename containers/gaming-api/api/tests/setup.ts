import { PrismaClient } from '../generated/prisma';

// Mock Prisma client for testing
        jest.mock('../generated/prisma', () => ({
          PrismaClient: jest.fn().mockImplementation(() => ({
            item_categories: {
              create: jest.fn(),
              createMany: jest.fn().mockResolvedValue({ count: 0 }),
              findMany: jest.fn().mockResolvedValue([
                { id: 1, name: 'Weapons' },
                { id: 2, name: 'Armor' },
                { id: 3, name: 'Consumables' },
                { id: 4, name: 'Accessories' },
                { id: 5, name: 'Materials' },
                { id: 6, name: 'Miscellaneous' },
              ]),
              findUnique: jest.fn(),
              delete: jest.fn(),
              deleteMany: jest.fn(),
            },
            items: {
              create: jest.fn(),
              createMany: jest.fn().mockResolvedValue({ count: 0 }),
              findMany: jest.fn(),
              findUnique: jest.fn(),
              delete: jest.fn(),
              deleteMany: jest.fn(),
            },
            $disconnect: jest.fn(),
          })),
        }));

// Global test utilities
global.testUtils = {
  createMockPrismaClient: () => new PrismaClient(),
};
