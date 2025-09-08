import { PrismaClient } from '../generated/prisma';

// Mock Prisma client for testing
jest.mock('../generated/prisma', () => ({
  PrismaClient: jest.fn().mockImplementation(() => ({
    item_categories: {
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
