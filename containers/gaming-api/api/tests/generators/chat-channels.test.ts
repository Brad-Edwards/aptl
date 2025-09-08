import { ChatChannelsGenerator } from '../../src/generators/chat-channels';
import { PrismaClient } from '../../generated/prisma';

describe('ChatChannelsGenerator', () => {
  let generator: ChatChannelsGenerator;
  let mockPrisma: jest.Mocked<PrismaClient>;

  beforeEach(() => {
    mockPrisma = new PrismaClient() as jest.Mocked<PrismaClient>;
    generator = new ChatChannelsGenerator(mockPrisma);
  });

  describe('generate', () => {
    it('should clear existing data and insert new channels', async () => {
      await generator.generate();
      
      expect(mockPrisma.chat_channels.deleteMany).toHaveBeenCalledWith({});
      expect(mockPrisma.chat_channels.createMany).toHaveBeenCalledWith({
        data: expect.arrayContaining([
          expect.objectContaining({ name: 'general', is_private: false, max_users: 100 }),
          expect.objectContaining({ name: 'trade', is_private: false, max_users: 50 }),
          expect.objectContaining({ name: 'guild', is_private: true, max_users: 25 }),
          expect.objectContaining({ name: 'help', is_private: false, max_users: 200 }),
          expect.objectContaining({ name: 'admin', is_private: false, max_users: 1000 }),
        ]),
      });
    });

    it('should handle database errors gracefully', async () => {
      (mockPrisma.chat_channels.deleteMany as jest.Mock).mockRejectedValue(new Error('Database error'));
      
      await expect(generator.generate()).rejects.toThrow('Database error');
    });
  });
});
