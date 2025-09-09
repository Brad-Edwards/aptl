import { PrismaClient } from '../generated/prisma/index.js';
import { ItemCategoriesGenerator } from '../src/generators/item-categories.js';
import { ItemsGenerator } from '../src/generators/items.js';
import { GameLocationsGenerator } from '../src/generators/game-locations.js';
import { ChatChannelsGenerator } from '../src/generators/chat-channels.js';
import { UsersGenerator } from '../src/generators/users.js';

async function seedDatabase() {
  const prisma = new PrismaClient();
  
  try {
    console.log('🚀 Starting database seeding...\n');
    
    // 1. Users - Base user accounts (no dependencies)
    console.log('👥 Generating users...');
    const usersGenerator = new UsersGenerator(prisma);
    await usersGenerator.generate();
    console.log('✅ Users generated successfully\n');
    
    // 2. Item Categories - Item categorization (no dependencies)
    console.log('📦 Generating item categories...');
    const itemCategoriesGenerator = new ItemCategoriesGenerator(prisma);
    await itemCategoriesGenerator.generate();
    console.log('✅ Item categories generated successfully\n');
    
    // 3. Items - Game items (depends on item_categories)
    console.log('🎮 Generating items...');
    const itemsGenerator = new ItemsGenerator(prisma);
    await itemsGenerator.generate();
    console.log('✅ Items generated successfully\n');
    
    // 4. Game Locations - Game areas (no dependencies)
    console.log('🗺️ Generating game locations...');
    const gameLocationsGenerator = new GameLocationsGenerator(prisma);
    await gameLocationsGenerator.generate();
    console.log('✅ Game locations generated successfully\n');
    
    // 5. Chat Channels - Chat rooms (no dependencies)
    console.log('💬 Generating chat channels...');
    const chatChannelsGenerator = new ChatChannelsGenerator(prisma);
    await chatChannelsGenerator.generate();
    console.log('✅ Chat channels generated successfully\n');
    
    // Verify data was inserted
    console.log('📊 Verifying data insertion...');
    const userCount = await prisma.users.count();
    const categoryCount = await prisma.item_categories.count();
    const itemCount = await prisma.items.count();
    const locationCount = await prisma.game_locations.count();
    const channelCount = await prisma.chat_channels.count();
    
    console.log(`\n📈 Database Statistics:`);
    console.log(`   Users: ${userCount}`);
    console.log(`   Item Categories: ${categoryCount}`);
    console.log(`   Items: ${itemCount}`);
    console.log(`   Game Locations: ${locationCount}`);
    console.log(`   Chat Channels: ${channelCount}`);
    
    console.log('\n🎉 Database seeding completed successfully!');
    
  } catch (error) {
    console.error('❌ Error during database seeding:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Run the seeding script
seedDatabase()
  .then(() => {
    console.log('✅ Script completed successfully');
    process.exit(0);
  })
  .catch((error) => {
    console.error('❌ Script failed:', error);
    process.exit(1);
  });