#!/usr/bin/env node

const path = require('path');
const fs = require('fs');

// Import configuration and utilities
const config = require('./config/base-config');
const Database = require('./database/connection');
const DataInserters = require('./database/inserters');
const DataValidator = require('./database/validators');

// Import generators
const UserGenerator = require('./generators/user-generator');
const CharacterGenerator = require('./generators/character-generator');
const ItemGenerator = require('./generators/item-generator');
const SessionGenerator = require('./generators/session-generator');
const ActivityGenerator = require('./generators/activity-generator');
const TransactionGenerator = require('./generators/transaction-generator');

class DataGenerationOrchestrator {
  constructor(config) {
    this.config = config;
    this.db = new Database();
    this.inserters = new DataInserters();
    
    // Initialize generators
    this.userGenerator = new UserGenerator(config);
    this.characterGenerator = new CharacterGenerator(config);
    this.itemGenerator = new ItemGenerator(config);
    this.sessionGenerator = new SessionGenerator(config);
    this.activityGenerator = new ActivityGenerator(config);
    this.transactionGenerator = new TransactionGenerator(config);
    
    this.generatedData = {};
    this.startTime = null;
  }

  async run() {
    try {
      this.startTime = Date.now();
      console.log('🚀 Starting Gaming API Data Generation');
      console.log('=====================================');
      
      // Connect to database
      await this.connectDatabase();
      
      // Verify schema exists
      await this.verifySchema();
      
      // Generate all data
      await this.generateAllData();
      
      // Validate data relationships
      await this.validateAllData();
      
      // Insert data into database
      await this.insertAllData();
      
      // Generate reports
      await this.generateReports();
      
      // Complete
      await this.complete();
      
    } catch (error) {
      console.error('❌ Data generation failed:', error.message);
      console.error(error.stack);
      process.exit(1);
    }
  }

  async connectDatabase() {
    console.log('🔌 Connecting to database...');
    await this.db.connect();
    await this.inserters.connect();
    
    console.log('✅ Database connection established');
  }

  async verifySchema() {
    console.log('🔍 Verifying database schema...');
    
    const requiredTables = [
      'users', 'characters', 'items', 'player_sessions', 'login_history', 
      'transactions', 'gameplay_activities', 'marketplace_activities', 
      'social_activities', 'character_progression', 'character_inventory'
    ];
    
    const missingTables = [];
    
    for (const table of requiredTables) {
      const exists = await this.db.tableExists(table);
      if (!exists) {
        missingTables.push(table);
      }
    }
    
    if (missingTables.length > 0) {
      throw new Error(`Missing required tables: ${missingTables.join(', ')}`);
    }
    
    console.log('✅ Schema verification complete');
  }

  async generateAllData() {
    console.log('📊 Generating data...');
    
    // Step 1: Generate users
    console.log('  👥 Generating users...');
    this.generatedData.users = await this.userGenerator.generateUsers();
    console.log(`    Generated ${this.generatedData.users.length} users`);
    
    // Step 2: Generate items (needed before characters for inventory)
    console.log('  🗡️  Generating items...');
    this.generatedData.items = await this.itemGenerator.generateItems();
    console.log(`    Generated ${this.generatedData.items.length} items`);
    
    // Step 3: Generate characters
    console.log('  🧙 Generating characters...');
    this.generatedData.characters = this.characterGenerator.generateCharacters(this.generatedData.users);
    console.log(`    Generated ${this.generatedData.characters.length} characters`);
    
    // Step 4: Generate sessions and login history
    console.log('  🔐 Generating sessions and login history...');
    const sessionData = this.sessionGenerator.generateSessions(this.generatedData.users, this.generatedData.characters);
    this.generatedData.sessions = sessionData.sessions;
    this.generatedData.loginHistory = sessionData.loginHistory;
    console.log(`    Generated ${this.generatedData.sessions.length} sessions`);
    console.log(`    Generated ${this.generatedData.loginHistory.length} login history entries`);
    
    // Step 5: Generate transactions
    console.log('  💰 Generating transactions...');
    const transactionData = this.transactionGenerator.generateTransactions(
      this.generatedData.users,
      this.generatedData.characters,
      this.generatedData.items,
      this.generatedData.sessions
    );
    this.generatedData.transactions = transactionData.transactions;
    this.generatedData.transactionDetails = transactionData.transactionDetails;
    console.log(`    Generated ${this.generatedData.transactions.length} transactions`);
    
    // Step 6: Generate activities for sessions
    console.log('  🎮 Generating gameplay activities...');
    await this.generateSessionActivities();
    
    // Step 7: Generate character progression
    console.log('  📈 Generating character progression...');
    this.generatedData.characterProgression = this.generateCharacterProgression();
    console.log(`    Generated ${this.generatedData.characterProgression.length} progression events`);
    
    // Step 8: Generate character inventories
    console.log('  🎒 Generating character inventories...');
    this.generatedData.characterInventory = this.generateCharacterInventories();
    console.log(`    Generated ${this.generatedData.characterInventory.length} inventory records`);
    
    console.log('✅ Data generation complete');
  }

  async generateSessionActivities() {
    this.generatedData.gameplayActivities = [];
    this.generatedData.marketplaceActivities = [];
    this.generatedData.socialActivities = [];
    
    let processedSessions = 0;
    const totalSessions = this.generatedData.sessions.length;
    
    for (const session of this.generatedData.sessions) {
      const character = this.generatedData.characters.find(c => c.id === session.character_id);
      if (!character) continue;
      
      const sessionPattern = session.session_pattern || 'direct_gameplay';
      const activities = this.activityGenerator.generateSessionActivities(session, character, sessionPattern);
      
      this.generatedData.gameplayActivities.push(...activities.gameplay);
      this.generatedData.marketplaceActivities.push(...activities.marketplace);
      this.generatedData.socialActivities.push(...activities.social);
      
      processedSessions++;
      if (processedSessions % 50 === 0) {
        console.log(`    Processed ${processedSessions}/${totalSessions} sessions`);
      }
    }
    
    console.log(`    Generated ${this.generatedData.gameplayActivities.length} gameplay activities`);
    console.log(`    Generated ${this.generatedData.marketplaceActivities.length} marketplace activities`);
    console.log(`    Generated ${this.generatedData.socialActivities.length} social activities`);
  }

  generateCharacterProgression() {
    const progressions = [];
    
    for (const character of this.generatedData.characters) {
      const charProgressions = this.characterGenerator.generateCharacterProgression(character);
      progressions.push(...charProgressions);
    }
    
    return progressions;
  }

  generateCharacterInventories() {
    const inventories = [];
    const inventoryMap = new Map(); // Track unique character-item pairs
    
    for (const character of this.generatedData.characters) {
      // Generate starting inventory
      const startingInventory = this.characterGenerator.generateInitialInventory(character, this.generatedData.items);
      
      for (const item of startingInventory) {
        const key = `${item.character_id}-${item.item_id}`;
        if (!inventoryMap.has(key)) {
          inventoryMap.set(key, item);
          inventories.push(item);
        }
      }
      
      // Add items from transactions (simplified) - avoid duplicates
      const charTransactions = this.generatedData.transactionDetails.filter(t => t.to_character_id === character.id);
      for (const transaction of charTransactions.slice(0, 3)) { // Reduced limit
        const key = `${character.id}-${transaction.item_id}`;
        if (!inventoryMap.has(key)) {
          const inventoryItem = {
            character_id: character.id,
            item_id: transaction.item_id,
            quantity: transaction.quantity,
            acquired_date: this.generatedData.transactions.find(t => t.id === transaction.transaction_id)?.timestamp,
            source: 'trade'
          };
          inventoryMap.set(key, inventoryItem);
          inventories.push(inventoryItem);
        }
      }
    }
    
    return inventories;
  }

  async validateAllData() {
    console.log('🔍 Validating generated data...');
    
    const allData = this.generatedData;
    const validation = DataValidator.validateAllData(allData, this.config);
    
    if (validation.errors.length > 0) {
      console.error('❌ Validation errors found:');
      validation.errors.slice(0, 10).forEach(error => console.error(`  - ${error}`));
      if (validation.errors.length > 10) {
        console.error(`  ... and ${validation.errors.length - 10} more errors`);
      }
      throw new Error('Data validation failed');
    }
    
    if (validation.warnings.length > 0) {
      console.warn('⚠️  Validation warnings:');
      validation.warnings.forEach(warning => console.warn(`  - ${warning}`));
    }
    
    console.log('✅ Data validation complete');
  }

  async insertAllData() {
    console.log('💾 Inserting data into database...');
    
    try {
      // Insert in dependency order
      console.log('  Inserting users...');
      await this.inserters.insertUsers(this.generatedData.users);
      
      console.log('  Inserting characters...');
      await this.inserters.insertCharacters(this.generatedData.characters);
      
      console.log('  Inserting items...');
      await this.inserters.insertItems(this.generatedData.items);
      
      console.log('  Inserting player sessions...');
      await this.inserters.insertPlayerSessions(this.generatedData.sessions);
      
      console.log('  Inserting login history...');
      await this.inserters.insertLoginHistory(this.generatedData.loginHistory);
      
      console.log('  Inserting transactions...');
      await this.inserters.insertTransactions(this.generatedData.transactions);
      
      console.log('  Inserting gameplay activities...');
      await this.inserters.insertGameplayActivities(this.generatedData.gameplayActivities);
      
      console.log('  Inserting marketplace activities...');
      await this.inserters.insertMarketplaceActivities(this.generatedData.marketplaceActivities);
      
      console.log('  Inserting social activities...');
      await this.inserters.insertSocialActivities(this.generatedData.socialActivities);
      
      console.log('  Inserting character progression...');
      await this.inserters.insertCharacterProgression(this.generatedData.characterProgression);
      
      console.log('  Inserting character inventory...');
      await this.inserters.insertCharacterInventory(this.generatedData.characterInventory);
      
    } catch (error) {
      console.error('❌ Database insertion failed:', error.message);
      throw error;
    }
    
    console.log('✅ Database insertion complete');
  }

  async generateReports() {
    console.log('📋 Generating reports...');
    
    const reports = {
      summary: this.generateSummaryReport(),
      users: this.generateUserReport(),
      characters: this.characterGenerator.generateCharacterReport(this.generatedData.characters),
      items: this.itemGenerator.generateItemReport(this.generatedData.items),
      sessions: this.sessionGenerator.generateSessionReport(this.generatedData.sessions),
      transactions: this.transactionGenerator.generateTransactionReport(this.generatedData.transactions),
      activities: this.generateActivityReport()
    };
    
    // Write reports to file
    const reportPath = path.join(__dirname, 'reports', `data-generation-report-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`);
    const reportDir = path.dirname(reportPath);
    
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }
    
    fs.writeFileSync(reportPath, JSON.stringify(reports, null, 2));
    
    // Print summary to console
    console.log('📊 Generation Summary:');
    console.log(`  Users: ${reports.summary.users}`);
    console.log(`  Characters: ${reports.summary.characters}`);
    console.log(`  Items: ${reports.summary.items}`);
    console.log(`  Sessions: ${reports.summary.sessions}`);
    console.log(`  Transactions: ${reports.summary.transactions}`);
    console.log(`  Total Activities: ${reports.summary.totalActivities}`);
    console.log(`📄 Full report saved to: ${reportPath}`);
  }

  generateSummaryReport() {
    return {
      users: this.generatedData.users.length,
      characters: this.generatedData.characters.length,
      items: this.generatedData.items.length,
      sessions: this.generatedData.sessions.length,
      loginHistory: this.generatedData.loginHistory.length,
      transactions: this.generatedData.transactions.length,
      gameplayActivities: this.generatedData.gameplayActivities.length,
      marketplaceActivities: this.generatedData.marketplaceActivities.length,
      socialActivities: this.generatedData.socialActivities.length,
      totalActivities: this.generatedData.gameplayActivities.length + 
                      this.generatedData.marketplaceActivities.length + 
                      this.generatedData.socialActivities.length,
      characterProgression: this.generatedData.characterProgression.length,
      characterInventory: this.generatedData.characterInventory.length,
      generationTime: Date.now() - this.startTime
    };
  }

  generateUserReport() {
    const report = {
      total: this.generatedData.users.length,
      byType: {},
      premiumUsers: 0,
      verifiedEmails: 0,
      averagePlaytime: 0
    };
    
    let totalPlaytime = 0;
    
    for (const user of this.generatedData.users) {
      const userType = user.user_type || 'unknown';
      report.byType[userType] = (report.byType[userType] || 0) + 1;
      
      if (user.is_premium) report.premiumUsers++;
      if (user.email_verified) report.verifiedEmails++;
      
      totalPlaytime += user.total_playtime_hours || 0;
    }
    
    report.averagePlaytime = Math.floor(totalPlaytime / this.generatedData.users.length);
    
    return report;
  }

  generateActivityReport() {
    return {
      gameplay: this.generatedData.gameplayActivities.length,
      marketplace: this.generatedData.marketplaceActivities.length,
      social: this.generatedData.socialActivities.length,
      progression: this.generatedData.characterProgression.length
    };
  }

  async complete() {
    const duration = Date.now() - this.startTime;
    const durationSeconds = Math.floor(duration / 1000);
    
    console.log('✅ Data generation completed successfully!');
    console.log(`⏱️  Total time: ${durationSeconds} seconds`);
    
    // Get final database stats
    const stats = await this.inserters.getInsertionStats();
    console.log('📈 Final database state:');
    Object.entries(stats).forEach(([table, count]) => {
      if (count > 0) {
        console.log(`  ${table}: ${count} records`);
      }
    });
    
    await this.inserters.disconnect();
    console.log('👋 Generation complete - database ready for CTF scenario!');
  }
}

// Command line interface
async function main() {
  const args = process.argv.slice(2);
  
  // Parse command line options
  const options = {
    config: 'base-config',
    dry: false,
    verbose: false
  };
  
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--config':
        options.config = args[i + 1];
        i++;
        break;
      case '--dry':
        options.dry = true;
        break;
      case '--verbose':
        options.verbose = true;
        break;
      case '--help':
        console.log('Gaming API Data Generator');
        console.log('Usage: node generate-data.js [options]');
        console.log('Options:');
        console.log('  --config <name>  Use specific config file (default: base-config)');
        console.log('  --dry           Generate data but don\'t insert into database');
        console.log('  --verbose       Enable verbose logging');
        console.log('  --help          Show this help message');
        process.exit(0);
      default:
        console.error(`Unknown option: ${args[i]}`);
        process.exit(1);
    }
  }
  
  // Load configuration
  let configModule;
  try {
    configModule = require(`./config/${options.config}`);
  } catch (error) {
    console.error(`Failed to load config: ${options.config}`);
    console.error('Available configs: base-config');
    process.exit(1);
  }
  
  // Set verbose logging
  if (options.verbose) {
    console.log('🔧 Verbose mode enabled');
  }
  
  // Run data generation
  const orchestrator = new DataGenerationOrchestrator(configModule);
  
  if (options.dry) {
    console.log('🔄 Dry run mode - data will not be inserted into database');
    // TODO: Implement dry run mode
  }
  
  await orchestrator.run();
}

// Run if called directly
if (require.main === module) {
  main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = { DataGenerationOrchestrator };