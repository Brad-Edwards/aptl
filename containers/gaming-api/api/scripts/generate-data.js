#!/usr/bin/env node

const config = require('./config');
const { generateUsers, generateItems, generateTransactions, generateAuthEvents } = require('./generators');
const { 
  connectToDatabase, 
  clearDatabase, 
  insertUsers, 
  insertItems, 
  insertTransactions, 
  insertAuthEvents,
  closeDatabase 
} = require('./database');

/**
 * Validate that generated data has proper relationships
 * @param {Object} data - Generated data object
 * @returns {boolean} True if data is valid
 */
function validateData(data) {
  const { users, items, transactions, authEvents } = data;
  
  console.log('Validating data relationships...');
  
  // Check that all transaction users exist
  const usernames = new Set(users.map(u => u.username));
  const invalidTransactions = transactions.filter(t => 
    !usernames.has(t.from_username) || !usernames.has(t.to_username)
  );
  
  if (invalidTransactions.length > 0) {
    console.error(`Found ${invalidTransactions.length} transactions with invalid usernames`);
    return false;
  }
  
  // Check that all transaction items exist
  const itemNames = new Set(items.map(i => i.name));
  const invalidItems = transactions.filter(t => !itemNames.has(t.item_name));
  
  if (invalidItems.length > 0) {
    console.error(`Found ${invalidItems.length} transactions with invalid items`);
    return false;
  }
  
  // Check that all auth events have valid usernames
  const invalidAuthEvents = authEvents.filter(e => !usernames.has(e.username));
  
  if (invalidAuthEvents.length > 0) {
    console.error(`Found ${invalidAuthEvents.length} auth events with invalid usernames`);
    return false;
  }
  
  console.log('Data validation passed');
  return true;
}

/**
 * Print summary statistics about generated data
 * @param {Object} data - Generated data object
 */
function printSummary(data) {
  const { users, items, transactions, authEvents } = data;
  
  console.log('\n=== Data Generation Summary ===');
  console.log(`Users: ${users.length}`);
  console.log(`Items: ${items.length}`);
  console.log(`Transactions: ${transactions.length}`);
  console.log(`Auth Events: ${authEvents.length}`);
  
  // User category breakdown
  const userCategories = users.reduce((acc, user) => {
    acc[user._category] = (acc[user._category] || 0) + 1;
    return acc;
  }, {});
  console.log('\nUser Categories:');
  Object.entries(userCategories).forEach(([category, count]) => {
    console.log(`  ${category}: ${count}`);
  });
  
  // Transaction value breakdown
  const totalValue = transactions.reduce((sum, t) => sum + t.gold_value, 0);
  console.log(`\nTotal Transaction Value: ${totalValue} gold`);
  console.log(`Average Transaction: ${Math.round(totalValue / transactions.length)} gold`);
  
  // Auth success rate
  const successfulLogins = authEvents.filter(e => e.success).length;
  const successRate = ((successfulLogins / authEvents.length) * 100).toFixed(1);
  console.log(`\nLogin Success Rate: ${successRate}%`);
}

/**
 * Main execution function
 */
async function main() {
  let db;
  
  try {
    console.log('Starting data generation...');
    console.log(`Target: ${config.userCount} users, ${config.transactionCount} transactions, ${config.authEventCount} auth events`);
    
    // Connect to database
    console.log('\nConnecting to database...');
    db = await connectToDatabase();
    
    // Clear existing data
    console.log('Clearing existing data...');
    await clearDatabase(db);
    
    // Generate all data
    console.log('\nGenerating users...');
    const users = await generateUsers(config.userCount);
    
    console.log('Generating items...');
    const items = generateItems();
    
    console.log('Generating transactions...');
    const transactions = generateTransactions(users, items, config.transactionCount);
    
    console.log('Generating auth events...');
    const authEvents = generateAuthEvents(users, config.authEventCount);
    
    // Validate data
    const data = { users, items, transactions, authEvents };
    if (!validateData(data)) {
      throw new Error('Data validation failed');
    }
    
    // Insert data into database
    console.log('\nInserting data into database...');
    console.log('  - Inserting users...');
    await insertUsers(db, users);
    
    console.log('  - Inserting items...');
    await insertItems(db, items);
    
    console.log('  - Inserting transactions...');
    await insertTransactions(db, transactions);
    
    console.log('  - Inserting auth events...');
    await insertAuthEvents(db, authEvents);
    
    // Print summary
    printSummary(data);
    
    console.log('\n✅ Data generation completed successfully!');
    
  } catch (error) {
    console.error('\n❌ Data generation failed:', error.message);
    process.exit(1);
  } finally {
    if (db) {
      await closeDatabase(db);
    }
  }
}

// Run the script
if (require.main === module) {
  main();
}

module.exports = { main };