#!/usr/bin/env node

const { generateUsers, generateItems, generateTransactions, generateAuthEvents } = require('./generators');
const config = require('./config');

/**
 * Simple test runner
 */
function test(description, testFunction) {
  try {
    testFunction();
    console.log(`✓ ${description}`);
  } catch (error) {
    console.error(`✗ ${description}: ${error.message}`);
    process.exit(1);
  }
}

/**
 * Async test runner
 */
async function testAsync(description, testFunction) {
  try {
    await testFunction();
    console.log(`✓ ${description}`);
  } catch (error) {
    console.error(`✗ ${description}: ${error.message}`);
    process.exit(1);
  }
}

// Test generateItems function
test('generateItems returns correct structure', () => {
  const items = generateItems();
  
  if (!Array.isArray(items)) {
    throw new Error('generateItems should return an array');
  }
  
  if (items.length !== config.items.length) {
    throw new Error(`Expected ${config.items.length} items, got ${items.length}`);
  }
  
  items.forEach(item => {
    if (!item.name || typeof item.name !== 'string') {
      throw new Error('Item missing or invalid name field');
    }
    if (!item.value || typeof item.value !== 'number') {
      throw new Error('Item missing or invalid value field');
    }
  });
});

// Test generateUsers function
await testAsync('generateUsers returns valid user objects', async () => {
  const users = await generateUsers(3);
  
  if (!Array.isArray(users)) {
    throw new Error('generateUsers should return an array');
  }
  
  if (users.length !== 3) {
    throw new Error('generateUsers should return requested number of users');
  }
  
  users.forEach(user => {
    const requiredFields = [
      'username', 'password_hash', 'email', 'created_at', 'last_login',
      'character_level', 'total_playtime_hours', 'account_value', 'is_premium',
      'last_ip', 'user_agent'
    ];
    
    requiredFields.forEach(field => {
      if (user[field] === undefined || user[field] === null) {
        throw new Error(`User missing required field: ${field}`);
      }
    });
    
    // Type checks
    if (typeof user.username !== 'string') {
      throw new Error('username should be string');
    }
    if (typeof user.character_level !== 'number') {
      throw new Error('character_level should be number');
    }
    if (typeof user.is_premium !== 'boolean') {
      throw new Error('is_premium should be boolean');
    }
    
    // Range checks
    if (user.character_level < 1 || user.character_level > 100) {
      throw new Error('character_level should be between 1 and 100');
    }
    if (user.account_value < 0) {
      throw new Error('account_value should be non-negative');
    }
  });
});

// Test generateTransactions function
await testAsync('generateTransactions returns valid transaction objects', async () => {
  const users = await generateUsers(5);
  const items = generateItems();
  const transactions = generateTransactions(users, items, 10);
  
  if (!Array.isArray(transactions)) {
    throw new Error('generateTransactions should return an array');
  }
  
  if (transactions.length === 0) {
    throw new Error('generateTransactions should return some transactions');
  }
  
  const usernames = users.map(u => u.username);
  const itemNames = items.map(i => i.name);
  
  transactions.forEach(transaction => {
    const requiredFields = ['from_username', 'to_username', 'item_name', 'gold_value', 'timestamp'];
    
    requiredFields.forEach(field => {
      if (transaction[field] === undefined || transaction[field] === null) {
        throw new Error(`Transaction missing required field: ${field}`);
      }
    });
    
    if (!usernames.includes(transaction.from_username)) {
      throw new Error('Transaction from_username not found in users');
    }
    if (!usernames.includes(transaction.to_username)) {
      throw new Error('Transaction to_username not found in users');
    }
    if (!itemNames.includes(transaction.item_name)) {
      throw new Error('Transaction item_name not found in items');
    }
    if (typeof transaction.gold_value !== 'number' || transaction.gold_value <= 0) {
      throw new Error('Transaction gold_value should be positive number');
    }
    
    // Check timestamp is valid ISO string
    const date = new Date(transaction.timestamp);
    if (isNaN(date.getTime())) {
      throw new Error('Transaction timestamp should be valid ISO date string');
    }
  });
});

// Test generateAuthEvents function
await testAsync('generateAuthEvents returns valid auth event objects', async () => {
  const users = await generateUsers(3);
  const authEvents = generateAuthEvents(users, 10);
  
  if (!Array.isArray(authEvents)) {
    throw new Error('generateAuthEvents should return an array');
  }
  
  if (authEvents.length === 0) {
    throw new Error('generateAuthEvents should return some events');
  }
  
  const usernames = users.map(u => u.username);
  
  authEvents.forEach(event => {
    const requiredFields = ['username', 'ip_address', 'user_agent', 'success', 'timestamp'];
    
    requiredFields.forEach(field => {
      if (event[field] === undefined || event[field] === null) {
        throw new Error(`Auth event missing required field: ${field}`);
      }
    });
    
    if (!usernames.includes(event.username)) {
      throw new Error('Auth event username not found in users');
    }
    if (typeof event.success !== 'boolean') {
      throw new Error('Auth event success should be boolean');
    }
    if (typeof event.ip_address !== 'string') {
      throw new Error('Auth event ip_address should be string');
    }
    
    // Check timestamp is valid ISO string
    const date = new Date(event.timestamp);
    if (isNaN(date.getTime())) {
      throw new Error('Auth event timestamp should be valid ISO date string');
    }
  });
});

// Test data relationships
await testAsync('Generated data has valid relationships', async () => {
  const users = await generateUsers(5);
  const items = generateItems();
  const transactions = generateTransactions(users, items, 10);
  const authEvents = generateAuthEvents(users, 10);
  
  const usernames = new Set(users.map(u => u.username));
  const itemNames = new Set(items.map(i => i.name));
  
  // All transaction users should exist
  const invalidTransactionUsers = transactions.filter(t => 
    !usernames.has(t.from_username) || !usernames.has(t.to_username)
  );
  if (invalidTransactionUsers.length > 0) {
    throw new Error('Found transactions with invalid usernames');
  }
  
  // All transaction items should exist
  const invalidTransactionItems = transactions.filter(t => !itemNames.has(t.item_name));
  if (invalidTransactionItems.length > 0) {
    throw new Error('Found transactions with invalid item names');
  }
  
  // All auth event users should exist
  const invalidAuthUsers = authEvents.filter(e => !usernames.has(e.username));
  if (invalidAuthUsers.length > 0) {
    throw new Error('Found auth events with invalid usernames');
  }
});

console.log('\n✅ All tests passed!');