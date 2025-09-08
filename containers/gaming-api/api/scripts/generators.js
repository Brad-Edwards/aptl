const bcrypt = require('bcrypt');
const config = require('./config');

/**
 * Get a random element from array based on weighted distribution
 * @param {Array} items - Array of {weight, ...data} objects
 * @returns {Object} Selected item
 */
function weightedRandom(items) {
  const totalWeight = items.reduce((sum, item) => sum + item.weight, 0);
  const random = Math.random() * totalWeight;
  
  let currentWeight = 0;
  for (const item of items) {
    currentWeight += item.weight;
    if (random <= currentWeight) {
      return item;
    }
  }
  return items[items.length - 1];
}

/**
 * Generate a random integer between min and max (inclusive)
 * @param {number} min - Minimum value
 * @param {number} max - Maximum value
 * @returns {number} Random integer
 */
function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * Generate a random date between min and max days ago
 * @param {number} minDaysAgo - Minimum days in the past
 * @param {number} maxDaysAgo - Maximum days in the past
 * @returns {string} ISO date string
 */
function randomDate(minDaysAgo, maxDaysAgo) {
  const now = new Date();
  const daysAgo = randomInt(minDaysAgo, maxDaysAgo);
  const date = new Date(now - (daysAgo * 24 * 60 * 60 * 1000));
  return date.toISOString();
}

/**
 * Generate a realistic gaming username
 * @returns {string} Username
 */
function generateUsername() {
  const prefix = config.usernamePatterns[randomInt(0, config.usernamePatterns.length - 1)];
  const suffix = config.nameEndings[randomInt(0, config.nameEndings.length - 1)];
  return prefix + suffix;
}

/**
 * Generate a realistic email from username
 * @param {string} username - Username
 * @returns {string} Email address
 */
function generateEmail(username) {
  const domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
  const domain = domains[randomInt(0, domains.length - 1)];
  return `${username}@${domain}`;
}

/**
 * Generate user accounts with realistic patterns
 * @param {number} count - Number of users to generate
 * @returns {Promise<Array>} Array of user objects
 */
async function generateUsers(count) {
  const users = [];
  
  for (let i = 0; i < count; i++) {
    const username = generateUsername();
    
    // Account age determines other characteristics
    const ageCategory = weightedRandom([
      { weight: config.users.accountAge.new.weight, ...config.users.accountAge.new, type: 'new' },
      { weight: config.users.accountAge.active.weight, ...config.users.accountAge.active, type: 'active' },
      { weight: config.users.accountAge.dormant.weight, ...config.users.accountAge.dormant, type: 'dormant' }
    ]);
    
    const createdAt = randomDate(ageCategory.min, ageCategory.max);
    
    // Level correlates with account age
    let levelCategory;
    if (ageCategory.type === 'new') {
      levelCategory = config.users.levels.newbie;
    } else if (ageCategory.type === 'active') {
      levelCategory = Math.random() < 0.7 ? config.users.levels.casual : config.users.levels.veteran;
    } else { // dormant
      levelCategory = Math.random() < 0.5 ? config.users.levels.casual : config.users.levels.veteran;
    }
    
    const characterLevel = randomInt(levelCategory.min, levelCategory.max);
    
    // Wealth roughly correlates with level
    let goldCategory;
    if (characterLevel < 20) {
      goldCategory = config.users.goldDistribution.poor;
    } else if (characterLevel < 60) {
      goldCategory = Math.random() < 0.8 ? config.users.goldDistribution.poor : config.users.goldDistribution.middle;
    } else {
      goldCategory = weightedRandom([
        { weight: 0.4, ...config.users.goldDistribution.poor },
        { weight: 0.4, ...config.users.goldDistribution.middle },
        { weight: 0.2, ...config.users.goldDistribution.wealthy }
      ]);
    }
    
    const accountValue = randomInt(goldCategory.min, goldCategory.max);
    
    // Playtime correlates with level and account age
    const basePlaytime = characterLevel * 2;
    const playtimeVariation = randomInt(-basePlaytime * 0.3, basePlaytime * 0.3);
    const totalPlaytimeHours = Math.max(1, basePlaytime + playtimeVariation);
    
    // Last login based on account type
    let lastLogin;
    if (ageCategory.type === 'dormant') {
      lastLogin = randomDate(30, ageCategory.max);
    } else if (ageCategory.type === 'active') {
      lastLogin = randomDate(1, 7);
    } else { // new
      lastLogin = randomDate(1, 3);
    }
    
    // Generate consistent IP and user agent
    const ipSubnet = config.ipSubnets[randomInt(0, config.ipSubnets.length - 1)];
    const lastIp = `${ipSubnet}.${randomInt(1, 254)}`;
    const userAgent = config.userAgents[randomInt(0, config.userAgents.length - 1)];
    
    // Premium status
    const isPremium = Math.random() < config.users.premiumChance;
    
    // Generate password hash (using simple password for demo)
    const passwordHash = await bcrypt.hash('password123', 10);
    
    users.push({
      username,
      password_hash: passwordHash,
      email: generateEmail(username),
      created_at: createdAt,
      last_login: lastLogin,
      character_level: characterLevel,
      total_playtime_hours: totalPlaytimeHours,
      account_value: accountValue,
      is_premium: isPremium,
      last_ip: lastIp,
      user_agent: userAgent,
      _category: ageCategory.type // Helper for other generators
    });
  }
  
  return users;
}

/**
 * Generate item definitions
 * @returns {Array} Array of item objects
 */
function generateItems() {
  return config.items.map(item => ({
    name: item.name,
    value: item.value
  }));
}

/**
 * Generate realistic transaction history
 * @param {Array} users - Array of user objects
 * @param {Array} items - Array of item objects  
 * @param {number} count - Number of transactions to generate
 * @returns {Array} Array of transaction objects
 */
function generateTransactions(users, items, count) {
  const transactions = [];
  
  // Filter users who would actually trade
  const activeTraders = users.filter(u => 
    u._category === 'active' || (u._category === 'dormant' && Math.random() < 0.3)
  );
  
  for (let i = 0; i < count; i++) {
    // Select random trader and recipient
    const fromUser = activeTraders[randomInt(0, activeTraders.length - 1)];
    const toUser = users[randomInt(0, users.length - 1)];
    
    // Don't trade with yourself
    if (fromUser.username === toUser.username) {
      continue;
    }
    
    // Select item based on transaction value distribution
    const valueCategory = weightedRandom([
      { weight: config.transactions.valueDistribution.small.weight, ...config.transactions.valueDistribution.small },
      { weight: config.transactions.valueDistribution.medium.weight, ...config.transactions.valueDistribution.medium },
      { weight: config.transactions.valueDistribution.large.weight, ...config.transactions.valueDistribution.large }
    ]);
    
    // Find items in the value range
    const suitableItems = items.filter(item => 
      item.value >= valueCategory.min && item.value <= valueCategory.max
    );
    
    if (suitableItems.length === 0) {
      continue;
    }
    
    const item = suitableItems[randomInt(0, suitableItems.length - 1)];
    
    // Generate transaction timestamp (trading happens during account's active period)
    const userCreated = new Date(fromUser.created_at);
    const userLastLogin = new Date(fromUser.last_login);
    const transactionDate = new Date(userCreated.getTime() + 
      Math.random() * (userLastLogin.getTime() - userCreated.getTime())
    );
    
    transactions.push({
      from_username: fromUser.username,
      to_username: toUser.username,
      item_name: item.name,
      gold_value: item.value,
      timestamp: transactionDate.toISOString()
    });
  }
  
  // Sort by timestamp for realistic ordering
  transactions.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  
  return transactions;
}

/**
 * Generate authentication events (login attempts)
 * @param {Array} users - Array of user objects
 * @param {number} count - Number of auth events to generate
 * @returns {Array} Array of auth event objects
 */
function generateAuthEvents(users, count) {
  const authEvents = [];
  
  for (let i = 0; i < count; i++) {
    const user = users[randomInt(0, users.length - 1)];
    
    // Login frequency based on user category
    let loginChance;
    if (user._category === 'active') {
      loginChance = 0.9;
    } else if (user._category === 'new') {
      loginChance = 0.8;
    } else { // dormant
      loginChance = 0.1;
    }
    
    // Skip if this user wouldn't be logging in
    if (Math.random() > loginChance) {
      continue;
    }
    
    // Generate login attempt timestamp
    const userCreated = new Date(user.created_at);
    const now = new Date();
    const attemptDate = new Date(userCreated.getTime() + 
      Math.random() * (now.getTime() - userCreated.getTime())
    );
    
    // Success/failure based on normal failure rate
    const success = Math.random() > config.authEvents.normalFailureRate;
    
    // Use consistent IP and user agent for successful logins
    let ipAddress = user.last_ip;
    let userAgent = user.user_agent;
    
    // For failed attempts, sometimes use different IP/UA
    if (!success && Math.random() < 0.3) {
      const randomSubnet = config.ipSubnets[randomInt(0, config.ipSubnets.length - 1)];
      ipAddress = `${randomSubnet}.${randomInt(1, 254)}`;
      userAgent = config.userAgents[randomInt(0, config.userAgents.length - 1)];
    }
    
    authEvents.push({
      username: user.username,
      ip_address: ipAddress,
      user_agent: userAgent,
      success: success,
      timestamp: attemptDate.toISOString()
    });
  }
  
  // Sort by timestamp
  authEvents.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  
  return authEvents;
}

module.exports = {
  generateUsers,
  generateItems,
  generateTransactions,
  generateAuthEvents
};