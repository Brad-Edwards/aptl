const DateHelpers = require('../utils/date-helpers');
const ProbabilityHelpers = require('../utils/probability');

class TransactionGenerator {
  constructor(config) {
    this.config = config;
  }

  generateTransactions(users, characters, items, sessions) {
    const transactions = [];
    const transactionDetails = [];
    
    console.log(`Generating ${this.config.economy.transactions.count} transactions`);
    
    // Create user and character lookup maps
    const userMap = new Map(users.map(u => [u.id, u]));
    const characterMap = new Map(characters.map(c => [c.id, c]));
    const charactersByUser = this.groupCharactersByUser(characters);
    
    // Filter active users (those with sessions) for more realistic trading
    const activeUserIds = new Set(sessions.map(s => s.user_id));
    const activeUsers = users.filter(u => activeUserIds.has(u.id));
    
    const targetCount = this.config.economy.transactions.count;
    
    for (let i = 0; i < targetCount; i++) {
      const transaction = this.generateTransaction(
        i + 1,
        activeUsers,
        charactersByUser,
        items,
        sessions,
        userMap,
        characterMap
      );
      
      if (transaction) {
        transactions.push(transaction.main);
        if (transaction.details) {
          transactionDetails.push(...transaction.details);
        }
      }
    }
    
    console.log(`Generated ${transactions.length} transactions with ${transactionDetails.length} detail records`);
    
    return { transactions, transactionDetails };
  }

  groupCharactersByUser(characters) {
    const grouped = {};
    for (const character of characters) {
      if (!grouped[character.user_id]) {
        grouped[character.user_id] = [];
      }
      grouped[character.user_id].push(character);
    }
    return grouped;
  }

  generateTransaction(transactionId, users, charactersByUser, items, sessions, userMap, characterMap) {
    // Select transaction type
    const transactionType = this.selectTransactionType(transactionId);
    
    // Select two different users for the transaction
    const { fromUser, toUser } = this.selectTransactionUsers(users, transactionId);
    if (!fromUser || !toUser || fromUser.id === toUser.id) {
      return null; // Skip if we can't find suitable users
    }
    
    // Select characters from each user
    const fromCharacters = charactersByUser[fromUser.id] || [];
    const toCharacters = charactersByUser[toUser.id] || [];
    
    if (fromCharacters.length === 0 || toCharacters.length === 0) {
      return null; // Skip if users don't have characters
    }
    
    const fromCharacter = ProbabilityHelpers.consistentSelect(fromCharacters, transactionId);
    const toCharacter = ProbabilityHelpers.consistentSelect(toCharacters, transactionId * 2);
    
    // Select item to trade
    const item = this.selectTransactionItem(items, fromCharacter, toCharacter, transactionId);
    if (!item) {
      return null; // Skip if no suitable item found
    }
    
    // Generate transaction price
    const price = this.generateTransactionPrice(item, transactionType, fromCharacter.level, toCharacter.level);
    
    // Generate transaction timestamp
    const timestamp = this.generateTransactionTimestamp(fromUser, toUser, sessions);
    
    // Create main transaction record (legacy format)
    const mainTransaction = {
      id: transactionId,
      from_username: fromUser.username,
      to_username: toUser.username,
      item_name: item.name,
      gold_value: price,
      timestamp: DateHelpers.formatForSQLite(timestamp)
    };
    
    // Create detailed transaction record (enhanced format)
    const transactionDetail = {
      transaction_id: transactionId,
      from_character_id: fromCharacter.id,
      to_character_id: toCharacter.id,
      item_id: item.id,
      quantity: this.generateTransactionQuantity(item, transactionType),
      unit_price: price,
      transaction_type: transactionType
    };
    
    return {
      main: mainTransaction,
      details: [transactionDetail]
    };
  }

  selectTransactionType(transactionId) {
    const types = this.config.economy.transactions.types;
    
    const random = ProbabilityHelpers.seededProbability(transactionId * 123, 0, 1);
    let cumulative = 0;
    
    for (const [type, probability] of Object.entries(types)) {
      cumulative += probability;
      if (random <= cumulative) {
        return type;
      }
    }
    
    return 'player_trade'; // Default fallback
  }

  selectTransactionUsers(users, transactionId) {
    // For realistic trading, bias towards users of similar levels and activity
    const shuffled = [...users].sort(() => 0.5 - Math.random());
    
    if (shuffled.length < 2) {
      return { fromUser: null, toUser: null };
    }
    
    // Select from user
    const fromIndex = ProbabilityHelpers.seededProbability(transactionId * 456, 0, 1) * shuffled.length;
    const fromUser = shuffled[Math.floor(fromIndex)];
    
    // Select to user (try to find someone with similar activity level)
    let toUser = null;
    const fromUserType = fromUser.user_type;
    
    // First try to find someone of similar type
    const similarUsers = shuffled.filter(u => u.id !== fromUser.id && u.user_type === fromUserType);
    if (similarUsers.length > 0) {
      const toIndex = ProbabilityHelpers.seededProbability(transactionId * 789, 0, 1) * similarUsers.length;
      toUser = similarUsers[Math.floor(toIndex)];
    } else {
      // Fallback to any other user
      const otherUsers = shuffled.filter(u => u.id !== fromUser.id);
      if (otherUsers.length > 0) {
        const toIndex = ProbabilityHelpers.seededProbability(transactionId * 987, 0, 1) * otherUsers.length;
        toUser = otherUsers[Math.floor(toIndex)];
      }
    }
    
    return { fromUser, toUser };
  }

  selectTransactionItem(items, fromCharacter, toCharacter, transactionId) {
    // Filter items appropriate for the characters' levels
    const fromLevel = fromCharacter.level;
    const toLevel = toCharacter.level;
    const avgLevel = (fromLevel + toLevel) / 2;
    
    // Select items that are appropriate for the level range
    const suitableItems = items.filter(item => {
      // Item should be usable by at least one character
      return item.level_requirement <= Math.max(fromLevel, toLevel) &&
             item.level_requirement >= Math.min(1, avgLevel - 10);
    });
    
    if (suitableItems.length === 0) {
      return items[transactionId % items.length]; // Fallback to any item
    }
    
    // Weight items by their suitability
    const weightedItems = suitableItems.map(item => ({
      item,
      weight: this.calculateItemTradeWeight(item, fromCharacter, toCharacter)
    }));
    
    return ProbabilityHelpers.weightedRandom(weightedItems).item;
  }

  calculateItemTradeWeight(item, fromCharacter, toCharacter) {
    let weight = 1.0;
    
    // More common items are traded more frequently
    const rarityWeights = {
      'common': 0.5,
      'rare': 0.3,
      'epic': 0.15,
      'legendary': 0.05
    };
    weight *= (rarityWeights[item.rarity] || 0.3);
    
    // Items closer to character levels are more likely to be traded
    const avgLevel = (fromCharacter.level + toCharacter.level) / 2;
    const levelDiff = Math.abs(item.level_requirement - avgLevel);
    weight *= Math.max(0.1, 1 - (levelDiff / 25)); // Reduce weight as level difference increases
    
    // Certain item types are more frequently traded
    const typeWeights = {
      'weapons': 1.2,
      'armor': 1.1,
      'consumables': 0.8, // Less traded, more used
      'materials': 1.3    // High demand for crafting
    };
    weight *= (typeWeights[item.item_type] || 1.0);
    
    return weight;
  }

  generateTransactionPrice(item, transactionType, fromLevel, toLevel) {
    let basePrice = item.gold_value;
    const priceVariation = this.config.economy.transactions.priceVariation;
    
    // Apply price variation
    const variance = (Math.random() - 0.5) * 2 * priceVariation;
    let finalPrice = Math.floor(basePrice * (1 + variance));
    
    // Transaction type affects price
    switch (transactionType) {
      case 'player_trade':
        // Fair market price
        break;
      case 'marketplace_sale':
        // Slightly higher than trade price (marketplace fee)
        finalPrice = Math.floor(finalPrice * 1.05);
        break;
      case 'gift':
        // Gifts are recorded at market value but no actual payment
        break;
    }
    
    // Character level affects negotiating ability
    const avgLevel = (fromLevel + toLevel) / 2;
    if (avgLevel > 30) {
      // High level players get better deals
      finalPrice = Math.floor(finalPrice * 0.95);
    } else if (avgLevel < 10) {
      // Low level players pay slightly more
      finalPrice = Math.floor(finalPrice * 1.05);
    }
    
    return Math.max(1, finalPrice);
  }

  generateTransactionQuantity(item, transactionType) {
    // Most items are traded in quantity of 1, but consumables and materials can be bulk
    if (item.item_type === 'consumables') {
      return ProbabilityHelpers.randomInt(1, 5); // 1-5 potions, etc.
    } else if (item.item_type === 'materials') {
      return ProbabilityHelpers.randomInt(1, 10); // 1-10 ore, etc.
    } else {
      return 1; // Weapons and armor typically traded individually
    }
  }

  generateTransactionTimestamp(fromUser, toUser, sessions) {
    // Find sessions from both users to generate realistic transaction timing
    const fromSessions = sessions.filter(s => s.user_id === fromUser.id);
    const toSessions = sessions.filter(s => s.user_id === toUser.id);
    
    // If both users have sessions, find overlapping time periods
    if (fromSessions.length > 0 && toSessions.length > 0) {
      // Try to find recent sessions from both users
      const recentFromSessions = fromSessions.slice(-3); // Last 3 sessions
      const recentToSessions = toSessions.slice(-3);
      
      // Pick a random session from the from user
      const fromSession = ProbabilityHelpers.getRandomElement(recentFromSessions);
      
      // Generate timestamp within reasonable time of from session
      const sessionTime = new Date(fromSession.login_time);
      const variance = 24 * 60 * 60 * 1000; // Within 24 hours of session
      
      return new Date(sessionTime.getTime() + (Math.random() - 0.5) * variance);
    }
    
    // Fallback to random time within last 30 days
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - (30 * 24 * 60 * 60 * 1000));
    
    return DateHelpers.randomDateBetween(thirtyDaysAgo, now);
  }

  // Generate guild transactions (internal trading)
  generateGuildTransactions(users, characters, items, sessions, guildId = 1) {
    const guildTransactions = [];
    
    // Select a subset of users to be in the guild
    const guildSize = Math.min(20, Math.floor(users.length * 0.3)); // 30% of users in guilds
    const guildUsers = ProbabilityHelpers.selectMultiple(users, guildSize);
    
    // Generate internal guild trades (often at discounted prices or as gifts)
    const guildTradeCount = Math.floor(this.config.economy.transactions.count * 0.2); // 20% guild trades
    
    for (let i = 0; i < guildTradeCount; i++) {
      if (guildUsers.length < 2) break;
      
      const fromUser = ProbabilityHelpers.getRandomElement(guildUsers);
      const toUser = ProbabilityHelpers.getRandomElement(guildUsers.filter(u => u.id !== fromUser.id));
      
      // Generate guild-style transaction (often gifts or heavily discounted)
      const transactionType = Math.random() < 0.3 ? 'gift' : 'player_trade';
      
      // ... rest of transaction generation similar to regular transactions
      // but with guild-specific pricing and item selection
    }
    
    return guildTransactions;
  }

  // Generate market listing activities (items put up for sale)
  generateMarketListings(users, characters, items, sessions) {
    const listings = [];
    
    // Some transactions represent marketplace listings rather than direct trades
    const listingCount = Math.floor(this.config.economy.transactions.count * 0.4);
    
    for (let i = 0; i < listingCount; i++) {
      const user = ProbabilityHelpers.getRandomElement(users);
      const userCharacters = characters.filter(c => c.user_id === user.id);
      
      if (userCharacters.length === 0) continue;
      
      const character = ProbabilityHelpers.getRandomElement(userCharacters);
      const item = ProbabilityHelpers.getRandomElement(items);
      
      // Generate listing (no buyer yet, represents item put up for sale)
      const listing = {
        character_id: character.id,
        item_id: item.id,
        quantity: this.generateTransactionQuantity(item, 'marketplace_sale'),
        listing_price: this.generateMarketListingPrice(item),
        listed_date: this.generateTransactionTimestamp(user, user, sessions),
        status: 'active' // Could be 'sold', 'expired', 'cancelled'
      };
      
      listings.push(listing);
    }
    
    return listings;
  }

  generateMarketListingPrice(item) {
    const basePrice = item.gold_value;
    const markup = 1.1 + Math.random() * 0.3; // 10-40% markup for listings
    return Math.floor(basePrice * markup);
  }

  // Generate character inventory updates based on transactions
  generateInventoryUpdates(transactions, transactionDetails) {
    const inventoryUpdates = [];
    
    for (const detail of transactionDetails) {
      // Item leaves from_character inventory
      inventoryUpdates.push({
        character_id: detail.from_character_id,
        item_id: detail.item_id,
        quantity_change: -detail.quantity,
        transaction_id: detail.transaction_id,
        change_type: 'trade_out'
      });
      
      // Item enters to_character inventory
      inventoryUpdates.push({
        character_id: detail.to_character_id,
        item_id: detail.item_id,
        quantity_change: detail.quantity,
        transaction_id: detail.transaction_id,
        change_type: 'trade_in'
      });
    }
    
    return inventoryUpdates;
  }

  // Validation
  validateTransactions(transactions, users, items) {
    const errors = [];
    const usernames = new Set(users.map(u => u.username));
    const itemNames = new Set(items.map(i => i.name));
    
    for (const transaction of transactions) {
      if (!usernames.has(transaction.from_username)) {
        errors.push(`Transaction references non-existent user: ${transaction.from_username}`);
      }
      
      if (!usernames.has(transaction.to_username)) {
        errors.push(`Transaction references non-existent user: ${transaction.to_username}`);
      }
      
      if (transaction.from_username === transaction.to_username) {
        errors.push('Transaction from user to same user (self-trade)');
      }
      
      if (!itemNames.has(transaction.item_name)) {
        errors.push(`Transaction references non-existent item: ${transaction.item_name}`);
      }
      
      if (transaction.gold_value <= 0) {
        errors.push('Transaction has invalid gold value');
      }
      
      if (!DateHelpers.isValidDate(transaction.timestamp)) {
        errors.push('Transaction has invalid timestamp');
      }
    }
    
    return errors;
  }

  // Generate transaction distribution report
  generateTransactionReport(transactions) {
    const report = {
      total: transactions.length,
      byType: {},
      priceRanges: {
        budget: 0,      // < 50 gold
        mid: 0,         // 50-200 gold
        expensive: 0,   // 200-1000 gold
        luxury: 0       // > 1000 gold
      },
      averageValue: 0,
      totalVolume: 0
    };
    
    let totalValue = 0;
    
    for (const transaction of transactions) {
      // By type (if available)
      const type = transaction.transaction_type || 'unknown';
      report.byType[type] = (report.byType[type] || 0) + 1;
      
      // By price range
      const value = transaction.gold_value;
      if (value < 50) report.priceRanges.budget++;
      else if (value < 200) report.priceRanges.mid++;
      else if (value < 1000) report.priceRanges.expensive++;
      else report.priceRanges.luxury++;
      
      totalValue += value;
    }
    
    report.averageValue = Math.floor(totalValue / transactions.length);
    report.totalVolume = totalValue;
    
    return report;
  }

  // Get most traded items
  getMostTradedItems(transactions) {
    const itemCounts = {};
    
    for (const transaction of transactions) {
      itemCounts[transaction.item_name] = (itemCounts[transaction.item_name] || 0) + 1;
    }
    
    return Object.entries(itemCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([item, count]) => ({ item, count }));
  }
}

module.exports = TransactionGenerator;