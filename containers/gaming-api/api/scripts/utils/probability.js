class ProbabilityHelpers {
  // Weighted random selection from array of objects with weight property
  static weightedRandom(items) {
    const totalWeight = items.reduce((sum, item) => sum + item.weight, 0);
    let random = Math.random() * totalWeight;
    
    for (const item of items) {
      random -= item.weight;
      if (random <= 0) {
        return item;
      }
    }
    
    // Fallback to first item if something goes wrong
    return items[0];
  }

  // Select random item based on probability distribution
  static selectByProbability(probabilities) {
    const random = Math.random();
    let cumulative = 0;
    
    for (const [item, probability] of Object.entries(probabilities)) {
      cumulative += probability;
      if (random <= cumulative) {
        return item;
      }
    }
    
    // Fallback to last item
    return Object.keys(probabilities).pop();
  }

  // Generate random integer within range
  static randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  // Generate random float within range
  static randomFloat(min, max) {
    return min + Math.random() * (max - min);
  }

  // Normal distribution (Box-Muller transform)
  static normalRandom(mean = 0, stdDev = 1) {
    let u1 = 0, u2 = 0;
    while (u1 === 0) u1 = Math.random(); // Converting [0,1) to (0,1)
    while (u2 === 0) u2 = Math.random();
    
    const z0 = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    return z0 * stdDev + mean;
  }

  // Generate value with bias towards certain range
  static biasedRandom(min, max, bias = 0.5, strength = 1) {
    const random = Math.random();
    const biased = Math.pow(random, strength);
    const result = bias < 0.5 
      ? min + biased * (max - min)  // Bias towards minimum
      : min + (1 - biased) * (max - min); // Bias towards maximum
    
    return Math.max(min, Math.min(max, result));
  }

  // Boolean with probability
  static chance(probability) {
    return Math.random() < probability;
  }

  // Select multiple items without replacement
  static selectMultiple(items, count) {
    const shuffled = [...items].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, Math.min(count, items.length));
  }

  // Generate distribution based on configuration
  static generateDistribution(config) {
    if (config.type === 'uniform') {
      return this.randomInt(config.min, config.max);
    } else if (config.type === 'normal') {
      const value = this.normalRandom(config.mean, config.stdDev);
      return Math.max(config.min || 0, Math.min(config.max || 100, Math.round(value)));
    } else if (config.type === 'weighted') {
      const selected = this.weightedRandom(config.options);
      return this.randomInt(selected.min, selected.max);
    }
    
    // Default to range
    return this.randomInt(config.min || 0, config.max || 100);
  }

  // Character level distribution based on player type
  static generateCharacterLevel(userType) {
    switch (userType) {
      case 'active':
        // Active players: bias towards higher levels
        return Math.floor(this.biasedRandom(5, 50, 0.7, 2));
      case 'casual':
        // Casual players: normal distribution around mid levels
        const level = this.normalRandom(20, 8);
        return Math.max(1, Math.min(50, Math.round(level)));
      case 'dormant':
        // Dormant players: bias towards lower levels
        return Math.floor(this.biasedRandom(1, 30, 0.3, 1.5));
      default:
        return this.randomInt(1, 50);
    }
  }

  // Generate gold amount based on character level and type
  static generateGoldAmount(characterLevel, userType = 'casual') {
    const baseGold = characterLevel * 100 + this.randomInt(0, characterLevel * 50);
    
    switch (userType) {
      case 'active':
        return Math.floor(baseGold * (1.2 + Math.random() * 0.8)); // 120-200% of base
      case 'casual':
        return Math.floor(baseGold * (0.8 + Math.random() * 0.4)); // 80-120% of base
      case 'dormant':
        return Math.floor(baseGold * (0.3 + Math.random() * 0.5)); // 30-80% of base
      default:
        return baseGold;
    }
  }

  // Generate experience based on character level
  static generateExperience(characterLevel) {
    // Experience required grows exponentially
    const baseExp = Math.pow(characterLevel, 2.2) * 100;
    const currentLevelExp = Math.random() * (Math.pow(characterLevel + 1, 2.2) - Math.pow(characterLevel, 2.2)) * 100;
    
    return Math.floor(baseExp + currentLevelExp);
  }

  // Determine user activity type
  static determineUserType(index) {
    // Use index for consistent type assignment
    const hash = index * 2654435761; // Large prime
    const random = (hash % 1000) / 1000;
    
    if (random < 0.4) return 'active';
    if (random < 0.8) return 'casual';
    return 'dormant';
  }

  // Generate activity frequency based on type
  static generateActivityFrequency(userType, baseFrequency) {
    const multipliers = {
      active: 1.5,
      casual: 1.0,
      dormant: 0.3
    };
    
    return Math.floor(baseFrequency * (multipliers[userType] || 1.0));
  }

  // Generate session pattern for user
  static selectSessionPattern() {
    const patterns = {
      marketplace_first: 0.3,
      direct_gameplay: 0.4,
      social_first: 0.2,
      economic_focus: 0.1
    };
    
    return this.selectByProbability(patterns);
  }

  // Generate item rarity
  static generateItemRarity() {
    const rarities = {
      common: 0.6,
      rare: 0.25,
      epic: 0.12,
      legendary: 0.03
    };
    
    return this.selectByProbability(rarities);
  }

  // Generate transaction price with variance
  static generateTransactionPrice(baseValue, variance = 0.15) {
    const multiplier = 1 + (Math.random() - 0.5) * 2 * variance;
    return Math.max(1, Math.floor(baseValue * multiplier));
  }

  // Generate activity duration with realistic distribution
  static generateActivityDuration(activityType, characterLevel = 20) {
    const baseDurations = {
      tutorial_complete: [10, 20],
      newbie_dungeon: [15, 30],
      first_quest: [20, 45],
      basic_exploration: [15, 35],
      dungeon_run: [20, 60],
      quest_chain: [30, 90],
      pvp_match: [15, 45],
      exploration: [25, 75],
      skill_training: [10, 30],
      raid_participation: [60, 180],
      advanced_pvp: [20, 60],
      guild_events: [45, 120],
      mentoring: [30, 90],
      rare_hunting: [40, 120]
    };
    
    const duration = baseDurations[activityType] || [15, 60];
    const levelMultiplier = 1 + (characterLevel - 20) * 0.02; // Slightly longer for higher levels
    
    const baseDuration = this.randomInt(duration[0], duration[1]);
    return Math.floor(baseDuration * levelMultiplier);
  }

  // Generate marketplace action sequence
  static generateMarketplaceActions(sessionPattern, duration) {
    const actionTypes = {
      browse_category: { weight: 0.3, duration: [2, 8] },
      search_item: { weight: 0.25, duration: [1, 5] },
      view_item_details: { weight: 0.2, duration: [1, 4] },
      compare_prices: { weight: 0.15, duration: [3, 10] },
      list_item: { weight: 0.05, duration: [2, 15] },
      purchase_item: { weight: 0.05, duration: [1, 3] }
    };
    
    const actions = [];
    let remainingTime = duration;
    
    while (remainingTime > 2) {
      const actionType = this.weightedRandom(Object.entries(actionTypes).map(([type, config]) => ({
        type,
        weight: config.weight,
        ...config
      })));
      
      const actionDuration = Math.min(
        remainingTime,
        this.randomInt(actionType.duration[0], actionType.duration[1])
      );
      
      actions.push({
        type: actionType.type,
        duration: actionDuration
      });
      
      remainingTime -= actionDuration;
    }
    
    return actions;
  }

  // Get random element from array
  static getRandomElement(array) {
    return array[Math.floor(Math.random() * array.length)];
  }

  // Consistent probability based on seed
  static seededProbability(seed, min = 0, max = 1) {
    // Simple linear congruential generator
    const a = 1664525;
    const c = 1013904223;
    const m = Math.pow(2, 32);
    
    const next = (a * seed + c) % m;
    const normalized = next / m;
    
    return min + normalized * (max - min);
  }

  // Generate consistent selection based on index
  static consistentSelect(items, index) {
    const hash = index * 2654435761 % 2147483647; // Large prime mod
    const idx = Math.abs(hash) % items.length;
    return items[idx];
  }
}

module.exports = ProbabilityHelpers;