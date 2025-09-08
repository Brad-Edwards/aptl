const NameGenerators = require('../utils/name-generators');
const ProbabilityHelpers = require('../utils/probability');

class ItemGenerator {
  constructor(config) {
    this.config = config;
  }

  async generateItems() {
    const items = [];
    const { count, categories, rarities } = this.config.economy.items;
    
    console.log(`Generating ${count} game items`);
    
    let itemId = 1;
    
    // Generate items for each category
    for (const [category, percentage] of Object.entries(categories)) {
      const categoryCount = Math.floor(count * percentage);
      
      for (let i = 0; i < categoryCount; i++) {
        const item = this.generateItem(itemId++, category, i);
        items.push(item);
      }
    }
    
    // Fill remaining slots with random items if needed
    while (items.length < count) {
      const randomCategory = ProbabilityHelpers.consistentSelect(Object.keys(categories), items.length);
      const item = this.generateItem(itemId++, randomCategory, items.length);
      items.push(item);
    }
    
    console.log(`Generated ${items.length} items across ${Object.keys(categories).length} categories`);
    return items;
  }

  generateItem(itemId, category, index) {
    // Generate rarity based on configuration
    const rarity = this.selectItemRarity(index);
    
    // Generate item name based on category and rarity
    const name = NameGenerators.generateItemName(category, rarity);
    
    // Generate base value and apply rarity multiplier
    const baseValue = this.generateBaseValue(category, index);
    const rarityConfig = this.config.economy.items.rarities[rarity];
    const goldValue = Math.floor(baseValue * rarityConfig.priceMultiplier);
    
    // Determine level requirement
    const levelRequirement = this.generateLevelRequirement(category, rarity, index);
    
    // Get category ID (will need to be populated in database first)
    const categoryId = this.getCategoryId(category);
    
    return {
      id: itemId,
      name: name,
      gold_value: goldValue,
      category_id: categoryId,
      rarity: rarity,
      item_type: category,
      level_requirement: levelRequirement,
      // Additional metadata for generation (not stored in DB)
      base_value: baseValue,
      category: category
    };
  }

  selectItemRarity(index) {
    const rarities = this.config.economy.items.rarities;
    
    // Use index for consistent rarity assignment
    const random = ProbabilityHelpers.seededProbability(index * 789, 0, 1);
    let cumulative = 0;
    
    for (const [rarity, config] of Object.entries(rarities)) {
      cumulative += config.weight;
      if (random <= cumulative) {
        return rarity;
      }
    }
    
    return 'common'; // Fallback
  }

  generateBaseValue(category, index) {
    const baseValues = {
      weapons: { min: 50, max: 200 },
      armor: { min: 30, max: 150 },
      consumables: { min: 5, max: 50 },
      materials: { min: 10, max: 80 }
    };
    
    const range = baseValues[category] || baseValues.weapons;
    const random = ProbabilityHelpers.seededProbability(index * 456, 0, 1);
    
    return Math.floor(range.min + random * (range.max - range.min));
  }

  generateLevelRequirement(category, rarity, index) {
    // Base level requirements by category and rarity
    const levelRanges = {
      weapons: {
        common: [1, 15],
        rare: [10, 30],
        epic: [25, 45],
        legendary: [40, 50]
      },
      armor: {
        common: [1, 12],
        rare: [8, 25],
        epic: [20, 40],
        legendary: [35, 50]
      },
      consumables: {
        common: [1, 1],
        rare: [1, 10],
        epic: [15, 30],
        legendary: [30, 50]
      },
      materials: {
        common: [1, 5],
        rare: [5, 20],
        epic: [15, 35],
        legendary: [25, 50]
      }
    };
    
    const categoryRanges = levelRanges[category] || levelRanges.weapons;
    const range = categoryRanges[rarity] || categoryRanges.common;
    
    const random = ProbabilityHelpers.seededProbability(index * 321, 0, 1);
    return Math.floor(range[0] + random * (range[1] - range[0] + 1));
  }

  getCategoryId(category) {
    // Map category names to IDs (these should match the enhanced schema)
    const categoryMap = {
      weapons: 1,
      armor: 2,
      consumables: 3,
      materials: 4
    };
    
    return categoryMap[category] || 1;
  }

  // Generate specific item lists for different purposes
  generateStarterItems() {
    return [
      {
        name: 'Wooden Sword',
        category: 'weapons',
        rarity: 'common',
        gold_value: 25,
        level_requirement: 1
      },
      {
        name: 'Leather Vest',
        category: 'armor',
        rarity: 'common',
        gold_value: 20,
        level_requirement: 1
      },
      {
        name: 'Health Potion',
        category: 'consumables',
        rarity: 'common',
        gold_value: 5,
        level_requirement: 1
      }
    ];
  }

  generatePopularTradingItems() {
    // Items that are commonly traded
    return [
      {
        name: 'Iron Ore',
        category: 'materials',
        rarity: 'common',
        gold_value: 15,
        level_requirement: 5
      },
      {
        name: 'Mana Potion',
        category: 'consumables',
        rarity: 'common',
        gold_value: 8,
        level_requirement: 1
      },
      {
        name: 'Steel Blade',
        category: 'weapons',
        rarity: 'rare',
        gold_value: 150,
        level_requirement: 15
      }
    ];
  }

  generateRareItems() {
    // High-value items that drive economic activity
    return [
      {
        name: 'Dragon Scale Armor',
        category: 'armor',
        rarity: 'epic',
        gold_value: 1200,
        level_requirement: 35
      },
      {
        name: 'Excalibur',
        category: 'weapons',
        rarity: 'legendary',
        gold_value: 5000,
        level_requirement: 45
      },
      {
        name: 'Phoenix Feather',
        category: 'materials',
        rarity: 'legendary',
        gold_value: 2500,
        level_requirement: 40
      }
    ];
  }

  // Market price analysis for trading
  generateMarketPrices(items) {
    const marketPrices = {};
    
    for (const item of items) {
      const basePrice = item.gold_value;
      const variance = this.config.economy.transactions.priceVariation;
      
      // Generate market price range
      const minPrice = Math.floor(basePrice * (1 - variance));
      const maxPrice = Math.floor(basePrice * (1 + variance));
      const avgPrice = Math.floor((minPrice + maxPrice) / 2);
      
      marketPrices[item.name] = {
        min: minPrice,
        max: maxPrice,
        average: avgPrice,
        base: basePrice,
        demand: this.estimateItemDemand(item)
      };
    }
    
    return marketPrices;
  }

  estimateItemDemand(item) {
    // Estimate demand based on item characteristics
    let demandScore = 0;
    
    // Level requirement affects demand
    if (item.level_requirement <= 10) demandScore += 0.3; // High demand for starter items
    else if (item.level_requirement <= 25) demandScore += 0.2; // Medium demand
    else demandScore += 0.1; // Lower demand for high-level items
    
    // Rarity affects demand differently
    switch (item.rarity) {
      case 'common': demandScore += 0.4; break;      // High volume trading
      case 'rare': demandScore += 0.3; break;        // Steady demand
      case 'epic': demandScore += 0.2; break;        // Collector interest
      case 'legendary': demandScore += 0.1; break;   // Very rare trades
    }
    
    // Category affects demand
    switch (item.category) {
      case 'weapons': demandScore += 0.25; break;
      case 'armor': demandScore += 0.20; break;
      case 'consumables': demandScore += 0.35; break; // Always in demand
      case 'materials': demandScore += 0.20; break;
    }
    
    return Math.min(1.0, demandScore);
  }

  // Validation
  validateItems(items) {
    const errors = [];
    const itemNames = new Set();
    
    for (const item of items) {
      // Check for duplicates
      if (itemNames.has(item.name)) {
        errors.push(`Duplicate item name: ${item.name}`);
      } else {
        itemNames.add(item.name);
      }
      
      // Validate required fields
      if (!item.name || item.name.trim().length === 0) {
        errors.push(`Invalid name for item ${item.id}`);
      }
      
      if (!item.gold_value || item.gold_value <= 0) {
        errors.push(`Invalid gold value for item ${item.name}`);
      }
      
      if (!item.level_requirement || item.level_requirement < 1 || item.level_requirement > 50) {
        errors.push(`Invalid level requirement for item ${item.name}`);
      }
      
      if (!['common', 'rare', 'epic', 'legendary'].includes(item.rarity)) {
        errors.push(`Invalid rarity for item ${item.name}`);
      }
      
      if (!['weapons', 'armor', 'consumables', 'materials'].includes(item.item_type)) {
        errors.push(`Invalid item type for item ${item.name}`);
      }
    }
    
    return errors;
  }

  // Generate item distribution report
  generateItemReport(items) {
    const report = {
      total: items.length,
      byCategory: {},
      byRarity: {},
      priceRanges: {
        budget: 0,      // < 50 gold
        mid: 0,         // 50-200 gold
        expensive: 0,   // 200-1000 gold
        luxury: 0       // > 1000 gold
      },
      averageValue: 0
    };
    
    let totalValue = 0;
    
    for (const item of items) {
      // By category
      report.byCategory[item.item_type] = (report.byCategory[item.item_type] || 0) + 1;
      
      // By rarity
      report.byRarity[item.rarity] = (report.byRarity[item.rarity] || 0) + 1;
      
      // By price range
      if (item.gold_value < 50) report.priceRanges.budget++;
      else if (item.gold_value < 200) report.priceRanges.mid++;
      else if (item.gold_value < 1000) report.priceRanges.expensive++;
      else report.priceRanges.luxury++;
      
      totalValue += item.gold_value;
    }
    
    report.averageValue = Math.floor(totalValue / items.length);
    
    return report;
  }

  // Get items suitable for character level and class
  getItemsForCharacter(items, characterLevel, characterClass) {
    return items.filter(item => {
      // Level requirement check
      if (item.level_requirement > characterLevel) return false;
      
      // Class suitability check
      return this.isItemSuitableForClass(item, characterClass);
    });
  }

  isItemSuitableForClass(item, characterClass) {
    const classSuitability = {
      'Warrior': ['weapons', 'armor'],
      'Mage': ['weapons', 'armor', 'consumables', 'materials'],
      'Rogue': ['weapons', 'armor', 'materials'],
      'Archer': ['weapons', 'armor'],
      'Cleric': ['weapons', 'armor', 'consumables']
    };
    
    const suitableTypes = classSuitability[characterClass] || Object.keys(this.config.economy.items.categories);
    return suitableTypes.includes(item.item_type);
  }
}

module.exports = ItemGenerator;