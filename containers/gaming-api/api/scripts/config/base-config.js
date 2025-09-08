// Base configuration for gaming data generation
module.exports = {
  // Target data volumes for CTF scenario
  users: {
    count: 250,
    distribution: {
      active: 0.4,    // 40% active players (login 4-7x per week)
      casual: 0.4,    // 40% casual players (login 2-4x per week)  
      dormant: 0.2    // 20% dormant players (login 0-2x per week)
    }
  },

  characters: {
    perUser: {
      min: 1,
      max: 3,
      average: 1.6    // Most users have 1-2 characters
    },
    classes: [
      { name: 'Warrior', weight: 0.3 },
      { name: 'Mage', weight: 0.25 },
      { name: 'Rogue', weight: 0.2 },
      { name: 'Archer', weight: 0.15 },
      { name: 'Cleric', weight: 0.1 }
    ],
    levelDistribution: {
      newbie: { min: 1, max: 10, weight: 0.3 },
      casual: { min: 11, max: 25, weight: 0.5 },
      veteran: { min: 26, max: 50, weight: 0.2 }
    }
  },

  sessions: {
    totalCount: 1500,  // ~6 sessions per user on average
    durationMinutes: {
      min: 15,
      max: 240,
      average: 75
    },
    timing: {
      // Peak hours: 18:00-23:00 weekdays, 10:00-24:00 weekends
      peakHours: [18, 19, 20, 21, 22],
      weekendExtended: [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]
    }
  },

  activities: {
    gameplay: {
      totalCount: 3000,  // ~2 activities per session average
      types: {
        // Activity types by character level
        newbie: [
          { name: 'tutorial_complete', weight: 0.2, duration: [10, 20] },
          { name: 'newbie_dungeon', weight: 0.3, duration: [15, 30] },
          { name: 'first_quest', weight: 0.3, duration: [20, 45] },
          { name: 'basic_exploration', weight: 0.2, duration: [15, 35] }
        ],
        casual: [
          { name: 'dungeon_run', weight: 0.3, duration: [20, 60] },
          { name: 'quest_chain', weight: 0.25, duration: [30, 90] },
          { name: 'pvp_match', weight: 0.2, duration: [15, 45] },
          { name: 'exploration', weight: 0.15, duration: [25, 75] },
          { name: 'skill_training', weight: 0.1, duration: [10, 30] }
        ],
        veteran: [
          { name: 'raid_participation', weight: 0.25, duration: [60, 180] },
          { name: 'advanced_pvp', weight: 0.2, duration: [20, 60] },
          { name: 'guild_events', weight: 0.2, duration: [45, 120] },
          { name: 'mentoring', weight: 0.15, duration: [30, 90] },
          { name: 'rare_hunting', weight: 0.2, duration: [40, 120] }
        ]
      }
    },

    marketplace: {
      totalCount: 800,   // ~30% of users per session visit marketplace
      actions: {
        browse_category: { weight: 0.3, duration: [2, 8] },
        search_item: { weight: 0.25, duration: [1, 5] },
        view_item_details: { weight: 0.2, duration: [1, 4] },
        compare_prices: { weight: 0.15, duration: [3, 10] },
        list_item: { weight: 0.05, duration: [2, 15] },
        purchase_item: { weight: 0.05, duration: [1, 3] }
      }
    },

    social: {
      totalCount: 600,   // ~25% of sessions have social activity
      actions: {
        chat_send: { weight: 0.4, messages: [1, 5] },
        channel_join: { weight: 0.3, channels: [1, 3] },
        guild_activity: { weight: 0.2, duration: [10, 60] },
        friend_interaction: { weight: 0.1, duration: [5, 20] }
      }
    }
  },

  economy: {
    items: {
      count: 30,  // Pre-populate with 30 different items
      categories: {
        weapons: 0.4,
        armor: 0.3, 
        consumables: 0.2,
        materials: 0.1
      },
      rarities: {
        common: { weight: 0.6, priceMultiplier: 1.0 },
        rare: { weight: 0.25, priceMultiplier: 3.0 },
        epic: { weight: 0.12, priceMultiplier: 8.0 },
        legendary: { weight: 0.03, priceMultiplier: 25.0 }
      }
    },

    transactions: {
      count: 400,  // ~1.6 transactions per user
      types: {
        player_trade: 0.6,      // Direct player-to-player
        marketplace_sale: 0.35,  // Via marketplace
        gift: 0.05              // Gifts between players
      },
      priceVariation: 0.15  // ±15% from base item value
    }
  },

  // Realistic data patterns
  patterns: {
    loginFrequency: {
      active: { min: 4, max: 7 },      // times per week
      casual: { min: 2, max: 4 },
      dormant: { min: 0, max: 2 }
    },

    sessionPatterns: {
      // Probability of each session type
      marketplace_first: 0.3,   // login → marketplace → gameplay
      direct_gameplay: 0.4,     // login → gameplay  
      social_first: 0.2,        // login → chat → marketplace → gameplay
      economic_focus: 0.1       // login → heavy marketplace → minimal gameplay
    },

    progressionRates: {
      // Experience and gold earned per activity by level tier
      newbie: { experience: [10, 50], gold: [5, 25] },
      casual: { experience: [25, 100], gold: [15, 75] },
      veteran: { experience: [50, 200], gold: [50, 300] }
    }
  },

  // Time simulation parameters
  timeRange: {
    startDaysAgo: 90,    // Generate 90 days of historical data
    endDaysAgo: 0        // Up to present day
  },

  // Data quality settings
  validation: {
    maxRetriesPerGenerator: 3,
    requireAllRelationships: true,
    validateDataConsistency: true
  }
};