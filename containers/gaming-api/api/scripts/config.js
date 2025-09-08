// Configuration constants for data generation

const config = {
  // Dataset size
  userCount: 200,
  transactionCount: 800,
  authEventCount: 2000,

  // Item definitions with fixed values
  items: [
    { name: 'iron_sword', value: 50 },
    { name: 'steel_armor', value: 150 },
    { name: 'magic_ring', value: 300 },
    { name: 'rare_gem', value: 800 },
    { name: 'legendary_staff', value: 2000 },
    { name: 'dragon_scale', value: 5000 }
  ],

  // User generation parameters
  users: {
    // Account age distribution (days ago)
    accountAge: {
      new: { min: 1, max: 30, weight: 0.2 },
      active: { min: 31, max: 180, weight: 0.6 },
      dormant: { min: 181, max: 730, weight: 0.2 }
    },

    // Character level distribution
    levels: {
      newbie: { min: 1, max: 10, weight: 0.3 },
      casual: { min: 11, max: 50, weight: 0.5 },
      veteran: { min: 51, max: 100, weight: 0.2 }
    },

    // Gold distribution (follows power law)
    goldDistribution: {
      poor: { min: 10, max: 500, weight: 0.7 },
      middle: { min: 501, max: 2000, weight: 0.25 },
      wealthy: { min: 2001, max: 10000, weight: 0.05 }
    },

    // Premium account chance
    premiumChance: 0.15
  },

  // Transaction patterns
  transactions: {
    // Value distribution
    valueDistribution: {
      small: { min: 10, max: 100, weight: 0.6 },
      medium: { min: 101, max: 500, weight: 0.3 },
      large: { min: 501, max: 2000, weight: 0.1 }
    },

    // Time range for transaction history (days ago)
    timeRange: { min: 1, max: 90 }
  },

  // Authentication events
  authEvents: {
    // Normal failure rate
    normalFailureRate: 0.08,
    
    // Time range for auth history (days ago)
    timeRange: { min: 1, max: 90 },
    
    // Login frequency per user per week
    loginFrequency: {
      active: { min: 3, max: 7 },
      casual: { min: 1, max: 3 },
      dormant: { min: 0, max: 1 }
    }
  },

  // Common gaming usernames patterns
  usernamePatterns: [
    'warrior_', 'magic_', 'dark_', 'fire_', 'ice_',
    'shadow_', 'dragon_', 'knight_', 'archer_', 'mage_',
    'ninja_', 'sword_', 'thunder_', 'storm_', 'light_'
  ],

  // Common name endings
  nameEndings: [
    'john', 'sarah', 'mike', 'lisa', 'alex', 'emma',
    'master', 'lord', 'king', 'queen', 'blade', 'heart',
    '77', '88', '99', '123', '456', '2020', '2021'
  ],

  // IP subnets for geographic consistency
  ipSubnets: [
    '192.168.1', '10.0.0', '172.16.1', '192.168.0',
    '10.1.1', '172.20.0', '192.168.100', '10.0.1'
  ],

  // User agents for device consistency
  userAgents: [
    'GameClient/1.2.3 (Windows NT 10.0)',
    'GameClient/1.2.3 (macOS 11.0)',
    'GameClient/1.1.8 (Windows NT 10.0)',
    'GameClient/1.2.1 (Ubuntu 20.04)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
  ]
};

module.exports = config;