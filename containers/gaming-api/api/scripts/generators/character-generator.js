const NameGenerators = require('../utils/name-generators');
const DateHelpers = require('../utils/date-helpers');
const ProbabilityHelpers = require('../utils/probability');

class CharacterGenerator {
  constructor(config) {
    this.config = config;
  }

  generateCharacters(users) {
    const characters = [];
    let characterId = 1;
    
    console.log(`Generating characters for ${users.length} users`);
    
    for (const user of users) {
      const characterCount = this.determineCharacterCount(user.user_type, user.id);
      
      for (let i = 0; i < characterCount; i++) {
        const character = this.generateCharacter(characterId++, user, i);
        characters.push(character);
      }
    }
    
    console.log(`Generated ${characters.length} characters`);
    return characters;
  }

  determineCharacterCount(userType, userId) {
    const { min, max, average } = this.config.characters.perUser;
    
    // Use user ID as seed for consistency
    const seed = userId * 1234;
    const random = ProbabilityHelpers.seededProbability(seed, 0, 1);
    
    // Bias based on user type
    let probability;
    switch (userType) {
      case 'active':
        // Active users more likely to have multiple characters
        if (random < 0.2) return 1;
        if (random < 0.6) return 2;
        return 3;
      case 'casual':
        // Casual users typically have 1-2 characters
        if (random < 0.5) return 1;
        if (random < 0.9) return 2;
        return 3;
      case 'dormant':
        // Dormant users mostly have just 1 character
        if (random < 0.8) return 1;
        if (random < 0.95) return 2;
        return 3;
      default:
        return Math.max(min, Math.min(max, Math.round(random * (max - min) + min)));
    }
  }

  generateCharacter(characterId, user, characterIndex) {
    const userType = user.user_type;
    const seed = user.id * 1000 + characterIndex;
    
    // Select character class
    const characterClass = this.selectCharacterClass(seed);
    
    // Generate character name
    const characterName = NameGenerators.generateConsistentData('characterName', seed, characterClass.name);
    
    // Generate character level based on user type
    const level = this.generateCharacterLevel(userType, seed);
    
    // Generate experience based on level
    const experience = ProbabilityHelpers.generateExperience(level);
    
    // Generate gold based on level and user type
    const gold = ProbabilityHelpers.generateGoldAmount(level, userType);
    
    // Generate creation date (after user account creation)
    const createdAt = DateHelpers.generateCharacterCreationDate(user.created_at);
    
    // Generate last played date
    const lastPlayed = DateHelpers.generateCharacterLastPlayed(createdAt, userType);
    
    return {
      id: characterId,
      user_id: user.id,
      name: characterName,
      level: level,
      class: characterClass.name,
      gold: gold,
      experience: experience,
      created_at: DateHelpers.formatForSQLite(createdAt),
      last_played: DateHelpers.formatForSQLite(lastPlayed),
      // Additional metadata for generation (not stored in DB)
      user_type: userType,
      character_index: characterIndex
    };
  }

  selectCharacterClass(seed) {
    const classes = this.config.characters.classes;
    
    // Use seed to consistently select class
    let random = ProbabilityHelpers.seededProbability(seed, 0, 1);
    let cumulative = 0;
    
    for (const classInfo of classes) {
      cumulative += classInfo.weight;
      if (random <= cumulative) {
        return classInfo;
      }
    }
    
    // Fallback to first class
    return classes[0];
  }

  generateCharacterLevel(userType, seed) {
    const levelConfig = this.config.characters.levelDistribution;
    
    // Select tier based on user type and seed
    const tierRandom = ProbabilityHelpers.seededProbability(seed, 0, 1);
    let selectedTier;
    
    switch (userType) {
      case 'active':
        // Active users bias towards higher levels
        if (tierRandom < 0.1) selectedTier = 'newbie';
        else if (tierRandom < 0.5) selectedTier = 'casual';
        else selectedTier = 'veteran';
        break;
      case 'casual':
        // Casual users normal distribution
        if (tierRandom < levelConfig.newbie.weight) selectedTier = 'newbie';
        else if (tierRandom < levelConfig.newbie.weight + levelConfig.casual.weight) selectedTier = 'casual';
        else selectedTier = 'veteran';
        break;
      case 'dormant':
        // Dormant users bias towards lower levels
        if (tierRandom < 0.6) selectedTier = 'newbie';
        else if (tierRandom < 0.9) selectedTier = 'casual';
        else selectedTier = 'veteran';
        break;
      default:
        selectedTier = 'casual';
    }
    
    const tier = levelConfig[selectedTier];
    const levelRandom = ProbabilityHelpers.seededProbability(seed * 2, 0, 1);
    
    return Math.floor(tier.min + levelRandom * (tier.max - tier.min + 1));
  }

  // Generate initial inventory for character
  generateInitialInventory(character, allItems) {
    const inventory = [];
    const characterLevel = character.level;
    const characterClass = character.class;
    
    // Starting equipment based on class and level
    const startingItems = this.getStartingItems(characterClass, characterLevel, allItems);
    
    for (const item of startingItems) {
      inventory.push({
        character_id: character.id,
        item_id: item.id,
        quantity: item.quantity || 1,
        acquired_date: character.created_at,
        source: 'character_creation'
      });
    }
    
    return inventory;
  }

  getStartingItems(characterClass, characterLevel, allItems) {
    const startingItems = [];
    
    // Filter items appropriate for this character
    const classItems = allItems.filter(item => 
      item.level_requirement <= characterLevel &&
      this.isAppropriateForClass(item, characterClass)
    );
    
    // Starting weapon
    const weapons = classItems.filter(item => item.item_type === 'weapon');
    if (weapons.length > 0) {
      const startingWeapon = weapons.find(w => w.rarity === 'common') || weapons[0];
      startingItems.push({ ...startingWeapon, quantity: 1 });
    }
    
    // Starting armor pieces
    const armor = classItems.filter(item => item.item_type === 'armor');
    const commonArmor = armor.filter(a => a.rarity === 'common').slice(0, 2);
    startingItems.push(...commonArmor.map(a => ({ ...a, quantity: 1 })));
    
    // Starting consumables
    const consumables = allItems.filter(item => 
      item.item_type === 'consumable' && 
      item.rarity === 'common'
    ).slice(0, 3);
    
    startingItems.push(...consumables.map(c => ({ 
      ...c, 
      quantity: Math.floor(Math.random() * 3) + 1 
    })));
    
    return startingItems;
  }

  isAppropriateForClass(item, characterClass) {
    const classAffinities = {
      'Warrior': ['weapon', 'armor'],
      'Mage': ['weapon', 'armor', 'consumable'],
      'Rogue': ['weapon', 'armor'],
      'Archer': ['weapon', 'armor'],
      'Cleric': ['weapon', 'armor', 'consumable']
    };
    
    const appropriateTypes = classAffinities[characterClass] || ['weapon', 'armor', 'consumable'];
    return appropriateTypes.includes(item.item_type);
  }

  // Generate character progression history
  generateCharacterProgression(character) {
    const progressions = [];
    const characterLevel = character.level;
    
    if (characterLevel <= 1) {
      return progressions; // No progression for level 1 characters
    }
    
    // Generate level-up events
    const accountCreated = new Date(character.created_at);
    const lastPlayed = new Date(character.last_played);
    
    for (let level = 2; level <= characterLevel; level++) {
      // Distribute level-ups over time
      const progressionDate = this.generateProgressionDate(accountCreated, lastPlayed, level, characterLevel);
      
      // Experience gained for this level
      const expGained = Math.floor(Math.pow(level, 1.8) * 50 + Math.random() * 100);
      
      // Gold change (sometimes cost gold for training)
      const goldChange = Math.random() < 0.7 ? Math.floor(level * 10 + Math.random() * 50) : -Math.floor(Math.random() * 20);
      
      progressions.push({
        character_id: character.id,
        session_id: null, // Will be linked to sessions later
        event_type: 'level_up',
        old_level: level - 1,
        new_level: level,
        experience_gained: expGained,
        gold_change: goldChange,
        timestamp: DateHelpers.formatForSQLite(progressionDate),
        details: JSON.stringify({
          class: character.class,
          milestone: this.getLevelMilestone(level)
        })
      });
    }
    
    return progressions;
  }

  generateProgressionDate(accountCreated, lastPlayed, currentLevel, maxLevel) {
    // Distribute level progressions over character lifetime
    const totalTime = lastPlayed.getTime() - accountCreated.getTime();
    const levelProgress = (currentLevel - 1) / (maxLevel - 1);
    
    // Add some randomness but maintain chronological order
    const baseTime = accountCreated.getTime() + (totalTime * levelProgress);
    const variance = totalTime * 0.1; // 10% variance
    const finalTime = baseTime + (Math.random() - 0.5) * variance;
    
    return new Date(Math.max(accountCreated.getTime(), Math.min(lastPlayed.getTime(), finalTime)));
  }

  getLevelMilestone(level) {
    if (level === 10) return 'Novice Milestone';
    if (level === 20) return 'Journeyman Milestone';
    if (level === 30) return 'Expert Milestone';
    if (level === 40) return 'Master Milestone';
    if (level === 50) return 'Grand Master';
    return null;
  }

  // Validation
  validateCharacters(characters, users) {
    const errors = [];
    const characterNames = new Set();
    const userIds = new Set(users.map(u => u.id));
    
    for (const character of characters) {
      // Check user reference
      if (!userIds.has(character.user_id)) {
        errors.push(`Character ${character.name} references non-existent user ${character.user_id}`);
      }
      
      // Check for duplicate names (should be rare but possible)
      const nameKey = `${character.user_id}-${character.name}`;
      if (characterNames.has(nameKey)) {
        errors.push(`Duplicate character name ${character.name} for user ${character.user_id}`);
      } else {
        characterNames.add(nameKey);
      }
      
      // Validate level range
      if (character.level < 1 || character.level > 50) {
        errors.push(`Invalid level ${character.level} for character ${character.name}`);
      }
      
      // Validate gold and experience
      if (character.gold < 0) {
        errors.push(`Negative gold for character ${character.name}`);
      }
      
      if (character.experience < 0) {
        errors.push(`Negative experience for character ${character.name}`);
      }
      
      // Check date consistency
      const user = users.find(u => u.id === character.user_id);
      if (user && new Date(character.created_at) < new Date(user.created_at)) {
        errors.push(`Character ${character.name} created before user account`);
      }
    }
    
    return errors;
  }

  // Generate character distribution report
  generateCharacterReport(characters) {
    const report = {
      total: characters.length,
      byClass: {},
      byLevel: { newbie: 0, casual: 0, veteran: 0 },
      averageLevel: 0,
      averageGold: 0
    };
    
    let totalLevel = 0;
    let totalGold = 0;
    
    for (const character of characters) {
      // By class
      report.byClass[character.class] = (report.byClass[character.class] || 0) + 1;
      
      // By level tier
      if (character.level <= 10) report.byLevel.newbie++;
      else if (character.level <= 25) report.byLevel.casual++;
      else report.byLevel.veteran++;
      
      totalLevel += character.level;
      totalGold += character.gold;
    }
    
    report.averageLevel = (totalLevel / characters.length).toFixed(1);
    report.averageGold = Math.floor(totalGold / characters.length);
    
    return report;
  }
}

module.exports = CharacterGenerator;