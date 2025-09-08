const DateHelpers = require('../utils/date-helpers');
const ProbabilityHelpers = require('../utils/probability');
const NameGenerators = require('../utils/name-generators');

class ActivityGenerator {
  constructor(config) {
    this.config = config;
  }

  // Generate all activities for a session
  generateSessionActivities(session, character, sessionPattern) {
    const activities = {
      gameplay: [],
      marketplace: [],
      social: []
    };

    const sessionStart = new Date(session.login_time);
    const sessionEnd = session.logout_time ? new Date(session.logout_time) : 
      new Date(sessionStart.getTime() + (120 * 60 * 1000)); // Default 2 hour session

    const sessionDuration = (sessionEnd - sessionStart) / (1000 * 60); // Minutes

    // Generate activities based on session pattern
    switch (sessionPattern) {
      case 'marketplace_first':
        activities.marketplace = this.generateMarketplaceActivities(session, character, sessionStart, sessionDuration * 0.25);
        activities.gameplay = this.generateGameplayActivities(session, character, 
          new Date(sessionStart.getTime() + (sessionDuration * 0.25 * 60 * 1000)), 
          sessionDuration * 0.70);
        activities.social = this.generateSocialActivities(session, character, sessionStart, sessionDuration * 0.05);
        break;

      case 'direct_gameplay':
        activities.gameplay = this.generateGameplayActivities(session, character, sessionStart, sessionDuration * 0.85);
        activities.marketplace = this.generateMarketplaceActivities(session, character, 
          new Date(sessionStart.getTime() + (sessionDuration * 0.85 * 60 * 1000)), 
          sessionDuration * 0.10);
        activities.social = this.generateSocialActivities(session, character, sessionStart, sessionDuration * 0.05);
        break;

      case 'social_first':
        activities.social = this.generateSocialActivities(session, character, sessionStart, sessionDuration * 0.15);
        activities.marketplace = this.generateMarketplaceActivities(session, character, 
          new Date(sessionStart.getTime() + (sessionDuration * 0.15 * 60 * 1000)), 
          sessionDuration * 0.20);
        activities.gameplay = this.generateGameplayActivities(session, character, 
          new Date(sessionStart.getTime() + (sessionDuration * 0.35 * 60 * 1000)), 
          sessionDuration * 0.65);
        break;

      case 'economic_focus':
        activities.marketplace = this.generateMarketplaceActivities(session, character, sessionStart, sessionDuration * 0.70);
        activities.social = this.generateSocialActivities(session, character, 
          new Date(sessionStart.getTime() + (sessionDuration * 0.70 * 60 * 1000)), 
          sessionDuration * 0.20);
        activities.gameplay = this.generateGameplayActivities(session, character, 
          new Date(sessionStart.getTime() + (sessionDuration * 0.90 * 60 * 1000)), 
          sessionDuration * 0.10);
        break;

      default:
        // Default balanced pattern
        activities.gameplay = this.generateGameplayActivities(session, character, sessionStart, sessionDuration * 0.70);
        activities.marketplace = this.generateMarketplaceActivities(session, character, 
          new Date(sessionStart.getTime() + (sessionDuration * 0.70 * 60 * 1000)), 
          sessionDuration * 0.20);
        activities.social = this.generateSocialActivities(session, character, sessionStart, sessionDuration * 0.10);
    }

    return activities;
  }

  // Generate gameplay activities
  generateGameplayActivities(session, character, startTime, durationMinutes) {
    const activities = [];
    
    if (durationMinutes < 10) return activities; // Skip if too short

    const characterLevel = character.level;
    const userType = character.user_type || 'casual';
    
    // Determine activity types based on character level
    const availableActivities = this.getAvailableActivities(characterLevel);
    
    let currentTime = new Date(startTime);
    let remainingTime = durationMinutes;
    
    while (remainingTime > 10) {
      // Select activity type
      const activityType = ProbabilityHelpers.weightedRandom(availableActivities);
      
      // Generate activity duration
      const activityDuration = Math.min(
        remainingTime - 5, // Leave some time for transitions
        ProbabilityHelpers.generateActivityDuration(activityType.name, characterLevel)
      );
      
      // Select location
      const location = this.selectActivityLocation(activityType.name, characterLevel);
      
      // Generate rewards
      const rewards = this.generateActivityRewards(activityType.name, characterLevel, activityDuration, userType);
      
      const activity = {
        user_id: session.user_id,
        character_id: session.character_id,
        session_id: session.session_id,
        activity_type: activityType.name,
        location: location,
        duration_minutes: activityDuration,
        experience_gained: rewards.experience,
        gold_earned: rewards.gold,
        timestamp: DateHelpers.formatForSQLite(currentTime),
        details: this.generateActivityDetails(activityType.name, characterLevel, rewards)
      };
      
      activities.push(activity);
      
      // Move to next activity
      currentTime = new Date(currentTime.getTime() + (activityDuration * 60 * 1000));
      remainingTime -= activityDuration;
      
      // Add transition time
      const transitionTime = ProbabilityHelpers.randomInt(2, 8);
      currentTime = new Date(currentTime.getTime() + (transitionTime * 60 * 1000));
      remainingTime -= transitionTime;
    }
    
    return activities;
  }

  getAvailableActivities(characterLevel) {
    const activityConfig = this.config.activities.gameplay.types;
    
    if (characterLevel <= 10) {
      return activityConfig.newbie.map(activity => ({
        name: activity.name,
        weight: activity.weight
      }));
    } else if (characterLevel <= 25) {
      return activityConfig.casual.map(activity => ({
        name: activity.name,
        weight: activity.weight
      }));
    } else {
      return activityConfig.veteran.map(activity => ({
        name: activity.name,
        weight: activity.weight
      }));
    }
  }

  selectActivityLocation(activityType, characterLevel) {
    const locationMap = {
      'tutorial_complete': 'Town Square',
      'newbie_dungeon': 'Newbie Dungeon',
      'first_quest': 'Town Square',
      'basic_exploration': 'Forest Clearing',
      'dungeon_run': characterLevel > 15 ? 'Advanced Dungeon' : 'Newbie Dungeon',
      'quest_chain': 'Town Square',
      'pvp_match': 'PvP Arena',
      'exploration': characterLevel > 20 ? 'Various Locations' : 'Forest Clearing',
      'skill_training': 'Town Square',
      'raid_participation': 'Raid Portal',
      'advanced_pvp': 'PvP Arena',
      'guild_events': 'Guild Hall',
      'mentoring': 'Town Square',
      'rare_hunting': 'Various Locations'
    };
    
    return locationMap[activityType] || 'Town Square';
  }

  generateActivityRewards(activityType, characterLevel, duration, userType) {
    const baseRewards = this.config.patterns.progressionRates;
    
    let tierRewards;
    if (characterLevel <= 10) tierRewards = baseRewards.newbie;
    else if (characterLevel <= 25) tierRewards = baseRewards.casual;
    else tierRewards = baseRewards.veteran;
    
    // Base experience and gold
    let experience = ProbabilityHelpers.randomInt(tierRewards.experience[0], tierRewards.experience[1]);
    let gold = ProbabilityHelpers.randomInt(tierRewards.gold[0], tierRewards.gold[1]);
    
    // Duration modifier (longer activities give more rewards)
    const durationMultiplier = Math.min(2.0, duration / 30); // Max 2x for 30+ minute activities
    experience = Math.floor(experience * durationMultiplier);
    gold = Math.floor(gold * durationMultiplier);
    
    // Activity type modifiers
    const activityModifiers = {
      'tutorial_complete': { exp: 0.5, gold: 0.3 },
      'raid_participation': { exp: 2.0, gold: 1.8 },
      'advanced_pvp': { exp: 1.5, gold: 1.2 },
      'mentoring': { exp: 1.0, gold: 0.5 },
      'rare_hunting': { exp: 1.2, gold: 2.0 }
    };
    
    const modifier = activityModifiers[activityType] || { exp: 1.0, gold: 1.0 };
    experience = Math.floor(experience * modifier.exp);
    gold = Math.floor(gold * modifier.gold);
    
    // User type modifier
    const userModifiers = {
      'active': { exp: 1.2, gold: 1.1 },
      'casual': { exp: 1.0, gold: 1.0 },
      'dormant': { exp: 0.8, gold: 0.9 }
    };
    
    const userMod = userModifiers[userType] || userModifiers.casual;
    experience = Math.floor(experience * userMod.exp);
    gold = Math.floor(gold * userMod.gold);
    
    return {
      experience: Math.max(1, experience),
      gold: Math.max(0, gold)
    };
  }

  generateActivityDetails(activityType, characterLevel, rewards) {
    const details = {
      character_level: characterLevel,
      activity_category: this.getActivityCategory(activityType),
      difficulty: this.getActivityDifficulty(activityType, characterLevel),
      success: Math.random() > 0.1 // 90% success rate
    };
    
    // Add activity-specific details
    switch (activityType) {
      case 'dungeon_run':
        details.dungeon_type = characterLevel > 15 ? 'advanced' : 'newbie';
        details.monsters_defeated = ProbabilityHelpers.randomInt(5, 15);
        break;
      case 'pvp_match':
        details.opponent_level = characterLevel + ProbabilityHelpers.randomInt(-5, 5);
        details.match_result = Math.random() > 0.5 ? 'victory' : 'defeat';
        break;
      case 'quest_chain':
        details.quests_completed = ProbabilityHelpers.randomInt(1, 4);
        details.quest_type = 'story';
        break;
      case 'raid_participation':
        details.raid_size = ProbabilityHelpers.randomInt(5, 20);
        details.role = this.getRaidRole(characterLevel);
        break;
    }
    
    return details;
  }

  getActivityCategory(activityType) {
    const categories = {
      'tutorial_complete': 'tutorial',
      'newbie_dungeon': 'pve',
      'first_quest': 'quest',
      'basic_exploration': 'exploration',
      'dungeon_run': 'pve',
      'quest_chain': 'quest',
      'pvp_match': 'pvp',
      'exploration': 'exploration',
      'skill_training': 'progression',
      'raid_participation': 'raid',
      'advanced_pvp': 'pvp',
      'guild_events': 'social',
      'mentoring': 'social',
      'rare_hunting': 'exploration'
    };
    
    return categories[activityType] || 'general';
  }

  getActivityDifficulty(activityType, characterLevel) {
    const difficultyMap = {
      'tutorial_complete': 'easy',
      'newbie_dungeon': 'easy',
      'first_quest': 'easy',
      'basic_exploration': 'easy',
      'dungeon_run': characterLevel > 20 ? 'medium' : 'easy',
      'quest_chain': 'medium',
      'pvp_match': 'medium',
      'exploration': characterLevel > 25 ? 'medium' : 'easy',
      'skill_training': 'easy',
      'raid_participation': 'hard',
      'advanced_pvp': 'hard',
      'guild_events': 'medium',
      'mentoring': 'easy',
      'rare_hunting': 'hard'
    };
    
    return difficultyMap[activityType] || 'medium';
  }

  getRaidRole(characterLevel) {
    const roles = ['damage', 'tank', 'healer', 'support'];
    return ProbabilityHelpers.consistentSelect(roles, characterLevel);
  }

  // Generate marketplace activities
  generateMarketplaceActivities(session, character, startTime, durationMinutes) {
    const activities = [];
    
    if (durationMinutes < 5) return activities; // Skip if too short

    const marketplaceConfig = this.config.activities.marketplace;
    
    let currentTime = new Date(startTime);
    let remainingTime = durationMinutes;
    
    while (remainingTime > 1) {
      // Select action type
      const action = ProbabilityHelpers.weightedRandom(
        Object.entries(marketplaceConfig.actions).map(([type, config]) => ({
          type,
          weight: config.weight,
          duration: config.duration
        }))
      );
      
      const actionDuration = Math.min(
        remainingTime,
        ProbabilityHelpers.randomInt(action.duration[0], action.duration[1])
      );
      
      const activity = {
        user_id: session.user_id,
        character_id: session.character_id,
        session_id: session.session_id,
        action_type: action.type,
        item_id: this.generateItemReference(action.type),
        item_name: this.generateItemName(action.type),
        price_viewed: this.generatePriceViewed(action.type),
        search_query: this.generateSearchQuery(action.type),
        category: this.generateCategory(action.type),
        timestamp: DateHelpers.formatForSQLite(currentTime)
      };
      
      activities.push(activity);
      
      // Move to next activity
      currentTime = new Date(currentTime.getTime() + (actionDuration * 60 * 1000));
      remainingTime -= actionDuration;
    }
    
    return activities;
  }

  generateItemReference(actionType) {
    if (['view_item_details', 'compare_prices', 'purchase_item'].includes(actionType)) {
      return ProbabilityHelpers.randomInt(1, 30); // Assuming 30 items
    }
    return null;
  }

  generateItemName(actionType) {
    if (['list_item', 'purchase_item'].includes(actionType)) {
      const categories = ['weapons', 'armor', 'consumables', 'materials'];
      const category = ProbabilityHelpers.consistentSelect(categories, Math.floor(Math.random() * 1000));
      const rarity = ProbabilityHelpers.generateItemRarity();
      return NameGenerators.generateItemName(category, rarity);
    }
    return null;
  }

  generatePriceViewed(actionType) {
    if (['view_item_details', 'compare_prices'].includes(actionType)) {
      return ProbabilityHelpers.randomInt(10, 500);
    }
    return null;
  }

  generateSearchQuery(actionType) {
    if (actionType === 'search_item') {
      const queries = [
        'iron sword', 'health potion', 'leather armor', 'mage staff',
        'rare materials', 'level 20 equipment', 'warrior gear', 'consumables'
      ];
      return ProbabilityHelpers.consistentSelect(queries, Math.floor(Math.random() * 1000));
    }
    return null;
  }

  generateCategory(actionType) {
    if (['browse_category', 'search_item'].includes(actionType)) {
      const categories = ['weapons', 'armor', 'consumables', 'materials'];
      return ProbabilityHelpers.consistentSelect(categories, Math.floor(Math.random() * 1000));
    }
    return null;
  }

  // Generate social activities
  generateSocialActivities(session, character, startTime, durationMinutes) {
    const activities = [];
    
    if (durationMinutes < 2) return activities; // Skip if too short

    const socialConfig = this.config.activities.social;
    
    let currentTime = new Date(startTime);
    let remainingTime = durationMinutes;
    
    while (remainingTime > 0.5) {
      // Select action type
      const action = ProbabilityHelpers.weightedRandom(
        Object.entries(socialConfig.actions).map(([type, config]) => ({
          type,
          weight: config.weight,
          ...config
        }))
      );
      
      const actionDuration = this.getSocialActionDuration(action.type);
      const duration = Math.min(remainingTime, actionDuration);
      
      const activity = {
        user_id: session.user_id,
        character_id: session.character_id,
        session_id: session.session_id,
        activity_type: action.type,
        channel_id: this.generateChannelId(action.type),
        channel_name: this.generateChannelName(action.type),
        message_count: this.generateMessageCount(action.type, duration),
        timestamp: DateHelpers.formatForSQLite(currentTime)
      };
      
      activities.push(activity);
      
      // Move to next activity
      currentTime = new Date(currentTime.getTime() + (duration * 60 * 1000));
      remainingTime -= duration;
    }
    
    return activities;
  }

  getSocialActionDuration(actionType) {
    const durations = {
      'chat_send': ProbabilityHelpers.randomFloat(0.5, 3),
      'channel_join': ProbabilityHelpers.randomFloat(1, 5),
      'guild_activity': ProbabilityHelpers.randomInt(10, 60),
      'friend_interaction': ProbabilityHelpers.randomInt(5, 20)
    };
    
    return durations[actionType] || 2;
  }

  generateChannelId(actionType) {
    const channelMap = {
      'chat_send': ProbabilityHelpers.randomInt(1, 3),
      'channel_join': ProbabilityHelpers.randomInt(1, 3),
      'guild_activity': 3, // Guild channel
      'friend_interaction': 1 // Global channel
    };
    
    return channelMap[actionType] || 1;
  }

  generateChannelName(actionType) {
    const channelMap = {
      'chat_send': ['Global', 'Trade', 'Guild'][ProbabilityHelpers.randomInt(0, 2)],
      'channel_join': ['Global', 'Trade', 'Guild'][ProbabilityHelpers.randomInt(0, 2)],
      'guild_activity': 'Guild',
      'friend_interaction': 'Global'
    };
    
    return channelMap[actionType] || 'Global';
  }

  generateMessageCount(actionType, duration) {
    const baseRates = {
      'chat_send': Math.floor(duration * 2), // 2 messages per minute
      'channel_join': 1,
      'guild_activity': Math.floor(duration * 0.5), // 0.5 messages per minute
      'friend_interaction': Math.floor(duration * 1.5) // 1.5 messages per minute
    };
    
    return Math.max(1, baseRates[actionType] || 1);
  }

  // Validation
  validateActivities(activities) {
    const errors = [];
    
    for (const activityGroup of Object.values(activities)) {
      for (const activity of activityGroup) {
        if (!activity.user_id || !activity.session_id) {
          errors.push('Missing required user_id or session_id');
        }
        
        if (!activity.timestamp || !DateHelpers.isValidDate(activity.timestamp)) {
          errors.push('Invalid timestamp');
        }
        
        if (activity.duration_minutes !== undefined && activity.duration_minutes < 0) {
          errors.push('Negative duration');
        }
      }
    }
    
    return errors;
  }
}

module.exports = ActivityGenerator;