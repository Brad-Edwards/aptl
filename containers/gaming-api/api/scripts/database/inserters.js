const Database = require('./connection');

class DataInserters {
  constructor() {
    this.db = new Database();
  }

  async connect() {
    await this.db.connect();
  }

  async disconnect() {
    await this.db.disconnect();
  }

  async insertUsers(users) {
    const columns = [
      'username', 'password_hash', 'email', 'created_at', 'last_login',
      'is_premium', 'account_value', 'email_verified', 'total_playtime_hours',
      'last_ip_address', 'preferred_language', 'timezone'
    ];

    const data = users.map(user => [
      user.username,
      user.password_hash,
      user.email,
      user.created_at,
      user.last_login,
      user.is_premium ? 1 : 0,
      user.account_value,
      user.email_verified ? 1 : 0,
      user.total_playtime_hours,
      user.last_ip_address,
      user.preferred_language,
      user.timezone
    ]);

    return await this.db.bulkInsert('users', columns, data);
  }

  async insertCharacters(characters) {
    const columns = [
      'user_id', 'name', 'level', 'class', 'gold', 'experience', 
      'created_at', 'last_played'
    ];

    const data = characters.map(char => [
      char.user_id,
      char.name,
      char.level,
      char.class,
      char.gold,
      char.experience,
      char.created_at,
      char.last_played
    ]);

    return await this.db.bulkInsert('characters', columns, data);
  }

  async insertItems(items) {
    const columns = [
      'name', 'gold_value', 'category_id', 'rarity', 'item_type', 'level_requirement'
    ];

    const data = items.map(item => [
      item.name,
      item.gold_value,
      item.category_id,
      item.rarity,
      item.item_type,
      item.level_requirement
    ]);

    return await this.db.bulkInsert('items', columns, data);
  }

  async insertPlayerSessions(sessions) {
    const columns = [
      'user_id', 'character_id', 'session_id', 'login_time', 'logout_time',
      'actions_count', 'locations_visited', 'ip_address', 'user_agent'
    ];

    const data = sessions.map(session => [
      session.user_id,
      session.character_id,
      session.session_id,
      session.login_time,
      session.logout_time,
      session.actions_count,
      session.locations_visited,
      session.ip_address,
      session.user_agent
    ]);

    return await this.db.bulkInsert('player_sessions', columns, data);
  }

  async insertLoginHistory(logins) {
    const columns = [
      'user_id', 'username', 'ip_address', 'user_agent', 'login_time',
      'success', 'failure_reason', 'geo_location', 'device_fingerprint'
    ];

    const data = logins.map(login => [
      login.user_id,
      login.username,
      login.ip_address,
      login.user_agent,
      login.login_time,
      login.success ? 1 : 0,
      login.failure_reason,
      login.geo_location,
      login.device_fingerprint
    ]);

    return await this.db.bulkInsert('login_history', columns, data);
  }

  async insertTransactions(transactions) {
    const columns = [
      'from_username', 'to_username', 'item_name', 'gold_value', 'timestamp'
    ];

    const data = transactions.map(tx => [
      tx.from_username,
      tx.to_username,
      tx.item_name,
      tx.gold_value,
      tx.timestamp
    ]);

    return await this.db.bulkInsert('transactions', columns, data);
  }

  async insertGameplayActivities(activities) {
    const columns = [
      'user_id', 'character_id', 'session_id', 'activity_type', 'location',
      'duration_minutes', 'experience_gained', 'gold_earned', 'timestamp', 'details'
    ];

    const data = activities.map(activity => [
      activity.user_id,
      activity.character_id,
      activity.session_id,
      activity.activity_type,
      activity.location,
      activity.duration_minutes,
      activity.experience_gained,
      activity.gold_earned,
      activity.timestamp,
      activity.details ? JSON.stringify(activity.details) : null
    ]);

    return await this.db.bulkInsert('gameplay_activities', columns, data);
  }

  async insertMarketplaceActivities(activities) {
    const columns = [
      'user_id', 'character_id', 'session_id', 'action_type', 'item_id',
      'item_name', 'price_viewed', 'search_query', 'category', 'timestamp'
    ];

    const data = activities.map(activity => [
      activity.user_id,
      activity.character_id,
      activity.session_id,
      activity.action_type,
      activity.item_id,
      activity.item_name,
      activity.price_viewed,
      activity.search_query,
      activity.category,
      activity.timestamp
    ]);

    return await this.db.bulkInsert('marketplace_activities', columns, data);
  }

  async insertSocialActivities(activities) {
    const columns = [
      'user_id', 'character_id', 'session_id', 'activity_type', 'channel_id',
      'channel_name', 'message_count', 'timestamp'
    ];

    const data = activities.map(activity => [
      activity.user_id,
      activity.character_id,
      activity.session_id,
      activity.activity_type,
      activity.channel_id,
      activity.channel_name,
      activity.message_count,
      activity.timestamp
    ]);

    return await this.db.bulkInsert('social_activities', columns, data);
  }

  async insertCharacterProgression(progressions) {
    const columns = [
      'character_id', 'session_id', 'event_type', 'old_level', 'new_level',
      'experience_gained', 'gold_change', 'timestamp', 'details'
    ];

    const data = progressions.map(prog => [
      prog.character_id,
      prog.session_id,
      prog.event_type,
      prog.old_level,
      prog.new_level,
      prog.experience_gained,
      prog.gold_change,
      prog.timestamp,
      prog.details ? JSON.stringify(prog.details) : null
    ]);

    return await this.db.bulkInsert('character_progression', columns, data);
  }

  async insertCharacterInventory(inventory) {
    const columns = [
      'character_id', 'item_id', 'quantity', 'acquired_date', 'source'
    ];

    const data = inventory.map(inv => [
      inv.character_id,
      inv.item_id,
      inv.quantity,
      inv.acquired_date,
      inv.source
    ]);

    return await this.db.bulkInsert('character_inventory', columns, data);
  }

  // Utility methods for data validation
  async validateUserReferences(userIds) {
    const placeholders = userIds.map(() => '?').join(',');
    const existing = await this.db.all(
      `SELECT id FROM users WHERE id IN (${placeholders})`,
      userIds
    );
    const existingIds = existing.map(row => row.id);
    const missing = userIds.filter(id => !existingIds.includes(id));
    
    if (missing.length > 0) {
      throw new Error(`Invalid user references: ${missing.join(', ')}`);
    }
    
    return true;
  }

  async validateCharacterReferences(characterIds) {
    const placeholders = characterIds.map(() => '?').join(',');
    const existing = await this.db.all(
      `SELECT id FROM characters WHERE id IN (${placeholders})`,
      characterIds
    );
    const existingIds = existing.map(row => row.id);
    const missing = characterIds.filter(id => !existingIds.includes(id));
    
    if (missing.length > 0) {
      throw new Error(`Invalid character references: ${missing.join(', ')}`);
    }
    
    return true;
  }

  async getInsertionStats() {
    const tables = [
      'users', 'characters', 'items', 'player_sessions', 'login_history',
      'transactions', 'gameplay_activities', 'marketplace_activities',
      'social_activities', 'character_progression', 'character_inventory'
    ];
    
    const stats = {};
    
    for (const table of tables) {
      try {
        stats[table] = await this.db.getRowCount(table);
      } catch (error) {
        stats[table] = 0; // Table might not exist yet
      }
    }
    
    return stats;
  }
}

module.exports = DataInserters;