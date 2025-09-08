class DataValidator {
  // User validation
  static validateUser(user) {
    const errors = [];

    if (!user.username || typeof user.username !== 'string' || user.username.length < 3) {
      errors.push('Username must be a string with at least 3 characters');
    }

    if (!user.password_hash || typeof user.password_hash !== 'string') {
      errors.push('Password hash is required');
    }

    if (!user.email || typeof user.email !== 'string' || !user.email.includes('@')) {
      errors.push('Valid email is required');
    }

    if (!user.created_at || !this.isValidDate(user.created_at)) {
      errors.push('Valid created_at date is required');
    }

    if (user.account_value && (typeof user.account_value !== 'number' || user.account_value < 0)) {
      errors.push('Account value must be a non-negative number');
    }

    return errors;
  }

  // Character validation  
  static validateCharacter(character) {
    const errors = [];

    if (!character.user_id || typeof character.user_id !== 'number') {
      errors.push('Valid user_id is required');
    }

    if (!character.name || typeof character.name !== 'string' || character.name.length < 2) {
      errors.push('Character name must be at least 2 characters');
    }

    if (!character.level || typeof character.level !== 'number' || character.level < 1 || character.level > 50) {
      errors.push('Character level must be between 1 and 50');
    }

    if (!character.class || typeof character.class !== 'string') {
      errors.push('Character class is required');
    }

    if (character.gold < 0 || character.experience < 0) {
      errors.push('Gold and experience cannot be negative');
    }

    if (!this.isValidDate(character.created_at)) {
      errors.push('Valid created_at date is required');
    }

    return errors;
  }

  // Session validation
  static validatePlayerSession(session) {
    const errors = [];

    if (!session.user_id || typeof session.user_id !== 'number') {
      errors.push('Valid user_id is required');
    }

    if (!session.session_id || typeof session.session_id !== 'string') {
      errors.push('Session ID is required');
    }

    if (!this.isValidDate(session.login_time)) {
      errors.push('Valid login_time is required');
    }

    if (session.logout_time && !this.isValidDate(session.logout_time)) {
      errors.push('If provided, logout_time must be valid');
    }

    if (session.logout_time && session.login_time && new Date(session.logout_time) <= new Date(session.login_time)) {
      errors.push('Logout time must be after login time');
    }

    if (session.actions_count < 0) {
      errors.push('Actions count cannot be negative');
    }

    return errors;
  }

  // Activity validation
  static validateGameplayActivity(activity) {
    const errors = [];

    if (!activity.user_id || typeof activity.user_id !== 'number') {
      errors.push('Valid user_id is required');
    }

    if (!activity.activity_type || typeof activity.activity_type !== 'string') {
      errors.push('Activity type is required');
    }

    if (activity.duration_minutes && (activity.duration_minutes < 0 || activity.duration_minutes > 300)) {
      errors.push('Duration must be between 0 and 300 minutes');
    }

    if (activity.experience_gained < 0 || activity.gold_earned < 0) {
      errors.push('Experience and gold earned cannot be negative');
    }

    if (!this.isValidDate(activity.timestamp)) {
      errors.push('Valid timestamp is required');
    }

    return errors;
  }

  static validateMarketplaceActivity(activity) {
    const errors = [];

    if (!activity.user_id || typeof activity.user_id !== 'number') {
      errors.push('Valid user_id is required');
    }

    if (!activity.action_type || typeof activity.action_type !== 'string') {
      errors.push('Action type is required');
    }

    if (activity.price_viewed && activity.price_viewed < 0) {
      errors.push('Price viewed cannot be negative');
    }

    if (!this.isValidDate(activity.timestamp)) {
      errors.push('Valid timestamp is required');
    }

    return errors;
  }

  // Transaction validation
  static validateTransaction(transaction) {
    const errors = [];

    if (!transaction.from_username || typeof transaction.from_username !== 'string') {
      errors.push('From username is required');
    }

    if (!transaction.to_username || typeof transaction.to_username !== 'string') {
      errors.push('To username is required');
    }

    if (transaction.from_username === transaction.to_username) {
      errors.push('Cannot trade with yourself');
    }

    if (!transaction.item_name || typeof transaction.item_name !== 'string') {
      errors.push('Item name is required');
    }

    if (!transaction.gold_value || transaction.gold_value <= 0) {
      errors.push('Gold value must be positive');
    }

    if (!this.isValidDate(transaction.timestamp)) {
      errors.push('Valid timestamp is required');
    }

    return errors;
  }

  // Relationship validation
  static validateDataRelationships(data) {
    const errors = [];
    const { users, characters, sessions, activities } = data;

    // Check all character user_ids exist
    if (characters && users) {
      const userIds = new Set(users.map(u => u.id).filter(id => id));
      const invalidCharacters = characters.filter(c => !userIds.has(c.user_id));
      
      if (invalidCharacters.length > 0) {
        errors.push(`Characters reference non-existent users: ${invalidCharacters.map(c => c.name).join(', ')}`);
      }
    }

    // Check all session user_ids exist
    if (sessions && users) {
      const userIds = new Set(users.map(u => u.id).filter(id => id));
      const invalidSessions = sessions.filter(s => !userIds.has(s.user_id));
      
      if (invalidSessions.length > 0) {
        errors.push(`${invalidSessions.length} sessions reference non-existent users`);
      }
    }

    // Check session character_ids exist (if provided)
    if (sessions && characters) {
      const characterIds = new Set(characters.map(c => c.id).filter(id => id));
      const invalidSessions = sessions.filter(s => s.character_id && !characterIds.has(s.character_id));
      
      if (invalidSessions.length > 0) {
        errors.push(`${invalidSessions.length} sessions reference non-existent characters`);
      }
    }

    // Check activity user_ids exist
    if (activities && users) {
      const userIds = new Set(users.map(u => u.id).filter(id => id));
      const invalidActivities = activities.filter(a => !userIds.has(a.user_id));
      
      if (invalidActivities.length > 0) {
        errors.push(`${invalidActivities.length} activities reference non-existent users`);
      }
    }

    return errors;
  }

  // Date consistency validation
  static validateDateConsistency(data) {
    const errors = [];
    const { users, characters, sessions } = data;

    if (users && characters) {
      // Character creation dates should be after user creation
      for (const character of characters) {
        const user = users.find(u => u.id === character.user_id);
        if (user && new Date(character.created_at) < new Date(user.created_at)) {
          errors.push(`Character ${character.name} created before user account`);
        }
      }
    }

    if (users && sessions) {
      // Session dates should be after user creation
      for (const session of sessions) {
        const user = users.find(u => u.id === session.user_id);
        if (user && new Date(session.login_time) < new Date(user.created_at)) {
          errors.push(`Session login time before user creation`);
        }
      }
    }

    return errors;
  }

  // Data distribution validation
  static validateDataDistribution(data, config) {
    const warnings = [];
    const { users, characters, sessions } = data;

    if (users && config.users) {
      const actualCount = users.length;
      const expectedCount = config.users.count;
      const tolerance = expectedCount * 0.1; // 10% tolerance
      
      if (Math.abs(actualCount - expectedCount) > tolerance) {
        warnings.push(`User count (${actualCount}) differs significantly from config (${expectedCount})`);
      }
    }

    if (characters && users) {
      const avgCharactersPerUser = characters.length / users.length;
      if (avgCharactersPerUser < 1.0 || avgCharactersPerUser > 3.5) {
        warnings.push(`Average characters per user (${avgCharactersPerUser.toFixed(2)}) outside expected range 1.0-3.5`);
      }
    }

    if (sessions && users) {
      const avgSessionsPerUser = sessions.length / users.length;
      if (avgSessionsPerUser < 3 || avgSessionsPerUser > 15) {
        warnings.push(`Average sessions per user (${avgSessionsPerUser.toFixed(2)}) outside expected range 3-15`);
      }
    }

    return warnings;
  }

  // Utility methods
  static isValidDate(dateString) {
    if (!dateString) return false;
    const date = new Date(dateString);
    return date instanceof Date && !isNaN(date.getTime());
  }

  static isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  static isUniqueArray(array, key) {
    const values = array.map(item => item[key]);
    return new Set(values).size === values.length;
  }

  // Comprehensive validation
  static validateAllData(data, config = {}) {
    const results = {
      errors: [],
      warnings: [],
      valid: true
    };

    // Individual record validation
    if (data.users) {
      data.users.forEach((user, index) => {
        const userErrors = this.validateUser(user);
        userErrors.forEach(error => {
          results.errors.push(`User ${index}: ${error}`);
        });
      });

      // Check username uniqueness
      if (!this.isUniqueArray(data.users, 'username')) {
        results.errors.push('Duplicate usernames found');
      }

      // Check email uniqueness
      if (!this.isUniqueArray(data.users, 'email')) {
        results.errors.push('Duplicate emails found');
      }
    }

    if (data.characters) {
      data.characters.forEach((character, index) => {
        const characterErrors = this.validateCharacter(character);
        characterErrors.forEach(error => {
          results.errors.push(`Character ${index}: ${error}`);
        });
      });
    }

    if (data.sessions) {
      data.sessions.forEach((session, index) => {
        const sessionErrors = this.validatePlayerSession(session);
        sessionErrors.forEach(error => {
          results.errors.push(`Session ${index}: ${error}`);
        });
      });
    }

    if (data.transactions) {
      data.transactions.forEach((transaction, index) => {
        const transactionErrors = this.validateTransaction(transaction);
        transactionErrors.forEach(error => {
          results.errors.push(`Transaction ${index}: ${error}`);
        });
      });
    }

    // Relationship validation
    const relationshipErrors = this.validateDataRelationships(data);
    results.errors.push(...relationshipErrors);

    // Date consistency validation
    const dateErrors = this.validateDateConsistency(data);
    results.errors.push(...dateErrors);

    // Distribution validation
    const distributionWarnings = this.validateDataDistribution(data, config);
    results.warnings.push(...distributionWarnings);

    results.valid = results.errors.length === 0;

    return results;
  }
}

module.exports = DataValidator;