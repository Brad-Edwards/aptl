class DateHelpers {
  // Generate random date within a range
  static randomDateBetween(start, end) {
    const startTime = start.getTime();
    const endTime = end.getTime();
    const randomTime = startTime + Math.random() * (endTime - startTime);
    return new Date(randomTime);
  }

  // Generate account creation date (90 days ago to now)
  static generateAccountCreationDate(daysAgo = 90) {
    const now = new Date();
    const earliest = new Date(now.getTime() - (daysAgo * 24 * 60 * 60 * 1000));
    return this.randomDateBetween(earliest, now);
  }

  // Generate last login date relative to account creation
  static generateLastLoginDate(createdAt, userType = 'casual') {
    const created = new Date(createdAt);
    const now = new Date();
    
    let maxDaysAgo;
    switch (userType) {
      case 'active':
        maxDaysAgo = Math.random() * 3; // Within last 3 days
        break;
      case 'casual':
        maxDaysAgo = Math.random() * 14; // Within last 2 weeks
        break;
      case 'dormant':
        maxDaysAgo = 7 + Math.random() * 60; // 1 week to 2 months ago
        break;
      default:
        maxDaysAgo = Math.random() * 7;
    }
    
    const lastLogin = new Date(now.getTime() - (maxDaysAgo * 24 * 60 * 60 * 1000));
    
    // Ensure last login is after account creation
    return lastLogin < created ? created : lastLogin;
  }

  // Generate character creation date (after account creation)
  static generateCharacterCreationDate(accountCreatedAt) {
    const accountDate = new Date(accountCreatedAt);
    const now = new Date();
    
    // Character created between account creation and now
    // Bias towards earlier dates (most characters created soon after account)
    const timeSinceAccount = now.getTime() - accountDate.getTime();
    const bias = Math.random() * Math.random(); // Square for bias towards 0
    const characterTime = accountDate.getTime() + (bias * timeSinceAccount);
    
    return new Date(characterTime);
  }

  // Generate last played date for character
  static generateCharacterLastPlayed(characterCreatedAt, userType = 'casual') {
    const created = new Date(characterCreatedAt);
    const now = new Date();
    
    // Similar to user last login but can be more recent
    let maxDaysAgo;
    switch (userType) {
      case 'active':
        maxDaysAgo = Math.random() * 2; // Within last 2 days
        break;
      case 'casual':
        maxDaysAgo = Math.random() * 10; // Within last 10 days
        break;
      case 'dormant':
        maxDaysAgo = 5 + Math.random() * 30; // 5 days to 1 month ago
        break;
      default:
        maxDaysAgo = Math.random() * 5;
    }
    
    const lastPlayed = new Date(now.getTime() - (maxDaysAgo * 24 * 60 * 60 * 1000));
    
    // Ensure last played is after character creation
    return lastPlayed < created ? created : lastPlayed;
  }

  // Generate session login time within realistic hours
  static generateSessionLoginTime(userCreatedAt, peakHours = true) {
    const userDate = new Date(userCreatedAt);
    const now = new Date();
    
    // Session within last 30 days but after user creation
    const maxDaysAgo = Math.min(30, (now - userDate) / (1000 * 60 * 60 * 24));
    const daysAgo = Math.random() * maxDaysAgo;
    
    const sessionDate = new Date(now.getTime() - (daysAgo * 24 * 60 * 60 * 1000));
    
    if (peakHours) {
      // Bias towards peak hours (18:00-23:00 weekdays, 10:00-24:00 weekends)
      const dayOfWeek = sessionDate.getDay();
      const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
      
      let hour;
      if (isWeekend) {
        // Weekend: 10:00-24:00 peak, but bias towards evening
        if (Math.random() < 0.7) {
          hour = 18 + Math.floor(Math.random() * 6); // 18-23
        } else {
          hour = 10 + Math.floor(Math.random() * 14); // 10-23
        }
      } else {
        // Weekday: stronger bias towards 18:00-23:00
        if (Math.random() < 0.8) {
          hour = 18 + Math.floor(Math.random() * 6); // 18-23
        } else {
          hour = Math.floor(Math.random() * 24); // Any hour
        }
      }
      
      sessionDate.setHours(hour, Math.floor(Math.random() * 60), Math.floor(Math.random() * 60));
    }
    
    return sessionDate;
  }

  // Generate session logout time based on duration
  static generateSessionLogoutTime(loginTime, sessionDurationMinutes) {
    const login = new Date(loginTime);
    return new Date(login.getTime() + (sessionDurationMinutes * 60 * 1000));
  }

  // Generate activity timestamp within session
  static generateActivityTimestamp(sessionLoginTime, sessionLogoutTime) {
    const login = new Date(sessionLoginTime);
    const logout = sessionLogoutTime ? new Date(sessionLogoutTime) : new Date(login.getTime() + (2 * 60 * 60 * 1000)); // Default 2 hour session
    
    return this.randomDateBetween(login, logout);
  }

  // Format date for SQLite
  static formatForSQLite(date) {
    return date.toISOString().slice(0, 19).replace('T', ' ');
  }

  // Generate realistic session duration based on user type
  static generateSessionDuration(userType = 'casual', timeOfDay = 'evening') {
    let baseMin, baseMax;
    
    switch (userType) {
      case 'active':
        baseMin = 60;
        baseMax = 240; // 1-4 hours
        break;
      case 'casual':
        baseMin = 30;
        baseMax = 120; // 30min-2 hours
        break;
      case 'dormant':
        baseMin = 15;
        baseMax = 60; // 15min-1 hour
        break;
      default:
        baseMin = 45;
        baseMax = 150;
    }
    
    // Adjust based on time of day
    if (timeOfDay === 'weekend' || timeOfDay === 'evening') {
      baseMax *= 1.3; // Longer sessions in evening/weekend
    } else if (timeOfDay === 'morning') {
      baseMax *= 0.7; // Shorter morning sessions
    }
    
    return Math.floor(baseMin + Math.random() * (baseMax - baseMin));
  }

  // Generate time between activities within a session
  static generateActivityGap(activityType = 'gameplay') {
    switch (activityType) {
      case 'marketplace':
        return 1 + Math.random() * 5; // 1-5 minutes between marketplace actions
      case 'chat':
        return 0.5 + Math.random() * 2; // 30sec-2min between chat actions
      case 'gameplay':
        return 5 + Math.random() * 15; // 5-15 minutes between gameplay activities
      default:
        return 2 + Math.random() * 8;
    }
  }

  // Generate realistic login frequency pattern
  static generateLoginPattern(userType, days = 30) {
    const pattern = [];
    const now = new Date();
    
    let frequency; // logins per week
    switch (userType) {
      case 'active':
        frequency = 4 + Math.random() * 3; // 4-7 times per week
        break;
      case 'casual':
        frequency = 2 + Math.random() * 2; // 2-4 times per week
        break;
      case 'dormant':
        frequency = Math.random() * 2; // 0-2 times per week
        break;
      default:
        frequency = 3;
    }
    
    const totalLogins = Math.floor((days / 7) * frequency);
    
    for (let i = 0; i < totalLogins; i++) {
      const daysAgo = Math.random() * days;
      const loginDate = new Date(now.getTime() - (daysAgo * 24 * 60 * 60 * 1000));
      pattern.push(loginDate);
    }
    
    // Sort chronologically (oldest first)
    pattern.sort((a, b) => a - b);
    
    return pattern;
  }

  // Get time of day category for session timing
  static getTimeOfDay(date) {
    const hour = date.getHours();
    const dayOfWeek = date.getDay();
    const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
    
    if (isWeekend) {
      return 'weekend';
    } else if (hour >= 6 && hour < 12) {
      return 'morning';
    } else if (hour >= 12 && hour < 18) {
      return 'afternoon';
    } else {
      return 'evening';
    }
  }

  // Calculate age in days
  static daysSince(date) {
    const now = new Date();
    const past = new Date(date);
    return Math.floor((now - past) / (1000 * 60 * 60 * 24));
  }

  // Generate consistent dates based on index
  static generateConsistentDate(baseDate, index, variationDays = 30) {
    const base = new Date(baseDate);
    const seed = index * 1234567; // Large prime for good distribution
    const variation = (Math.sin(seed) * variationDays * 24 * 60 * 60 * 1000);
    return new Date(base.getTime() + variation);
  }
}

module.exports = DateHelpers;