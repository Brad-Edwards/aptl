const DateHelpers = require('../utils/date-helpers');
const ProbabilityHelpers = require('../utils/probability');
const NameGenerators = require('../utils/name-generators');
const ActivityGenerator = require('./activity-generator');

class SessionGenerator {
  constructor(config) {
    this.config = config;
    this.activityGenerator = new ActivityGenerator(config);
  }

  generateSessions(users, characters) {
    const sessions = [];
    const loginHistory = [];
    let sessionCount = 0;
    
    console.log(`Generating sessions for ${users.length} users`);
    
    for (const user of users) {
      const userCharacters = characters.filter(c => c.user_id === user.id);
      const userType = user.user_type;
      
      // Determine number of sessions for this user
      const sessionCountForUser = this.determineSessionCount(userType, user.id);
      
      // Generate login pattern over time
      const loginTimes = this.generateLoginPattern(user, sessionCountForUser);
      
      for (let i = 0; i < sessionCountForUser; i++) {
        const loginTime = loginTimes[i];
        const session = this.generateSession(user, userCharacters, loginTime, sessionCount + 1);
        
        sessions.push(session);
        
        // Generate login history entry for this session
        const loginEntry = this.generateLoginHistoryEntry(user, session, true);
        loginHistory.push(loginEntry);
        
        sessionCount++;
      }
      
      // Generate some failed login attempts
      const failedAttempts = this.generateFailedLoginAttempts(user);
      loginHistory.push(...failedAttempts);
    }
    
    // Sort login history by timestamp
    loginHistory.sort((a, b) => new Date(a.login_time) - new Date(b.login_time));
    
    console.log(`Generated ${sessions.length} sessions and ${loginHistory.length} login history entries`);
    
    return { sessions, loginHistory };
  }

  determineSessionCount(userType, userId) {
    const baseCounts = {
      active: { min: 10, max: 20 },
      casual: { min: 4, max: 12 },
      dormant: { min: 1, max: 5 }
    };
    
    const range = baseCounts[userType] || baseCounts.casual;
    const random = ProbabilityHelpers.seededProbability(userId * 567, 0, 1);
    
    return Math.floor(range.min + random * (range.max - range.min + 1));
  }

  generateLoginPattern(user, sessionCount) {
    const loginTimes = [];
    const now = new Date();
    const accountCreated = new Date(user.created_at);
    const accountAgeInDays = DateHelpers.daysSince(accountCreated);
    const maxDaysBack = Math.min(accountAgeInDays, 90);
    
    const userType = user.user_type;
    
    // Generate session distribution over time
    for (let i = 0; i < sessionCount; i++) {
      let daysAgo;
      
      switch (userType) {
        case 'active':
          // Active users: Recent sessions with bias towards last 30 days
          daysAgo = ProbabilityHelpers.biasedRandom(0, maxDaysBack, 0.3, 2);
          break;
        case 'casual':
          // Casual users: Spread evenly over time
          daysAgo = Math.random() * maxDaysBack;
          break;
        case 'dormant':
          // Dormant users: Bias towards older sessions
          daysAgo = ProbabilityHelpers.biasedRandom(7, maxDaysBack, 0.7, 1.5);
          break;
        default:
          daysAgo = Math.random() * maxDaysBack;
      }
      
      const sessionDate = new Date(now.getTime() - (daysAgo * 24 * 60 * 60 * 1000));
      
      // Ensure session is after account creation
      const loginTime = sessionDate < accountCreated ? accountCreated : sessionDate;
      
      // Adjust for peak hours
      const adjustedLoginTime = this.adjustForPeakHours(loginTime);
      
      loginTimes.push(adjustedLoginTime);
    }
    
    // Sort chronologically
    loginTimes.sort((a, b) => a - b);
    
    return loginTimes;
  }

  adjustForPeakHours(loginTime) {
    const peakHours = this.config.sessions.timing.peakHours;
    const weekendExtended = this.config.sessions.timing.weekendExtended;
    
    const dayOfWeek = loginTime.getDay();
    const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
    
    // 70% chance to adjust to peak hours
    if (Math.random() < 0.7) {
      const targetHours = isWeekend ? weekendExtended : peakHours;
      const randomHour = ProbabilityHelpers.consistentSelect(targetHours, loginTime.getTime());
      
      loginTime.setHours(randomHour, Math.floor(Math.random() * 60), Math.floor(Math.random() * 60));
    }
    
    return loginTime;
  }

  generateSession(user, userCharacters, loginTime, sessionIndex) {
    const userType = user.user_type;
    
    // Select character for this session (if user has multiple)
    const character = userCharacters.length > 0 ? 
      this.selectCharacterForSession(userCharacters, sessionIndex) : null;
    
    // Generate session duration
    const timeOfDay = DateHelpers.getTimeOfDay(loginTime);
    const sessionDuration = DateHelpers.generateSessionDuration(userType, timeOfDay);
    
    // Calculate logout time
    const logoutTime = DateHelpers.generateSessionLogoutTime(loginTime, sessionDuration);
    
    // Generate session ID
    const sessionId = NameGenerators.generateSessionId();
    
    // Generate session pattern
    const sessionPattern = ProbabilityHelpers.selectSessionPattern();
    
    // Generate IP and user agent (consistent per user with some variation)
    const ipAddress = this.generateSessionIP(user.last_ip_address, sessionIndex);
    const userAgent = this.generateSessionUserAgent(user.id, sessionIndex);
    
    // Estimate actions count and locations visited based on session duration and pattern
    const { actionsCount, locationsVisited } = this.estimateSessionActivity(sessionDuration, sessionPattern, character);
    
    const session = {
      user_id: user.id,
      character_id: character ? character.id : null,
      session_id: sessionId,
      login_time: DateHelpers.formatForSQLite(loginTime),
      logout_time: DateHelpers.formatForSQLite(logoutTime),
      actions_count: actionsCount,
      locations_visited: locationsVisited,
      ip_address: ipAddress,
      user_agent: userAgent,
      // Additional metadata for activity generation
      duration_minutes: sessionDuration,
      session_pattern: sessionPattern,
      user_type: userType
    };
    
    return session;
  }

  selectCharacterForSession(userCharacters, sessionIndex) {
    if (userCharacters.length === 1) {
      return userCharacters[0];
    }
    
    // Bias towards higher level characters and most recently played
    const weights = userCharacters.map(char => {
      let weight = char.level / 10; // Level contributes to weight
      
      // Recently played bonus
      const daysSinceLastPlayed = DateHelpers.daysSince(char.last_played);
      if (daysSinceLastPlayed < 7) weight += 2;
      else if (daysSinceLastPlayed < 30) weight += 1;
      
      return { character: char, weight };
    });
    
    return ProbabilityHelpers.weightedRandom(weights).character;
  }

  estimateSessionActivity(sessionDuration, sessionPattern, character) {
    let baseActionsPerMinute = 0.5; // Base activity rate
    
    // Adjust based on session pattern
    const patternMultipliers = {
      marketplace_first: 1.2,  // More clicks in marketplace
      direct_gameplay: 0.8,    // Fewer but longer activities
      social_first: 1.5,       // Lots of chat messages
      economic_focus: 1.3      // High marketplace activity
    };
    
    const multiplier = patternMultipliers[sessionPattern] || 1.0;
    baseActionsPerMinute *= multiplier;
    
    // Character level affects activity (higher level = more complex activities)
    if (character) {
      const levelMultiplier = 1 + (character.level - 1) * 0.01; // 1% increase per level
      baseActionsPerMinute *= levelMultiplier;
    }
    
    const actionsCount = Math.floor(sessionDuration * baseActionsPerMinute);
    
    // Locations visited based on session pattern and duration
    let locationsCount = Math.min(8, Math.max(1, Math.floor(sessionDuration / 20))); // 1 location per ~20 minutes
    
    const locationMultipliers = {
      marketplace_first: 1.2,
      direct_gameplay: 0.8,    // Fewer location changes
      social_first: 1.0,
      economic_focus: 0.6      // Mainly marketplace
    };
    
    locationsCount = Math.floor(locationsCount * (locationMultipliers[sessionPattern] || 1.0));
    
    return {
      actionsCount: Math.max(1, actionsCount),
      locationsVisited: Math.max(1, locationsCount)
    };
  }

  generateSessionIP(baseIP, sessionIndex) {
    // 85% chance to use the same IP, 15% chance for variation (mobile, work, etc.)
    if (ProbabilityHelpers.seededProbability(sessionIndex * 654, 0, 1) < 0.85) {
      return baseIP;
    } else {
      return NameGenerators.generateIPAddress();
    }
  }

  generateSessionUserAgent(userId, sessionIndex) {
    // Generate consistent but occasionally varying user agents
    const agents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ];
    
    // Users typically stick to one browser but occasionally switch
    const primaryAgent = agents[userId % agents.length];
    
    if (ProbabilityHelpers.seededProbability(sessionIndex * 987, 0, 1) < 0.9) {
      return primaryAgent;
    } else {
      return ProbabilityHelpers.consistentSelect(agents, sessionIndex);
    }
  }

  generateLoginHistoryEntry(user, session, success) {
    const entry = {
      user_id: user.id,
      username: user.username,
      ip_address: session.ip_address,
      user_agent: session.user_agent,
      login_time: session.login_time,
      success: success,
      failure_reason: success ? null : this.generateFailureReason(),
      geo_location: this.ipToGeoLocation(session.ip_address),
      device_fingerprint: NameGenerators.generateDeviceFingerprint()
    };
    
    return entry;
  }

  generateFailedLoginAttempts(user) {
    const failedAttempts = [];
    const userType = user.user_type;
    
    // Determine number of failed attempts based on user type
    let failureCount = 0;
    switch (userType) {
      case 'active':
        failureCount = Math.random() < 0.3 ? ProbabilityHelpers.randomInt(1, 2) : 0; // 30% chance of 1-2 failures
        break;
      case 'casual':
        failureCount = Math.random() < 0.4 ? ProbabilityHelpers.randomInt(1, 3) : 0; // 40% chance of 1-3 failures
        break;
      case 'dormant':
        failureCount = Math.random() < 0.5 ? ProbabilityHelpers.randomInt(1, 4) : 0; // 50% chance of 1-4 failures
        break;
    }
    
    const now = new Date();
    const accountCreated = new Date(user.created_at);
    
    for (let i = 0; i < failureCount; i++) {
      // Generate failure time
      const daysAgo = Math.random() * Math.min(90, DateHelpers.daysSince(accountCreated));
      const failureTime = new Date(now.getTime() - (daysAgo * 24 * 60 * 60 * 1000));
      
      // Ensure failure is after account creation
      const adjustedTime = failureTime < accountCreated ? accountCreated : failureTime;
      
      const failedAttempt = {
        user_id: user.id,
        username: user.username,
        ip_address: this.generateFailureIP(user.last_ip_address),
        user_agent: NameGenerators.generateUserAgent(),
        login_time: DateHelpers.formatForSQLite(adjustedTime),
        success: false,
        failure_reason: this.generateFailureReason(),
        geo_location: this.ipToGeoLocation(user.last_ip_address),
        device_fingerprint: NameGenerators.generateDeviceFingerprint()
      };
      
      failedAttempts.push(failedAttempt);
    }
    
    return failedAttempts;
  }

  generateFailureIP(baseIP) {
    // Failed attempts might come from different IPs (attempted intrusions, user on different device, etc.)
    if (Math.random() < 0.7) {
      return baseIP; // Same user, wrong password
    } else {
      return NameGenerators.generateIPAddress(); // Different IP (potential attack or user on different network)
    }
  }

  generateFailureReason() {
    const reasons = [
      'invalid_password',
      'invalid_username', 
      'account_locked',
      'session_expired',
      'too_many_attempts'
    ];
    
    const weights = [0.6, 0.2, 0.1, 0.05, 0.05]; // Password errors most common
    
    let random = Math.random();
    for (let i = 0; i < reasons.length; i++) {
      random -= weights[i];
      if (random <= 0) {
        return reasons[i];
      }
    }
    
    return 'invalid_password';
  }

  ipToGeoLocation(ipAddress) {
    // Simple IP to geo mapping for common ranges
    const firstOctet = parseInt(ipAddress.split('.')[0]);
    
    if (firstOctet >= 200 && firstOctet <= 210) return 'São Paulo, BR';
    if (firstOctet >= 185 && firstOctet <= 195) return 'London, UK';
    if (firstOctet >= 203 && firstOctet <= 210) return 'Tokyo, JP';
    if (firstOctet >= 72 && firstOctet <= 80) return 'New York, NY, US';
    
    return 'Unknown';
  }

  // Generate detailed session activities
  generateSessionWithActivities(session, character) {
    const sessionPattern = session.session_pattern;
    
    // Generate all activities for this session
    const activities = this.activityGenerator.generateSessionActivities(session, character, sessionPattern);
    
    return {
      session,
      activities: {
        gameplay: activities.gameplay,
        marketplace: activities.marketplace,
        social: activities.social
      }
    };
  }

  // Validation
  validateSessions(sessions, users, characters) {
    const errors = [];
    const userIds = new Set(users.map(u => u.id));
    const characterIds = new Set(characters.map(c => c.id));
    
    for (const session of sessions) {
      if (!userIds.has(session.user_id)) {
        errors.push(`Session references non-existent user ${session.user_id}`);
      }
      
      if (session.character_id && !characterIds.has(session.character_id)) {
        errors.push(`Session references non-existent character ${session.character_id}`);
      }
      
      if (!session.session_id || session.session_id.length < 10) {
        errors.push('Invalid session ID');
      }
      
      const loginTime = new Date(session.login_time);
      const logoutTime = new Date(session.logout_time);
      
      if (logoutTime <= loginTime) {
        errors.push('Logout time must be after login time');
      }
      
      const duration = (logoutTime - loginTime) / (1000 * 60); // minutes
      if (duration > 600) { // 10 hours
        errors.push(`Unrealistic session duration: ${duration} minutes`);
      }
    }
    
    return errors;
  }

  // Generate session distribution report
  generateSessionReport(sessions) {
    const report = {
      total: sessions.length,
      byUserType: {},
      byPattern: {},
      averageDuration: 0,
      averageActions: 0,
      durationDistribution: {
        short: 0,    // < 30 minutes
        medium: 0,   // 30-120 minutes
        long: 0      // > 120 minutes
      }
    };
    
    let totalDuration = 0;
    let totalActions = 0;
    
    for (const session of sessions) {
      // By user type
      const userType = session.user_type || 'unknown';
      report.byUserType[userType] = (report.byUserType[userType] || 0) + 1;
      
      // By pattern
      const pattern = session.session_pattern || 'unknown';
      report.byPattern[pattern] = (report.byPattern[pattern] || 0) + 1;
      
      // Duration
      const duration = session.duration_minutes || 60;
      totalDuration += duration;
      
      if (duration < 30) report.durationDistribution.short++;
      else if (duration < 120) report.durationDistribution.medium++;
      else report.durationDistribution.long++;
      
      // Actions
      totalActions += session.actions_count || 0;
    }
    
    report.averageDuration = Math.floor(totalDuration / sessions.length);
    report.averageActions = Math.floor(totalActions / sessions.length);
    
    return report;
  }
}

module.exports = SessionGenerator;