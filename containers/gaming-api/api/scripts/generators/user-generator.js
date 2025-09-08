const bcrypt = require('bcryptjs');
const NameGenerators = require('../utils/name-generators');
const DateHelpers = require('../utils/date-helpers');
const ProbabilityHelpers = require('../utils/probability');

class UserGenerator {
  constructor(config) {
    this.config = config;
  }

  async generateUsers() {
    const users = [];
    const { count, distribution } = this.config.users;
    
    // Calculate user type distribution
    const activeCount = Math.floor(count * distribution.active);
    const casualCount = Math.floor(count * distribution.casual);
    const dormantCount = count - activeCount - casualCount;
    
    console.log(`Generating ${count} users: ${activeCount} active, ${casualCount} casual, ${dormantCount} dormant`);
    
    let userIndex = 0;
    
    // Generate active users
    for (let i = 0; i < activeCount; i++) {
      users.push(await this.generateUser(userIndex++, 'active'));
    }
    
    // Generate casual users
    for (let i = 0; i < casualCount; i++) {
      users.push(await this.generateUser(userIndex++, 'casual'));
    }
    
    // Generate dormant users
    for (let i = 0; i < dormantCount; i++) {
      users.push(await this.generateUser(userIndex++, 'dormant'));
    }
    
    return users;
  }

  async generateUser(index, userType) {
    const username = NameGenerators.generateConsistentData('username', index);
    const email = NameGenerators.generateConsistentData('email', index, username);
    
    // Generate password hash (use simple password + username for CTF scenario)
    const password = `password${index + 1}`; // Simple predictable passwords for testing
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Generate account creation date
    const createdAt = DateHelpers.generateAccountCreationDate(this.config.timeRange.startDaysAgo);
    
    // Generate last login based on user type
    const lastLogin = DateHelpers.generateLastLoginDate(createdAt, userType);
    
    // Premium status (more likely for active users)
    const isPremium = this.determinePremiumStatus(userType, index);
    
    // Account value based on user type and premium status
    const accountValue = this.generateAccountValue(userType, isPremium, index);
    
    // Total playtime based on user type and account age
    const totalPlaytimeHours = this.generatePlaytime(userType, createdAt, index);
    
    // Generate IP and location data
    const lastIpAddress = NameGenerators.generateConsistentData('ipAddress', index);
    const geoLocation = NameGenerators.generateConsistentData('geoLocation', index);
    
    // Other user attributes
    const preferredLanguage = this.selectPreferredLanguage(index);
    const timezone = this.selectTimezone(geoLocation, index);
    
    return {
      id: index + 1,
      username,
      password_hash: passwordHash,
      email,
      created_at: DateHelpers.formatForSQLite(createdAt),
      last_login: DateHelpers.formatForSQLite(lastLogin),
      is_premium: isPremium,
      account_value: accountValue,
      email_verified: ProbabilityHelpers.seededProbability(index, 0, 1) < 0.85, // 85% verified
      total_playtime_hours: totalPlaytimeHours,
      last_ip_address: lastIpAddress,
      preferred_language: preferredLanguage,
      timezone: timezone,
      // Additional fields for tracking
      user_type: userType, // Not stored in DB, just for generation
      raw_password: password // Not stored in DB, for testing purposes only
    };
  }

  determinePremiumStatus(userType, index) {
    const baseProbability = {
      active: 0.35,    // 35% of active users are premium
      casual: 0.15,    // 15% of casual users are premium
      dormant: 0.05    // 5% of dormant users are premium
    };
    
    return ProbabilityHelpers.seededProbability(index, 0, 1) < baseProbability[userType];
  }

  generateAccountValue(userType, isPremium, index) {
    let baseValue = 0;
    
    // Base value from user type
    switch (userType) {
      case 'active':
        baseValue = ProbabilityHelpers.seededProbability(index * 2, 50, 500);
        break;
      case 'casual':
        baseValue = ProbabilityHelpers.seededProbability(index * 3, 20, 200);
        break;
      case 'dormant':
        baseValue = ProbabilityHelpers.seededProbability(index * 4, 5, 50);
        break;
    }
    
    // Premium multiplier
    if (isPremium) {
      baseValue *= 2.5;
    }
    
    return Math.floor(baseValue);
  }

  generatePlaytime(userType, createdAt, index) {
    const accountAgeInDays = DateHelpers.daysSince(createdAt);
    
    // Base hours per day based on user type
    const baseHoursPerDay = {
      active: 2.5,
      casual: 1.2,
      dormant: 0.3
    };
    
    const dailyHours = baseHoursPerDay[userType] || 1.0;
    const variation = ProbabilityHelpers.seededProbability(index * 5, 0.7, 1.3);
    
    return Math.floor(accountAgeInDays * dailyHours * variation);
  }

  selectPreferredLanguage(index) {
    const languages = [
      'en-US', 'en-GB', 'es-ES', 'fr-FR', 'de-DE', 'ja-JP', 
      'ko-KR', 'zh-CN', 'pt-BR', 'ru-RU', 'it-IT', 'nl-NL'
    ];
    
    // Weight towards English but include variety
    const weights = [0.4, 0.15, 0.08, 0.06, 0.05, 0.05, 0.04, 0.04, 0.04, 0.03, 0.03, 0.03];
    
    return ProbabilityHelpers.consistentSelect(languages, index);
  }

  selectTimezone(geoLocation, index) {
    // Map geo locations to common timezones
    const timezoneMap = {
      'New York, NY, US': 'America/New_York',
      'Los Angeles, CA, US': 'America/Los_Angeles', 
      'London, UK': 'Europe/London',
      'Berlin, DE': 'Europe/Berlin',
      'Tokyo, JP': 'Asia/Tokyo',
      'Seoul, KR': 'Asia/Seoul',
      'Sydney, AU': 'Australia/Sydney',
      'Toronto, CA': 'America/Toronto',
      'São Paulo, BR': 'America/Sao_Paulo',
      'Moscow, RU': 'Europe/Moscow',
      'Mumbai, IN': 'Asia/Kolkata',
      'Singapore, SG': 'Asia/Singapore',
      'Paris, FR': 'Europe/Paris',
      'Amsterdam, NL': 'Europe/Amsterdam',
      'Stockholm, SE': 'Europe/Stockholm'
    };
    
    return timezoneMap[geoLocation] || 'UTC';
  }

  // Generate login history entries for user
  generateLoginHistory(user, sessionsCount = null) {
    const loginHistory = [];
    const userType = user.user_type;
    
    // Determine how many login attempts to generate
    const sessionCount = sessionsCount || this.estimateSessionCount(userType);
    const failureRate = this.getFailureRate(userType);
    const totalAttempts = Math.ceil(sessionCount / (1 - failureRate));
    
    // Generate login pattern over time
    const accountCreated = new Date(user.created_at);
    const now = new Date();
    const accountAgeInDays = DateHelpers.daysSince(accountCreated);
    
    for (let i = 0; i < totalAttempts; i++) {
      const isSuccess = Math.random() > failureRate;
      const attemptIndex = i + user.id * 1000; // Unique seed
      
      // Generate timestamp
      const daysAgo = Math.random() * Math.min(accountAgeInDays, 90);
      const timestamp = new Date(now.getTime() - (daysAgo * 24 * 60 * 60 * 1000));
      
      // Ensure timestamp is after account creation
      const loginTime = timestamp < accountCreated ? accountCreated : timestamp;
      
      const loginEntry = {
        user_id: user.id,
        username: user.username,
        ip_address: this.generateIPAddress(user.last_ip_address, attemptIndex),
        user_agent: NameGenerators.generateUserAgent(),
        login_time: DateHelpers.formatForSQLite(loginTime),
        success: isSuccess,
        failure_reason: isSuccess ? null : this.generateFailureReason(),
        geo_location: user.timezone ? this.timezoneToLocation(user.timezone) : 'Unknown',
        device_fingerprint: NameGenerators.generateDeviceFingerprint()
      };
      
      loginHistory.push(loginEntry);
    }
    
    // Sort by timestamp
    loginHistory.sort((a, b) => new Date(a.login_time) - new Date(b.login_time));
    
    return loginHistory;
  }

  estimateSessionCount(userType) {
    const baseCounts = {
      active: 15,
      casual: 8,
      dormant: 3
    };
    
    return baseCounts[userType] || 8;
  }

  getFailureRate(userType) {
    // Failure rates for different user types (simulating forgot password, typos, etc.)
    const failureRates = {
      active: 0.05,    // 5% failure rate
      casual: 0.10,    // 10% failure rate  
      dormant: 0.15    // 15% failure rate
    };
    
    return failureRates[userType] || 0.10;
  }

  generateIPAddress(baseIP, seed) {
    // Generate IP addresses that are similar to base but with some variation
    // This simulates users connecting from home, mobile, work, etc.
    if (Math.random() < 0.8) {
      return baseIP; // 80% same IP
    } else {
      // Generate nearby IP (simulating mobile/different ISP)
      return NameGenerators.generateIPAddress();
    }
  }

  generateFailureReason() {
    const reasons = [
      'invalid_password',
      'invalid_username',
      'account_locked',
      'too_many_attempts',
      'session_expired'
    ];
    
    return ProbabilityHelpers.getRandomElement(reasons);
  }

  timezoneToLocation(timezone) {
    const locationMap = {
      'America/New_York': 'New York, NY, US',
      'America/Los_Angeles': 'Los Angeles, CA, US',
      'Europe/London': 'London, UK',
      'Europe/Berlin': 'Berlin, DE',
      'Asia/Tokyo': 'Tokyo, JP',
      'Asia/Seoul': 'Seoul, KR',
      'Australia/Sydney': 'Sydney, AU',
      'America/Toronto': 'Toronto, CA',
      'America/Sao_Paulo': 'São Paulo, BR',
      'Europe/Moscow': 'Moscow, RU',
      'Asia/Kolkata': 'Mumbai, IN',
      'Asia/Singapore': 'Singapore, SG',
      'Europe/Paris': 'Paris, FR',
      'Europe/Amsterdam': 'Amsterdam, NL',
      'Europe/Stockholm': 'Stockholm, SE'
    };
    
    return locationMap[timezone] || 'Unknown';
  }

  // Validation
  validateUsers(users) {
    const errors = [];
    const usernames = new Set();
    const emails = new Set();
    
    for (const user of users) {
      // Check for duplicates
      if (usernames.has(user.username)) {
        errors.push(`Duplicate username: ${user.username}`);
      } else {
        usernames.add(user.username);
      }
      
      if (emails.has(user.email)) {
        errors.push(`Duplicate email: ${user.email}`);
      } else {
        emails.add(user.email);
      }
      
      // Validate required fields
      if (!user.username || user.username.length < 3) {
        errors.push(`Invalid username for user ${user.id}`);
      }
      
      if (!user.email || !user.email.includes('@')) {
        errors.push(`Invalid email for user ${user.id}`);
      }
      
      if (!user.password_hash) {
        errors.push(`Missing password hash for user ${user.id}`);
      }
    }
    
    return errors;
  }
}

module.exports = UserGenerator;