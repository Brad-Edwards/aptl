const crypto = require('crypto');

class NameGenerators {
  static usernames = [
    'ShadowHunter', 'DragonSlayer', 'MysticWanderer', 'IronFist', 'FireStorm',
    'NightRaven', 'SteelBlade', 'ThunderBolt', 'FrostMage', 'BloodWolf',
    'DarkKnight', 'LightBringer', 'StormRider', 'BladeMaster', 'RuneKeeper',
    'DeathWhisper', 'SoulReaper', 'WindWalker', 'EarthShaker', 'FlameKeeper',
    'IceQueen', 'StormLord', 'ShadowDancer', 'BattleAxe', 'MoonWalker',
    'StarGazer', 'VoidWalker', 'PhoenixRising', 'DragonHeart', 'WolfPack',
    'LionHeart', 'EagleEye', 'BearClaw', 'FalconStrike', 'TigerFang',
    'CrimsonBlade', 'GoldenArrow', 'SilverWing', 'BronzeShield', 'PlatinumCrown',
    'DiamondEdge', 'EmeraldEye', 'RubyHeart', 'SapphireSoul', 'OpalMoon',
    'GamerGod', 'PixelMaster', 'CodeWarrior', 'ByteBeast', 'DataDragon',
    'CyberSamurai', 'NetNinja', 'WebWizard', 'TechTitan', 'DigitalDemon',
    'VirtualViper', 'OnlineOrc', 'StreamSniper', 'ChatChampion', 'ForumFighter',
    'GuildMaster', 'RaidLeader', 'LootLord', 'ExpFarmer', 'GoldDigger',
    'ItemHunter', 'QuestMaster', 'DungeonDelver', 'BossSlayer', 'ElitePlayer',
    'ProGamer', 'SkillShot', 'HeadHunter', 'FragMaster', 'KillStreak',
    'ComboKing', 'SpeedRun', 'HighScore', 'TopTier', 'MLGPro',
    'NoobSlayer', 'VetPlayer', 'OldSchool', 'Hardcore', 'Casual',
    'WeekendWarrior', 'MidnightGamer', 'DawnBreaker', 'TwilightHunter', 'SunsetRider'
  ];

  static characterNames = {
    warrior: [
      'Thorgar', 'Grimlock', 'Ironwall', 'Shieldbreaker', 'Battleborn',
      'Warhammer', 'Steelhand', 'Bloodfang', 'Axemaster', 'Swordarm',
      'Ragnar', 'Bjorn', 'Gunnar', 'Magnus', 'Erik',
      'Gorath', 'Thane', 'Ulfric', 'Gareth', 'Roderick'
    ],
    mage: [
      'Eldara', 'Mystral', 'Arcanum', 'Spellweaver', 'Moonwhisper',
      'Starlight', 'Flameheart', 'Frostwind', 'Stormcaller', 'Voidwalker',
      'Celestine', 'Morgana', 'Seraphina', 'Isolde', 'Lyralei',
      'Khadgar', 'Jaina', 'Antonidas', 'Medivh', 'Aegwynn'
    ],
    rogue: [
      'Shadowstep', 'Silverblade', 'Nightfall', 'Whisperwind', 'Blackdagger',
      'Swiftarrow', 'Ghostwalk', 'Darkbane', 'Stabsalot', 'Sneakattack',
      'Valeera', 'Garona', 'Vanessa', 'Mathias', 'Edwin',
      'Zara', 'Kira', 'Sable', 'Raven', 'Nyx'
    ],
    archer: [
      'Eagleeye', 'Trueshot', 'Windshot', 'Swiftarrow', 'Longbow',
      'Marksman', 'Hawkeye', 'Bullseye', 'Deadshot', 'Sniper',
      'Artemis', 'Diana', 'Orion', 'Hunter', 'Ranger',
      'Sylvanas', 'Alleria', 'Vereesa', 'Tyrande', 'Maiev'
    ],
    cleric: [
      'Holylight', 'Divinegrace', 'Lightbringer', 'Peacekeeper', 'Soulguard',
      'Benediction', 'Sanctuary', 'Guardian', 'Protector', 'Healer',
      'Anduin', 'Uther', 'Tirion', 'Turalyon', 'Velen',
      'Elara', 'Serenity', 'Grace', 'Hope', 'Faith'
    ]
  };

  static domains = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'icloud.com', 'protonmail.com', 'tutanota.com', 'fastmail.com',
    'gamemail.com', 'playeremail.com', 'gamerzone.net', 'rpgmail.org'
  ];

  static getRandomElement(array) {
    return array[Math.floor(Math.random() * array.length)];
  }

  static generateUsername(index = null) {
    const baseNames = [...this.usernames];
    
    if (index !== null) {
      // Use index to ensure deterministic but varied names
      const nameIndex = index % baseNames.length;
      const baseName = baseNames[nameIndex];
      
      // Add variety with numbers or suffixes
      const variations = [
        baseName,
        `${baseName}${Math.floor(index / baseNames.length) + 1}`,
        `${baseName}_${(index * 7) % 99 + 1}`,
        `${baseName}${String.fromCharCode(65 + (index % 26))}`
      ];
      
      return variations[index % variations.length];
    }
    
    // Random generation
    const baseName = this.getRandomElement(baseNames);
    const rand = Math.floor(Math.random() * 100);
    
    if (rand < 60) {
      return baseName;
    } else if (rand < 85) {
      return `${baseName}${Math.floor(Math.random() * 999) + 1}`;
    } else {
      return `${baseName}_${Math.floor(Math.random() * 99) + 1}`;
    }
  }

  static generateCharacterName(characterClass, index = null) {
    const classNames = this.characterNames[characterClass.toLowerCase()];
    
    if (!classNames) {
      // Fallback to warrior names if class not found
      return this.generateCharacterName('warrior', index);
    }
    
    if (index !== null) {
      const nameIndex = index % classNames.length;
      const baseName = classNames[nameIndex];
      
      // Add slight variations to avoid duplicates
      const variations = [
        baseName,
        `${baseName}${String.fromCharCode(97 + (index % 26))}`,
        `${baseName}the${['Bold', 'Brave', 'Swift', 'Wise', 'Strong'][index % 5]}`
      ];
      
      return variations[index % variations.length];
    }
    
    return this.getRandomElement(classNames);
  }

  static generateEmail(username, index = null) {
    if (index !== null) {
      const domainIndex = index % this.domains.length;
      const domain = this.domains[domainIndex];
      return `${username.toLowerCase()}@${domain}`;
    }
    
    const domain = this.getRandomElement(this.domains);
    return `${username.toLowerCase()}@${domain}`;
  }

  static generateSessionId() {
    return crypto.randomBytes(16).toString('hex');
  }

  static generateDeviceFingerprint() {
    const browsers = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera'];
    const oses = ['Windows 10', 'Windows 11', 'macOS', 'Ubuntu', 'Android', 'iOS'];
    const screens = ['1920x1080', '1366x768', '2560x1440', '1440x900', '1280x720'];
    
    const browser = this.getRandomElement(browsers);
    const os = this.getRandomElement(oses);
    const screen = this.getRandomElement(screens);
    
    return `${browser}|${os}|${screen}`;
  }

  static generateUserAgent() {
    const userAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
    ];
    
    return this.getRandomElement(userAgents);
  }

  static generateIPAddress() {
    // Generate realistic IP ranges (avoiding private ranges for public-facing game)
    const ranges = [
      () => `203.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`, // Asia-Pacific
      () => `185.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`, // Europe
      () => `72.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,  // North America
      () => `200.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}` // South America
    ];
    
    const generator = this.getRandomElement(ranges);
    return generator();
  }

  static generateGeoLocation() {
    const locations = [
      'New York, NY, US',
      'Los Angeles, CA, US', 
      'London, UK',
      'Berlin, DE',
      'Tokyo, JP',
      'Seoul, KR',
      'Sydney, AU',
      'Toronto, CA',
      'São Paulo, BR',
      'Moscow, RU',
      'Mumbai, IN',
      'Singapore, SG',
      'Paris, FR',
      'Amsterdam, NL',
      'Stockholm, SE'
    ];
    
    return this.getRandomElement(locations);
  }

  static generateItemName(category, rarity = 'common') {
    const itemNames = {
      weapons: {
        common: ['Iron Sword', 'Wooden Staff', 'Simple Bow', 'Bronze Dagger', 'Club'],
        rare: ['Steel Blade', 'Mystic Wand', 'Elven Bow', 'Silver Dagger', 'War Hammer'],
        epic: ['Flame Sword', 'Staff of Power', 'Dragon Bow', 'Shadow Blade', 'Thunder Mace'],
        legendary: ['Excalibur', 'Staff of Eternity', 'Bow of the Ancients', 'Void Ripper', 'Mjolnir']
      },
      armor: {
        common: ['Leather Vest', 'Cloth Robe', 'Iron Helmet', 'Simple Shield', 'Basic Boots'],
        rare: ['Chain Mail', 'Mage Robe', 'Steel Helmet', 'Kite Shield', 'Leather Boots'],
        epic: ['Plate Armor', 'Arcane Robe', 'Dragon Helm', 'Tower Shield', 'Winged Boots'],
        legendary: ['Aegis Armor', 'Robe of the Archmage', 'Crown of Kings', 'Shield Eternal', 'Boots of Hermes']
      },
      consumables: {
        common: ['Health Potion', 'Mana Potion', 'Bread', 'Water', 'Bandage'],
        rare: ['Greater Health Potion', 'Magic Elixir', 'Fine Wine', 'Healing Herb', 'Antidote'],
        epic: ['Elixir of Strength', 'Potion of Wisdom', 'Ambrosia', 'Phoenix Tears', 'Dragon Blood'],
        legendary: ['Elixir of Immortality', 'Nectar of Gods', 'Life Essence', 'Time Potion', 'Divine Grace']
      },
      materials: {
        common: ['Iron Ore', 'Wood', 'Cloth', 'Leather', 'Stone'],
        rare: ['Mithril Ore', 'Enchanted Wood', 'Silk', 'Dragon Leather', 'Marble'],
        epic: ['Adamantium', 'World Tree Wood', 'Phantom Silk', 'Demon Hide', 'Celestial Stone'],
        legendary: ['Unobtainium', 'Yggdrasil Branch', 'Void Fabric', 'God Scale', 'Reality Crystal']
      }
    };
    
    const categoryItems = itemNames[category];
    if (!categoryItems || !categoryItems[rarity]) {
      return 'Unknown Item';
    }
    
    return this.getRandomElement(categoryItems[rarity]);
  }

  // Generate consistent data based on seed
  static seededRandom(seed) {
    const x = Math.sin(seed) * 10000;
    return x - Math.floor(x);
  }

  static generateConsistentData(type, index, ...params) {
    switch (type) {
      case 'username':
        return this.generateUsername(index);
      case 'characterName':
        return this.generateCharacterName(params[0], index);
      case 'email':
        return this.generateEmail(params[0], index);
      case 'ipAddress':
        return this.generateIPAddress();
      case 'geoLocation':
        return this.generateGeoLocation();
      default:
        return 'unknown';
    }
  }
}

module.exports = NameGenerators;