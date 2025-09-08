# Realistic Player Behavior Patterns for Data Generation

## Player Session Flow Patterns

### Pattern 1: Marketplace-First Players (30%)
```
login → check character stats → marketplace (browse/search) → buy items → gameplay → logout
```
- Session duration: 45-120 minutes
- Marketplace time: 10-20% of session
- Activities: item browsing, price comparison, strategic purchases
- Character types: Usually mid-level players building their equipment

### Pattern 2: Direct Gameplay Players (40%)
```
login → brief inventory check → straight to gameplay → logout
```
- Session duration: 30-180 minutes  
- Minimal marketplace activity
- Activities: dungeon runs, quests, PvP matches
- Character types: All levels, focused on progression

### Pattern 3: Social-First Players (20%)
```
login → chat channels → marketplace → gameplay → more chat → logout
```
- Session duration: 60-200 minutes
- High chat activity throughout session
- Activities: social interaction, group planning, trading discussions
- Character types: Guild members, established players

### Pattern 4: Economic Players (10%)
```
login → marketplace → extensive trading → minimal gameplay → logout
```
- Session duration: 20-90 minutes
- Heavy marketplace focus
- Activities: item flipping, market analysis, bulk trading
- Character types: High-level players, economic specialists

## Activity Generation Logic

### Gameplay Activities by Character Level

**Levels 1-10 (Newbie)**
- Activities: `tutorial_complete`, `newbie_dungeon`, `first_quest`, `basic_exploration`
- Locations: `Town Square`, `Newbie Dungeon`, `Forest Clearing`
- Duration: 15-45 minutes per activity
- Experience: 10-50 per activity
- Gold: 5-25 per activity

**Levels 11-25 (Casual)**
- Activities: `dungeon_run`, `quest_chain`, `pvp_match`, `exploration`, `skill_training`
- Locations: `Advanced Dungeon`, `PvP Arena`, `Guild Hall`, various exploration areas
- Duration: 20-60 minutes per activity
- Experience: 25-100 per activity  
- Gold: 15-75 per activity

**Levels 26+ (Veteran)**
- Activities: `raid_participation`, `advanced_pvp`, `guild_events`, `mentoring`, `rare_hunting`
- Locations: `Raid Portal`, `PvP Arena`, `Guild Hall`, high-level areas
- Duration: 30-120 minutes per activity
- Experience: 50-200 per activity
- Gold: 50-300 per activity

### Marketplace Activities by Player Type

**Browsers (Most Common)**
- Actions: `browse_category`, `search_item`, `view_item_details`, `compare_prices`
- Frequency: 5-15 actions per marketplace visit
- Purchase rate: 20-40% of marketplace sessions
- Typical items: equipment upgrades, consumables

**Sellers**
- Actions: `list_item`, `check_listings`, `update_price`, `remove_listing`
- Frequency: 2-8 actions per marketplace visit
- Success rate: 60-80% of listings eventually sell
- Typical items: outgrown equipment, excess materials

**Traders/Flippers**
- Actions: `search_deals`, `bulk_purchase`, `relist_higher`, `market_analysis`
- Frequency: 10-30 actions per marketplace visit
- Profit margin: 10-50% markup on flipped items
- Typical items: rare items, materials, popular equipment

### Social Activities

**Chat Patterns**
- Global chat: 1-5 messages per hour during gameplay
- Trade chat: Active when selling/buying (10-20 messages)
- Guild chat: Regular members 3-10 messages per session
- Channel joining: Players join 2-4 channels on average

**Guild Activities** (if applicable)
- Guild hall visits: 1-3 per session for guild members
- Guild events: 1-2 hours duration, 5-20 participants
- Guild chat activity spikes during events

## Progression and Economic Patterns

### Character Progression Events
- Level up: Every 2-5 gameplay sessions for active players
- Equipment upgrades: Every 3-7 sessions
- Skill improvements: Consistent small gains per session
- Achievement unlocks: Periodic based on activity type

### Transaction Patterns
- **Player-to-Player Trades**: Usually involve negotiation, fair market prices
- **Marketplace Sales**: List at market rate, may adjust prices over time  
- **Guild Trading**: Often at discount or free for guild members
- **Material Exchange**: Common for crafting-focused players

### Inventory Management
- Players typically keep 20-40 items in inventory
- Regular cleanup every 5-10 sessions (sell old equipment)
- Hoarding behavior: Materials and rare items kept longer
- Equipment rotation: Upgrade and sell old gear every few levels

## Data Generation Parameters

### Session Timing
- **Peak Hours**: 18:00-23:00 weekdays, 10:00-24:00 weekends  
- **Session Distribution**: 70% evening, 20% afternoon, 10% morning
- **Login Frequency**: 
  - Active players: 4-7 times per week
  - Casual players: 2-4 times per week  
  - Dormant players: 0-2 times per week

### Activity Ratios per Session
- **Gameplay**: 60-80% of session time
- **Marketplace**: 10-25% of session time
- **Social**: 5-15% of session time
- **Inventory Management**: 5-10% of session time

### Economic Behavior
- **Spending Rate**: Players spend 60-90% of earned gold
- **Saving Rate**: 10-40% kept for major purchases
- **Trading Volume**: 1 transaction per 3-5 sessions on average
- **Price Sensitivity**: 80% of players compare prices before buying

This behavior model ensures generated data shows realistic player engagement patterns that clearly distinguish legitimate players from automated attackers.