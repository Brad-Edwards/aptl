# Data Generation Script Architecture

## Simple, Clean Approach

We need to generate realistic gaming data without over-engineering. Keep it simple and maintainable.

## File Structure

```
api/scripts/
├── generate-data.js           # Main script - run this
├── generators.js              # All data generation functions  
├── database.js               # Database operations
└── config.js                 # Configuration constants
```

## Core Concept

1. **generate-data.js**: Main entry point, orchestrates everything
2. **generators.js**: Pure functions that create realistic data
3. **database.js**: Simple database operations (connect, insert, transaction)
4. **config.js**: All the constants and distributions in one place

## Data Generation Flow

```
Load Config -> Generate Users -> Generate Items -> Generate Transactions -> Insert to DB
```

## Design Principles

- **Functions do one thing**: Each generator function creates one type of data
- **No classes unless needed**: Plain functions and objects
- **Fail fast**: If something's wrong, crash with a clear message
- **Readable over clever**: Code should be obvious

## Key Functions

### generators.js
- `generateUsers(count)` - Returns array of user objects
- `generateItems()` - Returns array of item definitions
- `generateTransactions(users, items, count)` - Returns transaction history
- `generateAuthEvents(users)` - Returns login attempt history

### database.js  
- `connectToDatabase()` - Returns database connection
- `insertUsers(db, users)` - Inserts user data
- `insertTransactions(db, transactions)` - Inserts transaction data
- `clearDatabase(db)` - Wipes existing data

### Main Script Logic
1. Connect to database
2. Clear existing data
3. Generate all data in memory
4. Basic validation (check relationships exist)
5. Insert data in dependency order
6. Log summary statistics

## No Over-Engineering

- No interfaces or abstract classes
- No dependency injection containers  
- No complex validation frameworks
- No layered architecture patterns
- No enterprise design patterns

Just clean, readable functions that solve the actual problem.