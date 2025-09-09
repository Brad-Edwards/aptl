const fs = require('fs');
const path = require('path');

// Load both datasets
const jsonlPath = path.join(__dirname, '../../../../files/moar_fake_users (2)/data.jsonl');
const jsonlContent = fs.readFileSync(jsonlPath, 'utf8');
const realUsers = jsonlContent.trim().split('\n').map(line => JSON.parse(line));

const staticDataPath = path.join(__dirname, '../data/static-data.json');
const staticData = JSON.parse(fs.readFileSync(staticDataPath, 'utf8'));

console.log(`Enhancing ${staticData.users.length} users...`);

// Step through both arrays together
for (let i = 0; i < staticData.users.length; i++) {
    const gamingUser = staticData.users[i];
    const realUser = realUsers[i];
    
    // Add first and last name
    gamingUser.first_name = realUser.first_name;
    gamingUser.last_name = realUser.last_name;
    
    // 60% chance to overwrite with name-style email
    if (Math.random() < 0.6) {
        gamingUser.email = realUser.email;
    }
}

// Write back to file
fs.writeFileSync(staticDataPath, JSON.stringify(staticData, null, 4));

console.log('✅ Users enhanced successfully!');