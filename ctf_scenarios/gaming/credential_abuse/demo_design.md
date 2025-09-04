# Credential Abuse Demo Design

## Demo: SOC Analyst Investigating Credential Stuffing

**Lab Setup**:
- Simple auth API (Django/Flask/Express) in APTL victim container
- Seed with users:
  - Some with passwords matching dump list
  - Some with different passwords
  - Some usernames not in system
- Kali container runs credential stuffing attack using common lists (/usr/share/wordlists or custom)

**Attack Execution**:
1. Red team agent uses credential list against API
2. Mix successful and failed attempts
3. All auth attempts logged to Wazuh via rsyslog

**Demo Flow**:
1. Present Wazuh logs showing auth attempts
2. LLM analyzes as SOC analyst:
   - Identifies credential stuffing pattern
   - Distinguishes from normal failed logins
   - Finds compromised accounts
   - Calculates attack velocity and source IPs
3. LLM generates Wazuh alert rules
4. LLM recommends mitigations

**Real-World Mapping**:
- SOC analysts review auth logs for anomalies
- Must identify automated attacks vs legitimate failures
- Create detection rules for SIEM
- Recommend incident response actions

**Log Data Contains**:
- Timestamps
- Source IPs
- User agents
- Username attempted
- Success/failure status
- Response times

## DRAFT Mock Game API

**Endpoints**:
- `POST /api/login` - Username/password authentication, returns JWT
- `GET /api/inventory` - View player items/currency (requires auth)
- `POST /api/transfer` - Transfer items/currency to another player
- `POST /api/marketplace/sell` - List items for sale

**Telemetry Format**:
```json
{
  "timestamp": "2024-01-03T14:23:45Z",
  "event_type": "login_success",
  "username": "player123",
  "ip": "192.168.1.50",
  "user_agent": "Mozilla/5.0...",
  "session_id": "sess_abc123",
  "post_auth_activity": [
    {"action": "inventory_check", "time_offset": "+2s"},
    {"action": "transfer_items", "time_offset": "+5s", "value": 450, "recipient": "buyer456"},
    {"action": "marketplace_list", "time_offset": "+8s", "items": ["rare_skin_01"]}
  ]
}
```

**Attack Behavior Patterns**:
- Legitimate users: Login → Play game → Occasional marketplace activity
- Attackers: Login → Immediate inventory check → Rapid transfer/sell → Logout
- Failed stuffing: Multiple rapid login attempts, varying passwords, same IP block

**User Account Properties**:
- Username
- Password  
- Inventory value ($50-$5000)
- Last legitimate login timestamp
- Normal activity pattern (for comparison)