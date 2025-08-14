# Wazuh Blue Team Platform

The Wazuh SIEM stack provides blue team analyst capabilities through REST API access. AI agents perform SOC analyst operations like threat hunting, alert analysis, and detection rule creation via MCP integration for defensive cybersecurity operations.

## Overview

The Wazuh integration consists of a three-component architecture (Manager, Indexer, Dashboard) providing SIEM capabilities. It's configured for purple team operations with MCP integration for AI-driven blue team analyst activities.

### Key Features

- **SIEM API Access**: REST API for programmatic security operations
- **AI Integration**: Model Context Protocol (MCP) server integration for analyst workflows
- **Alert Analysis**: Query and investigate security events
- **Threat Hunting**: Search for IOCs and attack patterns
- **Detection Creation**: Build custom alert rules for new threats
- **Event Correlation**: Link related security events across time

## Container Architecture

```mermaid
flowchart TD
    A[Host System] --> B[HTTPS Port 443]
    B --> C[Wazuh Dashboard<br/>172.20.0.11]
    
    subgraph "Wazuh SIEM Stack"
        D[Wazuh Manager<br/>172.20.0.10]
        E[Wazuh Indexer<br/>172.20.0.12]
        F[Wazuh Dashboard<br/>172.20.0.11]
    end
    
    C --> D
    D --> E
    E --> F
    
    G[AI Blue Team Agent] --> H[MCP Server]
    H --> I[Wazuh API<br/>Port 55000]
    H --> J[Indexer API<br/>Port 9200]
    I --> D
    J --> E
    
    K[Victim Container<br/>172.20.0.20] --> L[Syslog<br/>Port 514]
    M[Kali Container<br/>172.20.0.30] --> L
    L --> D
    
    classDef wazuh fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef ai fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef sources fill:#ffebee,stroke:#c62828,stroke-width:2px
    classDef external fill:#e3f2fd,stroke:#0277bd,stroke-width:2px
    
    class D,E,F,I,J,L wazuh
    class G,H ai
    class K,M sources
    class A,B external
```

## Container Configuration

### Wazuh Manager (172.20.0.10)

Central log processing and alert generation:

```yaml
wazuh.manager:
  image: wazuh/wazuh-manager:4.12.0
  hostname: wazuh.manager
  ports:
    - "514:514/udp"    # Syslog receiver
    - "55000:55000"    # REST API
  environment:
    - INDEXER_URL=https://wazuh.indexer:9200
    - API_USERNAME=wazuh-wui
    - API_PASSWORD=MyS3cr37P450r.*-
  networks:
    aptl-network:
      ipv4_address: 172.20.0.10
```

### Wazuh Indexer (172.20.0.12)

OpenSearch-based data storage:

```yaml
wazuh.indexer:
  image: wazuh/wazuh-indexer:4.12.0
  hostname: wazuh.indexer
  ports:
    - "9200:9200"    # OpenSearch API
  environment:
    - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
  networks:
    aptl-network:
      ipv4_address: 172.20.0.12
```

### Wazuh Dashboard (172.20.0.11)

Web interface for security monitoring:

```yaml
wazuh.dashboard:
  image: wazuh/wazuh-dashboard:4.12.0
  hostname: wazuh.dashboard
  ports:
    - "443:5601"     # HTTPS dashboard
  environment:
    - INDEXER_USERNAME=admin
    - INDEXER_PASSWORD=SecretPassword
    - API_USERNAME=wazuh-wui
    - API_PASSWORD=MyS3cr37P450r.*-
  networks:
    aptl-network:
      ipv4_address: 172.20.0.11
```

## Log Integration

### Syslog Forwarding

Both lab containers forward logs via rsyslog, not agents:

```bash
# Victim container: /etc/rsyslog.d/90-forward.conf
*.* @@172.20.0.10:514

# Kali container: similar rsyslog configuration
*.* @@172.20.0.10:514
```

**Log Sources:**
- Victim Container: System logs, application logs, attack target logs
- Kali Container: Red team activity logs, tool execution logs
- No agent enrollment required - pure syslog forwarding

**SIEM Processing:**
- Logs indexed by source IP (172.20.0.20, 172.20.0.30)
- Rules process logs and generate alerts
- Alerts stored in `wazuh-alerts-*` indices

## API Capabilities

### Authentication

JWT token-based authentication:

```python
import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(InsecureRequestWarning)

def authenticate():
    response = requests.post(
        "https://172.20.0.10:55000/security/user/authenticate",
        auth=("wazuh-wui", "MyS3cr37P450r.*-"), 
        verify=False
    )
    return response.json()['data']['token']

token = authenticate()
headers = {'Authorization': f'Bearer {token}'}
```

### Core Endpoints

#### Alert Queries (via Indexer)

```python
# Query recent alerts
def query_alerts(time_range="1h", min_level=1, source_ip=None):
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"timestamp": {"gte": f"now-{time_range}"}}},
                    {"range": {"rule.level": {"gte": min_level}}}
                ]
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 1000
    }
    
    if source_ip:
        query["query"]["bool"]["filter"].append({
            "term": {"data.srcip": source_ip}
        })
    
    response = requests.post(
        "https://172.20.0.12:9200/wazuh-alerts-*/_search",
        headers={
            'Authorization': 'Basic YWRtaW46U2VjcmV0UGFzc3dvcmQ=',
            'Content-Type': 'application/json'
        },
        json=query,
        verify=False
    )
    
    return response.json()
```

#### Rule Management

```python
# Create custom detection rule
def create_rule(rule_xml, rule_file="local_rules.xml"):
    response = requests.put(
        f"https://172.20.0.10:55000/rules/files/{rule_file}",
        headers={**headers, 'Content-Type': 'application/xml'},
        data=rule_xml,
        verify=False
    )
    return response.json()

# Get existing rules
def get_rules(search=None, level=None):
    params = {}
    if search:
        params['search'] = search
    if level:
        params['level'] = level
    
    response = requests.get(
        "https://172.20.0.10:55000/rules",
        headers=headers,
        params=params,
        verify=False
    )
    return response.json()
```

## MCP Integration

### Blue Team Tools

```typescript
// Blue Team MCP tool definitions
const tools = [
  {
    name: "query_alerts",
    description: "Search and filter security alerts",
    inputSchema: {
      type: "object",
      properties: {
        time_range: { type: "string", enum: ["15m", "1h", "6h", "24h", "7d"] },
        min_level: { type: "number", minimum: 1, maximum: 15 },
        source_ip: { type: "string" },
        search_term: { type: "string" }
      }
    }
  },
  {
    name: "investigate_ip",
    description: "Get all activity from specific IP address",
    inputSchema: {
      type: "object",
      properties: {
        ip_address: { type: "string" },
        time_range: { type: "string", enum: ["1h", "6h", "24h", "7d"] }
      },
      required: ["ip_address"]
    }
  },
  {
    name: "hunt_threats",
    description: "Search for indicators of compromise",
    inputSchema: {
      type: "object", 
      properties: {
        ioc_type: { type: "string", enum: ["ip", "domain", "hash", "command"] },
        ioc_value: { type: "string" },
        time_range: { type: "string", enum: ["1h", "6h", "24h", "7d"] }
      },
      required: ["ioc_type", "ioc_value"]
    }
  },
  {
    name: "create_detection_rule",
    description: "Create custom alert rule for new threats",
    inputSchema: {
      type: "object",
      properties: {
        rule_xml: { type: "string" },
        rule_description: { type: "string" },
        rule_level: { type: "number", minimum: 1, maximum: 15 }
      },
      required: ["rule_xml"]
    }
  },
  {
    name: "build_timeline",
    description: "Create chronological sequence of events",
    inputSchema: {
      type: "object",
      properties: {
        source_ip: { type: "string" },
        target_ip: { type: "string" },
        time_range: { type: "string", enum: ["1h", "6h", "24h"] }
      }
    }
  }
];
```

### Tool Implementation

```typescript
// Alert querying implementation
async function handleQueryAlerts(params: any) {
  const indexerClient = new WazuhIndexerClient();
  
  const query = buildAlertQuery(params);
  const results = await indexerClient.search("wazuh-alerts-*", query);
  
  // Log blue team activity
  await logBlueTeamActivity({
    action: "query_alerts",
    parameters: params,
    results_count: results.hits.total.value,
    timestamp: new Date().toISOString()
  });
  
  return {
    alert_count: results.hits.total.value,
    alerts: results.hits.hits.map(formatAlert)
  };
}

// IP investigation implementation
async function handleInvestigateIP(params: any) {
  const alerts = await handleQueryAlerts({
    source_ip: params.ip_address,
    time_range: params.time_range || "24h"
  });
  
  // Group alerts by rule type
  const ruleBreakdown = groupAlertsByRule(alerts.alerts);
  
  return {
    ip_address: params.ip_address,
    total_alerts: alerts.alert_count,
    rule_breakdown: ruleBreakdown,
    timeline: alerts.alerts.slice(0, 50)
  };
}

// Detection rule creation
async function handleCreateDetectionRule(params: any) {
  const wazuhAPI = new WazuhAPIClient();
  await wazuhAPI.authenticate();
  
  // Validate XML format
  if (!validateRuleXML(params.rule_xml)) {
    throw new Error("Invalid rule XML format");
  }
  
  const result = await wazuhAPI.createRule(params.rule_xml, "aptl_custom_rules.xml");
  
  await logBlueTeamActivity({
    action: "create_detection_rule",
    rule_preview: params.rule_xml.substring(0, 200),
    timestamp: new Date().toISOString()
  });
  
  return {
    success: true,
    rule_file: "aptl_custom_rules.xml",
    restart_required: true
  };
}
```

### Safety Controls

#### Query Validation

```typescript
function validateQuery(params: any): ValidationResult {
  // Limit time ranges
  const maxTimeRanges = ["15m", "1h", "6h", "24h", "7d"];
  if (params.time_range && !maxTimeRanges.includes(params.time_range)) {
    return { safe: false, reason: "Invalid time range" };
  }
  
  // Limit result sizes
  if (params.size && params.size > 1000) {
    return { safe: false, reason: "Result size too large" };
  }
  
  // Validate IP addresses
  if (params.source_ip && !isValidIP(params.source_ip)) {
    return { safe: false, reason: "Invalid IP address format" };
  }
  
  return { safe: true };
}
```

#### Rule Validation

```typescript
function validateRuleXML(ruleXML: string): boolean {
  // Basic XML structure validation
  if (!ruleXML.includes('<rule') || !ruleXML.includes('</rule>')) {
    return false;
  }
  
  // Check for required attributes
  if (!ruleXML.includes('id=') || !ruleXML.includes('level=')) {
    return false;
  }
  
  // Prevent dangerous rule content
  const blockedPatterns = [
    /<active-response>/,
    /<command>/,
    /<executable>/
  ];
  
  return !blockedPatterns.some(pattern => pattern.test(ruleXML));
}
```

## Network Configuration

### API Access

- **Wazuh API**: HTTPS on port 55000 (JWT authentication)
- **Indexer API**: HTTPS on port 9200 (Basic authentication)
- **Dashboard**: HTTPS on port 443 (web interface)

### Log Sources

| Source | IP Address | Log Types | Transport |
|--------|------------|-----------|-----------|
| Victim Container | 172.20.0.20 | System, application, SSH | UDP 514 |
| Kali Container | 172.20.0.30 | Red team activities, tools | UDP 514 |

### Firewall Configuration

```bash
# Container-to-container communication within lab network
# Wazuh Manager: Accepts syslog on 514/udp
# Wazuh API: Accepts HTTPS on 55000/tcp
# Wazuh Indexer: Accepts HTTPS on 9200/tcp
```

## Blue Team Logging

### Activity Logging

All blue team operations are logged with structured data:

```typescript
interface BlueTeamActivityLog {
  timestamp: string;
  analyst_id: string;
  operation: string;
  parameters: Record<string, any>;
  results: {
    success: boolean;
    count?: number;
    error?: string;
  };
  context: {
    session_id: string;
    investigation_id?: string;
  };
}

async function logBlueTeamActivity(activity: BlueTeamActivityLog) {
  // Log to local file
  await appendToFile('./logs/blue-team-activity.log', JSON.stringify(activity));
  
  // Forward to SIEM
  await forwardToSIEM('172.20.0.10:514', {
    facility: 'local2',
    severity: 'info',
    tag: 'APTL-BlueTeam',
    message: JSON.stringify(activity)
  });
}
```

### Log Format

Blue team logs follow structured format for analysis:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "source": "blue-team-mcp",
  "analyst_id": "ai-agent-001",
  "operation": "query_alerts",
  "parameters": {
    "time_range": "1h",
    "min_level": 10,
    "source_ip": "172.20.0.30"
  },
  "results": {
    "success": true,
    "count": 15
  }
}
```

### SIEM Integration

Blue team activities generate their own alerts in Wazuh:

```xml
<!-- Blue team activity detection rules -->
<group name="aptl,blue_team,ai_analyst">
  <rule id="100150" level="3">
    <decoded_as>json</decoded_as>
    <field name="tag">APTL-BlueTeam</field>
    <description>AI blue team analyst activity</description>
  </rule>
  
  <rule id="100151" level="5">
    <if_sid>100150</if_sid>
    <field name="operation">query_alerts</field>
    <description>AI threat hunting query executed</description>
  </rule>
  
  <rule id="100152" level="7">
    <if_sid>100150</if_sid>
    <field name="operation">create_detection_rule</field>
    <description>AI created custom detection rule</description>
  </rule>
</group>
```

## Access Methods

### MCP Client Access

AI agents access blue team tools via MCP:

```bash
# Blue team MCP server connection
# AI agents connect through IDE MCP client configuration
# All operations validated and logged
```

### Direct API Access

Manual API access for debugging:

```bash
# Get authentication token
TOKEN=$(curl -k -u wazuh-wui:MyS3cr37P450r.*- \
  "https://172.20.0.10:55000/security/user/authenticate?raw=true")

# Query alerts
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://172.20.0.10:55000/"

# Search indexer
curl -k -u admin:SecretPassword \
  "https://172.20.0.12:9200/wazuh-alerts-*/_search" \
  -d '{"size":10}'
```

### Dashboard Access

Web interface for manual analysis:

```bash
# Access dashboard
https://localhost:443

# Credentials: wazuh-wui / MyS3cr37P450r.*-
```

## Operational Workflows

### Standard Blue Team Process

1. **Alert Monitoring**
   ```typescript
   // Get recent high-level alerts
   const criticalAlerts = await blueTeam.query_alerts("1h", 10);
   ```

2. **Threat Investigation**
   ```typescript
   // Investigate suspicious IP
   const investigation = await blueTeam.investigate_ip("172.20.0.30", "6h");
   ```

3. **IOC Hunting**
   ```typescript
   // Hunt for specific indicators
   const iocResults = await blueTeam.hunt_threats("command", "nmap", "24h");
   ```

4. **Detection Creation**
   ```typescript
   // Create custom rule for new threat
   const detectionRule = `
   <rule id="100200" level="8">
     <if_group>recon</if_group>
     <match>nmap</match>
     <description>Network scanning detected</description>
   </rule>`;
   
   await blueTeam.create_detection_rule(detectionRule);
   ```

## Container Management

### Lifecycle Operations

```bash
# Start Wazuh stack
docker compose up -d wazuh.manager wazuh.indexer wazuh.dashboard

# Check service status
docker compose ps

# View logs
docker compose logs -f wazuh.manager
```

### Health Monitoring

```bash
# API health check
curl -k "https://172.20.0.10:55000/" 

# Indexer health
curl -k -u admin:SecretPassword "https://172.20.0.12:9200/_cluster/health"

# Dashboard status
curl -k "https://172.20.0.11:5601/api/status"
```

### Resource Monitoring

```bash
# Container resources
docker stats wazuh.manager wazuh.indexer wazuh.dashboard

# Disk usage
du -h /var/lib/docker/volumes/aptl_wazuh-indexer-data

# Log sizes
docker exec wazuh.manager du -h /var/ossec/logs/
```

## Troubleshooting

### Common Issues

1. **API Authentication Failures**
   ```bash
   # Test credentials
   curl -k -u wazuh-wui:MyS3cr37P450r.*- \
     "https://172.20.0.10:55000/security/user/authenticate"
   ```

2. **Indexer Connection Issues**
   ```bash
   # Test indexer connectivity
   curl -k -u admin:SecretPassword \
     "https://172.20.0.12:9200/_cluster/health"
   ```

3. **No Alerts Appearing**
   ```bash
   # Check log forwarding
   docker exec aptl-victim logger "Test message"
   docker exec aptl-kali logger "Test message"
   
   # Check manager logs
   docker logs wazuh.manager | grep -i received
   ```

### Performance Issues

```bash
# Monitor resource usage
docker stats

# Check indexer performance
curl -k -u admin:SecretPassword \
  "https://172.20.0.12:9200/_nodes/stats"

# Monitor API response times
time curl -k -H "Authorization: Bearer $TOKEN" \
  "https://172.20.0.10:55000/"
```

### Log Analysis

```bash
# Check blue team activity
tail -f logs/blue-team-activity.log | jq .

# Monitor SIEM for blue team activities
docker exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.log | \
  grep "APTL-BlueTeam"

# Check API access logs
docker exec wazuh.manager tail -f /var/ossec/logs/api.log
```

## Security Considerations

### API Security

- **Authentication Required**: All API calls require valid JWT tokens
- **HTTPS Only**: All communications encrypted in transit
- **Network Isolation**: APIs only accessible within lab network
- **Rate Limiting**: Prevents API abuse and resource exhaustion

### Blue Team MCP Security

- **Query Validation**: All AI requests validated before execution
- **Result Limits**: Maximum query sizes and time ranges enforced
- **Audit Trail**: All blue team activities logged
- **Safe Operations**: AI limited to analyst functions, no system admin

### Data Protection

- **Lab Data Only**: No real credentials or sensitive data
- **Log Retention**: Configurable retention for security logs
- **Access Controls**: Multi-layered access controls for SIEM data

## Next Steps

- **[MCP Integration](mcp-integration.md)** - Complete dual MCP architecture
- **[Red Team Integration](kali-redteam.md)** - Red team platform details
- **[Usage Examples](../usage/exercises.md)** - Practical blue team scenarios