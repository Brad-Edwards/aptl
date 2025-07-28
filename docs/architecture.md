# Architecture

## Overview

APTL creates a purple team lab environment in AWS with:

- qRadar Community Edition 7.5 on t3a.2xlarge instance
- Victim machine on t3.micro instance
- Kali Linux red team instance on t3.micro instance
- Single VPC with all instances in same subnet
- Security groups restricting access to your IP address only

## Network Diagram

```mermaid
flowchart TD
    A[Internet] --> B[Internet Gateway]
    B --> C[Public Subnet<br/>10.0.1.0/24]
    C --> D[SIEM<br/>qRadar]
    C --> E[Victim<br/>Machine]
    C --> F[Kali Linux<br/>Red Team]
    E -.->|Logs| D
    F -.->|Attacks| E
    F -.->|Logs| D
    
    classDef default fill:#ffffff,stroke:#000000,stroke-width:2px,color:#000000
    classDef subnet fill:#f0f0f0,stroke:#000000,stroke-width:2px,color:#000000
    classDef instances fill:#e0e0e0,stroke:#000000,stroke-width:2px,color:#000000
    
    class A,B default
    class C subnet
    class D,E,F instances
```

## Infrastructure Components

### VPC and Networking

- **VPC**: 10.0.0.0/16 CIDR block
- **Public Subnet**: 10.0.1.0/24
- **Internet Gateway**: Provides internet access
- **Route Table**: Routes traffic to internet gateway
- **Security Groups**: Restrict access by IP and port

### Instance Details

#### qRadar SIEM (t3a.2xlarge)
- **Purpose**: IBM qRadar Community Edition SIEM
- **OS**: Amazon Linux 2
- **Storage**: 250GB root + 200GB /store partition
- **Ports**: 22 (SSH), 443 (HTTPS), 514 (Syslog)
- **Features**:
  - Log collection and analysis
  - Security event correlation
  - Offense management
  - Custom properties for red team logging

#### Victim Machine (t3.micro)
- **Purpose**: Target for red team activities
- **OS**: Amazon Linux 2
- **Storage**: 30GB root volume
- **Ports**: 22 (SSH), 3389 (RDP)
- **Features**:
  - Automatic log forwarding to SIEM
  - Test event generators
  - Vulnerable services for testing

#### Kali Linux Red Team (t3.micro)
- **Purpose**: Red team attack platform
- **OS**: Kali Linux
- **Storage**: 30GB root volume
- **Ports**: 22 (SSH)
- **Features**:
  - Pre-installed penetration testing tools
  - MCP server for AI integration
  - Red team activity logging

### Security Groups

#### SIEM Security Group
- **SSH (22)**: Your IP only
- **HTTPS (443)**: Your IP only
- **Syslog (514)**: Internal subnet only

#### Victim Security Group
- **SSH (22)**: Your IP + Kali instance
- **RDP (3389)**: Your IP + Kali instance
- **All Ports**: From Kali instance (for attack simulation)

#### Kali Security Group
- **SSH (22)**: Your IP only
- **Outbound**: All traffic (for red team activities)

## Data Flow

### Log Forwarding

1. **Victim Machine**: Generates system and application logs
2. **rsyslog**: Forwards logs to qRadar via UDP 514
3. **qRadar**: Receives, parses, and analyzes logs
4. **Alerts**: Generated based on correlation rules

### Red Team Activities

1. **Kali Instance**: Executes attacks against victim
2. **Activity Logging**: Commands logged with metadata
3. **SIEM Integration**: Red team logs sent to qRadar
4. **Correlation**: Red team actions correlated with detections

### AI Integration

1. **MCP Server**: Provides controlled access to Kali tools
2. **AI Agents**: Execute red team activities via MCP
3. **Safety Controls**: Validate targets and filter commands
4. **Logging**: All AI actions logged for analysis

## Detailed Network Topology

```mermaid
flowchart TB
    Internet[Internet] --> IGW[Internet Gateway]
    
    subgraph VPC["VPC: 10.0.0.0/16"]
        IGW --> RT[Route Table]
        RT --> PubSub[Public Subnet: 10.0.1.0/24]
        
        subgraph SIEMSSG["SIEM Security Group"]
            SIEM[qRadar SIEM<br/>t3a.2xlarge<br/>Public + Private IP]
        end
        
        subgraph VICTIMSG["Victim Security Group"]
            VICTIM[Victim Machine<br/>t3.micro<br/>Public + Private IP]
        end
        
        subgraph KALISG["Kali Security Group"]
            KALI[Kali Linux<br/>t3.micro<br/>Public + Private IP]
        end
        
        PubSub --> SIEM
        PubSub --> VICTIM
        PubSub --> KALI
    end
    
    subgraph Storage["EBS Storage"]
        SIEMROOT[qRadar Root 250GB]
        SIEMSTORE[qRadar Store 200GB]
        VICTIMROOT[Victim Root 30GB]
        KALIROOT[Kali Root 20GB]
    end
    
    VICTIM -.->|Syslog 514| SIEM
    KALI -.->|Red Team Logs 514| SIEM
    KALI -.->|Attacks| VICTIM
    
    Internet -.->|SSH/HTTPS| SIEM
    Internet -.->|SSH/RDP/HTTP| VICTIM
    Internet -.->|SSH| KALI
    
    SIEM --- SIEMROOT
    SIEM --- SIEMSTORE
    VICTIM --- VICTIMROOT
    KALI --- KALIROOT
```

## Terraform Modules

### Bootstrap Module
- **Purpose**: Creates S3 backend for state management
- **Components**: S3 bucket with versioning and encryption
- **Security**: Unique UUID-based naming

### Network Module
- **Purpose**: VPC, subnets, and networking infrastructure
- **Components**: VPC, IGW, route tables, security groups
- **Features**: Configurable CIDR blocks and access controls

### SIEM Module
- **Purpose**: qRadar SIEM deployment
- **Components**: EC2 instance, EBS volumes, scripts
- **Features**: Automated preparation and installation scripts

### Victim Module
- **Purpose**: Target machine deployment
- **Components**: EC2 instance, log forwarding configuration
- **Features**: Test event generators and vulnerable services

### Kali Module
- **Purpose**: Red team platform deployment
- **Components**: EC2 instance, penetration testing tools
- **Features**: MCP server and red team logging

## Purple Team Scenario Workflow

```mermaid
sequenceDiagram
    participant User as Security Analyst
    participant AI as AI Red Team Agent
    participant Kali as Kali Linux
    participant Victim as Victim Machine
    participant SIEM as qRadar SIEM
    participant MCP as Kali MCP Server
    
    User->>+SIEM: 1. Access qRadar Console
    User->>User: 2. Plan defensive monitoring
    
    User->>+AI: 3. Brief AI on lab environment
    AI->>+MCP: 4. Connect via MCP protocol
    MCP->>+Kali: 5. SSH to Kali instance
    
    Kali->>+Victim: 6. Port scan & enumeration
    Victim->>+SIEM: 7. Forward connection logs
    SIEM->>User: 8. Alert on suspicious scanning
    
    Kali->>Kali: 9. Select exploit tools
    Kali->>+Victim: 10. Launch attack
    Victim->>+SIEM: 11. Forward security events
    Kali->>+SIEM: 12. Log red team activity
    
    SIEM->>SIEM: 13. Correlate events
    SIEM->>User: 14. Generate offense/alert
    User->>SIEM: 15. Investigate in console
    
    User->>SIEM: 16. Query red team logs
    User->>SIEM: 17. Compare victim vs attacker view
    User->>User: 18. Tune detection rules
```

## Component Interaction Diagram

```mermaid
flowchart LR
    subgraph UserGroup["Security Analyst"]
        Browser[Web Browser]
        SSHClient[SSH Client]
        IDE[AI Coding Assistant]
    end
    
    subgraph AWS["AWS Infrastructure"]
        subgraph Lab["APTL Lab Environment"]
            SIEM[qRadar SIEM]
            VICTIM[Victim Machine]
            KALI[Kali Linux]
        end
    end
    
    subgraph MCPLayer["MCP Integration"]
        MCPServer[Kali MCP Server]
    end
    
    subgraph LogProcessing["Log Processing"]
        VictimLogs[Victim Logs]
        RedTeamLogs[Red Team Logs]
    end
    
    Browser -->|HTTPS| SIEM
    SSHClient -->|SSH| SIEM
    SSHClient -->|SSH| VICTIM
    SSHClient -->|SSH| KALI
    
    IDE -->|MCP Protocol| MCPServer
    MCPServer -->|SSH| KALI
    MCPServer -->|Commands| VICTIM
    
    VICTIM -->|Syslog 514| SIEM
    KALI -->|Red Team Logs 514| SIEM
    KALI -->|Attacks| VICTIM
    
    VICTIM --> VictimLogs
    KALI --> RedTeamLogs
    VictimLogs --> SIEM
    RedTeamLogs --> SIEM
```
