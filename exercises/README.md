# APTL Purple Team Exercises

This directory contains a comprehensive collection of purple team exercises designed for the Advanced Purple Team Lab (APTL) infrastructure. These exercises are specifically designed to work with:

- AI red-teamers using Kali Linux via the MCP (Model Context Protocol)
- Splunk Enterprise Security or IBM qRadar Community Edition SIEM
- AWS-based lab infrastructure with 1-5 target machines

## Exercise Organization

Exercises are organized by difficulty level to support SecOps teams at different maturity stages:

### 🟢 Beginner (`beginner/`)

- **Target Audience**: New SOC analysts, fresh cybersecurity graduates, teams new to purple teaming
- **Focus**: Basic detection capabilities, fundamental MITRE ATT&CK techniques, simple attack chains
- **Duration**: 2-4 hours per exercise
- **Prerequisites**: Basic understanding of SIEM concepts, familiarity with common attack types

### 🟡 Intermediate (`intermediate/`)

- **Target Audience**: SOC analysts with 1-2 years experience, established purple teams, mature detection programs
- **Focus**: Complex multi-stage attacks, evasion techniques, lateral movement, advanced persistence
- **Duration**: 4-8 hours per exercise
- **Prerequisites**: Solid SIEM query skills, understanding of Windows/Linux internals, experience with incident response

### 🔴 Expert (`expert/`)

- **Target Audience**: Senior threat hunters, advanced red/blue teams, security architects
- **Focus**: Advanced persistent threats, zero-day simulation, custom malware behaviors, supply chain attacks
- **Duration**: 8+ hours per exercise
- **Prerequisites**: Deep technical knowledge, advanced scripting skills, threat intelligence experience

## Exercise Structure

Each exercise follows a consistent format:

```
exercise-name.md
├── Overview & Learning Objectives
├── Infrastructure Requirements
├── Setup Instructions (for Blue Team)
├── Red Team AI Instructions
├── Detection Scenarios
├── Expected Outcomes
└── Cleanup & Lessons Learned
```

## Using These Exercises

### For Blue Team/Lab Operators

1. Review infrastructure requirements
2. Complete setup instructions
3. Provide the Red Team AI Instructions to your AI assistant (Cursor/Cline)
4. Monitor SIEM for detection events
5. Analyze results and improve detections

### For AI Red Teams

- Each exercise contains specific `Red Team AI Instructions` sections
- Follow the provided procedures exactly as specified
- Document all actions with timestamps
- Provide clear indicators of compromise (IoCs)

## Best Practices

1. **Always run in isolated lab environment** - Never on production systems
2. **Document everything** - Maintain detailed logs of all activities
3. **Coordinate timing** - Ensure blue team is ready before starting red team activities
4. **Start simple** - Begin with beginner exercises even for experienced teams
5. **Iterate and improve** - Use lessons learned to enhance detection capabilities

## Integration with APTL

These exercises are designed to work seamlessly with:

- **Kali MCP Server**: AI agents can execute commands via the MCP interface
- **SIEM Integration**: All activities generate logs forwarded to your chosen SIEM
- **AWS Infrastructure**: Exercises scale from single machine to multi-host scenarios

## Contributing

When adding new exercises:

- Follow the established template format
- Include clear learning objectives
- Provide specific AI instructions
- Test thoroughly in the APTL environment
- Document any special requirements or dependencies

---

*Built for the Advanced Purple Team Lab (APTL) - Unlimited AI-driven purple team exercises on a shoestring budget.*
