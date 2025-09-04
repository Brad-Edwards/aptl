# DBK64.sys Reverse Engineering Demo Design

## Demo: AI Agent Reverse Engineering Kernel Driver

**Data Source**: 
- dbk64.sys kernel driver (Cheat Engine component)
- Test environment with controlled execution

**Demo Flow**:
1. Present driver binary to AI agent as "new cheat discovered on forums"
2. Agent performs static analysis:
   - Identifies driver structure and entry points
   - Discovers IOCTL handlers
   - Maps out privileged operations (memory read/write, process manipulation)
3. Agent explains cheat capabilities in plain language
4. Agent generates YARA rules for detection
5. Test YARA rules against sample (show detection working)

**Real-World Mapping**:
- Anti-cheat teams receive new kernel cheats daily
- Must rapidly understand capabilities to create detections
- Need to explain technical findings to non-technical stakeholders
- Generate signatures before cheat spreads widely