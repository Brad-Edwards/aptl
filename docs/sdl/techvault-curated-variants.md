# Retired APTL-local TechVault variants

The four reduced TechVault selectors formerly maintained by APTL are retired:

- `techvault-attacker-target`
- `techvault-enterprise-web`
- `techvault-defensive-min`
- `techvault-observability-core`

They were APTL-local SDL documents and are not members of the acquired
`techvault` pack. APTL does not synthesize them, map them to the full pack, or
retain shadow copies. Selecting any of these identifiers fails closed.

New reduced scenarios must be authored, released, and assigned their own
verified identity by the environment-pack owner before APTL can consume them.
Current operators should use:

```bash
aptl lab scenarios
aptl lab start --scenario techvault
```

Historical architecture and recorded validation evidence remain available for
design archaeology, but they are not current startup guidance.
