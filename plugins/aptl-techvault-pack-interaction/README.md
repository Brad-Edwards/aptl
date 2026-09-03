# TechVault pack/backend serving interaction

This independently installable distribution assigns components from the exact
TechVault env-pack release to APTL operator start groups. It supplies deployment
serving labels only: it cannot add services, images, commands, artifacts,
materialization rules, or realization behavior.

Install it explicitly beside APTL:

```bash
pip install -e ./plugins/aptl-techvault-pack-interaction --no-deps
```

APTL discovers the provider through the exact `techvault.aptl` entry point.
Installation grants normal Python code-execution authority; entry points are a
discovery mechanism, not a sandbox.
