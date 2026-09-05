# TechVault scenario overview

TechVault is APTL's default acquired environment pack. Its RAES SDL and all
scenario-owned files are maintained in
[OpenRAE/env-packs](https://github.com/OpenRAE/env-packs/tree/main/packs/techvault),
not in the APTL source tree or wheel.

## Selection and identity

```bash
aptl lab scenarios
aptl lab start --scenario techvault
```

The catalog command stages and validates the configured pack through the same
ingestion path used for startup. It reports the pack id, released version,
associated-artifact set digest, and maturity. Those values are the scenario's
durable identity; the private staging path is not an identity and is not written
to run records or API responses.

APTL fails closed when pack content is missing, corrupt, has undeclared files,
or does not match its released identity. It never falls back to an old in-tree
copy. `--scenario-path` is reserved for an explicit project-contained
development SDL.

## Ownership boundary

The environment pack owns SDL, target content, scenario configuration, and the
exact interaction-provider artifact used by clean-install parity validation.
APTL owns the Docker realization backend, generic build infrastructure, lab
lifecycle, generated credentials, operator UI, and evidence capture.

The former `techvault-operational`, reduced-variant, paper, and bounded
participant SDLs are not current selectors. See the
[retired variants note](../sdl/techvault-curated-variants.md).
