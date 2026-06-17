### Fixed

**`aptl lab start` no longer fails the compose parse when `APTL_API_TOKEN` is unset.**
The web control-plane auth work (ADR-039) made `APTL_API_TOKEN` a hard-required
docker-compose variable but never added it to `.env.example`, so a `.env`
copied from the example could not start the lab. `.env.example` now documents
`APTL_API_TOKEN` with a generation hint; the `aptl-web-api` service still
rejects a placeholder value at runtime.
