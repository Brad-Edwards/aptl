# Security Review — APTL Cyber Range

> **Context**: APTL is a local Docker-based purple team lab for security training.
> Many findings below are **intentional** scenario content designed for training—these
> are clearly marked. Actual infrastructure vulnerabilities that have been fixed or
> require operator attention are marked separately.

## Fixed Vulnerabilities

### 1. Hardcoded Secrets in `docker-compose.yml` (HIGH)

**Status**: ✅ Fixed

Credentials for MISP, TheHive, Shuffle SOAR, the PostgreSQL database, and the AD
domain controller were hardcoded directly in `docker-compose.yml`. Anyone with
read access to the repository had production credentials.

**Fix**: All secrets now reference `${ENV_VAR}` placeholders and are loaded from the
operator's `.env` file, which is git-ignored. `.env.example` uses `CHANGE_ME_*`
placeholders and no longer ships real passwords.

### 2. Shell Injection via `sed` in `start-lab.sh` (MEDIUM)

**Status**: ✅ Fixed

`API_PASSWORD` and `WAZUH_CLUSTER_KEY` were interpolated into `sed` replacement
strings without escaping. Characters like `|`, `&`, or `\` in passwords could
alter sed behavior or execute unintended substitutions.

**Fix**: A `sed_escape()` helper now backslash-escapes sed metacharacters before
interpolation.

### 3. Weak Random Identifiers in MCP TypeScript (LOW)

**Status**: ✅ Fixed

Session IDs and command IDs in `ssh.ts` and `handlers.ts` used
`Math.random().toString(36)`, which is not cryptographically secure and has
limited entropy.

**Fix**: Replaced with `crypto.randomUUID()` for all session and command IDs.

### 4. Prototype Pollution in `.env` Parser (LOW)

**Status**: ✅ Fixed

`parseDotEnv()` in `config.ts` could accept keys like `__proto__`, `constructor`,
or `prototype`, potentially mutating object prototypes.

**Fix**: These keys are now explicitly skipped during parsing.

### 5. Path Traversal in SSH Key Path Expansion (MEDIUM)

**Status**: ✅ Fixed

`expandTilde()` in `utils.ts` resolved `~/../etc/passwd` to a path outside the
home directory without validation.

**Fix**: The resolved path is now verified to start with the home directory. Paths
that escape it throw an error.

## Accepted Design Decisions (Lab Environment)

The following are intentional for a locally-run cyber range and do not represent
vulnerabilities in production deployments:

| Item | Rationale |
|------|-----------|
| SSL verification disabled (`verify_ssl: false`) | Self-signed certificates are expected in the lab |
| `StrictHostKeyChecking=no` in SSH | Containers are dynamically provisioned; TOFU is impractical |
| `seccomp:unconfined` on Kali and victim containers | Required for security tooling (packet capture, ptrace, etc.) |
| Docker socket mounts on Shuffle/Cortex | Required for SOAR job orchestration |
| `NET_RAW`, `NET_ADMIN`, `SYS_ADMIN` capabilities | Required for IDS, AD, and red-team tooling |
| Weak passwords in AD provisioning scripts | **Intentional scenario content** for attack exercises |
| Vulnerable web application (`containers/webapp/`) | **Intentional scenario content** with SQLi, XSS, IDOR |
| World-readable SSH keys in victim setup | **Intentional scenario content** for privilege escalation |
| Plaintext credentials in SMB file shares | **Intentional scenario content** for data exfiltration |

## Operator Recommendations

1. **Always change `.env` values** before deploying. Never use `CHANGE_ME_*` defaults.
2. **Restrict network exposure** — the lab should only bind to `localhost` or a
   private interface. Do not expose lab ports to untrusted networks.
3. **Rotate credentials** periodically, even in lab environments.
4. **Review Docker socket access** — if Shuffle/Cortex are not needed, disable
   the `soc` profile to avoid mounting `/var/run/docker.sock`.
5. **Enable Elasticsearch security** on `thehive-es` if the SOC profile is used in
   a shared environment (`xpack.security.enabled=true`).
