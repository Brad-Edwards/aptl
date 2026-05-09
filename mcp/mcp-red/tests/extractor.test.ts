import { describe, it, expect } from 'vitest';
import { classifyCommand } from '../src/classifier.js';
import { extractMetadata } from '../src/extractor.js';

function extract(command: string) {
  return extractMetadata(command, classifyCommand(command));
}

describe('extractMetadata — IPv4', () => {
  it('extracts a bare IPv4 destination from an nmap command', () => {
    const m = extract('nmap 192.168.1.5');
    expect(m.dst_endpoint?.ip).toBe('192.168.1.5');
  });

  it('rejects out-of-range octets', () => {
    // 999.0.0.1 is not a valid IPv4 — extractor must not surface it.
    const m = extract('nmap 999.0.0.1 192.168.1.5');
    expect(m.dst_endpoint?.ip).toBe('192.168.1.5');
  });

  it('extracts an IPv4 CIDR as a multi-target endpoint', () => {
    const m = extract('nmap 10.0.0.0/24');
    expect(m.dst_endpoint?.cidr).toBe('10.0.0.0/24');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.0');
  });

  it('rejects an out-of-range CIDR suffix', () => {
    // /99 isn't a valid IPv4 prefix length — the bare IP should still be
    // extracted but not the bogus CIDR.
    const m = extract('nmap 10.0.0.0/99');
    expect(m.dst_endpoint?.cidr).toBeUndefined();
    expect(m.dst_endpoint?.ip).toBe('10.0.0.0');
  });
});

describe('extractMetadata — ports', () => {
  it('parses a single -p value', () => {
    const m = extract('nmap -p 22 10.0.0.1');
    expect(m.dst_endpoint?.ports).toEqual([22]);
  });

  it('parses comma-separated ports', () => {
    const m = extract('nmap -p 22,80,443 10.0.0.1');
    expect(m.dst_endpoint?.ports).toEqual([22, 80, 443]);
  });

  it('expands a port range', () => {
    const m = extract('nmap -p 1-1024 10.0.0.1');
    expect(m.dst_endpoint?.ports?.length).toBe(1024);
    expect(m.dst_endpoint?.ports?.[0]).toBe(1);
    expect(m.dst_endpoint?.ports?.[1023]).toBe(1024);
  });

  it('parses a host:port positional form', () => {
    const m = extract('nc 10.0.0.1 8080');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.dst_endpoint?.port).toBe(8080);
  });

  it('parses a hostname:port positional form too (cycle-4 review)', () => {
    // Hostname-based network commands like `nc target.example 4444` must
    // produce a destination port — previously the host/port pair check
    // only matched IP-shaped first tokens.
    const m = extract('nc target.example 4444');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
    expect(m.dst_endpoint?.port).toBe(4444);
  });

  it('rejects an invalid port number', () => {
    // 99999 is not a valid TCP port — should not be treated as one.
    const m = extract('nc 10.0.0.1 99999');
    expect(m.dst_endpoint?.port).toBeUndefined();
  });
});

describe('extractMetadata — IPv6', () => {
  it('extracts a compressed IPv6 loopback', () => {
    const m = extract('nmap -6 ::1');
    expect(m.dst_endpoint?.ip).toBe('::1');
  });

  it('extracts a full IPv6 address', () => {
    const m = extract('nmap -6 2001:db8::1');
    expect(m.dst_endpoint?.ip).toBe('2001:db8::1');
  });
});

describe('extractMetadata — SSH-style targets', () => {
  it('parses ssh user@host[:port]', () => {
    const m = extract('ssh user@10.0.0.1');
    expect(m.target_user).toBe('user');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
  });

  it('parses ssh -l user host -p port', () => {
    const m = extract('ssh -l alice 10.0.0.1 -p 2222');
    expect(m.target_user).toBe('alice');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.dst_endpoint?.port).toBe(2222);
  });

  it('parses an ssh hostname (not just an IP)', () => {
    const m = extract('ssh alice@kali-target.lab');
    expect(m.target_user).toBe('alice');
    expect(m.dst_endpoint?.hostname).toBe('kali-target.lab');
  });
});

describe('extractMetadata — credential brute force', () => {
  it('extracts target_user from hydra -l and the host from positional args', () => {
    const m = extract('hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.5 ssh');
    expect(m.target_user).toBe('admin');
    expect(m.dst_endpoint?.ip).toBe('192.168.1.5');
    expect(m.protocol).toBe('ssh');
    // Wordlist path is recorded as file.path; the contents stay redacted by
    // the logger. We never lift `-P` value into `target_user` (it's a list
    // file, not a credential).
    expect(m.file?.path).toBe('/usr/share/wordlists/rockyou.txt');
  });

  it('does not record the secret value of -p', () => {
    // The redactor in the logger handles `-p hunter2`; the extractor
    // intentionally does NOT bubble passwords up into structured fields,
    // even named ones. `target_user` from `-l` is fine; `-p` is not surfaced.
    const m = extract('hydra -l admin -p hunter2 192.168.1.5 ssh');
    expect(m.target_user).toBe('admin');
    expect(JSON.stringify(m)).not.toContain('hunter2');
  });
});

describe('extractMetadata — URLs', () => {
  it('extracts a URL and the dst_endpoint hostname/port from a curl command', () => {
    const m = extract('curl https://target.example:8443/api/v1/items');
    expect(m.url).toBe('https://target.example:8443/api/v1/items');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
    expect(m.dst_endpoint?.port).toBe(8443);
    expect(m.protocol).toBe('https');
  });

  it('handles a bare http URL with no explicit port', () => {
    const m = extract('sqlmap -u http://target.example/login');
    expect(m.url).toBe('http://target.example/login');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
    expect(m.protocol).toBe('http');
  });

  it('extracts the wordlist path from -w', () => {
    const m = extract('gobuster dir -u http://target.example -w /usr/share/wordlists/dirb/common.txt');
    expect(m.file?.path).toBe('/usr/share/wordlists/dirb/common.txt');
  });
});

describe('extractMetadata — quoted argument handling (review-finding regression)', () => {
  it('parses a URL inside a double-quoted argument', () => {
    // Real shell users quote URLs to escape `&`, `?`, etc. The extractor
    // must still surface URL/host/protocol when the URL is the entire
    // quoted token.
    const m = extract('sqlmap -u "https://target.example/login"');
    expect(m.url).toBe('https://target.example/login');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
    expect(m.protocol).toBe('https');
  });

  it('parses a flag-pair value inside a double-quoted argument', () => {
    // `-l "alice"` and `-l alice` should be equivalent.
    const m = extract('hydra -l "alice" -P /list 10.0.0.1 ssh');
    expect(m.target_user).toBe('alice');
  });

  it('still ignores IPs that appear only inside a multi-token quoted string', () => {
    // The quoted-token guardrail (`echo "the host is 192.168.1.5"`) must
    // remain — IPs that are just commentary should not be surfaced.
    const m = extract('echo "the host is 192.168.1.5"');
    expect(m.dst_endpoint).toBeUndefined();
  });
});

describe('extractMetadata — port range cap (review-finding regression)', () => {
  it('does not expand a full-port-space scan into a 65535-entry array', () => {
    const m = extract('nmap -p 1-65535 10.0.0.1');
    // Either (a) ports is omitted in favour of a compact spec string, or
    // (b) the array is capped at a reasonable bound. We accept both, but
    // we must NOT see 65535 entries — that would bloat every scan record.
    expect((m.dst_endpoint?.ports?.length ?? 0)).toBeLessThanOrEqual(1024);
    // The original spec must be preserved somewhere so SIEM consumers can
    // still see the requested range.
    expect(m.dst_endpoint?.port_range ?? '').toContain('1-65535');
  });

  it('still expands a small port range fully', () => {
    const m = extract('nmap -p 1-1024 10.0.0.1');
    expect(m.dst_endpoint?.ports?.length).toBe(1024);
  });
});

describe('extractMetadata — URL userinfo (security-finding regression)', () => {
  it('strips userinfo from dst_endpoint.hostname', () => {
    // CVE-shaped: a URL with embedded credentials must NOT leak the
    // password into the structured hostname field — even though the
    // verbatim command line is later redacted at the cmd_line boundary.
    const m = extract('curl https://alice:hunter2@target.example/path');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
    expect(JSON.stringify(m.dst_endpoint)).not.toContain('hunter2');
  });

  it('strips userinfo from the recorded url too', () => {
    // The structured `url` field also must not echo the credentials.
    const m = extract('curl https://alice:hunter2@target.example/path');
    expect(m.url ?? '').not.toContain('hunter2');
  });
});

describe('extractMetadata — credential-tool values not promoted to dst (cycle-3 review)', () => {
  it('does not promote a hydra -p value to dst_endpoint.hostname even when dot-shaped', () => {
    // Even though `secret.value` looks hostname-shaped, it is the password
    // for hydra; structured fields must never leak credential material.
    const m = extract('hydra -l admin -p secret.value 10.0.0.1 ssh');
    expect(m.target_user).toBe('admin');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.dst_endpoint?.hostname).toBeUndefined();
    expect(JSON.stringify(m)).not.toContain('secret.value');
  });

  it('does not promote a hydra -P wordlist filename to dst_endpoint.hostname', () => {
    // Relative wordlist with dot-shape could match the hostname regex.
    // It must be recorded as file.path only.
    const m = extract('hydra -l admin -P passwords.txt 10.0.0.1 ssh');
    expect(m.file?.path).toBe('passwords.txt');
    expect(m.dst_endpoint?.hostname).toBeUndefined();
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
  });
});

describe('extractMetadata — file-flag values must not become destinations (review-finding regression)', () => {
  it('does not treat a hashcat hash file as a destination hostname', () => {
    const m = extract('hashcat hashes.txt');
    // `password_cracking` has no network destination — the extractor must
    // not fabricate one from a filename argument.
    expect(m.dst_endpoint?.hostname).toBeUndefined();
    expect(m.dst_endpoint?.ip).toBeUndefined();
  });

  it('does not promote a -o output filename to dst_endpoint.hostname', () => {
    const m = extract('nmap -o scan.txt 10.0.0.1');
    // The IP is the real target; scan.txt is the output file.
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.dst_endpoint?.hostname).toBeUndefined();
    expect(m.file?.path).toBe('scan.txt');
  });

  it('does not promote a -w wordlist filename to dst_endpoint.hostname', () => {
    const m = extract('gobuster dir -u http://target.example -w wordlists/common.txt');
    // URL provides the destination hostname; wordlist is a file path.
    expect(m.dst_endpoint?.hostname).toBe('target.example');
    expect(m.file?.path).toBe('wordlists/common.txt');
  });
});

describe('extractMetadata — URL extraction guardrail (cycle-5 review)', () => {
  it('does not promote a URL embedded in quoted commentary for echo', () => {
    // The URL is inside a multi-word quoted string; classification is
    // generic process_execution. SIEM records must not fabricate a
    // destination from prose like `echo "visit https://target.example"`.
    const m = extract('echo "visit https://target.example"');
    expect(m.url).toBeUndefined();
    expect(m.dst_endpoint).toBeUndefined();
  });

  it('still extracts a URL when the URL is the entire quoted token', () => {
    // `sqlmap -u "https://target.example/login"` — quoted but the quoted
    // run is exactly the URL. This must continue to work.
    const m = extract('sqlmap -u "https://target.example/login"');
    expect(m.url).toBe('https://target.example/login');
  });

  it('still extracts an unquoted URL passed to a generic command (curl)', () => {
    // curl is unclassified (process_execution fallback) but the URL is a
    // standalone token, not commentary — extraction is still useful.
    const m = extract('curl https://target.example/x');
    expect(m.url).toBe('https://target.example/x');
  });
});

describe('extractMetadata — per-tool flag semantics (cycle-6 review)', () => {
  it('does not promote curl --user user:password into actor.user.name', () => {
    // curl `--user` is a Basic-auth credential pair, NOT a target user.
    // Prior behaviour leaked the password into actor.user.name.
    const m = extract('curl --user alice:hunter2 https://target.example/x');
    expect(m.target_user).toBeUndefined();
    expect(JSON.stringify(m)).not.toContain('hunter2');
  });

  it('does not record nc -p (local source port) as dst_endpoint.port[s]', () => {
    // For `nc target.example 80 -p 4444`, `-p` is the local source port,
    // not the destination. The positional pair extracts the real dest.
    const m = extract('nc 10.0.0.1 80 -p 4444');
    expect(m.dst_endpoint?.ports).toBeUndefined();
    expect(m.dst_endpoint?.port).toBe(80);
  });

  it('does not record nc -w (timeout) as file.path', () => {
    // `nc -w 5 target 80` — `-w 5` is the connection timeout in seconds,
    // not a wordlist. file.path must stay unset.
    const m = extract('nc -w 5 10.0.0.1 80');
    expect(m.file).toBeUndefined();
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.dst_endpoint?.port).toBe(80);
  });

  it('still records gobuster -w wordlist as file.path', () => {
    const m = extract('gobuster dir -u http://target.example -w common.txt');
    expect(m.file?.path).toBe('common.txt');
  });
});

describe('extractMetadata — URL extraction must not be hijacked by headers (cycle-9 review)', () => {
  it('does not promote a header-embedded URL over the real -u target', () => {
    // `sqlmap -H 'Referer: https://decoy' -u https://target/login` —
    // earlier code returned the decoy as the URL because it appeared
    // before the -u flag during scanning.
    const m = extract(
      "sqlmap -H 'Referer: https://decoy.example' -u https://target.example/login",
    );
    expect(m.url).toBe('https://target.example/login');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
  });
});

describe('extractMetadata — host-discovery -u username (cycle-9 review)', () => {
  it('extracts -u alice for nxc as actor.user.name', () => {
    const m = extract('nxc smb dc.example -u alice -p hunter2');
    expect(m.target_user).toBe('alice');
    expect(m.dst_endpoint?.hostname).toBe('dc.example');
  });

  it('does not promote a UPN -u value (alice@example.com) into dst_endpoint.hostname', () => {
    const m = extract('crackmapexec smb dc.example -u alice@example.com -p hunter2');
    expect(m.target_user).toBe('alice@example.com');
    expect(m.dst_endpoint?.hostname).toBe('dc.example');
  });
});

describe('extractMetadata — file/list flags must not become hosts (cycle-9 review)', () => {
  it('does not record hydra -L users.txt as a destination', () => {
    const m = extract('hydra -L users.txt -P passwords.txt dc.example ssh');
    // `users.txt` and `passwords.txt` are list files, not destinations.
    expect(m.dst_endpoint?.hostname).toBe('dc.example');
    expect(JSON.stringify(m.dst_endpoint)).not.toContain('.txt');
  });

  it('does not record nmap -iL targets.txt as a destination', () => {
    const m = extract('nmap -iL targets.txt -p 22');
    // -iL is "input list of targets" — a file path, not a hostname.
    expect(m.dst_endpoint?.hostname).toBeUndefined();
  });
});

describe('extractMetadata — credential-using host_discovery tools (cycle-8 review)', () => {
  it('does not promote nxc -p value into dst_endpoint.hostname', () => {
    // `nxc smb -u alice -p corp.example dc.example` — nxc/cme/crackmapexec
    // classify as host_discovery but their `-p` is a password.
    const m = extract('nxc smb -u alice -p corp.example dc.example');
    expect(m.dst_endpoint?.hostname).toBe('dc.example');
    // The -p value (corp.example) MUST NOT have been promoted to a host
    // even though it is dot-shaped.
    expect(JSON.stringify(m.dst_endpoint)).not.toContain('corp.example');
  });

  it('does not surface a Samba username%password pair as actor.user.name', () => {
    // `rpcclient --user alice%corp.example dc.example` — Samba accepts
    // `username%password`; only the username should be promoted.
    const m = extract('rpcclient --user alice%corp.example dc.example');
    expect(m.target_user).toBe('alice');
    expect(JSON.stringify(m)).not.toContain('corp.example');
  });
});

describe('extractMetadata — leading sub-command isolation (cycle-7 review)', () => {
  it('does not pull URL/host from the second command in a compound shell line', () => {
    // Classifier classifies `nmap host` (port_scan); the extractor must
    // not enrich that record with curl's URL from the && segment.
    const m = extract('nmap 10.0.0.1 && curl https://callback.example/');
    expect(m.url).toBeUndefined();
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.dst_endpoint?.hostname).toBeUndefined();
  });

  it('does not pull credential from a second command in a pipe', () => {
    const m = extract('nmap 10.0.0.1 | tee out.txt && hydra -l u -p secret host ssh');
    // Leading sub-command is the nmap part — hydra fields must not leak.
    expect(m.target_user).toBeUndefined();
  });
});

describe('extractMetadata — URL IP-literal handling (cycle-7 review)', () => {
  it('stores an IPv4-literal URL authority in dst_endpoint.ip, not hostname', () => {
    const m = extract('curl http://10.0.0.1:8080/path');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.dst_endpoint?.hostname).toBeUndefined();
    expect(m.dst_endpoint?.port).toBe(8080);
  });

  it('preserves a query-only URL (no path) including its query string', () => {
    const m = extract('sqlmap -u "https://target.example?id=1"');
    expect(m.url).toBe('https://target.example?id=1');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
  });
});

describe('extractMetadata — per-tool flag semantics (cycle-7 review)', () => {
  it('does not treat ldapsearch -l as a username (it is a time limit)', () => {
    const m = extract('ldapsearch -l 5 -h dc.lab -b "dc=lab" "(objectClass=user)"');
    expect(m.target_user).toBeUndefined();
  });

  it('still treats ssh -l alice as a target user', () => {
    const m = extract('ssh -l alice 10.0.0.1');
    expect(m.target_user).toBe('alice');
  });

  it('does not treat ssh -o KEY=VAL as an output file path', () => {
    const m = extract('ssh -o StrictHostKeyChecking=no user@host');
    expect(m.file).toBeUndefined();
  });

  it('still treats nmap -o output.txt as an output file path', () => {
    const m = extract('nmap -o scan.txt 10.0.0.1');
    expect(m.file?.path).toBe('scan.txt');
  });
});

describe('extractMetadata — shell-meta tokens (pre-emptive cycle-10)', () => {
  it('does not promote a `${VAR}` parameter expansion as a hostname', () => {
    const m = extract('nmap ${TARGET}');
    expect(m.dst_endpoint?.hostname).toBeUndefined();
    expect(m.dst_endpoint?.ip).toBeUndefined();
  });

  it('does not promote a `$(cmd)` command substitution as a hostname or IP', () => {
    const m = extract('nmap $(cat targets.txt)');
    expect(m.dst_endpoint).toBeUndefined();
  });

  it('does not promote a backtick `cmd` substitution as a hostname', () => {
    const m = extract('nmap `cat targets.txt`');
    expect(m.dst_endpoint).toBeUndefined();
  });

  it('does not promote a `<(cmd)` process-substitution as a hostname', () => {
    const m = extract('diff <(cmd1) <(cmd2)');
    expect(m.dst_endpoint).toBeUndefined();
  });

  it('does not parse an IP-shaped value out of a `${VAR}` token', () => {
    // `${HOST_192_168_1_5}` looks IP-shaped to a naive regex.
    const m = extract('nmap ${HOST_192_168_1_5}');
    expect(m.dst_endpoint).toBeUndefined();
  });
});

describe('extractMetadata — additional flag semantics (pre-emptive cycle-10)', () => {
  it('does not surface ssh -J jumphost as a destination', () => {
    const m = extract('ssh -J jump.example user@target.example');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
    expect(m.target_user).toBe('user');
    expect(JSON.stringify(m.dst_endpoint)).not.toContain('jump.example');
  });

  it('does not surface curl --user-agent value as actor.user.name', () => {
    const m = extract("curl --user-agent 'Mozilla/5.0' https://target.example/x");
    expect(m.target_user).toBeUndefined();
    expect(m.url).toBe('https://target.example/x');
  });

  it('consumes nxc -H <hash> so it cannot leak as a hostname', () => {
    // `0123456789abcdef` is a hex-only token but my hostname regex
    // requires a leading letter; defence in depth here is the
    // consumed-next contract.
    const m = extract(
      'nxc smb dc.example -u alice -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c',
    );
    expect(m.target_user).toBe('alice');
    expect(m.dst_endpoint?.hostname).toBe('dc.example');
    expect(JSON.stringify(m)).not.toContain('aad3b435');
  });

  it('consumes nxc -d <domain> without promoting the domain as a hostname', () => {
    const m = extract('nxc smb dc.example -u alice -p hunter2 -d corp.example');
    expect(m.dst_endpoint?.hostname).toBe('dc.example');
    expect(JSON.stringify(m.dst_endpoint)).not.toContain('corp.example');
  });
});

describe('extractMetadata — proxy URLs do not hijack the real target (cycle-13 review)', () => {
  it('prefers `-u <target>` over an earlier `--proxy <url>` for sqlmap', () => {
    const m = extract('sqlmap --proxy http://127.0.0.1:8080 -u https://target.example/login');
    expect(m.url).toBe('https://target.example/login');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
  });

  it('skips a proxy URL value when no target flag is present (best-effort)', () => {
    // No explicit `-u` target — just a `--proxy` and a positional URL.
    const m = extract('curl --proxy http://proxy:8080 https://target.example/');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
  });

  it('skips a `-x <proxy>` URL value (curl short proxy)', () => {
    const m = extract('curl -x http://127.0.0.1:8080 https://target.example/x');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
  });
});

describe('extractMetadata — nmap -A is not a user-agent flag (cycle-13 review)', () => {
  it('extracts `nmap -A 10.0.0.1` target correctly', () => {
    const m = extract('nmap -A 10.0.0.1');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
  });

  it('still treats curl -A as User-Agent (consumes the value)', () => {
    const m = extract("curl -A 'Mozilla/5.0' https://target.example/x");
    expect(m.url).toBe('https://target.example/x');
    expect(m.target_user).toBeUndefined();
  });
});

describe('extractMetadata — equals/attached flag forms (cycle-12 review)', () => {
  it('handles `--url=https://target/x` equals form for sqlmap', () => {
    const m = extract('sqlmap --url=https://target.example/login');
    expect(m.url).toBe('https://target.example/login');
  });

  it('handles `-l=alice` equals short form for hydra', () => {
    const m = extract('hydra -l=alice -P=words.txt 10.0.0.1 ssh');
    expect(m.target_user).toBe('alice');
  });

  it('handles `-p22` attached short form for nmap', () => {
    const m = extract('nmap -p22 10.0.0.1');
    expect(m.dst_endpoint?.ports).toEqual([22]);
  });

  it('does NOT split `-iL targets.txt` (-iL is a flag-with-suffix, not attached value)', () => {
    const m = extract('nmap -iL targets.txt -p 22');
    expect(m.file?.path).toBe('targets.txt');
  });
});

describe('extractMetadata — bloodhound-python -p does not leak as hostname (cycle-12 security)', () => {
  it('treats bloodhound-python -p as password and consumes it', () => {
    const m = extract('bloodhound-python -u alice -p Password.2026 -d corp.example -c All');
    expect(m.target_user).toBe('alice');
    // `Password.2026` is dot-shaped but is the password, not a host.
    expect(m.dst_endpoint?.hostname).toBeUndefined();
    expect(JSON.stringify(m)).not.toContain('Password.2026');
  });

  it('treats evil-winrm -p as password and consumes it', () => {
    const m = extract('evil-winrm -i 10.0.0.1 -u alice -p Password.2026');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.target_user).toBe('alice');
    expect(JSON.stringify(m)).not.toContain('Password.2026');
  });
});

describe('extractMetadata — extractor unwraps bash/proxychains the same way classifier does (cycle-11 review)', () => {
  it('extracts targets from `bash -c "<inner>"`', () => {
    const m = extract("bash -c 'nmap -p 22 10.0.0.1'");
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.dst_endpoint?.ports).toEqual([22]);
  });

  it('extracts targets from `proxychains4 -f cfg <inner>`', () => {
    const m = extract('proxychains4 -f /tmp/p.conf hydra -l alice -P p.txt 10.0.0.1 ssh');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.target_user).toBe('alice');
    // proxy.conf must NOT have been promoted as a hostname.
    expect(JSON.stringify(m.dst_endpoint)).not.toContain('p.conf');
  });
});

describe('extractMetadata — remote_execution targets (cycle-11 review)', () => {
  it('extracts evil-winrm `-i <host> -u <user>`', () => {
    const m = extract('evil-winrm -i 10.0.0.1 -u alice -p hunter2');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.target_user).toBe('alice');
  });

  it('extracts impacket `alice@dc.example` user@host shape', () => {
    const m = extract('impacket-psexec alice@dc.example');
    expect(m.target_user).toBe('alice');
    expect(m.dst_endpoint?.hostname).toBe('dc.example');
  });
});

describe('extractMetadata — quoted standalone URLs (cycle-11 review)', () => {
  it('still accepts a quoted whole-token URL for curl', () => {
    const m = extract('curl "https://target.example/path?x=1"');
    expect(m.url).toBe('https://target.example/path?x=1');
    expect(m.dst_endpoint?.hostname).toBe('target.example');
  });

  it('still rejects a URL embedded in multi-word quoted commentary', () => {
    const m = extract('echo "visit https://target.example"');
    expect(m.url).toBeUndefined();
  });
});

describe('extractMetadata — nmap -oN/-oX/-oG/-oA output forms (cycle-11 review)', () => {
  it('records `-oN <file>` as file.path and consumes it', () => {
    const m = extract('nmap -oN scan.txt 10.0.0.1');
    expect(m.file?.path).toBe('scan.txt');
    expect(m.dst_endpoint?.ip).toBe('10.0.0.1');
    expect(m.dst_endpoint?.hostname).toBeUndefined();
  });

  it('records `-oA <basename>` similarly', () => {
    const m = extract('nmap -oA scan-output 10.0.0.1');
    expect(m.file?.path).toBe('scan-output');
  });
});

describe('extractMetadata — bracketed IPv6 URL authorities (pre-emptive)', () => {
  it('parses http://[::1]:8080/path correctly', () => {
    const m = extract('curl http://[::1]:8080/path');
    expect(m.url).toBe('http://[::1]:8080/path');
    expect(m.dst_endpoint?.port).toBe(8080);
    // The IP-literal goes to dst.ip (with brackets stripped).
    expect(m.dst_endpoint?.ip).toBe('::1');
  });
});

describe('extractMetadata — robustness', () => {
  it('returns an empty object for an empty command without throwing', () => {
    const m = extract('');
    // Implementations are free to omit fields rather than emit empty objects;
    // the contract is "no crash, no fabricated targets."
    expect(m.dst_endpoint).toBeUndefined();
    expect(m.target_user).toBeUndefined();
  });

  it('does not extract IPs from inside a comment-shaped quoted string', () => {
    // The IP is in a quoted string, not a target.
    const m = extract('echo "the host is 192.168.1.5"');
    expect(m.dst_endpoint).toBeUndefined();
  });
});
