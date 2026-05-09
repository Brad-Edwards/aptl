/**
 * Red-team command classifier.
 *
 * Maps an arbitrary shell command to an OCSF activity classification per the
 * taxonomy in `docs/red-team-taxonomy.md`. Falls back to a generic
 * `process_execution` (OCSF Process Activity, no MITRE technique) for
 * commands that don't match any known tool family — never throws and never
 * returns null, so the logger can build a record for every command.
 *
 * Severity numbers mirror `SeverityId` in `src/aptl/core/detection.py`
 * (OCSF 0–6).
 */

// ---------------------------------------------------------------------------
// OCSF / severity constants
// ---------------------------------------------------------------------------
// Class UIDs and their owning category UIDs come from the OCSF schema
// (https://schema.ocsf.io). class_uid = category_uid * 1000 + class_index
// in the canonical schema; we keep the mapping explicit so SIEM consumers
// can normalise without inferring.

const OCSF = {
  // category_uid 4 — Network Activity
  NETWORK_ACTIVITY: 4001,
  // category_uid 1 — System Activity
  PROCESS_ACTIVITY: 1007,
  // category_uid 3 — Identity & Access Management
  AUTHENTICATION: 3002,
  // category_uid 5 — Discovery (class 5001 Device Inventory Info)
  DEVICE_INVENTORY_INFO: 5001,
  // category_uid 6 — Application Activity
  WEB_RESOURCES_ACTIVITY: 6001,
} as const;

const OCSF_CLASS_NAMES: Record<number, string> = {
  [OCSF.NETWORK_ACTIVITY]: 'Network Activity',
  [OCSF.PROCESS_ACTIVITY]: 'Process Activity',
  [OCSF.AUTHENTICATION]: 'Authentication',
  [OCSF.DEVICE_INVENTORY_INFO]: 'Device Inventory Info',
  [OCSF.WEB_RESOURCES_ACTIVITY]: 'Web Resources Activity',
};

const OCSF_CATEGORY_UIDS: Record<number, number> = {
  [OCSF.NETWORK_ACTIVITY]: 4,
  [OCSF.PROCESS_ACTIVITY]: 1,
  [OCSF.AUTHENTICATION]: 3,
  [OCSF.DEVICE_INVENTORY_INFO]: 5,
  [OCSF.WEB_RESOURCES_ACTIVITY]: 6,
};

const OCSF_CATEGORY_NAMES: Record<number, string> = {
  1: 'System Activity',
  3: 'Identity & Access Management',
  4: 'Network Activity',
  5: 'Discovery',
  6: 'Application Activity',
};

/** OCSF activity_id 99 means "Other" — used when no canonical activity */
/** in the class matches the red-team intent. */
const ACTIVITY_OTHER = 99;

/** OCSF severity_id values — mirrors src/aptl/core/detection.py SeverityId. */
export const SeverityId = {
  UNKNOWN: 0,
  INFO: 1,
  LOW: 2,
  MEDIUM: 3,
  HIGH: 4,
  CRITICAL: 5,
  FATAL: 6,
} as const;
export type SeverityIdValue = (typeof SeverityId)[keyof typeof SeverityId];

// ---------------------------------------------------------------------------
// Classification result
// ---------------------------------------------------------------------------

export interface ActivityClassification {
  activity_type: string;
  category_uid: number;
  category_name: string;
  class_uid: number;
  class_name: string;
  activity_id: number;
  type_uid: number;
  technique_uid?: string;
  tactic?: string;
  tool?: string;
  default_severity_id: SeverityIdValue;
}

// ---------------------------------------------------------------------------
// Tool table
// ---------------------------------------------------------------------------

interface ToolEntry {
  tools: readonly string[];
  template: Omit<
    ActivityClassification,
    'tool' | 'type_uid' | 'category_uid' | 'category_name'
  >;
}

// First match wins. Order matters only when a tool would otherwise be
// ambiguous; current entries are disjoint by command name.
const TOOL_TABLE: readonly ToolEntry[] = [
  {
    tools: ['nmap', 'masscan', 'rustscan', 'unicornscan'],
    template: {
      activity_type: 'port_scan',
      class_uid: OCSF.NETWORK_ACTIVITY,
      class_name: OCSF_CLASS_NAMES[OCSF.NETWORK_ACTIVITY],
      activity_id: 1,
      technique_uid: 'T1046',
      tactic: 'Discovery',
      default_severity_id: SeverityId.LOW,
    },
  },
  {
    tools: ['nc', 'ncat', 'socat'],
    template: {
      activity_type: 'network_connection',
      class_uid: OCSF.NETWORK_ACTIVITY,
      class_name: OCSF_CLASS_NAMES[OCSF.NETWORK_ACTIVITY],
      activity_id: 6,
      technique_uid: 'T1095',
      tactic: 'Command and Control',
      default_severity_id: SeverityId.MEDIUM,
    },
  },
  {
    tools: ['hydra', 'medusa', 'patator', 'crowbar'],
    template: {
      activity_type: 'credential_brute_force',
      class_uid: OCSF.AUTHENTICATION,
      class_name: OCSF_CLASS_NAMES[OCSF.AUTHENTICATION],
      activity_id: 1,
      technique_uid: 'T1110',
      tactic: 'Credential Access',
      default_severity_id: SeverityId.HIGH,
    },
  },
  {
    tools: ['ssh', 'plink'],
    template: {
      activity_type: 'ssh_login_attempt',
      class_uid: OCSF.AUTHENTICATION,
      class_name: OCSF_CLASS_NAMES[OCSF.AUTHENTICATION],
      activity_id: 1,
      technique_uid: 'T1021.004',
      tactic: 'Lateral Movement',
      default_severity_id: SeverityId.LOW,
    },
  },
  {
    tools: ['john', 'hashcat'],
    template: {
      activity_type: 'password_cracking',
      class_uid: OCSF.PROCESS_ACTIVITY,
      class_name: OCSF_CLASS_NAMES[OCSF.PROCESS_ACTIVITY],
      activity_id: 1,
      technique_uid: 'T1110.002',
      tactic: 'Credential Access',
      default_severity_id: SeverityId.MEDIUM,
    },
  },
  {
    // OCSF Web Resources Activity activity IDs 1..7 are
    // Create/Read/Update/Delete/Send/Import/Export — none cleanly maps to
    // "attack". Use Other (99) and rely on `aptl.activity_type` plus the
    // MITRE technique for downstream semantics.
    tools: ['sqlmap', 'nikto', 'wpscan', 'xsstrike'],
    template: {
      activity_type: 'web_attack',
      class_uid: OCSF.WEB_RESOURCES_ACTIVITY,
      class_name: OCSF_CLASS_NAMES[OCSF.WEB_RESOURCES_ACTIVITY],
      activity_id: ACTIVITY_OTHER,
      technique_uid: 'T1190',
      tactic: 'Initial Access',
      default_severity_id: SeverityId.MEDIUM,
    },
  },
  {
    // Same Other-activity rationale as web_attack — discovery via wordlist
    // scanning isn't one of OCSF's CRUD/Send activity IDs.
    tools: ['gobuster', 'dirb', 'dirbuster', 'wfuzz', 'ffuf', 'feroxbuster'],
    template: {
      activity_type: 'web_discovery',
      class_uid: OCSF.WEB_RESOURCES_ACTIVITY,
      class_name: OCSF_CLASS_NAMES[OCSF.WEB_RESOURCES_ACTIVITY],
      activity_id: ACTIVITY_OTHER,
      technique_uid: 'T1595.003',
      tactic: 'Reconnaissance',
      default_severity_id: SeverityId.LOW,
    },
  },
  {
    tools: [
      'enum4linux',
      'enum4linux-ng',
      'smbclient',
      'smbmap',
      'crackmapexec',
      'cme',
      'nxc',
      'nbtscan',
      'rpcclient',
      'ldapsearch',
      'kerbrute',
      'bloodhound-python',
      'bloodhound.py',
      'sharphound',
      'arping',
      'fping',
      'fierce',
      'whatweb',
      'wafw00f',
      'dnsenum',
      'dnsrecon',
      'dig',
      'host',
      'nslookup',
      'tcpdump',
      'tshark',
    ],
    template: {
      activity_type: 'host_discovery',
      class_uid: OCSF.DEVICE_INVENTORY_INFO,
      class_name: OCSF_CLASS_NAMES[OCSF.DEVICE_INVENTORY_INFO],
      activity_id: 1,
      technique_uid: 'T1018',
      tactic: 'Discovery',
      default_severity_id: SeverityId.LOW,
    },
  },
  {
    // Lateral movement / remote-execution tools that create remote
    // sessions to RUN code (psexec, evil-winrm, wmiexec, dcomexec,
    // atexec, smbexec). NOT credential-dumping / kerberoasting tools —
    // those are split into the credential_dumping bucket below per
    // ATT&CK semantics.
    tools: [
      'evil-winrm',
      'psexec.py',
      'smbexec.py',
      'wmiexec.py',
      'dcomexec.py',
      'atexec.py',
      'impacket-psexec',
      'impacket-smbexec',
      'impacket-wmiexec',
      'impacket-dcomexec',
      'impacket-atexec',
    ],
    template: {
      activity_type: 'remote_execution',
      class_uid: OCSF.AUTHENTICATION,
      class_name: OCSF_CLASS_NAMES[OCSF.AUTHENTICATION],
      activity_id: 1,
      technique_uid: 'T1021',
      tactic: 'Lateral Movement',
      default_severity_id: SeverityId.HIGH,
    },
  },
  {
    // LLMNR / NBT-NS / mDNS poisoning + relay tools. ntlmrelayx is
    // here because its primary effect is relay/coercion, not running
    // code as a logged-on user.
    tools: ['responder', 'inveigh', 'mitm6', 'ntlmrelayx.py', 'impacket-ntlmrelayx'],
    template: {
      activity_type: 'network_poisoning',
      class_uid: OCSF.NETWORK_ACTIVITY,
      class_name: OCSF_CLASS_NAMES[OCSF.NETWORK_ACTIVITY],
      activity_id: 6,
      technique_uid: 'T1557',
      tactic: 'Credential Access',
      default_severity_id: SeverityId.HIGH,
    },
  },
  {
    // OS-credential dumping AND impacket credential-access flows
    // (secretsdump, kerberoasting via GetUserSPNs, AS-REP roasting via
    // GetNPUsers). All three have a credential-access semantics rather
    // than remote-execution semantics.
    tools: [
      'mimikatz',
      'pypykatz',
      'lsassy',
      'gosecretsdump',
      'secretsdump.py',
      'impacket-secretsdump',
      'getuserspns.py',
      'impacket-getuserspns',
      'getnpusers.py',
      'impacket-getnpusers',
    ],
    template: {
      activity_type: 'credential_dumping',
      class_uid: OCSF.PROCESS_ACTIVITY,
      class_name: OCSF_CLASS_NAMES[OCSF.PROCESS_ACTIVITY],
      activity_id: 1,
      technique_uid: 'T1003',
      tactic: 'Credential Access',
      default_severity_id: SeverityId.HIGH,
    },
  },
  {
    tools: ['msfconsole', 'msfvenom', 'setoolkit', 'searchsploit', 'cewl'],
    template: {
      activity_type: 'exploit_framework',
      class_uid: OCSF.PROCESS_ACTIVITY,
      class_name: OCSF_CLASS_NAMES[OCSF.PROCESS_ACTIVITY],
      activity_id: 1,
      technique_uid: 'T1059',
      tactic: 'Execution',
      default_severity_id: SeverityId.HIGH,
    },
  },
];

const GENERIC_FALLBACK: Omit<
  ActivityClassification,
  'tool' | 'type_uid' | 'category_uid' | 'category_name'
> = {
  activity_type: 'process_execution',
  class_uid: OCSF.PROCESS_ACTIVITY,
  class_name: OCSF_CLASS_NAMES[OCSF.PROCESS_ACTIVITY],
  activity_id: 1,
  default_severity_id: SeverityId.INFO,
};

// ---------------------------------------------------------------------------
// Tokeniser
// ---------------------------------------------------------------------------

/**
 * Return the first executable token of the leading sub-command.
 *
 * Splits on top-level shell separators (`&&`, `||`, `;`, `|`) but ignores
 * any separator that appears inside single or double quotes so that
 * `echo "nmap is a scanner"` does not split before "is".
 *
 * Strips a leading `sudo` and any leading `KEY=value` env assignments, and
 * returns the basename of the resulting executable so that `/usr/bin/nmap`
 * matches the same entry as `nmap`.
 *
 * Returns `''` if the command is empty or has no recognisable executable.
 */
// Shell wrappers — `bash -c '<inner-command>'`, `sh -c`, `zsh -c`,
// `dash -c`. The interesting executable is the FIRST token of the
// quoted inner command, not the shell. We treat these distinctly from
// transparent wrappers because the inner command lives inside a quoted
// string, not as a separate shell token.
const SHELL_WRAPPERS: ReadonlySet<string> = new Set(['bash', 'sh', 'zsh', 'dash', 'ash', 'ksh']);

// Transparent wrappers — tools that take options of their own and then
// invoke another command whose semantics are what we want to classify.
// `sudo` is special-cased because it has a richer option set; the rest
// share a "skip wrapper plus its leading flags" loop with per-wrapper
// rules for which flags consume a separate argument token.
const TRANSPARENT_WRAPPERS: ReadonlySet<string> = new Set([
  'proxychains',
  'proxychains4',
  'time',
  'nice',
  'ionice',
  'stdbuf',
  'unbuffer',
  'env',
  'nohup',
  'taskset',
]);

const WRAPPER_FLAGS_TAKING_ARG: Record<string, ReadonlySet<string>> = {
  nice: new Set(['-n']),
  ionice: new Set(['-c', '-n', '-p']),
  taskset: new Set(['-c', '-p']),
  stdbuf: new Set(['-i', '-o', '-e']),
  env: new Set(['-u', '--unset']),
  // proxychains[4] -f <config> is a common red-team option. -q (quiet)
  // and -h (help) take no arg; the empty value-set entries handle
  // those by leaving the standalone-flag default branch in effect.
  proxychains: new Set(['-f']),
  proxychains4: new Set(['-f']),
  // time, unbuffer, nohup: no short flags that take an arg in the
  // leading position.
};

// `sudo` short-flags that consume their next token (e.g. `sudo -u kali …`).
// Listed explicitly because skipping every short-option arg would also
// swallow flags like `-E` / `-n` that take no argument.
const SUDO_FLAGS_TAKING_ARG = new Set([
  '-u',
  '--user',
  '-g',
  '--group',
  '-h',
  '--host',
  '-p',
  '--prompt',
  '-r',
  '--role',
  '-t',
  '--type',
  '-C',
  '--close-from',
  '-D',
  '--chdir',
  '-T',
  '--command-timeout',
  '-U',
  '--other-user',
]);

export function leadingExecutable(command: string): string {
  const head = leadingSubCommand(command);
  const tokens = tokenize(head);
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (t === 'sudo') {
      i += 1;
      // After sudo, skip its options (anything starting with `-`) until
      // we hit the real command. Honor the `--` end-of-options separator.
      while (i < tokens.length) {
        const opt = tokens[i];
        if (opt === '--') {
          i += 1;
          break;
        }
        if (!opt.startsWith('-')) break;
        // Long flag with embedded `=value` (e.g. `--preserve-env=PATH`)
        // never consumes the next token.
        if (opt.includes('=')) {
          i += 1;
          continue;
        }
        // Long-form `--xxx` with separate value: skip the next token only
        // if the option is in the known set or a generic long flag.
        if (SUDO_FLAGS_TAKING_ARG.has(opt)) {
          i += 2;
          continue;
        }
        i += 1;
      }
      continue;
    }
    // Drop a leading env assignment `KEY=value` (no spaces around `=`).
    // The value can contain `/`, `:`, etc. — we identify env-vars by the
    // shape of the prefix, not by the value. These appear both at the
    // very start of a command (`PATH=/foo nmap …`) and after `sudo` plus
    // its options (`sudo FOO=bar nmap …`); strip them in either case.
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
      i += 1;
      continue;
    }
    // basename without using `path.basename` to keep this module dep-free.
    const slash = t.lastIndexOf('/');
    const exec = slash === -1 ? t : t.slice(slash + 1);
    // Transparent wrapper (`proxychains4 hydra …`, `time nmap …`,
    // `env -i hydra …`, `nice -n 5 nmap …`): skip the wrapper plus any
    // leading short-flag arguments (and arguments-of-flags for the
    // common `nice -n N` / `taskset -c N` shape) and continue resolving.
    // sshpass `-p <pass> ssh user@target` — like sudo, sshpass takes
    // its own credential options and then invokes the real ssh/plink
    // command. Resolve through to the inner ssh tool so the event
    // classifies as ssh_login_attempt with proper user/host
    // extraction. The redactor masks `sshpass -p <value>` separately.
    if (exec === 'sshpass') {
      i += 1;
      while (i < tokens.length) {
        const opt = tokens[i];
        if (opt === '--') {
          i += 1;
          break;
        }
        if (!opt.startsWith('-')) break;
        // sshpass flags that take an argument: -p (password), -f (file),
        // -d (fd), -P (prompt). All consume the next token.
        if (
          opt === '-p' ||
          opt === '-f' ||
          opt === '-d' ||
          opt === '-P' ||
          opt.startsWith('-p') ||
          opt.startsWith('-f') ||
          opt.startsWith('-d') ||
          opt.startsWith('-P')
        ) {
          // Attached form (`-phunter2`) consumes nothing extra; spaced
          // form consumes the next token.
          if (opt.length === 2) i += 2;
          else i += 1;
          continue;
        }
        i += 1;
      }
      continue;
    }
    // Shell wrapper `bash -c '…'` — recurse into the quoted inner
    // command. The inner string is what we actually want to classify.
    // Also handles option clusters like `-lc` / `-ic` / `-cl` (POSIX
    // shells support combining short options) — `bash -lc 'nmap …'`
    // is a common login-shell form.
    if (SHELL_WRAPPERS.has(exec)) {
      let cIdx = -1;
      for (let j = i + 1; j < tokens.length; j++) {
        const t = tokens[j];
        // Standalone `-c` OR an option cluster containing `c`.
        if (t === '-c' || /^-[A-Za-z]*c[A-Za-z]*$/.test(t)) {
          cIdx = j;
          break;
        }
      }
      if (cIdx !== -1 && cIdx + 1 < tokens.length) {
        const inner = tokens[cIdx + 1];
        const innerExec = leadingExecutable(inner);
        if (innerExec) return innerExec;
      }
      return exec;
    }
    if (TRANSPARENT_WRAPPERS.has(exec)) {
      const flagsTakingArg = WRAPPER_FLAGS_TAKING_ARG[exec] ?? new Set<string>();
      i += 1;
      while (i < tokens.length) {
        const opt = tokens[i];
        if (opt === '--') {
          i += 1;
          break;
        }
        if (!opt.startsWith('-')) break;
        // Long-form `--name=value` consumes no extra token.
        if (opt.includes('=')) {
          i += 1;
          continue;
        }
        // Per-wrapper rule for which short flags consume the next
        // token. Other flags are standalone (`env -i`, `-0`).
        const nextTok = tokens[i + 1];
        if (flagsTakingArg.has(opt) && nextTok !== undefined && !nextTok.startsWith('-')) {
          i += 2;
          continue;
        }
        i += 1;
      }
      continue;
    }
    return exec;
  }
  return '';
}

/**
 * Split a command line into its top-level shell segments using the
 * same separator rules as `leadingSubCommand`. Used by the OCSF
 * logger to emit one record per executed red-team segment so a
 * compound command like `cd /tmp && nmap -p 22 host` doesn't drop the
 * nmap event.
 */
export function topLevelSegments(command: string): string[] {
  const segments: string[] = [];
  let start = 0;
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (!inDouble && ch === "'") {
      inSingle = !inSingle;
      continue;
    }
    if (!inSingle && ch === '"') {
      inDouble = !inDouble;
      continue;
    }
    if (inSingle || inDouble) continue;
    if (ch === '|' || ch === ';') {
      segments.push(command.slice(start, i));
      start = i + 1;
      continue;
    }
    if (ch === '&') {
      const prev = command[i - 1];
      const next = command[i + 1];
      if (prev === '>' || prev === '<' || next === '>') continue;
      segments.push(command.slice(start, i));
      start = next === '&' ? i + 2 : i + 1;
      continue;
    }
  }
  segments.push(command.slice(start));
  return segments
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function leadingSubCommand(command: string): string {
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (!inDouble && ch === "'") {
      inSingle = !inSingle;
      continue;
    }
    if (!inSingle && ch === '"') {
      inDouble = !inDouble;
      continue;
    }
    if (inSingle || inDouble) continue;
    // `|` and `;` are unconditional top-level separators.
    if (ch === '|' || ch === ';') {
      return command.slice(0, i);
    }
    // `&` is a separator UNLESS it's part of a redirection target
    // (`2>&1`, `<&3`, `&>file`). Specifically, if the preceding
    // non-whitespace character is `>` or `<`, or the next char is `>`,
    // the `&` is part of redirection syntax — keep scanning.
    if (ch === '&') {
      const prev = command[i - 1];
      const next = command[i + 1];
      if (prev === '>' || prev === '<' || next === '>') continue;
      // `&&` — split before the first `&`.
      // single `&` (backgrounding + next command) — also split.
      return command.slice(0, i);
    }
  }
  return command;
}

function tokenize(segment: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (!inDouble && ch === "'") {
      inSingle = !inSingle;
      continue;
    }
    if (!inSingle && ch === '"') {
      inDouble = !inDouble;
      continue;
    }
    if (!inSingle && !inDouble && /\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
      continue;
    }
    current += ch;
  }
  if (current.length > 0) tokens.push(current);
  return tokens;
}

// ---------------------------------------------------------------------------
// Classifier entry point
// ---------------------------------------------------------------------------

function buildResult(
  template: Omit<ActivityClassification, 'tool' | 'type_uid' | 'category_uid' | 'category_name'>,
  tool?: string,
): ActivityClassification {
  const category_uid = OCSF_CATEGORY_UIDS[template.class_uid];
  return {
    ...template,
    category_uid,
    category_name: OCSF_CATEGORY_NAMES[category_uid],
    type_uid: template.class_uid * 100 + template.activity_id,
    ...(tool !== undefined ? { tool } : {}),
  };
}

export function classifyCommand(command: string): ActivityClassification {
  const exec = leadingExecutable(command);
  if (!exec) {
    return buildResult(GENERIC_FALLBACK);
  }
  for (const entry of TOOL_TABLE) {
    if (entry.tools.includes(exec)) {
      return buildResult(entry.template, exec);
    }
  }
  // Generic fallback retains the executable token so SIEM consumers can
  // still discriminate `curl`, `python`, `bash`, etc. via `aptl.tool`.
  return buildResult(GENERIC_FALLBACK, exec);
}

/**
 * Resolve the "extraction-ready" command string for a given input —
 * the same surface the classifier used to pick `tool`. For shell
 * wrappers (`bash -c '<inner>'`) and transparent wrappers (`proxychains
 * -f cfg <inner...>`), this returns the inner command so the extractor
 * sees the same tokens the classifier classified. Everything else is
 * returned verbatim (already its own leading sub-command).
 */
export function extractionSurface(command: string): string {
  const head = leadingSubCommand(command);
  const tokens = tokenize(head);
  let i = 0;
  let scanning = true;
  while (scanning && i < tokens.length) {
    scanning = false;
    const t = tokens[i];
    if (t === 'sudo') {
      i += 1;
      while (i < tokens.length) {
        const opt = tokens[i];
        if (opt === '--') {
          i += 1;
          break;
        }
        if (!opt.startsWith('-')) break;
        if (opt.includes('=')) {
          i += 1;
          continue;
        }
        if (SUDO_FLAGS_TAKING_ARG.has(opt)) {
          i += 2;
          continue;
        }
        i += 1;
      }
      scanning = true;
      continue;
    }
    if (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) {
      i += 1;
      scanning = true;
      continue;
    }
    if (i >= tokens.length) break;
    const exec = tokens[i].includes('/')
      ? tokens[i].slice(tokens[i].lastIndexOf('/') + 1)
      : tokens[i];
    if (SHELL_WRAPPERS.has(exec)) {
      let cIdx = -1;
      for (let j = i + 1; j < tokens.length; j++) {
        const t = tokens[j];
        if (t === '-c' || /^-[A-Za-z]*c[A-Za-z]*$/.test(t)) {
          cIdx = j;
          break;
        }
      }
      if (cIdx !== -1 && cIdx + 1 < tokens.length) {
        return extractionSurface(tokens[cIdx + 1]);
      }
      return head;
    }
    if (exec === 'sshpass') {
      // Skip sshpass and its credential options; the inner ssh command
      // is what extractor should see.
      i += 1;
      while (i < tokens.length) {
        const opt = tokens[i];
        if (opt === '--') {
          i += 1;
          break;
        }
        if (!opt.startsWith('-')) break;
        if (
          opt === '-p' ||
          opt === '-f' ||
          opt === '-d' ||
          opt === '-P' ||
          opt.startsWith('-p') ||
          opt.startsWith('-f') ||
          opt.startsWith('-d') ||
          opt.startsWith('-P')
        ) {
          if (opt.length === 2) i += 2;
          else i += 1;
          continue;
        }
        i += 1;
      }
      scanning = true;
      continue;
    }
    if (TRANSPARENT_WRAPPERS.has(exec)) {
      const flagsTakingArg = WRAPPER_FLAGS_TAKING_ARG[exec] ?? new Set<string>();
      i += 1;
      while (i < tokens.length) {
        const opt = tokens[i];
        if (opt === '--') {
          i += 1;
          break;
        }
        if (!opt.startsWith('-')) break;
        if (opt.includes('=')) {
          i += 1;
          continue;
        }
        const nextTok = tokens[i + 1];
        if (flagsTakingArg.has(opt) && nextTok !== undefined && !nextTok.startsWith('-')) {
          i += 2;
          continue;
        }
        i += 1;
      }
      scanning = true;
      continue;
    }
  }
  if (i === 0) return head;
  return tokens.slice(i).join(' ');
}
