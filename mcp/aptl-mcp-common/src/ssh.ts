
// Issue #790: ssh.ts is a thin compatibility facade. The implementation is
// split into a shared contracts leaf (ssh-contracts.ts), the PersistentSession
// lifecycle module (ssh-session.ts), and the SSHConnectionManager
// orchestration module (ssh-manager.ts). This file re-exports the exact
// public surface consumers already depend on through `./ssh.js` and, via
// index.ts, the package root. Do not add logic here — extend the owning
// module instead.
export { SSHError } from './ssh-contracts.js';
export type {
  CommandResult,
  SessionType,
  SessionMode,
  SessionMetadata,
  CommandRequest,
  SessionConnectOptions,
} from './ssh-contracts.js';
export { PersistentSession } from './ssh-session.js';
export { SSHConnectionManager } from './ssh-manager.js';
