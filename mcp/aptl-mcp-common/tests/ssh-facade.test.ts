import { describe, it, expect } from 'vitest';

// Issue #790: ssh.ts is split into a contracts leaf, a PersistentSession
// module, and an SSHConnectionManager module, behind a thin ssh.ts
// compatibility facade. This test locks the facade's runtime re-export
// identities so the split cannot silently introduce a second class
// definition, a wrapper class, or a dropped runtime export.
//
// The type-only re-exports (CommandResult, SessionType, SessionMode,
// SessionMetadata, CommandRequest) are NOT asserted here: they are erased at
// runtime, and this file is not type-checked (tsconfig `include` is
// `src/**/*` only, so `npm run build` never compiles tests/, and vitest has
// no `typecheck` block). Those re-exports are instead enforced by
// `npm run build` (tsc), which runs before vitest in CI: src/index.ts
// re-exports the same five types from './ssh.js', and index.ts IS inside the
// tsc `include`, so dropping a facade type re-export (or re-exporting it as
// the wrong kind) fails compilation.

import * as facade from '../src/ssh.js';
import { PersistentSession } from '../src/ssh-session.js';
import { SSHConnectionManager } from '../src/ssh-manager.js';
import { SSHError } from '../src/ssh-contracts.js';

describe('ssh.ts facade re-exports', () => {
  it('re-exports the same PersistentSession class identity as ssh-session.ts', () => {
    expect(facade.PersistentSession).toBe(PersistentSession);
  });

  it('re-exports the same SSHConnectionManager class identity as ssh-manager.ts', () => {
    expect(facade.SSHConnectionManager).toBe(SSHConnectionManager);
  });

  it('re-exports the same SSHError class identity as ssh-contracts.ts', () => {
    expect(facade.SSHError).toBe(SSHError);
  });

  it('defines every runtime public name on the facade module', () => {
    expect(facade.SSHConnectionManager).toBeDefined();
    expect(facade.PersistentSession).toBeDefined();
    expect(facade.SSHError).toBeDefined();
  });
});
