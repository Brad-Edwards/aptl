# Issue #1162: Seat Acceptance

This record covers manual checks performed on 2026-09-23 and 2026-09-24 for
[issue #1162](https://github.com/Brad-Edwards/aptl/issues/1162).
The checks used the existing `aptl` CLI, public GHCR artifacts and a real
QEMU/KVM guest. Automated regression tests and hosted CI are separate evidence.

## Published Image

The local build recorded clean source commit
`63c6e91d691ff322a8a037e465ab5e5867d07903` and passed the golden-image scan.
The disk declares 128 GiB, eight vCPUs and 32 GiB RAM. Its compressed size is
9,505,352,704 bytes. Image publication is independent of the package release.

| Identity | SHA-256 |
| --- | --- |
| OCI manifest | `36362c1091ed9afba545f4f81e9c02e3f875a99d81458bef5654df82650f3424` |
| Guest disk | `28757cbd9e4ebef03a64e36e4697bf80a08a69ed4cf02f2d1a0c2ecec9350ad6` |
| Launch config | `450be9247cc1499f97d60c26bedc2f42f7dd6b63fbc122a27baceef1893318d9` |
| Publisher public key | `fc7f16f8c881125d93fccdb398ea555610a35e45b16dd5e63b09cf847b488161` |

The candidate reference is
`ghcr.io/brad-edwards/aptl-seat:candidate-1162-63c6e91d691f`.
Anonymous manifest acquisition and Cosign 3.1.3 verification passed, including
verification of the transparency-log entry. No registry login was used by the
verifier. The publisher signed the immutable manifest after comparing its disk
and config descriptors with the local build record.

The acceptance host wheel includes the subsequent client-refresh repairs in
this PR. Its SHA-256 is
`e6b5bf2b11f1dc21a5668011c459b27b7a79c035a03e518f1f7b79f7995c9718`.
Those changes affect host client configuration; the guest remains the clean
source cut above. No guest disk or overlay was patched to make acceptance pass.

## Runtime Acceptance

The signed replacement was admitted through `aptl seat update --yes` and booted
with KVM. The full TechVault range reached `ready` with a clean taint state.

- All eight live MCP qualification checks passed, covering red-team execution,
  SSH authentication events, the indexer, Wazuh, network tooling, case handling,
  threat intelligence and workflow operations.
- The enrolled host MCP connection initialized, listed nine tools, and executed
  `kali_info` and `kali_run_command` successfully through restricted SSH.
- Chrome logged in through the private bootstrap file and displayed the running
  full range. The launch token was absent from the browser's process arguments.
- Offline restart reached ready with registry access blocked and no Cosign
  invocation. The real host MCP command and authenticated browser passed again.
- Native guest CLI cleanup after the host command exited zero. The broker and
  census both recorded three sessions. Finalization returned `SEALED_READY`,
  an OK collector status and no diagnostic codes.

The clean range startup exited zero. All eight live MCP checks passed again,
and the final native guest stop exited zero. Its two expected sessions matched
the broker export; finalization again returned `SEALED_READY` with an OK
collector status and no diagnostic codes. The observation helpers called the
real CLI and capture methods without replacing their results.

Host `aptl seat stop` closed the participant, recovery and host MCP endpoints,
advanced the generation and removed the old web token. The guest records were
exported only after QEMU stopped.

## Consent and Replacement

With a fresh wheel and separate empty state/cache directories, declining the
first-use prompt and providing EOF both exited without creating either root.
A configured alternate source was named in the prompt and did not fall back
to the default channel. The `--yes` candidate acquisition passed signature
verification without an interactive prompt.

The running-seat update was refused. Declining an update, sending EOF at its
prompt and declining cache pruning preserved the existing seat record. With
the VM stopped, blocked registry access caused update to fail while preserving
the record, overlay and cache selection. Confirmed replacement succeeded,
advanced the generation and removed the old disposable overlay.

A dedicated moving test channel exercised replacement between the two real
signed public candidates. Declining preserved the old selection and cached
image. Interactive approval admitted the new digest and deleted the superseded
cache entry, while a separate cache's copy remained intact. This check reused
blobs from verified downloads and performed real anonymous Cosign verification
for both manifests.

## Default Channel

After the manual lifecycle passed, the publisher promoted this manifest to
`ghcr.io/brad-edwards/aptl-seat:latest`. Promotion and anonymous digest
verification succeeded on the first bounded attempt.

A separate fresh CLI installation then ran `aptl seat stage` with an empty
cache, no local image, an empty project configuration and no image-source
environment override. It prompted for the default `:latest` download. After
interactive approval, it downloaded the public disk anonymously, verified the
publisher signature and artifact digests, and staged the exact image identified
above. No `--image` or auto-approval switch was supplied.

## Repairs Found by Manual Testing

An earlier diagnostic VM exposed web binding and browser launch-token defects.
The first signed candidate exposed a private census ownership defect after a
real host MCP command: three broker sessions were accepted, but only two were
recorded by the dispatcher. Finalization rejected that mismatch. Ownership is
now assigned after qualification creates the private directories and before
the listener opens. The replacement image contains that repair; the earlier
candidate was not promoted to the default channel.

The replacement also exposed host client configuration rejecting an intentional
instance change after image update. Refresh now permits a replacement instance
only in a newer generation, preserving owner/seat identity and rejecting stale
or conflicting bindings. Regression checks also found and repaired empty
managed TOML blocks. The 27 targeted client and seat-access tests passed.

Cosign 3 statement and repository identities were verified against the real
publisher output. The parser accepts both supported Cosign formats and rejects
wrong repositories, wrong digests, unknown statement types and changed trust
anchors.

## Evidence Retention and Scope

Local command results, build records, public Cosign claims and browser
screenshots are retained under `build/issue-1162/` in the implementation
workspace. Guest logs and browser session material stay private and are not
published in repository metadata. The exercised overlays are disposable;
the published base is the sanitized build output.

This record proves operation on one Linux KVM host. It does not claim the
independent multi-machine qualification required to complete APP-3, whose
status remains ACTIVE.
