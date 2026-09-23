# Issue #1162: Seat Acceptance

This record covers the manual checks performed on 2026-09-23 for
[issue #1162](https://github.com/Brad-Edwards/aptl/issues/1162).
The commands used the existing `aptl` CLI and a real QEMU/KVM guest.
Automated regression tests and hosted CI are separate evidence.

## Published Candidate

The local build recorded clean source commit
`5ca7f59af868809eda2d08a3f180acbef05d37cd` and passed the golden-image scan.
The disk declares 128 GiB, eight vCPUs and 32 GiB RAM. Its compressed size is
9,505,835,008 bytes. Image publication is independent of the package release.

| Identity | SHA-256 |
| --- | --- |
| OCI manifest | `c49a8b9c626bb521cf1607b1fb8bae7e78f438e77e330486c53ee0cfd2a9e8c1` |
| Guest disk | `beb3e5ac5627a34af050a58c92b4c026942b6a1c1d7dfb92805f099f336f9f46` |
| Launch config | `ec75d273f74aaf3c73f7ec323d5f0475dfd90ed206e6d2e72db4a7270939bd21` |
| Publisher public key | `fc7f16f8c881125d93fccdb398ea555610a35e45b16dd5e63b09cf847b488161` |

The candidate reference is
`ghcr.io/brad-edwards/aptl-seat:candidate-1162-5ca7f59af868`.
Anonymous manifest acquisition and Cosign 3.1.3 verification passed, including
verification of the transparency-log entry. No registry login was used by the
verifier. The publisher signed the immutable manifest after comparing its disk
and config descriptors with the local build record.

The first fresh-CLI attempt correctly stopped before downloading the disk:
its claim parser did not recognize Cosign 3's statement type and digest-bearing
identity. The host-side parser was repaired and tested against both Cosign
formats, wrong repositories, wrong digests, unknown statement types and changed
trust anchors. A rebuilt wheel is used for the remaining acceptance checks;
the published guest bytes remain the clean source cut identified above.

## Diagnostic VM Results

An earlier unsigned diagnostic image was used to find and repair guest startup
problems. These results are diagnostic evidence, separate from acceptance of
the published candidate.

- The full TechVault range started through `aptl seat start`.
- All eight live MCP qualification checks passed, covering red-team execution,
  SSH authentication events, the indexer, Wazuh, network tooling, case handling,
  threat intelligence and workflow operations.
- The enrolled host MCP connection initialized, listed nine tools, and executed
  `kali_info` and `kali_run_command` successfully through restricted SSH.
- The actual participant browser logged in and displayed the running lab after
  fixing preservation of the supervisor-provided launch token.
- Native guest CLI cleanup, clean range startup and clean stop each exited zero.
  An earlier diagnostic command run inside a container's chroot failed; it was
  rerun in the guest's native namespaces before recording these passing results.
- Host CLI stop closed all three forwarded endpoints, advanced the generation
  and removed the old web token. The disposable diagnostic disk was removed.

## Consent Checks

With a fresh wheel and separate empty state/cache directories, declining the
first-use prompt and providing EOF both exited without creating either root.
A configured alternate source was named in the prompt and did not fall back
to the default channel. The `--yes` candidate acquisition passed signature
verification without an interactive prompt.

## Candidate Runtime Acceptance

The candidate was acquired anonymously into an empty private cache through
`aptl seat start --yes --image` using the candidate reference. It booted with
KVM and reported `ready` with a clean taint state. No edits were made to the
candidate base or its overlay to repair startup.

- All eight live MCP qualification checks passed on the candidate.
- The enrolled host MCP connection listed nine tools and successfully executed
  `kali_info` and `kali_run_command`.
- Chrome logged in through the private bootstrap file and displayed the running
  full range. The launch token was absent from the browser's process arguments.
- `aptl seat update --yes` refused to replace the running VM.
- Declining update, sending EOF at its prompt and declining cache pruning each
  left the seat record unchanged.

Offline reuse passed with registry access blocked and no Cosign invocation.
The range reached ready and the host MCP command succeeded again.

Cleanup then exposed a guest ownership defect: startup qualification created
root-owned private census directories after the dispatcher ownership transfer.
The broker accepted the host command, but the dispatcher could not record it
in that census, so transcript finalization correctly rejected the mismatch.
The transfer now runs after qualification and before opening the listener.
A regression test checks ownership of the newly created census files.
The candidate above is not approved for the default channel; a new clean image
cut and manual lifecycle proof are required. Stopped-seat replacement and
default-channel acquisition also remain pending.

## Evidence Retention

Local command results, the exact build record, public Cosign claims and browser
screenshots are retained under `build/issue-1162/` in the implementation
workspace. Guest logs and browser session material stay private and are not
published in repository metadata. The exercised overlays are disposable;
the published base is the sanitized build output.
