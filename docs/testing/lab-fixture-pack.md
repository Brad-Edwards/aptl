# Lab fixture pack

APTL's tests of its own lab machinery use a small environment pack that APTL
owns, instead of the released TechVault pack. A pack release therefore can't
break a test of pack admission, content resolution, realization, or the live
gate. Issue #985 introduced it.

## Where it lives and why

The pack is `tests/fixtures/packs/materialization-envelope/`. It stays in this
repository and is **not published**. Its only consumers are this test suite and
this repository's CI, so a separate distribution would add a release process
with no one outside the repository to serve. Publish it only when an external
consumer needs it, and keep this in-tree copy as the one the tests use.

The pack contains:

| Member | Purpose |
| --- | --- |
| `sdl/materialization-envelope.sdl.yaml` | The canonical product-neutral scenario: #993's causal chain of inline content, service unit, listener, loopback publication, and one workflow |
| `assets/content/notice.txt` | A small file artifact for pack-file resolution and satisfaction tests |
| `assets/content/tree.tar` | A one-member archive for pack-directory extraction tests |
| `pack.yaml`, `docs/provenance-ledger.yaml` | Pack identity and provenance, as env-packs requires |
| `associated-artifacts.json` | The content manifest binding every member above to its SHA-256 digest |

The scenario's `name` is the pack identity, because env-packs binds the content
manifest to it.

## How tests use it

`tests/fixture_pack.py` admits the pack with the production resolver,
`env_pack_bundle(staging_root, identity, source_pack=...)`. That resolver stages
an isolated copy and runs env-packs' own `validate_pack` and content-manifest
gates, exactly as it does for a released pack. The module is import-safe: it
reads no project `.env` and runs no lab script.

Generic resolver, content, realization, and live-gate cases use the fixture.
Cases that pin a released pack stay on TechVault and remain separate: its
exact content identity, its evidence contracts, plugin compatibility, and the
TechVault realization, static, and live gates.

The clean-install boot job copies the same SDL into a fresh project and starts
it with `--scenario-path`. An explicit path is a project-tree selection, so that
job proves the installed wheel's lifecycle, not pack admission. Unit tests
prove admission.

## Changing the pack

Every member is byte-bound, so any edit, including to the SDL, needs a new
manifest before the pack validates again:

1. Edit the member. To add a member, also add its entry to
   `associated-artifacts.json`, since the manifest must list the pack's exact
   inventory.
2. Re-derive the manifest with env-packs' own tooling:

   ```bash
   uv run python - <<'EOF'
   import json
   from pathlib import Path

   from raes_env_packs import derive_pack_content_manifest

   pack = Path("tests/fixtures/packs/materialization-envelope")
   derived = derive_pack_content_manifest(str(pack))
   (pack / "associated-artifacts.json").write_text(
       json.dumps(derived.model_dump(mode="json"), indent=2) + "\n",
       encoding="utf-8",
   )
   EOF
   ```

3. Run `tests/test_scenario_bundle.py` and the tests that read the fixture.

Never re-derive the manifest to make an unexplained byte change pass: a failing
digest means something changed a member. `.gitattributes` marks the pack
`-text`, so Git never converts its line endings.

Keep the pack small. A new realization regression adds one declaration to the
scenario and one effect assertion to the boot verifier, as
[boot realization coverage](boot-realization-coverage.md) describes. It does
not add a second scenario or a second pack.
