"""Tests for ``aptl.core.experiment.resolver`` (ADR-047 "Authorized artifact
resolution").

Two layers are tested separately:

* ``parse_locator`` — pure string classification of an untrusted locator
  into a normalized :class:`ProjectFileLocator`. Never touches the
  filesystem.
* ``ProjectContainedResolver`` — the offline, project-contained resolver
  that actually opens bytes, via ``pathsafe`` no-follow one-open semantics,
  and enforces size/digest/aggregate/reference-count policy.
"""

from __future__ import annotations

import hashlib
import os

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aptl.core.experiment.errors import EXPERIMENT_ADMISSION_DOMAIN, AdmissionRejection
from aptl.core.experiment.policy import AdmissionPolicy, default_admission_policy
from aptl.core.experiment.resolver import (
    ProjectContainedResolver,
    ProjectFileLocator,
    ResolvedArtifact,
    parse_locator,
)


# ---------------------------------------------------------------------------
# parse_locator
# ---------------------------------------------------------------------------


class TestParseLocatorHappyPath:
    def test_bare_relative_path(self):
        locator = parse_locator("scenarios/techvault.sdl.yaml")

        assert locator == ProjectFileLocator(
            relative_path="scenarios/techvault.sdl.yaml",
            declared_size=None,
            declared_digest=None,
            media_type=None,
        )

    def test_explicit_file_scheme(self):
        locator = parse_locator("file:scenarios/techvault.sdl.yaml")

        assert locator.relative_path == "scenarios/techvault.sdl.yaml"

    def test_declared_size_digest_and_media_type_query_fields(self):
        locator = parse_locator(
            "file:scenarios/techvault.sdl.yaml"
            "?size=1234&digest=sha256:"
            + ("a" * 64)
            + "&media_type=application/yaml"
        )

        assert locator.relative_path == "scenarios/techvault.sdl.yaml"
        assert locator.declared_size == 1234
        assert locator.declared_digest == "sha256:" + ("a" * 64)
        assert locator.media_type == "application/yaml"

    def test_nested_relative_path(self):
        locator = parse_locator("a/b/c/d.txt")
        assert locator.relative_path == "a/b/c/d.txt"


class TestParseLocatorRejectsCredentialUserinfo:
    def test_rejects_userinfo_in_a_file_authority(self):
        with pytest.raises(AdmissionRejection):
            parse_locator("file://user:pass@localhost/etc/passwd")

    def test_rejects_userinfo_in_an_http_authority(self):
        with pytest.raises(AdmissionRejection):
            parse_locator("https://user:secret@example.test/guide")


class TestParseLocatorRejectsSecretBearingQuery:
    def test_rejects_a_sensitive_key_name(self):
        with pytest.raises(AdmissionRejection):
            parse_locator("file:scenario.yaml?token=abcd1234")

    def test_rejects_a_secret_shaped_value_under_a_recognized_key(self):
        with pytest.raises(AdmissionRejection):
            parse_locator("file:scenario.yaml?media_type=Authorization:%20Bearer%20abc")


class TestParseLocatorRejectsUnrecognizedQueryField:
    def test_rejects_a_benign_undeclared_query_key(self):
        # "color" is well-formed and not secret-shaped/sensitive at all --
        # it must still fail closed for not being one of the three
        # recognized keys (size/digest/media_type), never silently ignored.
        with pytest.raises(AdmissionRejection) as excinfo:
            parse_locator("file:scenario.yaml?color=blue")

        assert any(
            d.code == "aptl.experiment-admission.locator-unrecognized-query-field"
            for d in excinfo.value.diagnostics
        )


class TestParseLocatorRejectsUnsupportedScheme:
    @pytest.mark.parametrize(
        "raw",
        [
            "https://example.test/scenario.yaml",
            "http://example.test/scenario.yaml",
            "oci://registry.example.test/image:tag",
            "registry://example.test/artifact",
            "urn:sha256:" + "a" * 64,
        ],
    )
    def test_rejects_non_file_schemes(self, raw):
        with pytest.raises(AdmissionRejection):
            parse_locator(raw)


class TestParseLocatorRejectsTraversal:
    def test_rejects_absolute_path(self):
        with pytest.raises(AdmissionRejection):
            parse_locator("/etc/passwd")

    def test_rejects_dotdot_component(self):
        with pytest.raises(AdmissionRejection):
            parse_locator("../outside.yaml")

    def test_rejects_embedded_dotdot_component(self):
        with pytest.raises(AdmissionRejection):
            parse_locator("scenarios/../../../etc/passwd")

    def test_rejects_empty_locator(self):
        with pytest.raises(AdmissionRejection):
            parse_locator("")


class TestParseLocatorRejectionShape:
    def test_raises_admission_rejection_with_a_safe_diagnostic(self):
        with pytest.raises(AdmissionRejection) as excinfo:
            parse_locator("/etc/passwd")

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)
        assert all(d.is_error for d in excinfo.value.diagnostics)


# ---------------------------------------------------------------------------
# ProjectContainedResolver
# ---------------------------------------------------------------------------


class TestProjectContainedResolverHappyPath:
    def test_resolves_correct_bytes_digest_and_portable_locator(self, tmp_path):
        (tmp_path / "scenario.yaml").write_bytes(b"name: canonical-minimal\n")
        resolver = ProjectContainedResolver(tmp_path)
        locator = parse_locator("scenario.yaml")

        artifact = resolver.resolve(locator, policy=default_admission_policy())

        assert isinstance(artifact, ResolvedArtifact)
        assert artifact.data == b"name: canonical-minimal\n"
        assert artifact.locator == "scenario.yaml"
        assert not os.path.isabs(artifact.locator)
        assert artifact.digest.startswith("sha256:")

        expected = hashlib.sha256(b"name: canonical-minimal\n").hexdigest()
        assert artifact.digest == f"sha256:{expected}"

    def test_media_type_carries_through_from_the_locator(self, tmp_path):
        (tmp_path / "f.json").write_bytes(b"{}")
        resolver = ProjectContainedResolver(tmp_path)
        locator = parse_locator("file:f.json?media_type=application/json")

        artifact = resolver.resolve(locator, policy=default_admission_policy())

        assert artifact.media_type == "application/json"

    def test_nested_directory_path(self, tmp_path):
        nested = tmp_path / "scenarios" / "sub"
        nested.mkdir(parents=True)
        (nested / "f.yaml").write_bytes(b"data")
        resolver = ProjectContainedResolver(tmp_path)

        artifact = resolver.resolve(parse_locator("scenarios/sub/f.yaml"), policy=default_admission_policy())

        assert artifact.data == b"data"


class TestProjectContainedResolverDeclaredSize:
    def test_rejects_a_declared_size_mismatch(self, tmp_path):
        (tmp_path / "f.txt").write_bytes(b"exactly-11b")  # 11 bytes
        resolver = ProjectContainedResolver(tmp_path)
        locator = parse_locator("file:f.txt?size=999")

        with pytest.raises(AdmissionRejection):
            resolver.resolve(locator, policy=default_admission_policy())

    def test_accepts_a_matching_declared_size(self, tmp_path):
        (tmp_path / "f.txt").write_bytes(b"exactly-11b")
        resolver = ProjectContainedResolver(tmp_path)
        locator = parse_locator("file:f.txt?size=11")

        artifact = resolver.resolve(locator, policy=default_admission_policy())

        assert len(artifact.data) == 11


class TestProjectContainedResolverDeclaredDigest:
    def test_rejects_a_declared_digest_mismatch(self, tmp_path):
        (tmp_path / "f.txt").write_bytes(b"hello world")
        resolver = ProjectContainedResolver(tmp_path)
        wrong_digest = "sha256:" + ("0" * 64)
        locator = parse_locator(f"file:f.txt?digest={wrong_digest}")

        with pytest.raises(AdmissionRejection):
            resolver.resolve(locator, policy=default_admission_policy())

    def test_accepts_a_matching_declared_digest(self, tmp_path):
        data = b"hello world"
        (tmp_path / "f.txt").write_bytes(data)
        resolver = ProjectContainedResolver(tmp_path)
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        locator = parse_locator(f"file:f.txt?digest={digest}")

        artifact = resolver.resolve(locator, policy=default_admission_policy())

        assert artifact.digest == digest

    def test_accepts_a_matching_blake3_declared_digest(self, tmp_path):
        import blake3

        data = b"hello blake3 world"
        (tmp_path / "f.txt").write_bytes(data)
        resolver = ProjectContainedResolver(tmp_path)
        digest = "blake3:" + blake3.blake3(data).hexdigest()
        locator = parse_locator(f"file:f.txt?digest={digest}")

        artifact = resolver.resolve(locator, policy=default_admission_policy())

        assert artifact.data == data

    def test_rejects_an_unsupported_digest_algorithm_on_a_hand_built_locator(self, tmp_path):
        # Bypasses parse_locator entirely: resolve() must independently
        # fail closed on an unsupported algorithm rather than trusting
        # that every locator came from the parser's own regex gate.
        (tmp_path / "f.txt").write_bytes(b"hello world")
        resolver = ProjectContainedResolver(tmp_path)
        locator = ProjectFileLocator(
            relative_path="f.txt",
            declared_size=None,
            declared_digest="md5:5eb63bbbe01eeed093cb22bb8f5acdc3",
            media_type=None,
        )

        with pytest.raises(AdmissionRejection):
            resolver.resolve(locator, policy=default_admission_policy())


class TestProjectContainedResolverSizeLimit:
    def test_rejects_over_max_artifact_bytes(self, tmp_path):
        (tmp_path / "big.txt").write_bytes(b"x" * 1000)
        resolver = ProjectContainedResolver(tmp_path)
        policy = AdmissionPolicy(max_artifact_bytes=10)

        with pytest.raises(AdmissionRejection):
            resolver.resolve(parse_locator("big.txt"), policy=policy)

    def test_accepts_at_exactly_the_limit(self, tmp_path):
        (tmp_path / "exact.txt").write_bytes(b"x" * 10)
        resolver = ProjectContainedResolver(tmp_path)
        policy = AdmissionPolicy(max_artifact_bytes=10)

        artifact = resolver.resolve(parse_locator("exact.txt"), policy=policy)
        assert len(artifact.data) == 10


class TestProjectContainedResolverSymlinks:
    def test_rejects_a_symlinked_leaf(self, tmp_path):
        target = tmp_path / "real.txt"
        target.write_bytes(b"real")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        resolver = ProjectContainedResolver(tmp_path)

        with pytest.raises(AdmissionRejection):
            resolver.resolve(parse_locator("link.txt"), policy=default_admission_policy())

    def test_rejects_a_symlinked_directory_component(self, tmp_path):
        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        (real_dir / "f.txt").write_bytes(b"data")
        link_dir = tmp_path / "link_dir"
        link_dir.symlink_to(real_dir, target_is_directory=True)
        resolver = ProjectContainedResolver(tmp_path)

        with pytest.raises(AdmissionRejection):
            resolver.resolve(parse_locator("link_dir/f.txt"), policy=default_admission_policy())


class TestProjectContainedResolverAggregateLimits:
    def test_fails_closed_past_max_aggregate_bytes(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"x" * 6)
        (tmp_path / "b.txt").write_bytes(b"x" * 6)
        resolver = ProjectContainedResolver(tmp_path)
        policy = AdmissionPolicy(max_artifact_bytes=100, max_aggregate_bytes=10)

        resolver.resolve(parse_locator("a.txt"), policy=policy)
        with pytest.raises(AdmissionRejection):
            resolver.resolve(parse_locator("b.txt"), policy=policy)

    def test_fails_closed_past_max_reference_count(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"a")
        (tmp_path / "b.txt").write_bytes(b"b")
        resolver = ProjectContainedResolver(tmp_path)
        policy = AdmissionPolicy(max_reference_count=1)

        resolver.resolve(parse_locator("a.txt"), policy=policy)
        with pytest.raises(AdmissionRejection):
            resolver.resolve(parse_locator("b.txt"), policy=policy)

    def test_independent_resolvers_do_not_share_accumulated_state(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"a")
        policy = AdmissionPolicy(max_reference_count=1)

        ProjectContainedResolver(tmp_path).resolve(parse_locator("a.txt"), policy=policy)
        # A second, independent resolver instance starts a fresh session.
        artifact = ProjectContainedResolver(tmp_path).resolve(parse_locator("a.txt"), policy=policy)
        assert artifact.data == b"a"


class TestProjectContainedResolverRejectionShape:
    def test_raises_admission_rejection_with_safe_diagnostics(self, tmp_path):
        resolver = ProjectContainedResolver(tmp_path)

        with pytest.raises(AdmissionRejection) as excinfo:
            resolver.resolve(parse_locator("missing.txt"), policy=default_admission_policy())

        assert excinfo.value.diagnostics
        assert all(d.domain == EXPERIMENT_ADMISSION_DOMAIN for d in excinfo.value.diagnostics)


# ---------------------------------------------------------------------------
# Fuzz
# ---------------------------------------------------------------------------


@pytest.mark.fuzz
class TestFuzzParseLocator:
    @given(
        raw=st.text(
            alphabet=st.characters(blacklist_categories=("Cs",), max_codepoint=0x2FFFF),
            min_size=0,
            max_size=200,
        )
    )
    @settings(max_examples=300, deadline=1000)
    def test_never_raises_anything_other_than_admission_rejection(self, raw):
        try:
            parse_locator(raw)
        except AdmissionRejection:
            pass

    @given(
        segments=st.lists(
            st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E), min_size=1, max_size=10)
            .filter(lambda s: "/" not in s and "?" not in s and "\x00" not in s),
            min_size=1,
            max_size=5,
        )
    )
    @settings(max_examples=200, deadline=1000)
    def test_a_parsed_relative_path_never_contains_a_dotdot_component(self, segments):
        raw = "/".join(segments)
        try:
            locator = parse_locator(raw)
        except AdmissionRejection:
            return
        assert ".." not in locator.relative_path.split("/")


@pytest.mark.fuzz
class TestFuzzProjectContainedResolver:
    @given(
        declared_size=st.integers(min_value=0, max_value=10_000).filter(lambda n: n != 4),
    )
    @settings(max_examples=50, deadline=1000)
    def test_declared_size_mismatch_always_rejects(self, tmp_path_factory, declared_size):
        base = tmp_path_factory.mktemp("resolver-fuzz")
        (base / "f.txt").write_bytes(b"data")  # 4 bytes
        resolver = ProjectContainedResolver(base)
        locator = ProjectFileLocator(
            relative_path="f.txt", declared_size=declared_size, declared_digest=None, media_type=None
        )

        with pytest.raises(AdmissionRejection):
            resolver.resolve(locator, policy=default_admission_policy())

    @given(bad_hex=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64))
    @settings(max_examples=50, deadline=1000)
    def test_declared_digest_mismatch_always_rejects(self, tmp_path_factory, bad_hex):
        real_digest = "sha256:" + hashlib.sha256(b"data").hexdigest()
        candidate = f"sha256:{bad_hex}"
        if candidate == real_digest:
            return
        base = tmp_path_factory.mktemp("resolver-fuzz")
        (base / "f.txt").write_bytes(b"data")
        resolver = ProjectContainedResolver(base)
        locator = ProjectFileLocator(
            relative_path="f.txt", declared_size=None, declared_digest=candidate, media_type=None
        )

        with pytest.raises(AdmissionRejection):
            resolver.resolve(locator, policy=default_admission_policy())
