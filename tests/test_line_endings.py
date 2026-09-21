"""Line-ending policy tests for cross-platform lab artifacts."""

from pathlib import Path


def test_gitattributes_locks_lab_artifacts_to_lf():
    attrs = Path(".gitattributes").read_text(encoding="utf-8")

    required_rules = {
        "docker-compose*.yml text eol=lf",
        "config/**/*.yml text eol=lf",
        "config/**/*.xml text eol=lf",
        "containers/**/*.sh text eol=lf",
        "containers/**/*.ps1 text eol=lf",
        "scripts/**/*.sh text eol=lf",
        ".aptl/config/** text eol=lf",
        ".aptl/realization/** text eol=lf",
    }

    missing = sorted(rule for rule in required_rules if rule not in attrs)
    assert missing == []


def test_git_never_converts_the_byte_bound_fixture_pack():
    """The fixture pack's manifest pins every member's bytes (issue #985).

    A CRLF conversion on a Windows checkout would change those bytes, and
    env-packs would then refuse the pack. Git itself is asked which ``text``
    attribute applies to every pack member, so a later, broader rule that
    re-enabled conversion fails here rather than on someone's checkout.
    """

    import subprocess

    root = Path(__file__).resolve().parents[1]
    pack_root = root / "tests" / "fixtures" / "packs"
    members = sorted(
        path.relative_to(root).as_posix()
        for path in pack_root.rglob("*")
        if path.is_file()
    )
    assert members, "the fixture pack has no members"

    completed = subprocess.run(
        ["git", "check-attr", "text", "--", *members],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    observed = dict(
        line.rsplit(": text: ", 1) for line in completed.stdout.splitlines()
    )

    assert observed == dict.fromkeys(members, "unset")
