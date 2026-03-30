"""Tests for attack models (aptl.core.attacks)."""

from aptl.core.attacks import PlatformCommand


class TestPlatformCommand:
    def test_basic(self):
        pc = PlatformCommand(command="whoami")
        assert pc.shell == "sh"
        assert pc.cleanup == ""

    def test_with_cleanup(self):
        pc = PlatformCommand(shell="psh", command="procdump.exe", cleanup="del dump.bin")
        assert pc.cleanup == "del dump.bin"
