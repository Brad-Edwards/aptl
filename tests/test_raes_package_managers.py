"""Tests for the generic package-manager mechanism registry (ADR-048).

The registry is OS-mechanism knowledge (how to drive apt/dnf/pip), not product
knowledge. It is parameterized entirely by the declared package manager and
package names; it has no notion of any product. An unknown manager fails closed.
"""

from __future__ import annotations

import pytest

from aptl.backends.raes_package_managers import (
    UnsupportedDependencyEcosystemError,
    UnsupportedPackageManagerError,
    install_argv,
    manifest_install_argv,
    manifest_query_argv,
    parse_installed,
    query_installed_argv,
)


class TestInstallArgv:
    def test_apt_install_is_noninteractive_and_sorted(self):
        argv = install_argv("apt", ("wazuh-manager", "curl"))
        # Deterministic, non-interactive, explicit-yes; packages sorted.
        assert argv[-2:] == ["curl", "wazuh-manager"]
        assert "-y" in argv
        assert argv[0] in {"apt-get", "env"}

    def test_dnf_and_pip_are_supported_generically(self):
        assert "install" in install_argv("dnf", ("httpd",))
        assert "install" in install_argv("pip", ("requests",))

    def test_pip_install_breaks_system_packages(self):
        # The generic base's system pip is PEP 668-protected (Debian's own
        # python3-pip); without this flag every pip install fails closed
        # with "externally-managed-environment" before installing anything.
        assert "--break-system-packages" in install_argv("pip", ("requests",))

    def test_unknown_manager_fails_closed(self):
        with pytest.raises(UnsupportedPackageManagerError):
            install_argv("brew", ("wget",))


class TestQueryAndParse:
    def test_apt_query_then_parse_returns_installed_set(self):
        argv = query_installed_argv("apt", ("curl", "wazuh-manager"))
        assert "dpkg-query" in argv
        stdout = "ii \tcurl\t1.0\tamd64\t\nii \twazuh-manager\t1.0\tamd64\t\n"
        assert parse_installed("apt", stdout) == frozenset({"curl", "wazuh-manager"})

    def test_apt_parse_ignores_not_installed_noise(self):
        # dpkg-query can print a known package with the `un` status while
        # returning nonzero. It is available to apt but not installed.
        stdout = "ii \tcurl\t1.0\tamd64\t\nun \topenssh-server\t1.0\tamd64\t\n"
        assert parse_installed("apt", stdout) == frozenset({"curl"})

    def test_pip_parse_reads_freeze_names(self):
        stdout = "requests==2.31.0\nurllib3==2.0.0\n"
        assert parse_installed("pip", stdout) == frozenset({"requests", "urllib3"})

    def test_unknown_manager_query_fails_closed(self):
        with pytest.raises(UnsupportedPackageManagerError):
            query_installed_argv("brew", ("wget",))
        with pytest.raises(UnsupportedPackageManagerError):
            parse_installed("brew", "")


class TestManifestInstall:
    def test_pip_manifest_install_targets_the_manifest_directory(self):
        argv = manifest_install_argv("pip", "/app")
        assert argv == ["pip", "install", "--break-system-packages", "/app"]

    def test_pip_manifest_query_checks_the_declared_name(self):
        argv = manifest_query_argv("pip", "aptl-labs")
        assert argv == ["pip", "show", "aptl-labs"]

    def test_unknown_ecosystem_fails_closed(self):
        with pytest.raises(UnsupportedDependencyEcosystemError):
            manifest_install_argv("npm", "/app")
        with pytest.raises(UnsupportedDependencyEcosystemError):
            manifest_query_argv("npm", "some-pkg")


@pytest.mark.parametrize("status", ["ii ", "hi "])
def test_apt_installed_provider_satisfies_virtual_package(status):
    output = f"{status}\tbind9-dnsutils\t9.20\tamd64\tdnsutils, dns-client (= 1.0)\n"
    assert {"bind9-dnsutils", "dnsutils", "dns-client"} <= parse_installed(
        "apt", output
    )


@pytest.mark.parametrize("status", ["rc ", "un ", "iU ", "iiR"])
def test_apt_unconfigured_provider_does_not_satisfy_package(status):
    output = f"{status}\tbind9-dnsutils\t9.20\tamd64\tdnsutils\n"
    assert not parse_installed("apt", output)


def test_virtual_version_comes_from_provides_not_provider_version():
    from aptl.backends.raes_package_managers import apt_package_rows

    rows = apt_package_rows("ii \tprovider\t9.20\tamd64\tvirtual, versioned (= 1.0)\n")
    assert rows["provider"] == ("9.20", "amd64")
    assert rows["virtual"] == ("", "amd64")
    assert rows["versioned"] == ("1.0", "amd64")


def test_virtual_package_query_includes_installed_providers():
    argv = query_installed_argv("apt", ("virtual-package",))
    assert "virtual-package" not in argv
    assert "${Provides}" in argv[-1]
