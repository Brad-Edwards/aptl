"""Local substrate image identities used by semantic backend selection."""

NODE22_SYSTEMD_BASE_IMAGE = "aptl/generic-systemd-node22-base:latest"
SAMBA_AD_BASE_IMAGE = "aptl/generic-samba-ad-base:latest"
WAZUH_DEBIAN_BASE_IMAGE = "aptl/generic-wazuh-agent-base-debian:latest"
WAZUH_DEBIAN_SYSTEMD_BASE_IMAGE = "aptl/generic-systemd-wazuh-agent-base-debian:latest"
WAZUH_RHEL_SYSTEMD_BASE_IMAGE = "aptl/generic-systemd-wazuh-agent-base:latest"
WAZUH_SAMBA_AD_BASE_IMAGE = "aptl/generic-samba-ad-wazuh-agent-base:latest"

__all__ = (
    "NODE22_SYSTEMD_BASE_IMAGE",
    "SAMBA_AD_BASE_IMAGE",
    "WAZUH_DEBIAN_BASE_IMAGE",
    "WAZUH_DEBIAN_SYSTEMD_BASE_IMAGE",
    "WAZUH_RHEL_SYSTEMD_BASE_IMAGE",
    "WAZUH_SAMBA_AD_BASE_IMAGE",
)
