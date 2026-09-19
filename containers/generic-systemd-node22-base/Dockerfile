# APTL backend substrate for nodes that require Node.js 22 and systemd-managed
# services.  The product/runtime state remains materialized from the admitted
# scenario; this image supplies only the selected language + init/SSH substrate.
FROM node:22-trixie@sha256:2082d2bf902c8835655c6bcfee3594c00ea900498a9f6e2b96d3352536f9e8d8
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus gnupg openssh-server \
        iputils-ping nmap python3 curl wget dnsutils netcat-openbsd \
        smbclient ldap-utils sqlmap hydra python3-impacket \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete
# First boot is sealed from the network. Prime npm's content-addressed cache
# from every exact MCP lockfile while the image is built, so materialization can
# still run npm ci against the scenario's own copied manifests and sources.
COPY mcp /opt/aptl/npm-source
ENV npm_config_cache=/opt/aptl/npm-cache
RUN set -eu; \
    for project in aptl-mcp-common mcp-casemgmt mcp-indexer mcp-network \
        mcp-red mcp-reverse mcp-soar mcp-threatintel mcp-wazuh; do \
        npm --prefix "/opt/aptl/npm-source/$project" ci \
            --include=dev --ignore-scripts --no-audit --no-fund; \
    done; \
    find /opt/aptl/npm-source -type d -name node_modules -prune -exec rm -rf {} +
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
