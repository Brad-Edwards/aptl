# APTL backend substrate for nodes that require Node.js 22 and systemd-managed
# services.  The product/runtime state remains materialized from the admitted
# scenario; this image supplies only the selected language + init/SSH substrate.
FROM node:25-trixie@sha256:b6cf8d20ee78aa10f0a6b98242e26d547869801abd6bc3f7094b0a54301dee02
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus gnupg openssh-server \
        iputils-ping nmap python3 python3-pip curl wget dnsutils netcat-openbsd \
        smbclient ldap-utils sqlmap hydra python3-impacket \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete
# First boot is sealed from the network. The admitted TechVault MCP sources are
# artifacts in the hash-pinned RAES pack, not the repository's mcp/ tree. Prime
# npm from those exact pack lockfiles so offline materialization uses the same
# dependency closure that the guest receives.
COPY requirements/runtime.txt /opt/aptl/runtime-requirements.txt
ENV npm_config_cache=/opt/aptl/npm-cache
RUN set -eu; \
    sed -n '/^raes-env-packs==/,/^[[:space:]]*# via /p' \
        /opt/aptl/runtime-requirements.txt > /tmp/raes-pack-requirement.txt; \
    python3 -m pip download --no-deps --require-hashes \
        --dest /tmp/raes-wheel -r /tmp/raes-pack-requirement.txt; \
    mkdir -p /tmp/raes-wheel/unpacked /opt/aptl/npm-source; \
    python3 -m zipfile -e /tmp/raes-wheel/raes_env_packs-*.whl \
        /tmp/raes-wheel/unpacked; \
    pack_content=/tmp/raes-wheel/unpacked/raes_env_packs/resources/packs/techvault/assets/content; \
    tar -xf "$pack_content/mcp-red-sources.tar" -C /opt/aptl/npm-source; \
    tar -xf "$pack_content/mcp-blue-sources.tar" -C /opt/aptl/npm-source; \
    for project in aptl-mcp-common mcp-casemgmt mcp-indexer mcp-network \
        mcp-red mcp-reverse mcp-soar mcp-threatintel mcp-wazuh; do \
        npm --prefix "/opt/aptl/npm-source/$project" ci \
            --include=dev --ignore-scripts --no-audit --no-fund; \
    done; \
    find /opt/aptl/npm-source -type d -name node_modules -prune -exec rm -rf {} +; \
    rm -rf /tmp/raes-wheel /tmp/raes-pack-requirement.txt
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
