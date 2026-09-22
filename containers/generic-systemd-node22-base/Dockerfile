# APTL backend substrate for nodes that require Node.js 22 and systemd-managed
# services.  The product/runtime state remains materialized from the admitted
# scenario; this image supplies only the selected language + init/SSH substrate.
FROM node:22-trixie@sha256:ae3b84a81a94a99f50110663c936ccda31a3bbf1e91bb6b23c638669f777a6f2
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus gnupg openssh-server \
        iputils-ping nmap python3 python3-pip curl wget dnsutils netcat-openbsd \
        smbclient ldap-utils sqlmap hydra python3-impacket \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete
# This image's offline cache is an APTL-owned build integration. Resolve the
# exact compatible pack through the normal acquisition/artifact validators;
# retain dependency cache + identity evidence, never a second runtime source.
COPY requirements/runtime.txt /opt/aptl/runtime-requirements.txt
COPY src/aptl /tmp/aptl-cache-src/aptl
COPY src/aptl_techvault /tmp/aptl-cache-src/aptl_techvault
ENV npm_config_cache=/opt/aptl/npm-cache
RUN set -eu; \
    python3 -m pip install --no-deps --require-hashes \
        --target /tmp/aptl-cache-deps -r /opt/aptl/runtime-requirements.txt; \
    PYTHONPATH=/tmp/aptl-cache-src:/tmp/aptl-cache-deps \
        python3 -m aptl_techvault.build_cache \
        > /opt/aptl/npm-cache-input-identity.json; \
    for project in aptl-mcp-common mcp-casemgmt mcp-indexer mcp-network \
        mcp-red mcp-reverse mcp-soar mcp-threatintel mcp-wazuh; do \
        npm --prefix "/opt/aptl/npm-source/$project" ci \
            --include=dev --ignore-scripts --no-audit --no-fund; \
    done; \
    rm -rf /opt/aptl/npm-source /tmp/aptl-cache-src /tmp/aptl-cache-deps /opt/aptl/npm-cache-pack
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
