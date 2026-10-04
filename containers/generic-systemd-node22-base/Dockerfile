# APTL backend substrate for nodes that require Node.js 22 and systemd-managed
# services.  The product/runtime state remains materialized from the admitted
# scenario; this image supplies only the selected language + init/SSH substrate.
# The backend selects it for a node declaring `nodejs` version 22, so the Node
# major is part of its contract: Dependabot refreshes the digest but never the
# major (issue #1193). The slim variant omits the full buildpack toolchain
# (desktop, media, and kernel-header packages) this substrate never uses.
FROM node:22-trixie-slim@sha256:b26b04c123d9ff8ab646ceb18b9d75a1173acf64b9a401094b906d27b29338d4
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus gnupg openssh-server ca-certificates \
        iputils-ping nmap python3 python3-pip curl wget dnsutils netcat-openbsd \
        smbclient ldap-utils sqlmap hydra python3-impacket \
    && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete
# Node 22 ships npm 10, whose bundled dependencies carry fixed advisories.
# Replace it with npm 11 (which supports Node >=22.9) from the registry
# tarball, verified against its published sha512 integrity (issue #1193).
ARG NPM_VERSION=11.21.0
ARG NPM_SHA512=668bfc2a16a63677a22dd10bb63e5800bb4d9895b82f87c22d3ce37e9cd71b6c3a3121dc7f453181d94ae6e9680ae92c593fbb986514ef08bbf5c3ba46a8af3e
RUN set -eu; \
    curl -fsSL "https://registry.npmjs.org/npm/-/npm-${NPM_VERSION}.tgz" -o /tmp/npm.tgz; \
    echo "${NPM_SHA512}  /tmp/npm.tgz" | sha512sum -c -; \
    rm -rf /usr/local/lib/node_modules/npm; \
    mkdir /usr/local/lib/node_modules/npm; \
    tar -xzf /tmp/npm.tgz -C /usr/local/lib/node_modules/npm --strip-components=1; \
    rm /tmp/npm.tgz; \
    test "$(npm --version)" = "${NPM_VERSION}"
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
# Ship no private keys; each container generates its own at boot (issue #1193).
COPY containers/_host-identity /tmp/aptl-host-identity
RUN sh /tmp/aptl-host-identity/install.sh && rm -rf /tmp/aptl-host-identity

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
