#!/bin/bash
set -e

echo "=== Reverse Engineering Tools Setup Starting ==="

# Check if already installed
if [ -f /opt/lab/.reverse_tools_installed ]; then
    echo "Reverse engineering tools already installed, exiting..."
    exit 0
fi

export DEBIAN_FRONTEND=noninteractive

echo "Step 1: Updating package lists..."
apt-get update

echo "Step 2: Installing core reverse engineering tools..."
apt-get install -y \
    binutils \
    llvm \
    yara \
    upx-ucl \
    osslsigncode \
    gdb \
    openjdk-17-jre \
    python3-pip \
    pipx \
    git \
    vim \
    nano \
    unzip \
    p7zip-full \
    bsdmainutils \
    file \
    build-essential \
    pkg-config

echo "Step 3: Installing radare2 from source..."
# Install radare2 from git repository (recommended method)
# Use /opt to avoid /tmp noexec issues
# Keep the directory since install creates symlinks back to it
cd /opt
git clone https://github.com/radareorg/radare2
cd radare2
bash sys/install.sh
cd /

echo "Step 4: Setting up pipx environment for labadmin..."
# Ensure pipx path is available
su - labadmin -c "pipx ensurepath" || true

echo "Step 5: Installing Python reverse engineering tools via pipx..."
# IMPORTANT: install the Mandiant/FLARE distributions by their real PyPI names,
# PINNED to known-good versions. The bare names `floss` and `capa` are
# DIFFERENT, unrelated PyPI projects (e.g. `floss` is an academic
# spectrum-based fault-localization framework, NOT the FLARE Obfuscated String
# Solver) — installing them silently puts the wrong software on a
# malware-analysis box and is a supply-chain hazard. The FLARE tools are
# published as `flare-floss` and `flare-capa`.
tool_failures=0

# FLOSS — FLARE Obfuscated String Solver (https://github.com/mandiant/flare-floss)
if ! su - labadmin -c "pipx install flare-floss==3.1.1"; then
    echo "ERROR: flare-floss did not install — FLOSS will be ABSENT from this box." >&2
    tool_failures=$((tool_failures + 1))
fi

# capa — FLARE capability identification tool (https://github.com/mandiant/capa)
if ! su - labadmin -c "pipx install flare-capa==9.4.0"; then
    echo "ERROR: flare-capa did not install — capa will be ABSENT from this box." >&2
    tool_failures=$((tool_failures + 1))
fi

if [ "$tool_failures" -ne 0 ]; then
    echo "WARNING: $tool_failures FLARE tool(s) failed to install; see errors above." >&2
fi


echo "=== Reverse Engineering Tools Setup Complete ==="
echo "Available tools:"
echo "  - radare2 (r2) - Binary analysis framework"
echo "  - strings - Extract strings from binaries"
echo "  - yara - Pattern matching engine"
echo "  - FLOSS - Advanced string analysis"
echo "  - CAPA - Capability analysis"
echo "  - hexdump - Hex viewer"
echo "  - upx - Packer/unpacker"
echo "  - osslsigncode - Code signing verification"
echo ""
echo "Workspace: /home/labadmin/reverse-workspace"
echo "Quick start: 'analyze <binary_file>'"

# Create flag to prevent re-running
mkdir -p /opt/lab
touch /opt/lab/.reverse_tools_installed
