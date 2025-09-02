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
    radare2 \
    binutils \
    llvm \
    yara \
    upx-ucl \
    osslsigncode \
    openjdk-17-jre \
    python3-pip \
    pipx \
    git \
    vim \
    nano \
    unzip \
    p7zip-full \
    hexdump \
    file

echo "Step 3: Setting up pipx environment for labadmin..."
# Ensure pipx path is available
su - labadmin -c "pipx ensurepath" || true

echo "Step 4: Installing Python reverse engineering tools via pipx..."
# Install FLOSS (FireEye Labs Obfuscated String Solver)
su - labadmin -c "pipx install floss" || echo "FLOSS installation failed, continuing..."

# Install CAPA (malware capability analysis tool)
su - labadmin -c "pipx install capa" || echo "CAPA installation failed, continuing..."

echo "Step 5: Creating reverse engineering workspace..."
mkdir -p /home/labadmin/reverse-workspace/{samples,analysis,output,scripts}
chown -R labadmin:labadmin /home/labadmin/reverse-workspace

echo "Step 6: Creating basic analysis scripts..."
cat > /home/labadmin/reverse-workspace/scripts/basic_analysis.sh << 'EOF'
#!/bin/bash
# Basic reverse engineering analysis script
if [ $# -eq 0 ]; then
    echo "Usage: $0 <binary_file>"
    exit 1
fi

BINARY="$1"
BASENAME=$(basename "$BINARY")
OUTPUT_DIR="$HOME/reverse-workspace/analysis/$BASENAME-$(date +%Y%m%d_%H%M%S)"

echo "Creating analysis directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

echo "=== Basic Analysis for $BINARY ==="

echo "1. File information:"
file "$BINARY" | tee "$OUTPUT_DIR/file_info.txt"

echo "2. Basic strings:"
strings "$BINARY" | head -50 | tee "$OUTPUT_DIR/strings_basic.txt"

echo "3. Binary information (rabin2):"
rabin2 -I "$BINARY" | tee "$OUTPUT_DIR/rabin2_info.txt"

echo "4. Imports/Exports:"
rabin2 -i "$BINARY" | tee "$OUTPUT_DIR/imports.txt"
rabin2 -E "$BINARY" | tee "$OUTPUT_DIR/exports.txt"

echo "5. Checksums:"
sha256sum "$BINARY" | tee "$OUTPUT_DIR/checksums.txt"
md5sum "$BINARY" | tee -a "$OUTPUT_DIR/checksums.txt"

echo "Analysis complete. Results saved in: $OUTPUT_DIR"
EOF

chmod +x /home/labadmin/reverse-workspace/scripts/basic_analysis.sh

echo "Step 7: Setting up analysis environment configuration..."
cat > /home/labadmin/.bashrc_re_tools << 'EOF'
# Reverse Engineering Tools Environment
export PATH="$HOME/.local/bin:$PATH"
export RE_WORKSPACE="$HOME/reverse-workspace"

# Aliases for common tools
alias r2='radare2'
alias strings-all='strings -a'
alias hexdump-c='hexdump -C'
alias analyze='$RE_WORKSPACE/scripts/basic_analysis.sh'

# Quick functions
yara_scan() {
    if [ $# -eq 2 ]; then
        yara "$1" "$2"
    else
        echo "Usage: yara_scan <rule_file> <target_file>"
    fi
}

re_workspace() {
    cd $RE_WORKSPACE
    echo "Current reverse engineering workspace:"
    ls -la
}

EOF

# Add to .bashrc if not already there
if ! grep -q "source.*bashrc_re_tools" /home/labadmin/.bashrc 2>/dev/null; then
    echo "source ~/.bashrc_re_tools" >> /home/labadmin/.bashrc
fi

echo "Step 8: Creating sample YARA rules..."
mkdir -p /home/labadmin/reverse-workspace/rules
cat > /home/labadmin/reverse-workspace/rules/basic_indicators.yar << 'EOF'
rule Suspicious_Strings
{
    meta:
        description = "Detects suspicious strings in binaries"
        author = "APTL Lab"
    
    strings:
        $debug1 = "CreateRemoteThread" ascii
        $debug2 = "VirtualAllocEx" ascii
        $debug3 = "WriteProcessMemory" ascii
        $debug4 = "ReadProcessMemory" ascii
        $network1 = "WinExec" ascii
        $network2 = "ShellExecute" ascii
        
    condition:
        any of them
}
EOF

chown -R labadmin:labadmin /home/labadmin/reverse-workspace
chown labadmin:labadmin /home/labadmin/.bashrc_re_tools

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