#!/bin/bash
# =============================================================================
# launch-ranges.sh -- spin up N Arsenal ranges from the baked AMI and write a
# per-range .rdp file (gitignored) under ranges/.
# =============================================================================
# Usage:
#   scripts/launch-ranges.sh <AMI_ID> <COUNT> [RDP_CIDR]
#
#   AMI_ID    the baked Arsenal AMI (has all fixes + RDP + aptl-range.service).
#   COUNT     how many ranges to launch (e.g. 12 per wave, or 36).
#   RDP_CIDR  optional; if given, opens tcp/3389 to that CIDR on the SG so
#             participants can RDP in. Use the venue/office CIDR, or 0.0.0.0/0
#             for open access (internet-exposed RDP -- password is the only
#             gate; acceptable only for a short, disposable workshop).
#
# Each range auto-provisions on boot via aptl-range.service (aptl lab start +
# env-pack fixups). Ranges take ~8-12 min after launch to be fully ready; the
# .rdp files are written as soon as the instances have public IPs.
#
# Output (gitignored): ranges/seat-NN.rdp, ranges/INDEX.txt, ranges/README.txt
# =============================================================================
set -euo pipefail

AMI="${1:?usage: launch-ranges.sh <AMI_ID> <COUNT> [RDP_CIDR]}"
COUNT="${2:?usage: launch-ranges.sh <AMI_ID> <COUNT> [RDP_CIDR]}"
RDP_CIDR="${3:-}"

PROFILE="${AWS_PROFILE:-aws-dev}"
REGION="${AWS_REGION:-us-east-2}"
KEY="${APTL_KEY:-aptl3-889}"
SG="${APTL_SG:-sg-084f884447d4e4888}"
SUBNET="${APTL_SUBNET:-subnet-005fbc9f68acb0fe3}"
TYPE="${APTL_TYPE:-m6a.4xlarge}"
IAM="${APTL_IAM:-aptl-arsenal-bedrock}"
RDP_USER="${APTL_RDP_USER:-ubuntu}"
RDP_PASS="${APTL_RDP_PASS:-AptlArsenal!2026}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO_ROOT/ranges"
mkdir -p "$OUT"

aws() { command aws --profile "$PROFILE" --region "$REGION" "$@"; }

if [ -n "$RDP_CIDR" ]; then
    echo "Opening tcp/3389 to $RDP_CIDR on $SG ..."
    aws ec2 authorize-security-group-ingress --group-id "$SG" \
        --protocol tcp --port 3389 --cidr "$RDP_CIDR" >/dev/null 2>&1 \
        && echo "  added." || echo "  (rule already present or failed; check manually)"
fi

echo "Launching $COUNT range(s) from $AMI ..."
IDS=$(aws ec2 run-instances \
    --image-id "$AMI" --count "$COUNT" --instance-type "$TYPE" \
    --key-name "$KEY" --security-group-ids "$SG" --subnet-id "$SUBNET" \
    --iam-instance-profile "Name=$IAM" \
    --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=${APTL_ROOT_GB:-150},VolumeType=gp3}" \
    --tag-specifications \
      'ResourceType=instance,Tags=[{Key=Name,Value=aptl-arsenal-seat},{Key=aptl-workshop,Value=arsenal-2026}]' \
    --query 'Instances[].InstanceId' --output text)

echo "Launched: $IDS"
: > "$OUT/INDEX.txt"

i=1
for id in $IDS; do
    seat=$(printf "seat-%02d" "$i")
    echo "[$seat] $id waiting for public IP ..."
    aws ec2 wait instance-running --instance-ids "$id"
    ip=$(aws ec2 describe-instances --instance-ids "$id" \
        --query 'Reservations[].Instances[].PublicIpAddress' --output text)
    aws ec2 create-tags --resources "$id" --tags "Key=Name,Value=aptl-arsenal-$seat" >/dev/null 2>&1 || true

    cat > "$OUT/$seat.rdp" <<RDP
full address:s:$ip:3389
username:s:$RDP_USER
screen mode id:i:2
use multimon:i:0
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
redirectclipboard:i:1
prompt for credentials:i:1
authentication level:i:0
negotiate security layer:i:1
RDP
    echo "$seat  $id  $ip" | tee -a "$OUT/INDEX.txt"
    i=$((i + 1))
done

cat > "$OUT/README.txt" <<TXT
APTL Arsenal ranges -- $(date -u)
AMI: $AMI

Connect: open the matching seat-NN.rdp in an RDP client.
  RDP user:     $RDP_USER
  RDP password: $RDP_PASS

Each range auto-provisions on boot (aptl lab start + env-pack fixups); allow
~8-12 min after launch before the SOC stack + kali are fully ready. Progress on
the box: /tmp/provision-range.log (look for RANGE_PROVISION_OK).

Inside the desktop: open a terminal in ~/aptl3 and run 'claude' to drive the
MCP agent; open the browser to the Wazuh dashboard for the SOC UI.

Instances: see INDEX.txt. Terminate with:
  aws --profile $PROFILE --region $REGION ec2 terminate-instances --instance-ids <ids>
TXT

echo
echo "Wrote $((i - 1)) .rdp file(s) to $OUT/ (gitignored). RDP password: $RDP_PASS"
echo "Ranges are still provisioning; give them ~8-12 min before connecting."
