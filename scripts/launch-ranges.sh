#!/bin/bash
# =============================================================================
# launch-ranges.sh -- spin up N Arsenal ranges from the baked v3 AMI, each with
# a unique human-typable passphrase, and write a plain-text credentials sheet.
# =============================================================================
# Usage:
#   scripts/launch-ranges.sh <AMI_ID> <COUNT>
#
# Each range auto-provisions on boot (aptl-range.service): rebuilds the lab,
# brings up Guacamole, applies the per-range passphrase (injected via EC2
# user-data), and starts the red/blue Claude agents. Only Guacamole (TLS, 9443)
# is internet-facing; RDP/SSH are not public.
#
# Participants connect in a browser to  https://<ip>:9443/guacamole  and log in
# as  guacadmin / <that range's passphrase>, then open "Kali Range Desktop".
#
# Output (gitignored): ranges/CREDENTIALS.txt (plain text, no markdown).
# =============================================================================
set -euo pipefail

AMI="${1:?usage: launch-ranges.sh <AMI_ID> <COUNT>}"
COUNT="${2:?usage: launch-ranges.sh <AMI_ID> <COUNT>}"

PROFILE="${AWS_PROFILE:-aws-dev}"
REGION="${AWS_REGION:-us-east-2}"
KEY="${APTL_KEY:-aptl3-889}"
SG="${APTL_SG:-sg-084f884447d4e4888}"
SUBNET="${APTL_SUBNET:-subnet-005fbc9f68acb0fe3}"
TYPE="${APTL_TYPE:-m6a.4xlarge}"
IAM="${APTL_IAM:-aptl-arsenal-bedrock}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO_ROOT/ranges"
mkdir -p "$OUT"
CREDS="$OUT/CREDENTIALS.txt"

aws() { command aws --profile "$PROFILE" --region "$REGION" "$@"; }

# Human-typable but secure passphrase: 4 short words + 2 digits, e.g.
# harbor-quartz-meadow-cobalt-58. ~150-word list; the words avoid ambiguity.
gen_pass() {
    python3 - <<'PY'
import secrets
W=("amber anchor apple arbor arrow autumn badge basil beacon birch bison bloom "
   "bracket branch brave breeze bridge bright bronze brook cactus canyon carbon "
   "cedar chalk cherry cinder clover cobalt comet copper coral cotton crane crater "
   "crest cyan dawn delta denim desert diamond dune ember falcon fern fjord flint "
   "forest fox garnet ginger glacier granite grove harbor hazel heron hickory "
   "hollow indigo iris ivory jade jasmine juniper kelp lagoon lantern larch laurel "
   "lemon lilac linen lotus lunar lynx maple marble meadow mesa mineral mint misty "
   "moss nectar nimbus north oak ocean olive onyx opal orbit otter pebble pewter "
   "pine plum polar poppy prairie quartz quill raven reef ridge river robin rowan "
   "ruby rustic saffron sage sapphire scarlet shale silver slate sparrow spruce "
   "storm summit sunset tamarind teal thistle thunder timber topaz tundra umber "
   "valley velvet violet walnut willow winter wren zephyr zinc").split()
print("-".join(secrets.choice(W) for _ in range(4)) + "-%02d" % secrets.randbelow(100))
PY
}

echo "Launching $COUNT range(s) from $AMI ..."
: > "$OUT/INDEX.txt"
{
  echo "APTL Arsenal - Range Credentials"
  echo "AMI: $AMI"
  echo "Generated (UTC stamp applied by launcher)"
  echo
  echo "HOW TO CONNECT (each participant):"
  echo "  1. Open the Guacamole URL for your seat in a browser."
  echo "  2. Log in with username guacadmin and your seat passphrase below."
  echo "  3. Open the connection named: Kali Range Desktop"
  echo "  Accept the browser certificate warning (self-signed lab TLS)."
  echo "  Allow ~8-12 minutes after launch before a seat is fully ready."
  echo
  echo "SOC tool logins (same on every seat, also on each desktop as SOC_ACCESS.md):"
  echo "  Wazuh    https://localhost/         admin / SecretPassword"
  echo "  TheHive  https://localhost:9000/    aptl-svc@thehive.local / AptlService2024!"
  echo "  MISP     https://localhost:8443/    admin@admin.test / admin"
  echo "  Shuffle  https://localhost:3443/    admin / ShuffleAdmin2024!"
  echo
  echo "SEATS:"
} > "$CREDS"

i=1
while [ "$i" -le "$COUNT" ]; do
    seat=$(printf "seat-%02d" "$i")
    pass="$(gen_pass)"
    ud="APTL_RANGE_PASS=$pass"
    id=$(aws ec2 run-instances \
        --image-id "$AMI" --count 1 --instance-type "$TYPE" \
        --key-name "$KEY" --security-group-ids "$SG" --subnet-id "$SUBNET" \
        --iam-instance-profile "Name=$IAM" \
        --user-data "$ud" \
        --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=${APTL_ROOT_GB:-150},VolumeType=gp3}" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=aptl-arsenal-$seat},{Key=aptl-workshop,Value=arsenal-2026}]" \
        --query 'Instances[0].InstanceId' --output text)
    echo "[$seat] $id launching ..."
    aws ec2 wait instance-running --instance-ids "$id"
    ip=$(aws ec2 describe-instances --instance-ids "$id" \
        --query 'Reservations[].Instances[].PublicIpAddress' --output text)
    echo "$seat  $id  $ip  $pass" | tee -a "$OUT/INDEX.txt"
    printf "  %s\n    URL:        https://%s:9443/guacamole\n    Login:      guacadmin / %s\n    Instance:   %s\n\n" \
        "$seat" "$ip" "$pass" "$id" >> "$CREDS"
    i=$((i + 1))
done

echo
echo "Wrote $((i - 1)) seat(s) to $CREDS (gitignored)."
echo "Ranges are provisioning; give them ~8-12 min before connecting."
