#!/bin/bash
# Per-boot CTF flag generator for the image-free generic nodes (#581 parity).
#
# The v5.0.0 base image generated CTF flags at container start (base entrypoint
# generate_flags), and the still-image AD node still does. The generic nodes
# (victim, workstation, webapp, fileshare) carry no baked entrypoint, so a
# oneshot systemd unit runs this at boot to reproduce it exactly: a fresh
# per-boot nonce and an md5-signed aptl:v1 token that src/aptl/core/flags.py
# (the scoring collector) verifies. One script serves every node; the per-node
# oneshot unit supplies the node name and user-flag placement via Environment=.
set -eu

KEY="${APTL_FLAG_KEY:-aptl-flag-key-2024}"
NODE="${APTL_FLAG_NODE:?APTL_FLAG_NODE required}"
USER_PATH="${APTL_FLAG_USER_PATH:?APTL_FLAG_USER_PATH required}"
USER_OWNER="${APTL_FLAG_USER_OWNER:?APTL_FLAG_USER_OWNER required}"

for level in user root; do
  nonce=$(od -A n -t x1 -N 16 /dev/urandom | tr -d ' \n')
  flag="APTL{${level}_${NODE}_${nonce}}"
  sig=$(printf '%s' "${KEY}:${NODE}:${level}:${nonce}" | md5sum | awk '{print $1}')
  token="aptl:v1:${NODE}:${level}:${nonce}:${sig}"

  if [ "$level" = user ]; then
    dest="$USER_PATH"
  else
    dest="/root/root.txt"
  fi

  mkdir -p "$(dirname "$dest")"
  cat > "$dest" <<EOF
===== APTL CTF Flag =====
Flag:  ${flag}
Token: ${token}
==========================
EOF

  if [ "$level" = user ]; then
    chown "$USER_OWNER" "$dest"
    chmod 644 "$dest"
  else
    chown root:root "$dest"
    chmod 600 "$dest"
  fi
done

echo "CTF flags generated for ${NODE}"
