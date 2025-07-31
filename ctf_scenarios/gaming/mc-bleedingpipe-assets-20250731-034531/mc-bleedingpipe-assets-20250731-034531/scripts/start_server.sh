#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../server"
if [ ! -f forge-1.7.10-10.13.4.1614-1.7.10-universal.jar ]; then
  echo "[!] Run the Forge installer to generate the universal JAR."
  exit 1
fi
exec screen -DmS mc java -Xms1G -Xmx2G -jar forge-1.7.10-10.13.4.1614-1.7.10-universal.jar nogui
