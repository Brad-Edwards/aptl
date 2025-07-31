#!/usr/bin/env bash
set -euo pipefail
date > "$(dirname "$0")/../server/pwned.txt"
