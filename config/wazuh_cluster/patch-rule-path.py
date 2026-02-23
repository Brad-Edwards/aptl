#!/usr/bin/env python3
"""Patch Wazuh framework rule.py to fix relative path resolution.

The Wazuh API's _create_dict function uses os.path.relpath with relative paths,
which produces incorrect paths when the API CWD != WAZUH_PATH. This patch makes
relative paths absolute before computing relpath.

Run at container start before wazuh-control starts the API.
"""
import re
import os

RULE_PY = "/var/ossec/framework/python/lib/python3.10/site-packages/wazuh/core/rule.py"
CACHE = RULE_PY + "c"
PYCACHE = os.path.join(os.path.dirname(RULE_PY), "__pycache__")

ORIGINAL = "        full_dir = os.path.dirname(item)\n        item_dir = os.path.relpath"
PATCHED = (
    "        full_dir = os.path.dirname(item)\n"
    "        if full_dir and not os.path.isabs(full_dir):\n"
    "            full_dir = os.path.join(common.WAZUH_PATH, full_dir)\n"
    "        item_dir = os.path.relpath"
)

with open(RULE_PY) as f:
    content = f.read()

if "os.path.isabs(full_dir)" in content:
    print("patch-rule-path: already patched, skipping")
else:
    content = content.replace(ORIGINAL, PATCHED, 1)
    with open(RULE_PY, "w") as f:
        f.write(content)
    # Remove bytecode caches
    if os.path.exists(CACHE):
        os.remove(CACHE)
    for f in os.listdir(PYCACHE):
        if "rule" in f and f.endswith(".pyc"):
            os.remove(os.path.join(PYCACHE, f))
    print("patch-rule-path: patched successfully")
