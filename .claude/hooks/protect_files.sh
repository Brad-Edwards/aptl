#!/bin/bash
# Block edits to sensitive files (.env, credentials, keys)
FILE_PATH=$(jq -r '.tool_input.file_path // empty')

if [[ -z "$FILE_PATH" ]]; then
    exit 0
fi

BASENAME=$(basename "$FILE_PATH")

# Block .env files, but allow committed templates (`.env.example`,
# `.env.*.example`) since those carry placeholders, not secrets.
if [[ "$BASENAME" == .env* ]] && [[ "$BASENAME" != *.example ]]; then
    echo "BLOCKED: Editing $BASENAME is not allowed. These files contain secrets." >&2
    exit 2
fi

if [[ "$BASENAME" == "local_settings.py" ]]; then
    echo "BLOCKED: Editing $BASENAME is not allowed. These files contain secrets." >&2
    exit 2
fi

# The config-rendering source module src/aptl/core/credentials.py is NOT a
# secret store — it renders credentialized service config from checked-in
# templates (ADR-028) and holds no secrets. The credential-store glob below
# (`credentials*`) otherwise catches it; exempt this one source path so the
# module stays editable while every real secret file (.env*, *.key, *.pem,
# credential data files) remains protected.
if [[ "$FILE_PATH" == */src/aptl/core/credentials.py || "$FILE_PATH" == "src/aptl/core/credentials.py" ]]; then
    exit 0
fi

# Block key/credential files
if [[ "$BASENAME" == *.key ]] || [[ "$BASENAME" == *.pem ]] || [[ "$BASENAME" == "credentials"* ]]; then
    echo "BLOCKED: Editing $BASENAME is not allowed. These files contain secrets." >&2
    exit 2
fi

exit 0
