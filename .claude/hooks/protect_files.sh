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

# Block key/credential files
if [[ "$BASENAME" == *.key ]] || [[ "$BASENAME" == *.pem ]] || [[ "$BASENAME" == "credentials"* ]]; then
    echo "BLOCKED: Editing $BASENAME is not allowed. These files contain secrets." >&2
    exit 2
fi

exit 0
