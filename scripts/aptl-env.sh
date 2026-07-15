#!/bin/bash

# Load one literal value from an APTL-generated .env file without sourcing or
# evaluating the file. An explicit process environment value always wins.
aptl_load_env_key() {
    local env_file="$1"
    local key="$2"
    local value=""

    if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        return 2
    fi
    if [ -n "${!key:-}" ] || [ ! -f "$env_file" ]; then
        return 0
    fi

    value=$(awk -v key="$key" '
        index($0, key "=") == 1 {
            sub(/^[^=]*=/, "")
            print
            exit
        }
    ' "$env_file")
    if [ -z "$value" ]; then
        return 0
    fi

    # hydrate_dotenv writes unquoted values, but accept a matching quote pair
    # for participant-maintained files without evaluating shell syntax.
    if [ "${#value}" -ge 2 ]; then
        if [[ "$value" == \"*\" ]] || [[ "$value" == \'*\' ]]; then
            value="${value:1:${#value}-2}"
        fi
    fi
    printf -v "$key" '%s' "$value"
    export "$key"
}
