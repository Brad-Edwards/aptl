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

# Serialize a fixed curl invocation through stdin. Shell functions and printf
# are builtins: header, credential and body values never become process argv.
# Callers pipe this into host curl or `docker exec -i ... curl --config -`.
aptl_curl_config() {
    printf '%s\0' "$@" | python3 -c '
import json, sys
arguments = iter(sys.stdin.buffer.read().decode().rstrip("\0").split("\0"))
values = {"-H": "header", "-d": "data", "-u": "user", "-X": "request",
          "-b": "cookie", "-c": "cookie-jar", "--cacert": "cacert",
          "--max-time": "max-time"}
flags = {"s": "silent", "S": "show-error", "f": "fail", "k": "insecure"}
for argument in arguments:
    if argument in values:
        value = next(arguments)
        print(values[argument] + " = " + json.dumps(value))
    elif argument.startswith("-") and all(c in flags for c in argument[1:]):
        for flag in argument[1:]:
            print(flags[flag])
    elif argument.startswith("-"):
        raise SystemExit("unsupported curl option")
    else:
        print("url = " + json.dumps(argument))
'
}
