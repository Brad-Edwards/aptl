#!/bin/sh
set -eu

# Cortex 3.1.8 performs exact Elasticsearch queries against key/status and uses
# a join field for every root and parent/child entity relation. Pre-create the
# complete product-native shape so key auth and child entities both work.
ES_URL="${CORTEX_ES_URL:-http://thehive-es:9200}"
INDEX="${CORTEX_INDEX:-cortex_6}"
MAPPING_FILE="${CORTEX_MAPPING_FILE:-/usr/local/share/aptl/cortex-index-mapping.json}"

if [ ! -r "$MAPPING_FILE" ]; then
    echo "ERROR: Cortex native mapping not readable at ${MAPPING_FILE}" >&2
    exit 1
fi
MAPPING="$(tr -d '\n' < "$MAPPING_FILE")"

if curl -sf "${ES_URL}/${INDEX}" >/dev/null; then
    mapping="$(curl -sf "${ES_URL}/${INDEX}/_mapping")"
    if printf '%s' "$mapping" | grep -q '"relations":{"type":"join"' \
        && printf '%s' "$mapping" | grep -q '"status":{"type":"keyword"}' \
        && printf '%s' "$mapping" | grep -q '"key":{"type":"keyword"}'; then
        exit 0
    fi

    count="$(curl -sf "${ES_URL}/${INDEX}/_count" \
        | sed -n 's/.*"count":\([0-9][0-9]*\).*/\1/p')"
    if [ "${count:-0}" != "0" ]; then
        echo "ERROR: ${INDEX} already has documents but lacks the required Cortex mapping" >&2
        exit 1
    fi

    curl -sf -X DELETE "${ES_URL}/${INDEX}" >/dev/null
fi

curl -sf -H "Content-Type: application/json" -X PUT "${ES_URL}/${INDEX}" -d "$MAPPING" >/dev/null
