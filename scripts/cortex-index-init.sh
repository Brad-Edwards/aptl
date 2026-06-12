#!/bin/sh
set -eu

# Cortex 3.1.8 key auth performs exact Elasticsearch term queries against
# these fields. Pre-create the index so dynamic mappings do not make them text.
ES_URL="${CORTEX_ES_URL:-http://thehive-es:9200}"
INDEX="${CORTEX_INDEX:-cortex_6}"
MAPPING='{"mappings":{"properties":{"relations":{"type":"keyword"},"status":{"type":"keyword"},"key":{"type":"keyword"}}}}'

if curl -sf "${ES_URL}/${INDEX}" >/dev/null; then
    mapping="$(curl -sf "${ES_URL}/${INDEX}/_mapping")"
    if printf '%s' "$mapping" | grep -q '"relations":{"type":"keyword"}' \
        && printf '%s' "$mapping" | grep -q '"status":{"type":"keyword"}' \
        && printf '%s' "$mapping" | grep -q '"key":{"type":"keyword"}'; then
        exit 0
    fi

    count="$(curl -sf "${ES_URL}/${INDEX}/_count" \
        | sed -n 's/.*"count":\([0-9][0-9]*\).*/\1/p')"
    if [ "${count:-0}" != "0" ]; then
        echo "ERROR: ${INDEX} already has documents but lacks keyword key-auth mappings" >&2
        exit 1
    fi

    curl -sf -X DELETE "${ES_URL}/${INDEX}" >/dev/null
fi

curl -sf -H "Content-Type: application/json" -X PUT "${ES_URL}/${INDEX}" -d "$MAPPING" >/dev/null
