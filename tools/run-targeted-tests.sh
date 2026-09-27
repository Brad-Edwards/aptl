#!/usr/bin/env bash
# Run changed or explicitly named tests without falling back to a full suite.
set -euo pipefail

if (($#)); then
    exec uv run pytest "$@"
fi

declare -A seen=()
test_paths=()

add_path() {
    local path=$1
    [[ -n "$path" && -f "$path" ]] || return 0
    case "$path" in
        tests/test_*.py|tests/**/test_*.py|mcp/*/tests/*.test.ts|mcp/*/tests/**/*.test.ts|web/tests/*.test.ts|web/tests/**/*.test.ts)
            ;;
        *)
            return 0
            ;;
    esac
    if [[ -z "${seen[$path]:-}" ]]; then
        seen[$path]=1
        test_paths+=("$path")
    fi
}

while IFS= read -r path; do
    add_path "$path"
done < <(
    {
        git diff --name-only --diff-filter=ACMR origin/dev...HEAD 2>/dev/null || true
        git diff --cached --name-only --diff-filter=ACMR
        git diff --name-only --diff-filter=ACMR
        git ls-files --others --exclude-standard
    } | sort -u
)

if ((${#test_paths[@]} == 0)); then
    echo "No changed test files found." >&2
    echo "Pass explicit targeted Python tests, for example:" >&2
    echo "  bash tools/run-targeted-tests.sh tests/test_feature.py" >&2
    echo "For Vitest, run npx vitest with exact test paths in the package." >&2
    exit 2
fi

python_tests=()
declare -A vitest_packages=()
for path in "${test_paths[@]}"; do
    case "$path" in
        tests/*.py|tests/**/*.py)
            python_tests+=("$path")
            ;;
        mcp/*/tests/*)
            package=${path%%/tests/*}
            relative=${path#"$package/"}
            vitest_packages["$package"]+=" $relative"
            ;;
        web/tests/*)
            relative=${path#web/}
            vitest_packages[web]+=" $relative"
            ;;
    esac
done

if ((${#python_tests[@]})); then
    uv run pytest "${python_tests[@]}"
fi

for package in "${!vitest_packages[@]}"; do
    # The paths originate from git, where whitespace-bearing test paths are not
    # used. Keep package-local Vitest resolution and avoid a package-wide run.
    read -r -a package_tests <<<"${vitest_packages[$package]}"
    (
        cd "$package"
        npx vitest run "${package_tests[@]}"
    )
done
