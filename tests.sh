#!/usr/bin/env bash

set -u

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export TCLLIBPATH="$repo_root${TCLLIBPATH:+ $TCLLIBPATH}"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 [jtcl|tclsh]" >&2
    exit 2
fi

case "$1" in
    jtcl|tclsh) ;;
    *)
        echo "Usage: $0 [jtcl|tclsh]" >&2
        exit 2
        ;;
esac

if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required interpreter not found: $1" >&2
    exit 127
fi

# Set to false in order to provoke warning during package loading
export DISABLE_TESTCL_INTERPRETER_WARNING=true;

function run_test() {
    if [ 'tclsh' == "$1" ] ; then tclsh "$2";
    elif [ 'jtcl' == "$1" ] ; then jtcl "$2";
    else echo "Usage: ./tests.sh [jtcl|tclsh]"; exit 1;
    fi
}

failures=()
output_dir=$(mktemp -d "${TMPDIR:-/tmp}/testcl.XXXXXX")
trap 'rm -rf "$output_dir"' EXIT

for file in "$repo_root"/test/test_*.tcl
do
    output_file="$output_dir/$(basename "$file").out"
    if ! (cd "$repo_root" && run_test "$1" "$file") >"$output_file" 2>&1; then
        failures+=("${file#"$repo_root"/}")
    fi
    cat "$output_file"
done

echo "Test Summary"
echo "============"
if [ ${#failures[@]} -gt 0 ] ; then
    echo "${#failures[@]} tests failed:"
    for failure in "${failures[@]}" ; do
        echo "    ${failure}"
    done
    exit ${#failures[@]}
else
    echo "All tests successful"
    exit 0
fi
