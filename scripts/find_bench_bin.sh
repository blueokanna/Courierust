#!/usr/bin/env bash
# Source this file to get `find_bench_bin` — the single, verified
# locator for `cargo bench --no-run` artifacts.
#
# `cargo bench` names its outputs `deps/<name>-<hash>` (no stable path),
# so any caller that must exec a bench binary cannot assume
# `target/release/<name>` exists. The cross-machine and TLS-interop
# workflows hit exactly this; both `source` this file.
#
#   source "$PWD/scripts/find_bench_bin.sh"
#   BIN="$(find_bench_bin "$DIR" network)" || exit 1
#
# Strategy: prefer `$dir/<name>` (cargo's non-bench layout), else the
# newest *executable* `$dir/deps/<name>-*`. Build-metadata that `cargo`
# drops next to the binary (dep-info, PDB, rlib/rmeta/so/o) is skipped —
# Windows reports those as executable, so `-x` alone is not enough.
find_bench_bin() {
    local dir="$1" name="$2" f
    if [[ -x "$dir/$name" ]]; then
        printf '%s\n' "$dir/$name"
        return 0
    fi
    while IFS= read -r f; do
        case "$f" in
            *.d|*.pdb|*.rlib|*.rmeta|*.so|*.dll|*.dylib|*.o) continue ;;
        esac
        if [[ -f "$f" && -x "$f" ]]; then
            printf '%s\n' "$f"
            return 0
        fi
    done < <(ls -t "$dir"/deps/${name}-* 2>/dev/null)
    return 1
}
