#!/usr/bin/env bash
# Fetches rustpush (a git submodule) and applies our patches to it. Run once after cloning.
# FairPlay certs are not part of the build; imsg-server loads them at runtime (see README).
set -euo pipefail
cd "$(dirname "$0")/.."

# rustpush's own submodules use SSH URLs; fetch them over HTTPS instead.
git -c url."https://github.com/".insteadOf="git@github.com:" submodule update --init --recursive

rp=third_party/rustpush
for patch in "$PWD"/patches/rustpush-*.patch; do
    if git -C "$rp" apply --reverse --check "$patch" 2>/dev/null; then
        echo "already applied: $(basename "$patch")"
    else
        git -C "$rp" apply "$patch"
        echo "applied: $(basename "$patch")"
    fi
done
echo "Ready: cargo build --release"
