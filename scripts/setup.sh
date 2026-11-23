#!/usr/bin/env bash
# Fetches rustpush (a git submodule) and installs the FairPlay cert chains + keys it embeds at
# compile time (third_party/rustpush/certs/fairplay). Run once after cloning, and again after
# changing certs.
#
# FairPlay source, first match wins:
#   1. $FAIRPLAY_CERTS_DIR         a directory in the layout scripts/fairplay_certs.py describes
#   2. $FAIRPLAY_CERTS_TGZ_B64     base64 of a .tar.gz of such a directory (for a CI secret)
#   3. ./fairplay-certs/           the same layout, gitignored
#   4. rustpush's public certs/legacy-fairplay (Albert now rejects it with
#      SIGNATURE_VERIFICATION_FAILED, so new devices cannot activate; existing ones keep working)
# Set FAIRPLAY_REQUIRE=1 to fail instead of falling back to 4.
#
# The keys end up inside the compiled binary, so anyone who has the binary can extract them.
set -euo pipefail
cd "$(dirname "$0")/.."

# rustpush's own submodules use SSH URLs; fetch them over HTTPS instead.
git -c url."https://github.com/".insteadOf="git@github.com:" submodule update --init --recursive

rp=third_party/rustpush
dest="$rp/certs/fairplay"

tmp=""
cleanup() { [[ -n "$tmp" ]] && rm -rf "$tmp"; }
trap cleanup EXIT

src=""
if [[ -n "${FAIRPLAY_CERTS_DIR:-}" ]]; then
    src="$FAIRPLAY_CERTS_DIR"
    echo "FairPlay certs: \$FAIRPLAY_CERTS_DIR ($src)"
elif [[ -n "${FAIRPLAY_CERTS_TGZ_B64:-}" ]]; then
    tmp=$(mktemp -d)
    chmod 700 "$tmp"
    printf '%s' "$FAIRPLAY_CERTS_TGZ_B64" | base64 -d | tar -xz -C "$tmp" --no-same-owner
    # Accept archives with the files at the top level or inside one directory.
    src="$tmp"
    shopt -s nullglob
    top=("$tmp"/*)
    if [[ ${#top[@]} -eq 1 && -d "${top[0]}" ]]; then src="${top[0]}"; fi
    echo "FairPlay certs: \$FAIRPLAY_CERTS_TGZ_B64"
elif [[ -d fairplay-certs ]]; then
    src=fairplay-certs
    echo "FairPlay certs: ./fairplay-certs"
fi

rm -rf "$dest"
if [[ -n "$src" ]]; then
    python3 scripts/fairplay_certs.py "$src" "$dest"
else
    if [[ "${FAIRPLAY_REQUIRE:-0}" == 1 ]]; then
        echo "error: FAIRPLAY_REQUIRE=1 but no FairPlay certs were supplied" >&2
        exit 1
    fi
    echo "warning: no FairPlay certs supplied; using rustpush's public legacy-fairplay pair." >&2
    echo "warning: albert.apple.com rejects it, so this build cannot activate new devices." >&2
    python3 scripts/fairplay_certs.py "$rp/certs/legacy-fairplay" "$dest"
fi
echo "Ready: cargo build --release"
