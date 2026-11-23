#!/usr/bin/env bash
# Fetches rustpush (a git submodule) and sets up its FairPlay key files the same way
# rustpush's own CI does: copies of certs/legacy-fairplay. Run once after cloning.
set -euo pipefail
cd "$(dirname "$0")/.."

# rustpush's own submodules use SSH URLs; fetch them over HTTPS instead.
git -c url."https://github.com/".insteadOf="git@github.com:" submodule update --init --recursive

rp=third_party/rustpush
mkdir -p "$rp/certs/fairplay"
for name in \
    4056631661436364584235346952193 4056631661436364584235346952194 \
    4056631661436364584235346952195 4056631661436364584235346952196 \
    4056631661436364584235346952197 4056631661436364584235346952198 \
    4056631661436364584235346952199 4056631661436364584235346952200 \
    4056631661436364584235346952201 4056631661436364584235346952208; do
    cp "$rp/certs/legacy-fairplay/fairplay.pem" "$rp/certs/fairplay/$name.pem"
    cp "$rp/certs/legacy-fairplay/fairplay.crt" "$rp/certs/fairplay/$name.crt"
done
echo "Ready: cargo build --release"
