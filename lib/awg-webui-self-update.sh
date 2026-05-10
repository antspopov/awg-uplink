#!/usr/bin/env bash
# Download awg-uplink from GitHub (branch or tag) and run bootstrap in update-only mode.
# Preserves /etc/awg-uplink-webui (credentials, JSON) and nginx/TLS — bootstrap skips those in --update-files-only.
set -euo pipefail

REPO="${1:-antspopov/awg-uplink}"
REF="${2:-main}"
LOG="${AWG_WEBUI_UPDATE_LOG:-/var/lib/awg-uplink-webui/self-update.log}"

if [[ ${EUID:-0} -ne 0 ]]; then
  echo "awg-webui-self-update: root required" >&2
  exit 1
fi

install -d -m 700 /var/lib/awg-uplink-webui
exec >>"$LOG" 2>&1

echo "=== $(date -Is) self-update start repo=${REPO} ref=${REF} ==="

TMP=$(mktemp -d "/tmp/awg-webui-src.XXXXXX")
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

URL="https://codeload.github.com/${REPO}/tar.gz/${REF}"
echo "Fetching ${URL}"
curl -fsSL -o "$TMP/archive.tgz" "$URL"

tar -xzf "$TMP/archive.tgz" -C "$TMP"
TOP=$(find "$TMP" -mindepth 1 -maxdepth 1 -type d ! -name '*.tgz' | head -1)
[[ -n "$TOP" ]] || { echo "empty extract"; exit 1; }
[[ -f "$TOP/awg-webui-bootstrap.sh" ]] || { echo "missing awg-webui-bootstrap.sh in archive"; exit 1; }

DEBIAN_FRONTEND=noninteractive bash "$TOP/awg-webui-bootstrap.sh" --update-files-only --install-deps

echo "=== $(date -Is) self-update finished OK ==="
