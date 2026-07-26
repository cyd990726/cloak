#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS_DIR="$ROOT_DIR/api/assets"

mkdir -p "$ASSETS_DIR/templates" "$ASSETS_DIR/data"

cp "$ROOT_DIR/config.yaml" "$ASSETS_DIR/config.yaml"
cp "$ROOT_DIR/templates/"*.gohtml "$ASSETS_DIR/templates/"

for file in \
  BIT4BF5.tmp \
  blacklist.txt \
  whitelist.txt \
  reviewer_asns.txt \
  reviewer_ips.txt \
  reviewer_ja3_hashes.txt
do
  cp "$ROOT_DIR/data/$file" "$ASSETS_DIR/data/$file"
done

find "$ASSETS_DIR" -type f \( -name '*.yaml' -o -name '*.txt' -o -name '*.gohtml' \) -print0 \
  | xargs -0 perl -0pi -e 's/\r\n/\n/g; s/[ \t]+\n/\n/g; s/\n+\z/\n/'

echo "Synced Vercel assets into api/assets"
