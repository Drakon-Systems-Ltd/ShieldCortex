#!/usr/bin/env bash
# Fetch LongMemEval-S (cleaned) from Hugging Face — NOT redistributed in-repo.
# License: respect upstream (xiaowu0162/longmemeval-cleaned).
#
# Usage:
#   bash benchmark/longmemeval/scripts/fetch-longmemeval-s.sh
#   OUT_DIR=~/.shieldcortex/benchmark/longmemeval bash benchmark/longmemeval/scripts/fetch-longmemeval-s.sh
set -euo pipefail

OUT_DIR="${OUT_DIR:-${HOME}/.shieldcortex/benchmark/longmemeval}"
mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

BASE="https://huggingface.co/datasets/xiaowu0162/longmemeval-cleaned/resolve/main"
FILE="longmemeval_s_cleaned.json"

if [[ -f "${FILE}" ]]; then
  echo "[fetch] already present: ${OUT_DIR}/${FILE} ($(wc -c < "${FILE}") bytes)"
else
  echo "[fetch] downloading ${FILE} → ${OUT_DIR}/"
  curl -L --fail --retry 3 -o "${FILE}.tmp" "${BASE}/${FILE}"
  mv "${FILE}.tmp" "${FILE}"
  echo "[fetch] done ($(wc -c < "${FILE}") bytes)"
fi

echo "[fetch] next:"
echo "  npx tsx benchmark/longmemeval/scripts/convert-upstream.ts \\"
echo "    --in ${OUT_DIR}/${FILE} \\"
echo "    --out ${OUT_DIR}/longmemeval-s.jsonl"
echo "  # labeled subset (honest, non-full):"
echo "  npx tsx benchmark/longmemeval/scripts/convert-upstream.ts \\"
echo "    --in ${OUT_DIR}/${FILE} \\"
echo "    --out ${OUT_DIR}/longmemeval-s-subset50.jsonl --limit 50 --seed 42"
echo "  npm run bench -- --dataset ${OUT_DIR}/longmemeval-s.jsonl"
