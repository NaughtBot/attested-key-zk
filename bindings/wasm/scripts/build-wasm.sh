#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)"

if ! command -v emcc >/dev/null 2>&1; then
  echo "emcc not found; install Emscripten first" >&2
  exit 1
fi

mkdir -p "$ROOT_DIR/bindings/wasm/dist"

emcc \
  -std=c++17 \
  -O3 \
  -I"$ROOT_DIR/bindings/wasm/shims" \
  -I"$ROOT_DIR/include" \
  -I"$ROOT_DIR/third_party/longfellow-zk/lib" \
  "$ROOT_DIR/src/approval_proof_v1_zk.cc" \
  "$ROOT_DIR/third_party/longfellow-zk/lib/util/log.cc" \
  "$ROOT_DIR/bindings/wasm/shims/util/crypto.cc" \
  "$ROOT_DIR/third_party/longfellow-zk/lib/algebra/nat.cc" \
  "$ROOT_DIR/third_party/longfellow-zk/lib/algebra/crt.cc" \
  "$ROOT_DIR/third_party/longfellow-zk/lib/ec/p256.cc" \
  "$ROOT_DIR/third_party/longfellow-zk/lib/circuits/sha/flatsha256_witness.cc" \
  "$ROOT_DIR/third_party/longfellow-zk/lib/circuits/sha/sha256_constants.cc" \
  -sMODULARIZE=1 \
  -sEXPORT_ES6=1 \
  -sENVIRONMENT=web,worker,node \
  -sALLOW_MEMORY_GROWTH=1 \
  -sSTACK_SIZE=8388608 \
  -sFILESYSTEM=0 \
  -sEXPORT_NAME=createAttestedKeyZkModule \
  -sEXPORTED_RUNTIME_METHODS='["UTF8ToString","getValue","HEAPU8"]' \
  -sEXPORTED_FUNCTIONS='["_malloc","_free","_generate_approval_proof_v1_circuit","_run_approval_proof_v1_prover_from_bytes","_run_approval_proof_v1_verifier_from_bytes","_approval_proof_v1_circuit_id","_approval_proof_v1_free","_approval_proof_v1_prover_error_string","_approval_proof_v1_verifier_error_string","_approval_proof_v1_circuit_generation_error_string","_approval_proof_v1_circuit_id_error_string"]' \
  -o "$ROOT_DIR/bindings/wasm/dist/attested_key_zk.mjs"
