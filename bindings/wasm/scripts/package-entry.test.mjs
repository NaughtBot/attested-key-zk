import assert from "node:assert/strict";
import test from "node:test";

test("package entry loads without a built wasm artifact and fails lazily", async () => {
  const module = await import("@naughtbot/attested-key-zk-wasm");

  assert.equal(typeof module.loadApprovalProofV1Wasm, "function");
  await assert.rejects(
    () => module.loadApprovalProofV1Wasm(),
    /Cannot find module|ERR_MODULE_NOT_FOUND/,
  );
});
