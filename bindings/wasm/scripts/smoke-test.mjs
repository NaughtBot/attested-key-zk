import {
  ApprovalProofError,
  ApprovalProofErrorStage,
  ApprovalProofVerifierErrorCode,
  buildApprovalAssertion,
  buildAttestation,
  loadApprovalProofV1Wasm,
  uint64BE,
} from "../lib/index.js";
import {
  generateKeyPairSync,
  sign,
} from "node:crypto";

function fillIncreasing(start) {
  const out = new Uint8Array(32);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = (start + i) & 0xff;
  }
  return out;
}

function base64urlToBytes(value) {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  return new Uint8Array(Buffer.from(b64 + pad, "base64"));
}

async function publicKeyXY(keyObject) {
  const jwk = keyObject.export({ format: "jwk" });
  return {
    x: base64urlToBytes(jwk.x),
    y: base64urlToBytes(jwk.y),
  };
}

function signP256Raw(privateKey, message) {
  return new Uint8Array(sign("sha256", message, {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  }));
}

async function main() {
  const service = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const device = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const servicePub = await publicKeyXY(service.publicKey);
  const devicePub = await publicKeyXY(device.publicKey);

  const statement = {
    issuerPublicKeyX: servicePub.x,
    issuerPublicKeyY: servicePub.y,
    appIDHash: fillIncreasing(0xa0),
    policyVersion: new Uint8Array([0, 0, 0, 1]),
    now: uint64BE(1000n),
    challengeNonce: fillIncreasing(0x10),
    audienceHash: fillIncreasing(0x20),
    approvalHash: fillIncreasing(0x30),
  };

  const attestation = buildAttestation(statement, devicePub.x, devicePub.y, 900n, 2000n);
  const approvalAssertion = buildApprovalAssertion(statement, 1500n);
  const input = {
    statement,
    attestation,
    attestationSignature: signP256Raw(service.privateKey, attestation),
    approvalAssertion,
    approvalAssertionSignature: signP256Raw(device.privateKey, approvalAssertion),
  };

  const wasm = await loadApprovalProofV1Wasm();
  const circuit = await wasm.generateCircuit();
  const proof = await wasm.prove(circuit, input);
  await wasm.verify(circuit, statement, proof);

  const wrong = {
    ...statement,
    challengeNonce: new Uint8Array(statement.challengeNonce),
  };
  wrong.challengeNonce[0] ^= 0xff;

  let caught;
  try {
    await wasm.verify(circuit, wrong, proof);
  } catch (err) {
    caught = err;
  }
  if (!caught) {
    throw new Error("expected verifier failure for mismatched nonce");
  }
  if (!(caught instanceof ApprovalProofError)) {
    throw new Error(`expected ApprovalProofError, got ${caught.constructor.name}: ${caught}`);
  }
  if (caught.stage !== ApprovalProofErrorStage.Verifier) {
    throw new Error(`expected verifier stage, got ${caught.stage}`);
  }
  if (caught.code !== ApprovalProofVerifierErrorCode.VerificationFailure) {
    throw new Error(`expected VerificationFailure code, got ${caught.code}`);
  }

  // Exercise the input-cap path: oversized circuit_bytes must produce a
  // typed error with INPUT_TOO_LARGE rather than a parser abort.
  const tooBig = new Uint8Array(64 * 1024 * 1024 + 1);
  let capError;
  try {
    await wasm.verify(tooBig, statement, proof);
  } catch (err) {
    capError = err;
  }
  if (!(capError instanceof ApprovalProofError) ||
      capError.code !== ApprovalProofVerifierErrorCode.InputTooLarge) {
    throw new Error(
      `expected InputTooLarge ApprovalProofError, got ${capError?.constructor?.name}: ${capError}`,
    );
  }

  console.log(`WASM smoke test passed: circuit=${circuit.length} bytes proof=${proof.length} bytes`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
