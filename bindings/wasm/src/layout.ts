export const HASH_LENGTH = 32;
export const P256_COORD_LENGTH = 32;
export const SIGNATURE_LENGTH = 64;
export const POLICY_VERSION_LENGTH = 4;
export const TIME_LENGTH = 8;
export const DOMAIN_LENGTH = 16;
export const ATTESTATION_LENGTH = 136;
export const APPROVAL_ASSERTION_LENGTH = 120;
export const STATEMENT_LENGTH = 204;
export const PROVER_INPUT_LENGTH = 588;

export const ATTESTATION_DOMAIN = new TextEncoder().encode("AKZK-ATTEST-KEY1");
export const APPROVAL_ASSERTION_DOMAIN = new TextEncoder().encode("AKZK-APPROVAL-V1");

export interface Statement {
  issuerPublicKeyX: Uint8Array;
  issuerPublicKeyY: Uint8Array;
  appIDHash: Uint8Array;
  policyVersion: Uint8Array;
  now: Uint8Array;
  challengeNonce: Uint8Array;
  audienceHash: Uint8Array;
  approvalHash: Uint8Array;
}

export interface ProverInput {
  statement: Statement;
  attestation: Uint8Array;
  attestationSignature: Uint8Array;
  approvalAssertion: Uint8Array;
  approvalAssertionSignature: Uint8Array;
}

export function uint64BE(value: bigint): Uint8Array {
  const out = new Uint8Array(TIME_LENGTH);
  let v = value;
  for (let i = TIME_LENGTH - 1; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function buildAttestation(
  statement: Statement,
  devicePublicKeyX: Uint8Array,
  devicePublicKeyY: Uint8Array,
  notBefore: bigint,
  notAfter: bigint,
  keyClass = 1,
): Uint8Array {
  expectLength(devicePublicKeyX, P256_COORD_LENGTH, "devicePublicKeyX");
  expectLength(devicePublicKeyY, P256_COORD_LENGTH, "devicePublicKeyY");
  const out = new Uint8Array(ATTESTATION_LENGTH);
  out.set(ATTESTATION_DOMAIN, 0);
  out.set(statement.appIDHash, 16);
  out.set(statement.policyVersion, 48);
  out[52] = keyClass;
  out.set(uint64BE(notBefore), 56);
  out.set(uint64BE(notAfter), 64);
  out.set(devicePublicKeyX, 72);
  out.set(devicePublicKeyY, 104);
  return out;
}

export function buildApprovalAssertion(statement: Statement, expiresAt: bigint): Uint8Array {
  const out = new Uint8Array(APPROVAL_ASSERTION_LENGTH);
  out.set(APPROVAL_ASSERTION_DOMAIN, 0);
  out.set(statement.challengeNonce, 16);
  out.set(statement.audienceHash, 48);
  out.set(statement.approvalHash, 80);
  out.set(uint64BE(expiresAt), 112);
  return out;
}

export function encodeStatement(statement: Statement): Uint8Array {
  expectLength(statement.issuerPublicKeyX, P256_COORD_LENGTH, "issuerPublicKeyX");
  expectLength(statement.issuerPublicKeyY, P256_COORD_LENGTH, "issuerPublicKeyY");
  expectLength(statement.appIDHash, HASH_LENGTH, "appIDHash");
  expectLength(statement.policyVersion, POLICY_VERSION_LENGTH, "policyVersion");
  expectLength(statement.now, TIME_LENGTH, "now");
  expectLength(statement.challengeNonce, HASH_LENGTH, "challengeNonce");
  expectLength(statement.audienceHash, HASH_LENGTH, "audienceHash");
  expectLength(statement.approvalHash, HASH_LENGTH, "approvalHash");

  const out = new Uint8Array(STATEMENT_LENGTH);
  out.set(statement.issuerPublicKeyX, 0);
  out.set(statement.issuerPublicKeyY, 32);
  out.set(statement.appIDHash, 64);
  out.set(statement.policyVersion, 96);
  out.set(statement.now, 100);
  out.set(statement.challengeNonce, 108);
  out.set(statement.audienceHash, 140);
  out.set(statement.approvalHash, 172);
  return out;
}

export function encodeProverInput(input: ProverInput): Uint8Array {
  expectLength(input.attestation, ATTESTATION_LENGTH, "attestation");
  expectLength(input.attestationSignature, SIGNATURE_LENGTH, "attestationSignature");
  expectLength(input.approvalAssertion, APPROVAL_ASSERTION_LENGTH, "approvalAssertion");
  expectLength(input.approvalAssertionSignature, SIGNATURE_LENGTH, "approvalAssertionSignature");

  const statement = encodeStatement(input.statement);
  const out = new Uint8Array(PROVER_INPUT_LENGTH);
  out.set(statement, 0);
  out.set(input.attestation, 204);
  out.set(input.attestationSignature, 340);
  out.set(input.approvalAssertion, 404);
  out.set(input.approvalAssertionSignature, 524);
  return out;
}

function expectLength(value: Uint8Array, expected: number, field: string): void {
  if (value.length !== expected) {
    throw new Error(`${field} length ${value.length}, expected ${expected}`);
  }
}
