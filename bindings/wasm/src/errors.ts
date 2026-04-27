// Numeric error codes mirroring the C-ABI enums in
// include/attested_key_zk/approval_proof_v1_zk.h. Values must stay in sync;
// the static_assert(offsetof(...)) checks in src/approval_proof_v1_zk.cc do
// not cover enums, so any reorder upstream needs a matching edit here.

export enum ApprovalProofErrorStage {
  CircuitGeneration = "circuit-generation",
  Prover = "prover",
  Verifier = "verifier",
  CircuitId = "circuit-id",
}

export enum ApprovalProofProverErrorCode {
  Success = 0,
  NullInput = 1,
  InvalidInput = 2,
  CircuitParsingFailure = 3,
  WitnessCreationFailure = 4,
  ProofFailure = 5,
  MemoryAllocationFailure = 6,
  CircuitIdMismatch = 7,
  InputTooLarge = 8,
  MalformedSignature = 9,
}

export enum ApprovalProofVerifierErrorCode {
  Success = 0,
  NullInput = 1,
  InvalidInput = 2,
  CircuitParsingFailure = 3,
  ProofParsingFailure = 4,
  VerificationFailure = 5,
  CircuitIdMismatch = 6,
  InputTooLarge = 7,
}

export enum ApprovalProofCircuitGenerationErrorCode {
  Success = 0,
  NullInput = 1,
  MemoryAllocationFailure = 2,
  GeneralFailure = 3,
}

export enum ApprovalProofCircuitIdErrorCode {
  Success = 0,
  NullInput = 1,
  InvalidInput = 2,
  CircuitParsingFailure = 3,
  InputTooLarge = 4,
}

// Discriminated union of every numeric code the WASM bindings can surface.
// Consumers can switch on err.stage + err.code to handle specific cases.
export type ApprovalProofErrorCode =
  | ApprovalProofProverErrorCode
  | ApprovalProofVerifierErrorCode
  | ApprovalProofCircuitGenerationErrorCode
  | ApprovalProofCircuitIdErrorCode;

// Error subclass thrown by every ApprovalProofV1Wasm method. The numeric
// `code` lets callers distinguish (e.g.) INVALID_INPUT from
// VERIFICATION_FAILURE without parsing the human-readable message string.
export class ApprovalProofError extends Error {
  readonly code: ApprovalProofErrorCode;
  readonly stage: ApprovalProofErrorStage;

  constructor(
    code: ApprovalProofErrorCode,
    stage: ApprovalProofErrorStage,
    message: string,
  ) {
    super(`${stage}: ${message}`);
    this.name = "ApprovalProofError";
    this.code = code;
    this.stage = stage;
    Object.setPrototypeOf(this, ApprovalProofError.prototype);
  }
}
