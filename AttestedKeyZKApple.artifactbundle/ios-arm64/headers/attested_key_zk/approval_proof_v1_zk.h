// Copyright 2026
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#ifndef ATTESTED_KEY_ZK_APPROVAL_PROOF_V1_ZK_H_
#define ATTESTED_KEY_ZK_APPROVAL_PROOF_V1_ZK_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  kApprovalProofV1HashLength = 32,
  kApprovalProofV1P256CoordLength = 32,
  kApprovalProofV1SignatureLength = 64,  // raw r||s, both 32-byte big-endian
  kApprovalProofV1PolicyVersionLength = 4,
  kApprovalProofV1TimeLength = 8,        // big-endian uint64
  kApprovalProofV1DomainLength = 16,
  kApprovalProofV1AttestationLength = 136,
  kApprovalProofV1ApprovalAssertionLength = 120,
  kApprovalProofV1CircuitHashBlocks = 3,
  kApprovalProofV1LigeroRate = 7,
  kApprovalProofV1LigeroNreq = 132,
  kApprovalProofV1KeyClassSecureHardwareP256 = 1,
  kApprovalProofV1StatementLength = 204,
  kApprovalProofV1ProverInputLength = 588,
  // Hard upper bounds enforced at the C-ABI boundary so malformed inputs are
  // rejected before they reach the longfellow-zk parser (which still calls
  // abort() on certain malformed structures). Sized at ~3-4x the legitimate
  // values measured on a freshly built circuit/proof so circuit growth from
  // future minor protocol revisions doesn't immediately bump against the cap.
  kApprovalProofV1MaxCircuitBytes = 64 * 1024 * 1024,  //  64 MiB
  kApprovalProofV1MaxProofBytes = 1 * 1024 * 1024,     //   1 MiB
};

typedef struct {
  uint8_t issuer_pk_x[kApprovalProofV1P256CoordLength];
  uint8_t issuer_pk_y[kApprovalProofV1P256CoordLength];
  uint8_t app_id_hash[kApprovalProofV1HashLength];
  uint8_t policy_version[kApprovalProofV1PolicyVersionLength];
  uint8_t now[kApprovalProofV1TimeLength];
  uint8_t challenge_nonce[kApprovalProofV1HashLength];
  uint8_t audience_hash[kApprovalProofV1HashLength];
  uint8_t approval_hash[kApprovalProofV1HashLength];
} ApprovalProofV1Statement;

typedef struct {
  ApprovalProofV1Statement statement;
  uint8_t attestation[kApprovalProofV1AttestationLength];
  uint8_t attestation_sig[kApprovalProofV1SignatureLength];
  uint8_t approval_assertion[kApprovalProofV1ApprovalAssertionLength];
  uint8_t approval_assertion_sig[kApprovalProofV1SignatureLength];
} ApprovalProofV1ProverInput;

typedef enum {
  APPROVAL_PROOF_V1_PROVER_SUCCESS = 0,
  APPROVAL_PROOF_V1_PROVER_NULL_INPUT,
  APPROVAL_PROOF_V1_PROVER_INVALID_INPUT,
  APPROVAL_PROOF_V1_PROVER_CIRCUIT_PARSING_FAILURE,
  APPROVAL_PROOF_V1_PROVER_WITNESS_CREATION_FAILURE,
  APPROVAL_PROOF_V1_PROVER_PROOF_FAILURE,
  APPROVAL_PROOF_V1_PROVER_MEMORY_ALLOCATION_FAILURE,
  APPROVAL_PROOF_V1_PROVER_CIRCUIT_ID_MISMATCH,
  APPROVAL_PROOF_V1_PROVER_INPUT_TOO_LARGE,
  APPROVAL_PROOF_V1_PROVER_MALFORMED_SIGNATURE,
} ApprovalProofV1ProverErrorCode;

typedef enum {
  APPROVAL_PROOF_V1_VERIFIER_SUCCESS = 0,
  APPROVAL_PROOF_V1_VERIFIER_NULL_INPUT,
  APPROVAL_PROOF_V1_VERIFIER_INVALID_INPUT,
  APPROVAL_PROOF_V1_VERIFIER_CIRCUIT_PARSING_FAILURE,
  APPROVAL_PROOF_V1_VERIFIER_PROOF_PARSING_FAILURE,
  APPROVAL_PROOF_V1_VERIFIER_VERIFICATION_FAILURE,
  APPROVAL_PROOF_V1_VERIFIER_CIRCUIT_ID_MISMATCH,
  APPROVAL_PROOF_V1_VERIFIER_INPUT_TOO_LARGE,
} ApprovalProofV1VerifierErrorCode;

typedef enum {
  APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS = 0,
  APPROVAL_PROOF_V1_CIRCUIT_GENERATION_NULL_INPUT,
  APPROVAL_PROOF_V1_CIRCUIT_GENERATION_MEMORY_ALLOCATION_FAILURE,
  APPROVAL_PROOF_V1_CIRCUIT_GENERATION_GENERAL_FAILURE,
} ApprovalProofV1CircuitGenerationErrorCode;

typedef enum {
  APPROVAL_PROOF_V1_CIRCUIT_ID_SUCCESS = 0,
  APPROVAL_PROOF_V1_CIRCUIT_ID_NULL_INPUT,
  APPROVAL_PROOF_V1_CIRCUIT_ID_INVALID_INPUT,
  APPROVAL_PROOF_V1_CIRCUIT_ID_CIRCUIT_PARSING_FAILURE,
  APPROVAL_PROOF_V1_CIRCUIT_ID_INPUT_TOO_LARGE,
} ApprovalProofV1CircuitIdErrorCode;

// Canonical circuit id for this build of the protocol. A relying-party
// verifier can pin against this constant to ensure it only accepts proofs
// against the canonical circuit. Computed by approval_proof_v1_circuit_id()
// over the bytes returned by generate_approval_proof_v1_circuit(); a
// regression test recomputes and asserts equality so a circuit change that
// alters the id will be caught at CI rather than silently shipping a
// version mismatch.
extern const uint8_t kApprovalProofV1ExpectedCircuitId[32];

// Returns the serialized byte size of ApprovalProofV1Statement.
size_t approval_proof_v1_statement_size(void);

// Returns the serialized byte size of ApprovalProofV1ProverInput.
size_t approval_proof_v1_prover_input_size(void);

// Free memory returned by this library.
void approval_proof_v1_free(void* ptr);

const char* approval_proof_v1_prover_error_string(ApprovalProofV1ProverErrorCode code);
const char* approval_proof_v1_verifier_error_string(ApprovalProofV1VerifierErrorCode code);
const char* approval_proof_v1_circuit_generation_error_string(
    ApprovalProofV1CircuitGenerationErrorCode code);
const char* approval_proof_v1_circuit_id_error_string(
    ApprovalProofV1CircuitIdErrorCode code);

// Generate the serialized proving/verifying circuit. The caller owns the
// returned buffer and must free it with free().
ApprovalProofV1CircuitGenerationErrorCode generate_approval_proof_v1_circuit(
    uint8_t** circuit_bytes, size_t* circuit_len);

// Create a proof for the statement encoded in INPUT using the serialized
// circuit generated by generate_approval_proof_v1_circuit().
ApprovalProofV1ProverErrorCode run_approval_proof_v1_prover(
    const uint8_t* circuit_bytes, size_t circuit_len,
    const ApprovalProofV1ProverInput* input, uint8_t** proof, size_t* proof_len);

// Byte-oriented variant of run_approval_proof_v1_prover(). INPUT_BYTES must contain the
// fixed-width binary serialization of ApprovalProofV1ProverInput.
ApprovalProofV1ProverErrorCode run_approval_proof_v1_prover_from_bytes(
    const uint8_t* circuit_bytes, size_t circuit_len,
    const uint8_t* input_bytes, size_t input_len, uint8_t** proof,
    size_t* proof_len);

// Verify a proof against the public statement.
ApprovalProofV1VerifierErrorCode run_approval_proof_v1_verifier(
    const uint8_t* circuit_bytes, size_t circuit_len,
    const ApprovalProofV1Statement* statement, const uint8_t* proof, size_t proof_len);

// Byte-oriented variant of run_approval_proof_v1_verifier(). STATEMENT_BYTES must
// contain the fixed-width binary serialization of ApprovalProofV1Statement.
ApprovalProofV1VerifierErrorCode run_approval_proof_v1_verifier_from_bytes(
    const uint8_t* circuit_bytes, size_t circuit_len,
    const uint8_t* statement_bytes, size_t statement_len,
    const uint8_t* proof, size_t proof_len);

// Compute the Longfellow circuit id for the serialized circuit. Writes the
// 32-byte digest to ID and returns APPROVAL_PROOF_V1_CIRCUIT_ID_SUCCESS on
// success, or a typed error code otherwise.
ApprovalProofV1CircuitIdErrorCode approval_proof_v1_circuit_id(
    uint8_t id[32], const uint8_t* circuit_bytes, size_t circuit_len);

#ifdef __cplusplus
}
#endif

#endif  // ATTESTED_KEY_ZK_APPROVAL_PROOF_V1_ZK_H_
