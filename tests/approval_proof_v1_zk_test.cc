// Copyright 2026
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include "attested_key_zk/approval_proof_v1_zk.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"

namespace {

constexpr uint8_t kAttestationDomain[kApprovalProofV1DomainLength] = {
    'A', 'K', 'Z', 'K', '-', 'A', 'T', 'T',
    'E', 'S', 'T', '-', 'K', 'E', 'Y', '1'};
constexpr uint8_t kApprovalAssertionDomain[kApprovalProofV1DomainLength] = {
    'A', 'K', 'Z', 'K', '-', 'A', 'P', 'P',
    'R', 'O', 'V', 'A', 'L', '-', 'V', '1'};

void fail(const char* msg) {
  std::fprintf(stderr, "test failure: %s\n", msg);
  std::exit(1);
}

void expect(bool cond, const char* msg) {
  if (!cond) {
    fail(msg);
  }
}

void u64_to_be(uint64_t x, uint8_t out[8]) {
  for (size_t i = 0; i < 8; ++i) {
    out[7 - i] = static_cast<uint8_t>((x >> (8 * i)) & 0xff);
  }
}

class EcKey {
 public:
  EcKey()
      : key_(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)),
        group_(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) {
    expect(key_ != nullptr, "EC_KEY_new_by_curve_name");
    expect(group_ != nullptr, "EC_GROUP_new_by_curve_name");
    expect(EC_KEY_generate_key(key_) == 1, "EC_KEY_generate_key");
  }

  ~EcKey() {
    if (key_ != nullptr) {
      EC_KEY_free(key_);
    }
    if (group_ != nullptr) {
      EC_GROUP_free(group_);
    }
  }

  void public_key(uint8_t x[32], uint8_t y[32]) const {
    uint8_t buf[65];
    size_t len = EC_POINT_point2oct(group_, EC_KEY_get0_public_key(key_),
                                    POINT_CONVERSION_UNCOMPRESSED, buf,
                                    sizeof(buf), nullptr);
    expect(len == sizeof(buf), "EC_POINT_point2oct");
    std::memcpy(x, buf + 1, 32);
    std::memcpy(y, buf + 33, 32);
  }

  void sign_sha256(const uint8_t* msg, size_t len, uint8_t sig[64]) const {
    uint8_t hash[32];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    expect(mdctx != nullptr, "EVP_MD_CTX_new");
    expect(EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) == 1,
           "EVP_DigestInit_ex");
    expect(EVP_DigestUpdate(mdctx, msg, len) == 1, "EVP_DigestUpdate");
    unsigned hash_len = sizeof(hash);
    expect(EVP_DigestFinal_ex(mdctx, hash, &hash_len) == 1,
           "EVP_DigestFinal_ex");
    EVP_MD_CTX_free(mdctx);

    ECDSA_SIG* ecdsa_sig = ECDSA_do_sign(hash, sizeof(hash), key_);
    expect(ecdsa_sig != nullptr, "ECDSA_do_sign");
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(ecdsa_sig, &r, &s);
    expect(BN_bn2binpad(r, sig, 32) == 32, "BN_bn2binpad r");
    expect(BN_bn2binpad(s, sig + 32, 32) == 32, "BN_bn2binpad s");
    ECDSA_SIG_free(ecdsa_sig);
  }

 private:
  EC_KEY* key_;
  EC_GROUP* group_;
};

// Witness-side overrides for negative-path tests that need to mutate signed
// fields. The defaults match the canonical valid fixture and produce the same
// bytes that `make_input()` did originally; tests pass a non-default value to
// inject a single mutation, after which the attestation/assertion are re-signed
// so the in-circuit assertion under test (not signature verification) is the
// constraint that fires.
struct InputOverrides {
  uint64_t now = 1000;
  uint64_t not_before = 900;
  uint64_t not_after = 2000;
  uint64_t expires_at = 1500;
  uint8_t key_class = kApprovalProofV1KeyClassSecureHardwareP256;
};

ApprovalProofV1ProverInput make_input_with(const InputOverrides& ov) {
  EcKey service_key;
  EcKey device_key;

  ApprovalProofV1ProverInput input = {};
  service_key.public_key(input.statement.issuer_pk_x,
                         input.statement.issuer_pk_y);

  for (size_t i = 0; i < kApprovalProofV1HashLength; ++i) {
    input.statement.app_id_hash[i] = static_cast<uint8_t>(0xa0 + i);
    input.statement.challenge_nonce[i] = static_cast<uint8_t>(0x10 + i);
    input.statement.audience_hash[i] = static_cast<uint8_t>(0x20 + i);
    input.statement.approval_hash[i] = static_cast<uint8_t>(0x30 + i);
  }
  input.statement.policy_version[3] = 1;
  u64_to_be(ov.now, input.statement.now);

  std::memcpy(input.attestation, kAttestationDomain, sizeof(kAttestationDomain));
  std::memcpy(input.attestation + 16, input.statement.app_id_hash, 32);
  std::memcpy(input.attestation + 48, input.statement.policy_version, 4);
  input.attestation[52] = ov.key_class;
  u64_to_be(ov.not_before, input.attestation + 56);
  u64_to_be(ov.not_after, input.attestation + 64);
  device_key.public_key(input.attestation + 72, input.attestation + 104);

  std::memcpy(input.approval_assertion, kApprovalAssertionDomain, sizeof(kApprovalAssertionDomain));
  std::memcpy(input.approval_assertion + 16, input.statement.challenge_nonce, 32);
  std::memcpy(input.approval_assertion + 48, input.statement.audience_hash, 32);
  std::memcpy(input.approval_assertion + 80, input.statement.approval_hash, 32);
  u64_to_be(ov.expires_at, input.approval_assertion + 112);

  service_key.sign_sha256(input.attestation, sizeof(input.attestation),
                          input.attestation_sig);
  device_key.sign_sha256(input.approval_assertion, sizeof(input.approval_assertion),
                         input.approval_assertion_sig);
  return input;
}

ApprovalProofV1ProverInput make_input() {
  return make_input_with(InputOverrides{});
}

void prove_and_verify() {
  ApprovalProofV1ProverInput input = make_input();

  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  expect(generate_approval_proof_v1_circuit(&circuit, &circuit_len) ==
             APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS,
         "generate_approval_proof_v1_circuit");
  expect(circuit != nullptr && circuit_len > 0, "generated circuit");

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  expect(run_approval_proof_v1_prover(circuit, circuit_len, &input, &proof, &proof_len) ==
             APPROVAL_PROOF_V1_PROVER_SUCCESS,
         "run_approval_proof_v1_prover");
  expect(proof != nullptr && proof_len > 0, "generated proof");

  expect(run_approval_proof_v1_verifier(circuit, circuit_len, &input.statement, proof,
                              proof_len) == APPROVAL_PROOF_V1_VERIFIER_SUCCESS,
         "run_approval_proof_v1_verifier");

  std::free(proof);
  std::free(circuit);
}

void reject_mismatched_nonce() {
  ApprovalProofV1ProverInput input = make_input();

  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  expect(generate_approval_proof_v1_circuit(&circuit, &circuit_len) ==
             APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS,
         "generate circuit for negative test");

  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  expect(run_approval_proof_v1_prover(circuit, circuit_len, &input, &proof, &proof_len) ==
             APPROVAL_PROOF_V1_PROVER_SUCCESS,
         "prove for negative test");

  ApprovalProofV1Statement wrong = input.statement;
  wrong.challenge_nonce[0] ^= 0xff;
  expect(run_approval_proof_v1_verifier(circuit, circuit_len, &wrong, proof, proof_len) ==
             APPROVAL_PROOF_V1_VERIFIER_VERIFICATION_FAILURE,
         "reject mismatched nonce");

  std::free(proof);
  std::free(circuit);
}

// Bundles a proof against the canonical circuit so the negative-path tests
// below can each replay verification with a different mutation without
// paying the ~3s prover cost. All shared-state tests must clone `statement`
// before mutating to keep the harness pristine across cases.
struct ProvedFixture {
  ApprovalProofV1ProverInput input;
  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  uint8_t* proof = nullptr;
  size_t proof_len = 0;

  ProvedFixture() {
    input = make_input();
    expect(generate_approval_proof_v1_circuit(&circuit, &circuit_len) ==
               APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS,
           "fixture: generate_approval_proof_v1_circuit");
    expect(run_approval_proof_v1_prover(circuit, circuit_len, &input, &proof,
                                        &proof_len) ==
               APPROVAL_PROOF_V1_PROVER_SUCCESS,
           "fixture: prover_with_valid_input");
  }

  ~ProvedFixture() {
    std::free(proof);
    std::free(circuit);
  }

  // Convenience: assert the verifier rejects with the given error against a
  // mutated copy of `statement`.
  void verifier_rejects_mutation(
      const ApprovalProofV1Statement& mutated,
      ApprovalProofV1VerifierErrorCode want, const char* msg) const {
    auto got = run_approval_proof_v1_verifier(circuit, circuit_len, &mutated,
                                              proof, proof_len);
    if (got != want) {
      std::fprintf(stderr,
                   "verifier returned %d, expected %d (%s)\n",
                   static_cast<int>(got), static_cast<int>(want), msg);
      std::exit(1);
    }
  }
};

void reject_audience_hash_mismatch(const ProvedFixture& fx) {
  ApprovalProofV1Statement wrong = fx.input.statement;
  wrong.audience_hash[0] ^= 0xff;
  fx.verifier_rejects_mutation(wrong, APPROVAL_PROOF_V1_VERIFIER_VERIFICATION_FAILURE,
                               "reject_audience_hash_mismatch");
}

void reject_approval_hash_mismatch(const ProvedFixture& fx) {
  ApprovalProofV1Statement wrong = fx.input.statement;
  wrong.approval_hash[0] ^= 0xff;
  fx.verifier_rejects_mutation(wrong, APPROVAL_PROOF_V1_VERIFIER_VERIFICATION_FAILURE,
                               "reject_approval_hash_mismatch");
}

void reject_app_id_hash_mismatch(const ProvedFixture& fx) {
  ApprovalProofV1Statement wrong = fx.input.statement;
  wrong.app_id_hash[0] ^= 0xff;
  fx.verifier_rejects_mutation(wrong, APPROVAL_PROOF_V1_VERIFIER_VERIFICATION_FAILURE,
                               "reject_app_id_hash_mismatch");
}

void reject_policy_version_mismatch(const ProvedFixture& fx) {
  ApprovalProofV1Statement wrong = fx.input.statement;
  wrong.policy_version[3] = 99;  // bumped from 1
  fx.verifier_rejects_mutation(wrong, APPROVAL_PROOF_V1_VERIFIER_VERIFICATION_FAILURE,
                               "reject_policy_version_mismatch");
}

void reject_now_after_assertion_expiry(const ProvedFixture& fx) {
  ApprovalProofV1Statement wrong = fx.input.statement;
  u64_to_be(9000, wrong.now);  // assertion expires_at is 1500
  fx.verifier_rejects_mutation(wrong, APPROVAL_PROOF_V1_VERIFIER_VERIFICATION_FAILURE,
                               "reject_now_after_assertion_expiry");
}

void reject_circuit_bytes_too_large(const ProvedFixture& fx) {
  // Pass an oversized length without allocating the buffer; the cap check
  // runs before any read, so any non-null pointer is fine.
  size_t big = kApprovalProofV1MaxCircuitBytes + 1;
  expect(run_approval_proof_v1_verifier(fx.circuit, big, &fx.input.statement,
                                        fx.proof, fx.proof_len) ==
             APPROVAL_PROOF_V1_VERIFIER_INPUT_TOO_LARGE,
         "reject_circuit_bytes_too_large_verifier");
  expect(run_approval_proof_v1_prover(fx.circuit, big, &fx.input, nullptr,
                                      nullptr) ==
             APPROVAL_PROOF_V1_PROVER_NULL_INPUT,
         "prover null-output guard happens first");
  uint8_t* unused_proof = nullptr;
  size_t unused_len = 0;
  expect(run_approval_proof_v1_prover(fx.circuit, big, &fx.input,
                                      &unused_proof, &unused_len) ==
             APPROVAL_PROOF_V1_PROVER_INPUT_TOO_LARGE,
         "reject_circuit_bytes_too_large_prover");
  uint8_t id[32];
  expect(approval_proof_v1_circuit_id(id, fx.circuit, big) ==
             APPROVAL_PROOF_V1_CIRCUIT_ID_INPUT_TOO_LARGE,
         "reject_circuit_bytes_too_large_circuit_id");
}

void reject_proof_bytes_too_large(const ProvedFixture& fx) {
  size_t big = kApprovalProofV1MaxProofBytes + 1;
  expect(run_approval_proof_v1_verifier(fx.circuit, fx.circuit_len,
                                        &fx.input.statement, fx.proof, big) ==
             APPROVAL_PROOF_V1_VERIFIER_INPUT_TOO_LARGE,
         "reject_proof_bytes_too_large");
}

void reject_truncated_circuit_bytes(const ProvedFixture& fx) {
  // First 100 bytes of a valid circuit: parser must reject without abort().
  expect(run_approval_proof_v1_verifier(fx.circuit, 100, &fx.input.statement,
                                        fx.proof, fx.proof_len) ==
             APPROVAL_PROOF_V1_VERIFIER_CIRCUIT_PARSING_FAILURE,
         "reject_truncated_circuit_bytes");
}

void reject_tampered_circuit_bytes(const ProvedFixture& fx) {
  // Mutate one byte of the parsed region (offset 0 is the field id which is
  // sufficiently early to land inside the structure-derived id computation).
  std::vector<uint8_t> tampered(fx.circuit, fx.circuit + fx.circuit_len);
  tampered[0] ^= 0xff;
  // Either CIRCUIT_PARSING_FAILURE (parser refuses) or CIRCUIT_ID_MISMATCH
  // (parser accepts the tampered bytes and we catch it via the canonical
  // id compare) is acceptable; both prove the tamper-detection works.
  auto code = run_approval_proof_v1_verifier(
      tampered.data(), tampered.size(), &fx.input.statement, fx.proof,
      fx.proof_len);
  if (code != APPROVAL_PROOF_V1_VERIFIER_CIRCUIT_PARSING_FAILURE &&
      code != APPROVAL_PROOF_V1_VERIFIER_CIRCUIT_ID_MISMATCH) {
    std::fprintf(stderr,
                 "tampered circuit accepted: verifier returned %d\n",
                 static_cast<int>(code));
    std::exit(1);
  }
}

void reject_signature_r_zero() {
  ApprovalProofV1ProverInput input = make_input();
  std::memset(input.attestation_sig, 0, 32);  // r = 0
  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  expect(generate_approval_proof_v1_circuit(&circuit, &circuit_len) ==
             APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS,
         "gen circuit");
  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  expect(run_approval_proof_v1_prover(circuit, circuit_len, &input, &proof,
                                      &proof_len) ==
             APPROVAL_PROOF_V1_PROVER_MALFORMED_SIGNATURE,
         "reject_signature_r_zero");
  std::free(proof);
  std::free(circuit);
}

void reject_signature_s_zero() {
  ApprovalProofV1ProverInput input = make_input();
  std::memset(input.approval_assertion_sig + 32, 0, 32);  // s = 0
  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  expect(generate_approval_proof_v1_circuit(&circuit, &circuit_len) ==
             APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS,
         "gen circuit");
  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  expect(run_approval_proof_v1_prover(circuit, circuit_len, &input, &proof,
                                      &proof_len) ==
             APPROVAL_PROOF_V1_PROVER_MALFORMED_SIGNATURE,
         "reject_signature_s_zero");
  std::free(proof);
  std::free(circuit);
}

void reject_off_curve_issuer_pk() {
  ApprovalProofV1ProverInput input = make_input();
  // Set issuer_pk to (1, 1) which doesn't satisfy the P-256 curve equation.
  std::memset(input.statement.issuer_pk_x, 0, 32);
  input.statement.issuer_pk_x[31] = 1;
  std::memset(input.statement.issuer_pk_y, 0, 32);
  input.statement.issuer_pk_y[31] = 1;
  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  expect(generate_approval_proof_v1_circuit(&circuit, &circuit_len) ==
             APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS,
         "gen circuit");
  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  expect(run_approval_proof_v1_prover(circuit, circuit_len, &input, &proof,
                                      &proof_len) ==
             APPROVAL_PROOF_V1_PROVER_MALFORMED_SIGNATURE,
         "reject_off_curve_issuer_pk");
  std::free(proof);
  std::free(circuit);
}

// Witness-mutation negative-path helper. Each of these tests builds a
// fixture with a *signed* witness whose targeted field violates a single
// in-circuit assertion (time-window or key-class). Because we re-sign the
// mutated attestation/assertion with the test-harness keys, the signature
// constraint passes and the prover must reject because of the targeted
// constraint specifically — not because of a generic signature failure.
// The prover surfaces a failed in-circuit assertion as PROOF_FAILURE
// (longfellow-zk's `ZkProver::prove()` checks that the per-row evaluation of
// the circuit equals zero before continuing; a violated assertion bubbles up
// as `prove() == false` -> APPROVAL_PROOF_V1_PROVER_PROOF_FAILURE).
void prover_rejects_witness(const ApprovalProofV1ProverInput& input,
                            const char* msg) {
  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  expect(generate_approval_proof_v1_circuit(&circuit, &circuit_len) ==
             APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS,
         "gen circuit for witness-mutation test");
  uint8_t* proof = nullptr;
  size_t proof_len = 0;
  auto code = run_approval_proof_v1_prover(circuit, circuit_len, &input,
                                           &proof, &proof_len);
  if (code != APPROVAL_PROOF_V1_PROVER_PROOF_FAILURE) {
    std::fprintf(stderr,
                 "prover returned %d, expected PROOF_FAILURE (%d) for %s\n",
                 static_cast<int>(code),
                 static_cast<int>(APPROVAL_PROOF_V1_PROVER_PROOF_FAILURE), msg);
    std::exit(1);
  }
  std::free(proof);
  std::free(circuit);
}

// notBefore (witness) > now (public). Re-signed so the signature constraint
// passes; the in-circuit `attestation.notBefore <= statement.now` assertion
// is the one that must fire.
void reject_now_before_attestation_not_before() {
  InputOverrides ov;
  ov.now = 1000;
  ov.not_before = 1500;  // not_before > now
  ApprovalProofV1ProverInput input = make_input_with(ov);
  prover_rejects_witness(input, "reject_now_before_attestation_not_before");
}

// notAfter (witness) < now (public). Re-signed; the in-circuit
// `statement.now <= attestation.notAfter` assertion must fire.
void reject_now_after_attestation_not_after() {
  InputOverrides ov;
  ov.now = 1000;
  ov.not_after = 500;  // not_after < now
  // Keep not_before <= now so we exercise specifically the not_after path.
  ov.not_before = 100;
  ApprovalProofV1ProverInput input = make_input_with(ov);
  prover_rejects_witness(input, "reject_now_after_attestation_not_after");
}

// expiresAt (witness, in approval_assertion) < now (public). Companion to the
// public-mutation `reject_now_after_assertion_expiry` — that one mutates the
// statement after proving; this one re-signs the assertion with a too-early
// expiresAt so the in-circuit `now <= expiresAt` assertion fires at prove time.
void reject_now_after_assertion_expiry_via_witness() {
  InputOverrides ov;
  ov.now = 1000;
  ov.expires_at = 500;  // expires_at < now
  ApprovalProofV1ProverInput input = make_input_with(ov);
  prover_rejects_witness(input,
                         "reject_now_after_assertion_expiry_via_witness");
}

// attestation[52] (the keyClass byte) is not the canonical
// kApprovalProofV1KeyClassSecureHardwareP256 (=1). Re-signed; the in-circuit
// `assert_const_byte(attestation[52], 1)` is the assertion that must fire.
// This case is uncoverable from the bindings (Swift dropped the parameter,
// Go hardcodes `1`), so witness-mutation is the only way to exercise it.
void reject_wrong_key_class() {
  InputOverrides ov;
  ov.key_class = 2;  // any non-1 value violates the in-circuit constant check
  ApprovalProofV1ProverInput input = make_input_with(ov);
  prover_rejects_witness(input, "reject_wrong_key_class");
}

// Recomputes the canonical circuit id from a freshly generated circuit and
// asserts equality with the constant baked into the library. Catches any
// circuit change that alters the digest before it ships in a release.
void canonical_circuit_id_matches_constant() {
  uint8_t* circuit = nullptr;
  size_t circuit_len = 0;
  expect(generate_approval_proof_v1_circuit(&circuit, &circuit_len) ==
             APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS,
         "generate_approval_proof_v1_circuit");

  uint8_t computed[kApprovalProofV1HashLength];
  expect(approval_proof_v1_circuit_id(computed, circuit, circuit_len) ==
             APPROVAL_PROOF_V1_CIRCUIT_ID_SUCCESS,
         "approval_proof_v1_circuit_id");

  if (std::memcmp(computed, kApprovalProofV1ExpectedCircuitId,
                  sizeof(computed)) != 0) {
    std::fprintf(stderr,
                 "canonical circuit id drift! computed=");
    for (size_t i = 0; i < sizeof(computed); ++i) {
      std::fprintf(stderr, "%02x", computed[i]);
    }
    std::fprintf(stderr, " expected=");
    for (size_t i = 0; i < sizeof(computed); ++i) {
      std::fprintf(stderr, "%02x", kApprovalProofV1ExpectedCircuitId[i]);
    }
    std::fprintf(stderr,
                 "\n  Update kApprovalProofV1ExpectedCircuitId in "
                 "src/approval_proof_v1_zk.cc and SPEC.md, and bump the "
                 "wire version if the new circuit is not compatible.\n");
    std::exit(1);
  }
  std::free(circuit);
}

}  // namespace

int main() {
  prove_and_verify();
  reject_mismatched_nonce();
  canonical_circuit_id_matches_constant();
  // Boundary-validation tests run cheap (no prove call needed beyond fixture).
  reject_signature_r_zero();
  reject_signature_s_zero();
  reject_off_curve_issuer_pk();
  // Statement-mutation tests share a single proof to keep total runtime down.
  {
    ProvedFixture fx;
    reject_audience_hash_mismatch(fx);
    reject_approval_hash_mismatch(fx);
    reject_app_id_hash_mismatch(fx);
    reject_policy_version_mismatch(fx);
    reject_now_after_assertion_expiry(fx);
    reject_circuit_bytes_too_large(fx);
    reject_proof_bytes_too_large(fx);
    reject_truncated_circuit_bytes(fx);
    reject_tampered_circuit_bytes(fx);
  }
  // Witness-mutation tests each pay the prover cost (constraint failure has to
  // be observed inside `ZkProver::prove()`); kept after the shared-fixture
  // block to keep the cheap tests fast on iteration.
  reject_now_before_attestation_not_before();
  reject_now_after_attestation_not_after();
  reject_now_after_assertion_expiry_via_witness();
  reject_wrong_key_class();
  return 0;
}
