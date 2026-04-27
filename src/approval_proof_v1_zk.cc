// Copyright 2026
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

#include "attested_key_zk/approval_proof_v1_zk.h"

#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/memcmp.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/sha/flatsha256_witness.h"
#include "ec/p256.h"
#include "proto/circuit_reader.h"
#include "proto/circuit_writer.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/crypto.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

static_assert(sizeof(ApprovalProofV1Statement) == kApprovalProofV1StatementLength,
              "ApprovalProofV1Statement size mismatch");
static_assert(sizeof(ApprovalProofV1ProverInput) == kApprovalProofV1ProverInputLength,
              "ApprovalProofV1ProverInput size mismatch");

// Field offsets that every binding hard-codes (Go writes out[52]=1 for
// keyClass, WASM layout.ts indexes by literal numeric offsets, Swift
// indexes by hand). A reorder that preserves struct size would silently
// break all three; these asserts catch it at compile time.
static_assert(offsetof(ApprovalProofV1Statement, issuer_pk_x) == 0,
              "ApprovalProofV1Statement.issuer_pk_x offset drift");
static_assert(offsetof(ApprovalProofV1Statement, issuer_pk_y) == 32,
              "ApprovalProofV1Statement.issuer_pk_y offset drift");
static_assert(offsetof(ApprovalProofV1Statement, app_id_hash) == 64,
              "ApprovalProofV1Statement.app_id_hash offset drift");
static_assert(offsetof(ApprovalProofV1Statement, policy_version) == 96,
              "ApprovalProofV1Statement.policy_version offset drift");
static_assert(offsetof(ApprovalProofV1Statement, now) == 100,
              "ApprovalProofV1Statement.now offset drift");
static_assert(offsetof(ApprovalProofV1Statement, challenge_nonce) == 108,
              "ApprovalProofV1Statement.challenge_nonce offset drift");
static_assert(offsetof(ApprovalProofV1Statement, audience_hash) == 140,
              "ApprovalProofV1Statement.audience_hash offset drift");
static_assert(offsetof(ApprovalProofV1Statement, approval_hash) == 172,
              "ApprovalProofV1Statement.approval_hash offset drift");

static_assert(offsetof(ApprovalProofV1ProverInput, statement) == 0,
              "ApprovalProofV1ProverInput.statement offset drift");
static_assert(offsetof(ApprovalProofV1ProverInput, attestation) == 204,
              "ApprovalProofV1ProverInput.attestation offset drift");
static_assert(offsetof(ApprovalProofV1ProverInput, attestation_sig) == 340,
              "ApprovalProofV1ProverInput.attestation_sig offset drift");
static_assert(offsetof(ApprovalProofV1ProverInput, approval_assertion) == 404,
              "ApprovalProofV1ProverInput.approval_assertion offset drift");
static_assert(offsetof(ApprovalProofV1ProverInput, approval_assertion_sig) == 524,
              "ApprovalProofV1ProverInput.approval_assertion_sig offset drift");

namespace proofs {
namespace approval_proof_v1_internal {

using Field = Fp256Base;
using Nat = Field::N;
using Elt = Field::Elt;
using ScalarField = Fp256Scalar;
using Field2 = Fp2<Field>;
using Elt2 = Field2::Elt;
using FftExtConvolutionFactory = FFTExtConvolutionFactory<Field, Field2>;
using RSFactory = ReedSolomonFactory<Field, FftExtConvolutionFactory>;
using CompilerBackend = CompilerBackend<Field>;
using LogicCircuit = Logic<Field, CompilerBackend>;

constexpr size_t kProofVersion = 7;

// Fiat-Shamir transcript domain separator for this proof system. Used at
// both the prover and verifier `Transcript` construction sites; keeping
// the literal and its length in a single named pair makes a length/literal
// drift uncatchable. Any change to either the bytes or the length is a
// wire-format change and MUST bump kProofVersion (see SPEC.md
// "When to bump kProofVersion").
static constexpr char kTranscriptLabel[] = "approval_proof_v1";
static constexpr size_t kTranscriptLabelLen = sizeof(kTranscriptLabel) - 1;

// When true, CircuitReader::from_bytes recomputes the circuit id over the
// parsed structure and rejects bytes whose embedded id doesn't match. The
// C-ABI wrappers additionally compare the resulting id against
// kApprovalProofV1ExpectedCircuitId so a self-consistent but non-canonical
// circuit is also rejected.
constexpr bool kEnforceCircuitId = true;

constexpr uint8_t kAttestationDomain[kApprovalProofV1DomainLength] = {
    'A', 'K', 'Z', 'K', '-', 'A', 'T', 'T',
    'E', 'S', 'T', '-', 'K', 'E', 'Y', '1'};
constexpr uint8_t kApprovalAssertionDomain[kApprovalProofV1DomainLength] = {
    'A', 'K', 'Z', 'K', '-', 'A', 'P', 'P',
    'R', 'O', 'V', 'A', 'L', '-', 'V', '1'};

constexpr size_t kAttestationPaddedLength = 64 * kApprovalProofV1CircuitHashBlocks;
constexpr size_t kApprovalAssertionPaddedLength = 64 * kApprovalProofV1CircuitHashBlocks;

constexpr size_t kAttestationAppIdHashOffset = 16;
constexpr size_t kAttestationPolicyVersionOffset = 48;
constexpr size_t kAttestationKeyClassOffset = 52;
constexpr size_t kAttestationReservedOffset = 53;
constexpr size_t kAttestationNotBeforeOffset = 56;
constexpr size_t kAttestationNotAfterOffset = 64;
constexpr size_t kAttestationDevicePkXOffset = 72;
constexpr size_t kAttestationDevicePkYOffset = 104;

constexpr size_t kApprovalAssertionChallengeNonceOffset = 16;
constexpr size_t kApprovalAssertionAudienceHashOffset = 48;
constexpr size_t kApprovalAssertionApprovalHashOffset = 80;
constexpr size_t kApprovalAssertionExpiresAtOffset = 112;

static constexpr char kRootX[] =
    "112649224146410281873500457609690258373018840430489408729223714171582664"
    "680802";
static constexpr char kRootY[] =
    "84087994358540907695740461427818660560182168997182378749313018254450460212"
    "908";

// P-256 group order n in big-endian. Used to range-check ECDSA scalars at
// the C-ABI boundary (r, s must be in [1, n-1]).
constexpr uint8_t kP256OrderBE[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
};

bool is_zero_be(const uint8_t bytes[32]) {
  uint8_t acc = 0;
  for (size_t i = 0; i < 32; ++i) acc |= bytes[i];
  return acc == 0;
}

// Strict less-than on 32-byte big-endian unsigned integers.
bool less_than_be(const uint8_t a[32], const uint8_t b[32]) {
  for (size_t i = 0; i < 32; ++i) {
    if (a[i] < b[i]) return true;
    if (a[i] > b[i]) return false;
  }
  return false;
}

// Validates an ECDSA signature pair (r, s) against the P-256 group order:
// both must be in [1, n-1]. Returns false for r=0, s=0, r>=n, or s>=n.
bool valid_p256_signature_scalars(const uint8_t sig[64]) {
  return !is_zero_be(sig) && !is_zero_be(sig + 32) &&
         less_than_be(sig, kP256OrderBE) &&
         less_than_be(sig + 32, kP256OrderBE);
}

template <class NType>
NType nat_from_be(const uint8_t be[NType::kBytes]) {
  uint8_t tmp[NType::kBytes];
  for (size_t i = 0; i < NType::kBytes; ++i) {
    tmp[i] = be[NType::kBytes - i - 1];
  }
  return NType::of_bytes(tmp);
}

template <class F>
std::optional<typename F::Elt> parse_be_field(
    const uint8_t be[F::kBytes], const F& f) {
  uint8_t tmp[F::kBytes];
  for (size_t i = 0; i < F::kBytes; ++i) {
    tmp[i] = be[F::kBytes - i - 1];
  }
  return f.of_bytes_field(tmp);
}

// Validates that (issuer_pk_x, issuer_pk_y) is a P-256 affine point on the
// curve. Rejects malformed coordinates (>= field prime) and off-curve points.
// Note: the all-zero point is implicitly rejected because (0, 0) does not
// satisfy the P-256 curve equation.
bool valid_p256_issuer_pk(const ApprovalProofV1Statement& statement) {
  auto x = parse_be_field<Field>(statement.issuer_pk_x, p256_base);
  auto y = parse_be_field<Field>(statement.issuer_pk_y, p256_base);
  if (!x.has_value() || !y.has_value()) {
    return false;
  }
  return p256.is_on_curve(*x, *y);
}

void u64_to_be(uint64_t x, uint8_t out[8]) {
  for (size_t i = 0; i < 8; ++i) {
    out[7 - i] = static_cast<uint8_t>((x >> (8 * i)) & 0xff);
  }
}

template <class Logic, class Curve>
class ApprovalProofV1Circuit {
  using EltW = typename Logic::EltW;
  using v8 = typename Logic::v8;
  using v32 = typename Logic::v32;
  using v256 = typename Logic::v256;
  using Ecdsa = VerifyCircuit<Logic, Field, Curve>;
  using EcdsaWitness = typename Ecdsa::Witness;
  using Flatsha = FlatSHA256Circuit<Logic, BitPlucker<Logic, 3>>;
  using ShaBlockWitness = typename Flatsha::BlockWitness;
  using sha_packed_v32 = typename Flatsha::packed_v32;

 public:
  struct PublicInput {
    EltW issuer_pk_x;
    EltW issuer_pk_y;
    v8 app_id_hash[kApprovalProofV1HashLength];
    v8 policy_version[kApprovalProofV1PolicyVersionLength];
    v8 now[kApprovalProofV1TimeLength];
    v8 challenge_nonce[kApprovalProofV1HashLength];
    v8 audience_hash[kApprovalProofV1HashLength];
    v8 approval_hash[kApprovalProofV1HashLength];

    void input(const Logic& lc) {
      issuer_pk_x = lc.eltw_input();
      issuer_pk_y = lc.eltw_input();
      for (size_t i = 0; i < kApprovalProofV1HashLength; ++i) {
        app_id_hash[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kApprovalProofV1PolicyVersionLength; ++i) {
        policy_version[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kApprovalProofV1TimeLength; ++i) {
        now[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kApprovalProofV1HashLength; ++i) {
        challenge_nonce[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kApprovalProofV1HashLength; ++i) {
        audience_hash[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kApprovalProofV1HashLength; ++i) {
        approval_hash[i] = lc.template vinput<8>();
      }
    }
  };

  struct Witness {
    EcdsaWitness attestation_sig;
    EcdsaWitness approval_assertion_sig;
    v8 attestation_padded[kAttestationPaddedLength];
    v8 approval_assertion_padded[kApprovalAssertionPaddedLength];
    ShaBlockWitness auth_sha[kApprovalProofV1CircuitHashBlocks];
    ShaBlockWitness assertion_sha[kApprovalProofV1CircuitHashBlocks];

    void input(const Logic& lc) {
      attestation_sig.input(lc);
      approval_assertion_sig.input(lc);
      for (size_t i = 0; i < kAttestationPaddedLength; ++i) {
        attestation_padded[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kApprovalAssertionPaddedLength; ++i) {
        approval_assertion_padded[i] = lc.template vinput<8>();
      }
      for (size_t i = 0; i < kApprovalProofV1CircuitHashBlocks; ++i) {
        auth_sha[i].input(lc);
      }
      for (size_t i = 0; i < kApprovalProofV1CircuitHashBlocks; ++i) {
        assertion_sha[i].input(lc);
      }
    }
  };

  ApprovalProofV1Circuit(const Logic& lc, const Curve& ec, const Nat& order)
      : lc_(lc), ec_(ec), order_(order), sha_(lc), cmp_(lc) {
    for (size_t i = 0; i < 256; ++i) {
      bits_p_[i] = lc_.bit(ec_.f_.m_.bit(i));
    }
  }

  void assert_statement(const PublicInput& pub, Witness& w) const {
    Ecdsa ecc(lc_, ec_, order_);
    const auto three = lc_.template vbit<8>(kApprovalProofV1CircuitHashBlocks);

    sha_.assert_message(kApprovalProofV1CircuitHashBlocks, three, w.attestation_padded,
                        w.auth_sha);
    sha_.assert_message(kApprovalProofV1CircuitHashBlocks, three, w.approval_assertion_padded,
                        w.assertion_sha);

    assert_sha256_padding(kApprovalProofV1AttestationLength,
                          kAttestationPaddedLength, w.attestation_padded);
    assert_sha256_padding(kApprovalProofV1ApprovalAssertionLength,
                          kApprovalAssertionPaddedLength,
                          w.approval_assertion_padded);

    assert_const_bytes(kApprovalProofV1DomainLength, w.attestation_padded, kAttestationDomain);
    assert_public_bytes(kApprovalProofV1HashLength,
                        &w.attestation_padded[kAttestationAppIdHashOffset],
                        pub.app_id_hash);
    assert_public_bytes(kApprovalProofV1PolicyVersionLength,
                        &w.attestation_padded[kAttestationPolicyVersionOffset],
                        pub.policy_version);
    assert_const_byte(w.attestation_padded[kAttestationKeyClassOffset],
                      kApprovalProofV1KeyClassSecureHardwareP256);
    assert_zero_bytes(3, &w.attestation_padded[kAttestationReservedOffset]);

    lc_.assert1(cmp_.leq(kApprovalProofV1TimeLength,
                         &w.attestation_padded[kAttestationNotBeforeOffset], pub.now));
    lc_.assert1(cmp_.leq(kApprovalProofV1TimeLength, pub.now,
                         &w.attestation_padded[kAttestationNotAfterOffset]));

    lc_.assert1(
        lc_.vlt(bytes_to_bits(&w.attestation_padded[kAttestationDevicePkXOffset]), bits_p_));
    lc_.assert1(
        lc_.vlt(bytes_to_bits(&w.attestation_padded[kAttestationDevicePkYOffset]), bits_p_));
    EltW dpkx = repack_be32(&w.attestation_padded[kAttestationDevicePkXOffset]);
    EltW dpky = repack_be32(&w.attestation_padded[kAttestationDevicePkYOffset]);

    assert_const_bytes(kApprovalProofV1DomainLength, w.approval_assertion_padded,
                       kApprovalAssertionDomain);
    assert_public_bytes(kApprovalProofV1HashLength,
                        &w.approval_assertion_padded[kApprovalAssertionChallengeNonceOffset],
                        pub.challenge_nonce);
    assert_public_bytes(kApprovalProofV1HashLength,
                        &w.approval_assertion_padded[kApprovalAssertionAudienceHashOffset],
                        pub.audience_hash);
    assert_public_bytes(kApprovalProofV1HashLength,
                        &w.approval_assertion_padded[kApprovalAssertionApprovalHashOffset],
                        pub.approval_hash);
    lc_.assert1(cmp_.leq(kApprovalProofV1TimeLength, pub.now,
                         &w.approval_assertion_padded[kApprovalAssertionExpiresAtOffset]));

    EltW auth_hash = repack_sha256(w.auth_sha[kApprovalProofV1CircuitHashBlocks - 1].h1);
    EltW assertion_hash =
        repack_sha256(w.assertion_sha[kApprovalProofV1CircuitHashBlocks - 1].h1);

    ecc.verify_signature3(pub.issuer_pk_x, pub.issuer_pk_y, auth_hash,
                          w.attestation_sig);
    ecc.verify_signature3(dpkx, dpky, assertion_hash, w.approval_assertion_sig);
  }

 private:
  void assert_public_bytes(size_t n, const v8 got[], const v8 want[]) const {
    for (size_t i = 0; i < n; ++i) {
      lc_.assert1(lc_.eq(8, got[i].data(), want[i].data()));
    }
  }

  void assert_const_bytes(size_t n, const v8 got[], const uint8_t want[]) const {
    for (size_t i = 0; i < n; ++i) {
      assert_const_byte(got[i], want[i]);
    }
  }

  void assert_zero_bytes(size_t n, const v8 got[]) const {
    for (size_t i = 0; i < n; ++i) {
      assert_const_byte(got[i], 0);
    }
  }

  void assert_const_byte(const v8& got, uint8_t want) const {
    lc_.assert1(lc_.veq(got, static_cast<uint64_t>(want)));
  }

  void assert_sha256_padding(size_t msg_len, size_t padded_len,
                             const v8 in[/* padded_len bytes */]) const {
    assert_const_byte(in[msg_len], 0x80);
    for (size_t i = msg_len + 1; i < padded_len - 8; ++i) {
      assert_const_byte(in[i], 0);
    }
    uint8_t bit_len[8];
    u64_to_be(msg_len * 8, bit_len);
    for (size_t i = 0; i < 8; ++i) {
      assert_const_byte(in[padded_len - 8 + i], bit_len[i]);
    }
  }

  v256 bytes_to_bits(const v8 in[32]) const {
    v256 bits;
    for (size_t i = 0; i < 32; ++i) {
      for (size_t j = 0; j < 8; ++j) {
        bits[(31 - i) * 8 + j] = in[i][j];
      }
    }
    return bits;
  }

  EltW repack_be32(const v8 in[32]) const {
    EltW h = lc_.konst(0);
    EltW two = lc_.konst(2);
    for (size_t i = 0; i < 32; ++i) {
      for (size_t j = 0; j < 8; ++j) {
        h = lc_.add(lc_.eval(in[i][7 - j]), lc_.mul(h, two));
      }
    }
    return h;
  }

  EltW repack_sha256(const sha_packed_v32 H[]) const {
    EltW h = lc_.konst(0);
    auto twok = lc_.one();
    for (size_t j = 8; j-- > 0;) {
      auto hj = sha_.bp_.unpack_v32(H[j]);
      for (size_t k = 0; k < 32; ++k) {
        h = lc_.axpy(h, twok, lc_.eval(hj[k]));
        lc_.f_.add(twok, twok);
      }
    }
    return h;
  }

  const Logic& lc_;
  const Curve& ec_;
  const Nat& order_;
  Flatsha sha_;
  Memcmp<Logic> cmp_;
  v256 bits_p_;
};

std::unique_ptr<Circuit<Field>> make_circuit() {
  QuadCircuit<Field> q(p256_base);
  const CompilerBackend cbk(&q);
  const LogicCircuit lc(&cbk, p256_base);
  ApprovalProofV1Circuit<LogicCircuit, P256> auth(lc, p256, n256_order);

  typename ApprovalProofV1Circuit<LogicCircuit, P256>::PublicInput pub;
  pub.input(lc);
  q.private_input();

  typename ApprovalProofV1Circuit<LogicCircuit, P256>::Witness witness;
  witness.input(lc);
  auth.assert_statement(pub, witness);
  return q.mkcircuit(/*nc=*/1);
}

void fill_bytes(DenseFiller<Field>& filler, const uint8_t* buf, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    filler.push_back(buf[i], 8, p256_base);
  }
}

bool fill_public_inputs(DenseFiller<Field>& filler,
                        const ApprovalProofV1Statement& statement) {
  auto pkx = parse_be_field(statement.issuer_pk_x, p256_base);
  auto pky = parse_be_field(statement.issuer_pk_y, p256_base);
  if (!pkx.has_value() || !pky.has_value()) {
    return false;
  }
  filler.push_back(p256_base.one());
  filler.push_back(pkx.value());
  filler.push_back(pky.value());
  fill_bytes(filler, statement.app_id_hash, sizeof(statement.app_id_hash));
  fill_bytes(filler, statement.policy_version, sizeof(statement.policy_version));
  fill_bytes(filler, statement.now, sizeof(statement.now));
  fill_bytes(filler, statement.challenge_nonce, sizeof(statement.challenge_nonce));
  fill_bytes(filler, statement.audience_hash,
             sizeof(statement.audience_hash));
  fill_bytes(filler, statement.approval_hash, sizeof(statement.approval_hash));
  return true;
}

class WitnessBuilder {
 public:
  WitnessBuilder() : attestation_sig_(p256_scalar, p256), approval_assertion_sig_(p256_scalar, p256) {}

  bool compute(const ApprovalProofV1ProverInput& input) {
    auto issuer_pk_x = parse_be_field(input.statement.issuer_pk_x, p256_base);
    auto issuer_pk_y = parse_be_field(input.statement.issuer_pk_y, p256_base);
    auto dpkx = parse_be_field(&input.attestation[kAttestationDevicePkXOffset],
                               p256_base);
    auto dpky = parse_be_field(&input.attestation[kAttestationDevicePkYOffset],
                               p256_base);
    if (!issuer_pk_x.has_value() || !issuer_pk_y.has_value() ||
        !dpkx.has_value() || !dpky.has_value()) {
      return false;
    }

    uint8_t auth_hash[kSHA256DigestSize];
    SHA256 auth_sha;
    auth_sha.Update(input.attestation, sizeof(input.attestation));
    auth_sha.DigestData(auth_hash);
    Nat auth_e = nat_from_be<Nat>(auth_hash);
    Nat auth_r = nat_from_be<Nat>(&input.attestation_sig[0]);
    Nat auth_s = nat_from_be<Nat>(&input.attestation_sig[Field::kBytes]);
    if (!attestation_sig_.compute_witness(issuer_pk_x.value(), issuer_pk_y.value(),
                                   auth_e, auth_r, auth_s)) {
      return false;
    }

    uint8_t assertion_hash[kSHA256DigestSize];
    SHA256 assertion_sha;
    assertion_sha.Update(input.approval_assertion, sizeof(input.approval_assertion));
    assertion_sha.DigestData(assertion_hash);
    Nat assertion_e = nat_from_be<Nat>(assertion_hash);
    Nat assertion_r = nat_from_be<Nat>(&input.approval_assertion_sig[0]);
    Nat assertion_s = nat_from_be<Nat>(&input.approval_assertion_sig[Field::kBytes]);
    if (!approval_assertion_sig_.compute_witness(dpkx.value(), dpky.value(), assertion_e,
                                        assertion_r, assertion_s)) {
      return false;
    }

    uint8_t nb = 0;
    FlatSHA256Witness::transform_and_witness_message(
        sizeof(input.attestation), input.attestation, kApprovalProofV1CircuitHashBlocks, nb,
        attestation_padded_, auth_sha_);
    if (nb != kApprovalProofV1CircuitHashBlocks) {
      return false;
    }
    FlatSHA256Witness::transform_and_witness_message(
        sizeof(input.approval_assertion), input.approval_assertion, kApprovalProofV1CircuitHashBlocks, nb,
        approval_assertion_padded_, assertion_sha_);
    return nb == kApprovalProofV1CircuitHashBlocks;
  }

  void fill(DenseFiller<Field>& filler) const {
    attestation_sig_.fill_witness(filler);
    approval_assertion_sig_.fill_witness(filler);
    fill_bytes(filler, attestation_padded_, sizeof(attestation_padded_));
    fill_bytes(filler, approval_assertion_padded_, sizeof(approval_assertion_padded_));
    for (size_t i = 0; i < kApprovalProofV1CircuitHashBlocks; ++i) {
      fill_sha(filler, auth_sha_[i]);
    }
    for (size_t i = 0; i < kApprovalProofV1CircuitHashBlocks; ++i) {
      fill_sha(filler, assertion_sha_[i]);
    }
  }

 private:
  void fill_sha(DenseFiller<Field>& filler,
                const FlatSHA256Witness::BlockWitness& bw) const {
    BitPluckerEncoder<Field, 3> encoder(p256_base);
    for (size_t k = 0; k < 48; ++k) {
      filler.push_back(encoder.mkpacked_v32(bw.outw[k]));
    }
    for (size_t k = 0; k < 64; ++k) {
      filler.push_back(encoder.mkpacked_v32(bw.oute[k]));
      filler.push_back(encoder.mkpacked_v32(bw.outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) {
      filler.push_back(encoder.mkpacked_v32(bw.h1[k]));
    }
  }

  VerifyWitness3<P256, ScalarField> attestation_sig_;
  VerifyWitness3<P256, ScalarField> approval_assertion_sig_;
  uint8_t attestation_padded_[kAttestationPaddedLength];
  uint8_t approval_assertion_padded_[kApprovalAssertionPaddedLength];
  FlatSHA256Witness::BlockWitness auth_sha_[kApprovalProofV1CircuitHashBlocks];
  FlatSHA256Witness::BlockWitness assertion_sha_[kApprovalProofV1CircuitHashBlocks];
};

}  // namespace approval_proof_v1_internal
}  // namespace proofs

namespace {

template <typename T>
bool copy_struct_from_bytes(T* out, const uint8_t* bytes, size_t len,
                            size_t expected_len) {
  if (out == nullptr || bytes == nullptr || len != expected_len) {
    return false;
  }
  memcpy(out, bytes, expected_len);
  return true;
}

}  // namespace

extern "C" {

size_t approval_proof_v1_statement_size(void) { return sizeof(ApprovalProofV1Statement); }

size_t approval_proof_v1_prover_input_size(void) { return sizeof(ApprovalProofV1ProverInput); }

void approval_proof_v1_free(void* ptr) { free(ptr); }

const char* approval_proof_v1_prover_error_string(ApprovalProofV1ProverErrorCode code) {
  switch (code) {
    case APPROVAL_PROOF_V1_PROVER_SUCCESS:
      return "success";
    case APPROVAL_PROOF_V1_PROVER_NULL_INPUT:
      return "null input";
    case APPROVAL_PROOF_V1_PROVER_INVALID_INPUT:
      return "invalid input";
    case APPROVAL_PROOF_V1_PROVER_CIRCUIT_PARSING_FAILURE:
      return "circuit parsing failure";
    case APPROVAL_PROOF_V1_PROVER_WITNESS_CREATION_FAILURE:
      return "witness creation failure";
    case APPROVAL_PROOF_V1_PROVER_PROOF_FAILURE:
      return "proof generation failure";
    case APPROVAL_PROOF_V1_PROVER_MEMORY_ALLOCATION_FAILURE:
      return "memory allocation failure";
    case APPROVAL_PROOF_V1_PROVER_CIRCUIT_ID_MISMATCH:
      return "circuit id does not match canonical expected id";
    case APPROVAL_PROOF_V1_PROVER_INPUT_TOO_LARGE:
      return "input exceeds maximum supported length";
    case APPROVAL_PROOF_V1_PROVER_MALFORMED_SIGNATURE:
      return "malformed signature or off-curve issuer public key";
  }
  return "unknown prover error";
}

const char* approval_proof_v1_verifier_error_string(ApprovalProofV1VerifierErrorCode code) {
  switch (code) {
    case APPROVAL_PROOF_V1_VERIFIER_SUCCESS:
      return "success";
    case APPROVAL_PROOF_V1_VERIFIER_NULL_INPUT:
      return "null input";
    case APPROVAL_PROOF_V1_VERIFIER_INVALID_INPUT:
      return "invalid input";
    case APPROVAL_PROOF_V1_VERIFIER_CIRCUIT_PARSING_FAILURE:
      return "circuit parsing failure";
    case APPROVAL_PROOF_V1_VERIFIER_PROOF_PARSING_FAILURE:
      return "proof parsing failure";
    case APPROVAL_PROOF_V1_VERIFIER_VERIFICATION_FAILURE:
      return "verification failure";
    case APPROVAL_PROOF_V1_VERIFIER_CIRCUIT_ID_MISMATCH:
      return "circuit id does not match canonical expected id";
    case APPROVAL_PROOF_V1_VERIFIER_INPUT_TOO_LARGE:
      return "input exceeds maximum supported length";
  }
  return "unknown verifier error";
}

const char* approval_proof_v1_circuit_generation_error_string(
    ApprovalProofV1CircuitGenerationErrorCode code) {
  switch (code) {
    case APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS:
      return "success";
    case APPROVAL_PROOF_V1_CIRCUIT_GENERATION_NULL_INPUT:
      return "null input";
    case APPROVAL_PROOF_V1_CIRCUIT_GENERATION_MEMORY_ALLOCATION_FAILURE:
      return "memory allocation failure";
    case APPROVAL_PROOF_V1_CIRCUIT_GENERATION_GENERAL_FAILURE:
      return "general failure";
  }
  return "unknown circuit generation error";
}

const char* approval_proof_v1_circuit_id_error_string(
    ApprovalProofV1CircuitIdErrorCode code) {
  switch (code) {
    case APPROVAL_PROOF_V1_CIRCUIT_ID_SUCCESS:
      return "success";
    case APPROVAL_PROOF_V1_CIRCUIT_ID_NULL_INPUT:
      return "null input";
    case APPROVAL_PROOF_V1_CIRCUIT_ID_INVALID_INPUT:
      return "invalid input";
    case APPROVAL_PROOF_V1_CIRCUIT_ID_CIRCUIT_PARSING_FAILURE:
      return "circuit parsing failure";
    case APPROVAL_PROOF_V1_CIRCUIT_ID_INPUT_TOO_LARGE:
      return "input exceeds maximum supported length";
  }
  return "unknown circuit id error";
}

// Canonical circuit id for the protocol's approval-proof-v1 circuit.
// Recomputed and asserted-against by approval_proof_v1_zk_test so a
// circuit change that alters this digest fails CI rather than silently
// shipping a verifier that no longer matches deployed provers.
const uint8_t kApprovalProofV1ExpectedCircuitId[32] = {
    0x30, 0x6e, 0x58, 0x9e, 0xde, 0x1f, 0x83, 0xac,
    0xcc, 0x87, 0x9a, 0xd3, 0x7e, 0x2d, 0xbd, 0x27,
    0xa7, 0x3c, 0x03, 0x0f, 0x95, 0x38, 0xa1, 0x30,
    0x77, 0xd5, 0xfc, 0xda, 0x2d, 0xe4, 0x02, 0xab,
};

ApprovalProofV1CircuitGenerationErrorCode generate_approval_proof_v1_circuit(
    uint8_t** circuit_bytes, size_t* circuit_len) {
  using namespace proofs;
  using namespace proofs::approval_proof_v1_internal;

  if (circuit_bytes == nullptr || circuit_len == nullptr) {
    return APPROVAL_PROOF_V1_CIRCUIT_GENERATION_NULL_INPUT;
  }

  auto circuit = make_circuit();
  CircuitWriter<Field> writer(p256_base, P256_ID);
  std::vector<uint8_t> bytes;
  writer.to_bytes(*circuit, bytes);

  uint8_t* out =
      static_cast<uint8_t*>(malloc(bytes.size() == 0 ? 1 : bytes.size()));
  if (out == nullptr) {
    return APPROVAL_PROOF_V1_CIRCUIT_GENERATION_MEMORY_ALLOCATION_FAILURE;
  }
  memcpy(out, bytes.data(), bytes.size());
  *circuit_bytes = out;
  *circuit_len = bytes.size();
  return APPROVAL_PROOF_V1_CIRCUIT_GENERATION_SUCCESS;
}

ApprovalProofV1ProverErrorCode run_approval_proof_v1_prover(const uint8_t* circuit_bytes,
                                         size_t circuit_len,
                                         const ApprovalProofV1ProverInput* input,
                                         uint8_t** proof, size_t* proof_len) {
  using namespace proofs;
  using namespace proofs::approval_proof_v1_internal;

  if (circuit_bytes == nullptr || input == nullptr || proof == nullptr ||
      proof_len == nullptr) {
    return APPROVAL_PROOF_V1_PROVER_NULL_INPUT;
  }
  if (circuit_len == 0) {
    return APPROVAL_PROOF_V1_PROVER_INVALID_INPUT;
  }
  if (circuit_len > kApprovalProofV1MaxCircuitBytes) {
    return APPROVAL_PROOF_V1_PROVER_INPUT_TOO_LARGE;
  }
  if (!valid_p256_signature_scalars(input->attestation_sig) ||
      !valid_p256_signature_scalars(input->approval_assertion_sig) ||
      !valid_p256_issuer_pk(input->statement)) {
    return APPROVAL_PROOF_V1_PROVER_MALFORMED_SIGNATURE;
  }

  ReadBuffer rb(circuit_bytes, circuit_len);
  CircuitReader<Field> reader(p256_base, P256_ID);
  auto circuit = reader.from_bytes(rb, kEnforceCircuitId);
  if (circuit == nullptr) {
    return APPROVAL_PROOF_V1_PROVER_CIRCUIT_PARSING_FAILURE;
  }
  if (memcmp(circuit->id, kApprovalProofV1ExpectedCircuitId,
             sizeof(circuit->id)) != 0) {
    return APPROVAL_PROOF_V1_PROVER_CIRCUIT_ID_MISMATCH;
  }

  Dense<Field> witness(1, circuit->ninputs);
  DenseFiller<Field> filler(witness);
  if (!fill_public_inputs(filler, input->statement)) {
    return APPROVAL_PROOF_V1_PROVER_INVALID_INPUT;
  }

  WitnessBuilder builder;
  if (!builder.compute(*input)) {
    return APPROVAL_PROOF_V1_PROVER_WITNESS_CREATION_FAILURE;
  }
  builder.fill(filler);
  if (filler.size() != circuit->ninputs) {
    return APPROVAL_PROOF_V1_PROVER_INVALID_INPUT;
  }

  const Field2 base_2(p256_base);
  const Elt2 omega{p256_base.of_string(kRootX), p256_base.of_string(kRootY)};
  const FftExtConvolutionFactory fft(p256_base, base_2, omega, 1ull << 31);
  const RSFactory rsf(fft, p256_base);
  ZkProof<Field> zkpr(*circuit, kApprovalProofV1LigeroRate, kApprovalProofV1LigeroNreq);
  Transcript tp(reinterpret_cast<const uint8_t*>(kTranscriptLabel),
                kTranscriptLabelLen, kProofVersion);
  SecureRandomEngine rng;
  ZkProver<Field, RSFactory> prover_obj(*circuit, p256_base, rsf);
  // ZkProver::commit returns void; failures bubble out via prove() which is
  // checked next. If a future longfellow-zk version adds a fallible return,
  // surface it here as APPROVAL_PROOF_V1_PROVER_PROOF_FAILURE.
  prover_obj.commit(zkpr, witness, tp, rng);
  if (!prover_obj.prove(zkpr, witness, tp)) {
    return APPROVAL_PROOF_V1_PROVER_PROOF_FAILURE;
  }

  std::vector<uint8_t> proof_bytes;
  zkpr.write(proof_bytes, p256_base);

  uint8_t* out = static_cast<uint8_t*>(
      malloc(proof_bytes.size() == 0 ? 1 : proof_bytes.size()));
  if (out == nullptr) {
    return APPROVAL_PROOF_V1_PROVER_MEMORY_ALLOCATION_FAILURE;
  }
  memcpy(out, proof_bytes.data(), proof_bytes.size());
  *proof = out;
  *proof_len = proof_bytes.size();
  return APPROVAL_PROOF_V1_PROVER_SUCCESS;
}

ApprovalProofV1ProverErrorCode run_approval_proof_v1_prover_from_bytes(
    const uint8_t* circuit_bytes, size_t circuit_len,
    const uint8_t* input_bytes, size_t input_len, uint8_t** proof,
    size_t* proof_len) {
  ApprovalProofV1ProverInput input = {};
  if (!copy_struct_from_bytes(&input, input_bytes, input_len,
                              sizeof(ApprovalProofV1ProverInput))) {
    return input_bytes == nullptr ? APPROVAL_PROOF_V1_PROVER_NULL_INPUT
                                  : APPROVAL_PROOF_V1_PROVER_INVALID_INPUT;
  }
  return run_approval_proof_v1_prover(circuit_bytes, circuit_len, &input, proof,
                            proof_len);
}

ApprovalProofV1VerifierErrorCode run_approval_proof_v1_verifier(const uint8_t* circuit_bytes,
                                             size_t circuit_len,
                                             const ApprovalProofV1Statement* statement,
                                             const uint8_t* proof,
                                             size_t proof_len) {
  using namespace proofs;
  using namespace proofs::approval_proof_v1_internal;

  if (circuit_bytes == nullptr || statement == nullptr || proof == nullptr) {
    return APPROVAL_PROOF_V1_VERIFIER_NULL_INPUT;
  }
  if (circuit_len == 0 || proof_len == 0) {
    return APPROVAL_PROOF_V1_VERIFIER_INVALID_INPUT;
  }
  if (circuit_len > kApprovalProofV1MaxCircuitBytes ||
      proof_len > kApprovalProofV1MaxProofBytes) {
    return APPROVAL_PROOF_V1_VERIFIER_INPUT_TOO_LARGE;
  }

  ReadBuffer rb_circuit(circuit_bytes, circuit_len);
  CircuitReader<Field> reader(p256_base, P256_ID);
  auto circuit = reader.from_bytes(rb_circuit, kEnforceCircuitId);
  if (circuit == nullptr) {
    return APPROVAL_PROOF_V1_VERIFIER_CIRCUIT_PARSING_FAILURE;
  }
  if (memcmp(circuit->id, kApprovalProofV1ExpectedCircuitId,
             sizeof(circuit->id)) != 0) {
    return APPROVAL_PROOF_V1_VERIFIER_CIRCUIT_ID_MISMATCH;
  }

  Dense<Field> pub(1, circuit->npub_in);
  DenseFiller<Field> filler(pub);
  if (!fill_public_inputs(filler, *statement) || filler.size() != circuit->npub_in) {
    return APPROVAL_PROOF_V1_VERIFIER_INVALID_INPUT;
  }

  const Field2 base_2(p256_base);
  const Elt2 omega{p256_base.of_string(kRootX), p256_base.of_string(kRootY)};
  const FftExtConvolutionFactory fft(p256_base, base_2, omega, 1ull << 31);
  const RSFactory rsf(fft, p256_base);
  ZkProof<Field> zkp(*circuit, kApprovalProofV1LigeroRate, kApprovalProofV1LigeroNreq);
  ReadBuffer rb_proof(proof, proof_len);
  if (!zkp.read(rb_proof, p256_base)) {
    return APPROVAL_PROOF_V1_VERIFIER_PROOF_PARSING_FAILURE;
  }

  ZkVerifier<Field, RSFactory> verifier(*circuit, rsf, kApprovalProofV1LigeroRate,
                                        kApprovalProofV1LigeroNreq, p256_base);
  Transcript tv(reinterpret_cast<const uint8_t*>(kTranscriptLabel),
                kTranscriptLabelLen, kProofVersion);
  verifier.recv_commitment(zkp, tv);
  if (!verifier.verify(zkp, pub, tv)) {
    return APPROVAL_PROOF_V1_VERIFIER_VERIFICATION_FAILURE;
  }
  return APPROVAL_PROOF_V1_VERIFIER_SUCCESS;
}

ApprovalProofV1VerifierErrorCode run_approval_proof_v1_verifier_from_bytes(
    const uint8_t* circuit_bytes, size_t circuit_len,
    const uint8_t* statement_bytes, size_t statement_len,
    const uint8_t* proof, size_t proof_len) {
  ApprovalProofV1Statement statement = {};
  if (!copy_struct_from_bytes(&statement, statement_bytes, statement_len,
                              sizeof(ApprovalProofV1Statement))) {
    return statement_bytes == nullptr ? APPROVAL_PROOF_V1_VERIFIER_NULL_INPUT
                                      : APPROVAL_PROOF_V1_VERIFIER_INVALID_INPUT;
  }
  return run_approval_proof_v1_verifier(circuit_bytes, circuit_len, &statement, proof,
                              proof_len);
}

ApprovalProofV1CircuitIdErrorCode approval_proof_v1_circuit_id(
    uint8_t id[32], const uint8_t* circuit_bytes, size_t circuit_len) {
  using namespace proofs;
  using namespace proofs::approval_proof_v1_internal;

  if (id == nullptr || circuit_bytes == nullptr) {
    return APPROVAL_PROOF_V1_CIRCUIT_ID_NULL_INPUT;
  }
  if (circuit_len == 0) {
    return APPROVAL_PROOF_V1_CIRCUIT_ID_INVALID_INPUT;
  }
  if (circuit_len > kApprovalProofV1MaxCircuitBytes) {
    return APPROVAL_PROOF_V1_CIRCUIT_ID_INPUT_TOO_LARGE;
  }
  ReadBuffer rb(circuit_bytes, circuit_len);
  CircuitReader<Field> reader(p256_base, P256_ID);
  auto circuit = reader.from_bytes(rb, kEnforceCircuitId);
  if (circuit == nullptr) {
    return APPROVAL_PROOF_V1_CIRCUIT_ID_CIRCUIT_PARSING_FAILURE;
  }
  circuit_id(id, *circuit, p256_base);
  return APPROVAL_PROOF_V1_CIRCUIT_ID_SUCCESS;
}

}  // extern "C"
