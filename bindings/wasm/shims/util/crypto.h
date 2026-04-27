// Browser + Node compatible crypto shim for the WASM build.

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_

#include <cstddef>
#include <cstdint>
#include <array>
#include <cstring>
#include <vector>

namespace proofs {

constexpr size_t kSHA256DigestSize = 32;
constexpr size_t kPRFKeySize = 32;
constexpr size_t kPRFInputSize = 16;
constexpr size_t kPRFOutputSize = 16;

class SHA256 {
 public:
  SHA256() = default;
  SHA256(const SHA256&) = delete;
  SHA256& operator=(const SHA256&) = delete;

  void Update(const uint8_t bytes[/*n*/], size_t n);
  void DigestData(uint8_t digest[/* kSHA256DigestSize */]);
  void CopyState(const SHA256& src);
  void Update8(uint64_t x);

 private:
  std::vector<uint8_t> data_;
};

class PRF {
 public:
  explicit PRF(const uint8_t key[/*kPRFKeySize*/]);
  PRF(const PRF&) = delete;
  PRF& operator=(const PRF&) = delete;

 void Eval(uint8_t out[/*kPRFOutputSize*/], uint8_t in[/*kPRFInputSize*/]);

 private:
  std::array<uint8_t, 240> round_key_;
};

void rand_bytes(uint8_t out[/*n*/], size_t n);

void hex_to_str(char out[/* 2*n + 1*/], const uint8_t in[/*n*/], size_t n);

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_CRYPTO_H_
