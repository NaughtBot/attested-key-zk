#include "util/crypto.h"

#include <cstddef>
#include <cstdint>

#include <array>
#include <vector>

#include <emscripten.h>

namespace proofs {
namespace {

constexpr uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

constexpr uint8_t kAesSBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

constexpr uint8_t kAesRcon[15] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
};

inline uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

uint32_t load_be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

void store_be32(uint8_t* out, uint32_t x) {
  out[0] = static_cast<uint8_t>(x >> 24);
  out[1] = static_cast<uint8_t>(x >> 16);
  out[2] = static_cast<uint8_t>(x >> 8);
  out[3] = static_cast<uint8_t>(x);
}

void sha256_digest(const uint8_t* data, size_t n,
                   uint8_t digest[kSHA256DigestSize]) {
  std::vector<uint8_t> padded;
  padded.reserve(n + 72);
  if (n > 0) {
    padded.insert(padded.end(), data, data + n);
  }
  padded.push_back(0x80);
  while ((padded.size() % 64) != 56) {
    padded.push_back(0);
  }

  const uint64_t bit_len = static_cast<uint64_t>(n) * 8;
  for (int i = 7; i >= 0; --i) {
    padded.push_back(static_cast<uint8_t>(bit_len >> (i * 8)));
  }

  uint32_t h[8] = {
      0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
      0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
  };

  for (size_t off = 0; off < padded.size(); off += 64) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
      w[i] = load_be32(&padded[off + i * 4]);
    }
    for (size_t i = 16; i < 64; ++i) {
      const uint32_t s0 =
          rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const uint32_t s1 =
          rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    uint32_t f = h[5];
    uint32_t g = h[6];
    uint32_t hh = h[7];

    for (size_t i = 0; i < 64; ++i) {
      const uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const uint32_t ch = (e & f) ^ ((~e) & g);
      const uint32_t temp1 = hh + s1 + ch + kSha256K[i] + w[i];
      const uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temp2 = s0 + maj;

      hh = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }

  for (size_t i = 0; i < 8; ++i) {
    store_be32(&digest[i * 4], h[i]);
  }
}

inline uint8_t xtime(uint8_t x) {
  return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

void aes_sub_bytes(uint8_t state[16]) {
  for (size_t i = 0; i < 16; ++i) {
    state[i] = kAesSBox[state[i]];
  }
}

void aes_shift_rows(uint8_t state[16]) {
  uint8_t tmp[16];
  tmp[0] = state[0];
  tmp[1] = state[5];
  tmp[2] = state[10];
  tmp[3] = state[15];
  tmp[4] = state[4];
  tmp[5] = state[9];
  tmp[6] = state[14];
  tmp[7] = state[3];
  tmp[8] = state[8];
  tmp[9] = state[13];
  tmp[10] = state[2];
  tmp[11] = state[7];
  tmp[12] = state[12];
  tmp[13] = state[1];
  tmp[14] = state[6];
  tmp[15] = state[11];
  memcpy(state, tmp, sizeof(tmp));
}

void aes_mix_columns(uint8_t state[16]) {
  for (size_t c = 0; c < 4; ++c) {
    const size_t i = c * 4;
    const uint8_t s0 = state[i + 0];
    const uint8_t s1 = state[i + 1];
    const uint8_t s2 = state[i + 2];
    const uint8_t s3 = state[i + 3];
    const uint8_t t = s0 ^ s1 ^ s2 ^ s3;
    state[i + 0] = static_cast<uint8_t>(s0 ^ t ^ xtime(s0 ^ s1));
    state[i + 1] = static_cast<uint8_t>(s1 ^ t ^ xtime(s1 ^ s2));
    state[i + 2] = static_cast<uint8_t>(s2 ^ t ^ xtime(s2 ^ s3));
    state[i + 3] = static_cast<uint8_t>(s3 ^ t ^ xtime(s3 ^ s0));
  }
}

void aes_add_round_key(uint8_t state[16], const uint8_t* round_key) {
  for (size_t i = 0; i < 16; ++i) {
    state[i] ^= round_key[i];
  }
}

void aes_key_expansion_256(const uint8_t key[32], uint8_t round_key[240]) {
  memcpy(round_key, key, 32);
  size_t bytes_generated = 32;
  size_t rcon_index = 1;
  uint8_t temp[4];

  while (bytes_generated < 240) {
    for (size_t i = 0; i < 4; ++i) {
      temp[i] = round_key[bytes_generated - 4 + i];
    }

    if (bytes_generated % 32 == 0) {
      const uint8_t t0 = temp[0];
      temp[0] = kAesSBox[temp[1]];
      temp[1] = kAesSBox[temp[2]];
      temp[2] = kAesSBox[temp[3]];
      temp[3] = kAesSBox[t0];
      temp[0] ^= kAesRcon[rcon_index++];
    } else if (bytes_generated % 32 == 16) {
      temp[0] = kAesSBox[temp[0]];
      temp[1] = kAesSBox[temp[1]];
      temp[2] = kAesSBox[temp[2]];
      temp[3] = kAesSBox[temp[3]];
    }

    for (size_t i = 0; i < 4; ++i) {
      round_key[bytes_generated] =
          round_key[bytes_generated - 32] ^ temp[i];
      ++bytes_generated;
    }
  }
}

void aes_encrypt_block_256(const uint8_t round_key[240], const uint8_t in[16],
                           uint8_t out[16]) {
  uint8_t state[16];
  memcpy(state, in, sizeof(state));

  aes_add_round_key(state, round_key);
  for (size_t round = 1; round < 14; ++round) {
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_mix_columns(state);
    aes_add_round_key(state, &round_key[round * 16]);
  }

  aes_sub_bytes(state);
  aes_shift_rows(state);
  aes_add_round_key(state, &round_key[14 * 16]);
  memcpy(out, state, sizeof(state));
}

EM_JS(void, attested_key_zk_rand_bytes_js, (uint8_t* out, size_t n), {
  const target = HEAPU8.subarray(out, out + n);
  const g = globalThis;
  if (g && g.crypto && typeof g.crypto.getRandomValues === 'function') {
    g.crypto.getRandomValues(target);
    return;
  }
  if (typeof require === 'function') {
    const crypto = require('node:crypto');
    crypto.randomFillSync(target);
    return;
  }
  throw new Error('No secure random source available');
});

}  // namespace

void SHA256::Update(const uint8_t bytes[/*n*/], size_t n) {
  data_.insert(data_.end(), bytes, bytes + n);
}

void SHA256::DigestData(uint8_t digest[/* kSHA256DigestSize */]) {
  sha256_digest(data_.data(), data_.size(), digest);
}

void SHA256::CopyState(const SHA256& src) { data_ = src.data_; }

void SHA256::Update8(uint64_t x) {
  uint8_t buf[8];
  for (size_t i = 0; i < 8; ++i) {
    buf[i] = static_cast<uint8_t>(x & 0xff);
    x >>= 8;
  }
  Update(buf, 8);
}

PRF::PRF(const uint8_t key[/*kPRFKeySize*/]) {
  aes_key_expansion_256(key, round_key_.data());
}

void PRF::Eval(uint8_t out[/*kPRFOutputSize*/], uint8_t in[/*kPRFInputSize*/]) {
  aes_encrypt_block_256(round_key_.data(), in, out);
}

void rand_bytes(uint8_t out[/*n*/], size_t n) {
  attested_key_zk_rand_bytes_js(out, n);
}

void hex_to_str(char out[/* 2*n + 1*/], const uint8_t in[/*n*/], size_t n) {
  for (size_t i = 0; i < n; ++i) {
    out[2 * i] = "0123456789abcdef"[in[i] >> 4];
    out[2 * i + 1] = "0123456789abcdef"[in[i] & 0xf];
  }
  out[2 * n] = '\0';
}

}  // namespace proofs
