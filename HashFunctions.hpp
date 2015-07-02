#ifndef _KAPITAL_HASH_FUNCTIONS_HPP_
#define _KAPITAL_HASH_FUNCTIONS_HPP_

#include <array>
#include <cassert>
#include <climits>
#include <cstdint>
#include <random>
#include <vector>

#include <snarkfront.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// hash array types
//

typedef std::array<std::uint32_t, 8> HashDigest;
typedef std::array<std::uint32_t, 12> HashTrapdoor;

template <std::size_t N>
void randomize(std::array<std::uint32_t, N>& a) {
    std::random_device rd; // uses /dev/urandom

    for (auto& r : a) {
        r = rd();

#if UINT_MAX == 65535
        // unsigned int is 16 bits (rather than 32 bits)
        r <<= 16;
        r |= rd();
#endif
    }
}

template <std::size_t N>
std::array<std::uint32_t, N>
random_array(const std::array<std::uint32_t, N>& dummy) {
    std::array<std::uint32_t, N> a;
    randomize(a);
    return a;
}

template <std::size_t N, std::size_t M>
std::array<std::array<std::uint32_t, N>, M>
zero_array(const std::array<std::array<std::uint32_t, N>, M>& dummy) {
    std::array<std::array<std::uint32_t, N>, M> a;
    for (auto& r : a) r = snarkfront::zero(r);
    return a;
}

////////////////////////////////////////////////////////////////////////////////
// H is the SHA-256 compression function
//

template <typename HASH, typename T, std::size_t N>
std::array<T, 8> H(HASH algo, const std::array<T, N>& a) {
    constexpr std::size_t msgBlockCount = (N + 15) / 16;
    constexpr std::size_t L = msgBlockCount * 16;
    std::array<T, L> m;

    for (std::size_t i = 0; i < N; ++i) m[i] = a[i];
    for (std::size_t i = N; i < L; ++i) m[i] = snarkfront::zero(m[i]);

    algo.msgInput(m);
    algo.computeHash();
    return algo.digest();
}

template <typename HASH, typename T>
std::array<T, 8> H(HASH algo, const std::vector<T>& a) {
    const std::size_t msgBlockCount = (a.size() + 15) / 16;
    const std::size_t L = msgBlockCount * 16;
    std::vector<T> m(L, snarkfront::zero(m[0]));

    for (std::size_t i = 0; i < a.size(); ++i) m[i] = a[i];

    algo.msgInput(m);
    algo.computeHash();
    return algo.digest();
}

template <typename T, std::size_t N>
std::array<T, 8> H(const std::array<T, N>& a) {
    return H(snarkfront::HASH256(a), a);
}

template <typename T>
std::array<T, 8> H(const std::vector<T>& a) {
    return H(snarkfront::HASH256(a), a);
}

template <typename T, std::size_t M, std::size_t N>
std::array<T, 8> H(const std::array<T, M>& a,
                   const std::array<T, N>& b) {
    constexpr std::size_t msgBlockCount = (M + N + 15) / 16;
    constexpr std::size_t L = msgBlockCount * 16;
    std::array<T, L> m;

    for (std::size_t i = 0; i < M; ++i) m[i] = a[i];
    for (std::size_t i = 0; i < N; ++i) m[i + L - N] = b[i];
    for (std::size_t i = M; i < 16 - N; ++i) m[i] = snarkfront::zero(m[i]);

    return H(m);
}

template <typename T, std::size_t M>
std::array<T, 8> H(const std::array<T, M>& a,
                   const std::vector<T>& b) {
    const std::size_t msgBlockCount = (M + b.size() + 15) / 16;
    const std::size_t L = msgBlockCount * 16;
    std::vector<T> m(L, snarkfront::zero(m[0]));

    for (std::size_t i = 0; i < M; ++i) m[i] = a[i];
    for (std::size_t i = 0; i < b.size(); ++i) m[i + L - b.size()] = b[i];

    return H(m);
}

////////////////////////////////////////////////////////////////////////////////
// CRH - collision resistant hash
//

template <typename T>
std::array<std::uint32_t, 8> CRH(const T& s) {
    // message will be padded
    std::vector<std::uint8_t> preImage;
    for (const auto& c : s) preImage.push_back(c);
    return cryptl::digest(cryptl::SHA256(), preImage);
}

////////////////////////////////////////////////////////////////////////////////
// PRF - pseudo random function
//

template <typename T>
std::array<T, 8> PRF_variant(const std::array<T, 8>& x,
                             const uint32_t clear_mask,
                             const uint32_t set_mask,
                             const std::array<T, 8>& z) {
    std::array<T, 16> m;

    m[0] = x[0];
    m[8] = set_mask
        ? (clear_mask & z[0]) | set_mask
        : clear_mask & z[0];

    for (std::size_t i = 1; i < 8; ++i) {
        m[i] = x[i];
        m[i + 8] = z[i];
    }

    return H(m);
}

template <typename T>
std::array<T, 8> PRF_addr(const std::array<T, 8>& x,
                          const std::array<T, 8>& z) {
    // x || 00 || z
    return PRF_variant(x,
                       0xfffffffc, // 1100 = 0xc
                       0x0,        // 0000 = 0x0
                       z);
}

template <typename T>
std::array<T, 8> PRF_sn(const std::array<T, 8>& x,
                        const std::array<T, 8>& z) {
    // x || 01 || z
    return PRF_variant(x,
                       0xfffffffe, // 1110 = 0xe
                       0x2,        // 0010 = 0x2
                       z);
}

template <typename T>
std::array<T, 8> PRF_pk(const std::array<T, 8>& x,
                        const std::array<T, 8>& z) {
    // x || 10 || z
    return PRF_variant(x,
                       0xfffffffd, // 1101 = 0xd
                       0x1,        // 0001 = 0x1
                       z);
}

template <typename T>
std::array<T, 8> PRF_pk(const std::array<T, 8>& x,
                        const bool b,
                        const std::array<T, 8>& z) {
    // x || 10 || b || z
    return PRF_variant(x,
                       b ? 0xfffffffd : 0xfffffff9, // 1101 = 0xd, 1001 = 0x9
                       b ? 0x5 : 0x1,               // 0101 = 0x5, 0001 = 0x1
                       z);
}

////////////////////////////////////////////////////////////////////////////////
// COMM - commitment
//

template <typename T>
std::array<T, 8> COMM_r(const std::array<T, 12>& r,
                        const std::array<T, 8>& a_pk,
                        const std::array<T, 8>& rho) {
    const auto tmp = H(a_pk, rho);
    return H(r, std::array<T, 4>{tmp[4], tmp[5], tmp[6], tmp[7]});
}

// commitment randomness s is deliberately ignored:
// "...k, being the output of a statistically-hiding commitment, can
// serve as randomness for the next commitment scheme."
template <typename T>
std::array<T, 8> COMM_s(const std::vector<T>& v,
                        const std::array<T, 8>& k) {
    return H(k, v);
}

////////////////////////////////////////////////////////////////////////////////
// secret to public address
//

template <typename T>
std::array<T, 8>
addr_public_hash(const std::array<T, 8>& secretAddrDestHash) {
    return H(secretAddrDestHash);
}

////////////////////////////////////////////////////////////////////////////////
// coin commitments and serial numbers
//

template <typename T>
std::array<T, 8>
coin_commitment_k(const std::array<T, 12>& r,
                  const std::array<T, 8>& publicAddrDestHash,
                  const std::array<T, 8>& rho) {
    return COMM_r(r, publicAddrDestHash, rho);
}

template <typename T>
std::array<T, 8>
coin_commitment_cm(const std::vector<T>& value,
                   const std::array<T, 8>& k) {
    return COMM_s(value, k);
}

template <typename T>
std::array<T, 8>
coin_serial_number(const std::array<T, 8>& secretAddrDestHash,
                   const std::array<T, 8>& rho) {
    return PRF_sn(secretAddrDestHash, rho);
}

////////////////////////////////////////////////////////////////////////////////
// secret address hash signature commitment
//

template <typename T>
std::array<T, 8>
sig_secret_addr(const std::array<T, 8>& secretAddrDestHash,
                const std::size_t i,
                const std::array<T, 8>& hSig) {
#ifdef USE_ASSERT
    // spend no more than two coins
    assert(i < 2);
#endif
    return PRF_pk(secretAddrDestHash, i, hSig);
}

} // namespace kapital

#endif
