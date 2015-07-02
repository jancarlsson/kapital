#ifndef _KAPITAL_POUR_BODY_HPP_
#define _KAPITAL_POUR_BODY_HPP_

#include <array>
#include <cstdint>
#include <vector>

#include <snarkfront.hpp>

#include <kapital/PourInput.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// proof body: old coin
//

template <typename PAIRING>
class PourBodyOldCoin
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarkfront::uint32_x<FR> U32;
    typedef std::array<U32, 8> DIGEST;
    typedef std::array<U32, 12> TRAPDOOR;
    typedef typename snarkfront::zk::MerkleAuthPath_SHA256<FR> AUTHPATH;

public:
    // merkleRoot == authpath(CM)
    // CM == coin_commitment_cm(value, K)
    // publicHash == addr_public_hash(secretHash)
    // serialNumber == coin_serial_number(secretHash, rho)
    // K == coin_commitment_k(R, publicHash, rho)
    // h == sig_secret_addr(secretHash, sigIndex, hSig)
    PourBodyOldCoin(const PourInputRootSig<PAIRING>& inputRootSig,
                    const PourInputOldCoin<PAIRING>& inputCoin)
        : m_value(inputCoin.value().size())
    {
        DIGEST K, CM, secretHash, publicHash, rho;
        snarkfront::bless(K, inputCoin.k());
        snarkfront::bless(CM, inputCoin.cm());
        snarkfront::bless(secretHash, inputCoin.secretHash());
        snarkfront::bless(publicHash, inputCoin.publicHash());
        snarkfront::bless(rho, inputCoin.rho());

        TRAPDOOR R;
        snarkfront::bless(R, inputCoin.r());

        AUTHPATH path(inputCoin.authPath());
        path.updatePath(CM);
        snarkfront::assert_true(
            inputRootSig.merkleRoot() == path.rootHash());

        // coin commitment depends on value
        snarkfront::bless(m_value, inputCoin.value());

        // COMM relation between hidden K, old coin value and commitment
        snarkfront::assert_true(
            CM == coin_commitment_cm(m_value, K));

        // PRF relation between old secret and old public address
        snarkfront::assert_true(
            publicHash == addr_public_hash(secretHash));

        // PRF relation between old secret address and seed randomness
        snarkfront::assert_true(
            inputCoin.serialNumber() == coin_serial_number(secretHash, rho));

        // COMM relation between old public address, seed, and hidden K
        snarkfront::assert_true(
            K == coin_commitment_k(R, publicHash, rho));

        // PRF relation between old secret address and hash signature
        snarkfront::assert_true(
            inputCoin.h() == sig_secret_addr(secretHash,
                                             inputCoin.sigIndex(),
                                             inputRootSig.hSig()));
    }

    const std::vector<U32>& value() const { return m_value; }

private:
    // coin value is part of commitment
    std::vector<U32> m_value;
};

////////////////////////////////////////////////////////////////////////////////
// proof body: new coin
//

template <typename PAIRING>
class PourBodyNewCoin
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarkfront::uint32_x<FR> U32;
    typedef std::array<U32, 8> DIGEST;
    typedef std::array<U32, 12> TRAPDOOR;

public:
    // cm == coin_commitment_cm(value, K)
    // K == coin_commitment_k(R, public_hash, rho)
    PourBodyNewCoin(const PourInputNewCoin<PAIRING>& inputCoin)
        : m_value(inputCoin.value().size())
    {
        DIGEST K, publicHash, rho;
        snarkfront::bless(K, inputCoin.k());
        snarkfront::bless(publicHash, inputCoin.publicHash());
        snarkfront::bless(rho, inputCoin.rho());

        TRAPDOOR R;
        snarkfront::bless(R, inputCoin.r());

        // coin commitment depends on value
        snarkfront::bless(m_value, inputCoin.value());

        // COMM relation between hidden K, new coin value and commitment
        snarkfront::assert_true(
            inputCoin.cm() == coin_commitment_cm(m_value, K));

        // COMM relation between new public address, seed, and hidden K
        snarkfront::assert_true(
            K == coin_commitment_k(R, publicHash, rho));
    }

    const std::vector<U32>& value() const { return m_value; }

private:
    // coin value is part of commitment
    std::vector<U32> m_value;
};

////////////////////////////////////////////////////////////////////////////////
// proof body
//

template <typename PAIRING>
class PourBody
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarkfront::uint32_x<FR> U32;

public:
    PourBody(const PourInput<PAIRING>& a)
    {
        m_oldCoin.reserve(a.oldCoin().size());
        for (std::size_t i = 0; i < a.oldCoin().size(); ++i) {
            m_oldCoin.emplace_back(
                PourBodyOldCoin<PAIRING>(a.rootSig(), a.oldCoin()[i]));
        }

        m_newCoin.reserve(a.newCoin().size());
        for (std::size_t i = 0; i < a.newCoin().size(); ++i) {
            m_newCoin.emplace_back(
                PourBodyNewCoin<PAIRING>(a.newCoin()[i]));
        }
    }

    const std::vector<U32>& oldValue(const std::size_t idx) const {
        return m_oldCoin[idx].value();
    }

    const std::vector<U32>& newValue(const std::size_t idx) const {
        return m_newCoin[idx].value();
    }

private:
    std::vector<PourBodyOldCoin<PAIRING>> m_oldCoin;
    std::vector<PourBodyNewCoin<PAIRING>> m_newCoin;
};

} // namespace kapital

#endif
