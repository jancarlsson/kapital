#ifndef _KAPITAL_POUR_INPUT_HPP_
#define _KAPITAL_POUR_INPUT_HPP_

#include <array>
#include <cstdint>
#include <vector>

#include <snarkfront.hpp>

#include <kapital/ProvePour.hpp>
#include <kapital/VerifyPour.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// public input variables: Merkle root and signature hash
//

template <typename PAIRING>
class PourInputRootSig
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarkfront::uint32_x<FR> U32;
    typedef std::array<U32, 8> DIGEST;

public:
    template <typename FIELD>
    PourInputRootSig(const PourTX<FIELD>& a)
        : PourInputRootSig{a.merkleRoot(), a.hSig()}
    {}

    // public input variables to zero knowledge proof
    const DIGEST& merkleRoot() const { return m_merkleRoot; }
    const DIGEST& hSig() const { return m_hSig; }

private:
    // merkleRoot   - public consensus determines valid Merkle roots
    // hSig         - signature hash must be consistent with proof body
    PourInputRootSig(const HashDigest& merkleRoot,
                     const HashDigest& hSig) {
        snarkfront::bless(m_merkleRoot, merkleRoot);
        snarkfront::bless(m_hSig, hSig);
    }

    // public input variables to zero knowledge proof
    DIGEST m_merkleRoot, m_hSig;
};

////////////////////////////////////////////////////////////////////////////////
// public input variables: old coin
//

template <typename PAIRING>
class PourInputOldCoin
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarkfront::uint32_x<FR> U32;
    typedef std::array<U32, 8> DIGEST;
    typedef typename snarkfront::eval::MerkleAuthPath_SHA256 AUTHPATH;

public:
    template <typename FIELD>
    PourInputOldCoin(const ProvePour<FIELD>& a,
                     const std::size_t idx)
        : PourInputOldCoin{a.serial_number()[idx], a.h()[idx]}
    {
        const auto& coin = a.oldCoin()[idx];

        m_k = coin.commitment_k();
        m_cm = coin.commitment_cm(m_k);
        m_secretHash = a.secretHash()[idx];
        m_publicHash = coin.addr().destHash();
        m_rho = coin.rho();

        m_r = coin.r();

        m_authPath = a.authPath()[idx];
        m_value = coin.value();
        m_sigIndex = idx;
    }

    template <typename FIELD>
    PourInputOldCoin(const VerifyPour<FIELD>& a,
                     const std::size_t idx)
        : PourInputOldCoin{a.serial_number()[idx], a.h()[idx]}
    {}

    // public input variables to zero knowledge proof
    const DIGEST& serialNumber() const { return m_serialNumber; }
    const DIGEST& h() const { return m_h; }

    // pass to proof body for convenience
    const HashDigest& k() const { return m_k; }
    const HashDigest& cm() const { return m_cm; }
    const HashDigest& secretHash() const { return m_secretHash; }
    const HashDigest& publicHash() const { return m_publicHash; }
    const HashDigest& rho() const { return m_rho; }
    const HashTrapdoor& r() const { return m_r; }
    const AUTHPATH& authPath() const { return m_authPath; }
    const std::vector<std::uint32_t>& value() const { return m_value; }
    std::size_t sigIndex() const { return m_sigIndex; }

private:
    // serialNumber - serial numbers must be consistent with proof body
    // h            - hashes must be consistent with proof body
    PourInputOldCoin(const HashDigest& serialNumber,
                     const HashDigest& h) {
        snarkfront::bless(m_serialNumber, serialNumber);
        snarkfront::bless(m_h, h);
    }

    // public input variables to zero knowledge proof
    DIGEST m_serialNumber, m_h;

    // pass to proof body for convenience
    HashDigest m_k, m_cm, m_secretHash, m_publicHash, m_rho;
    HashTrapdoor m_r;
    AUTHPATH m_authPath;
    std::vector<std::uint32_t> m_value;
    std::size_t m_sigIndex;
};

////////////////////////////////////////////////////////////////////////////////
// public input variables: new coin
//

template <typename PAIRING>
class PourInputNewCoin
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarkfront::uint32_x<FR> U32;
    typedef std::array<U32, 8> DIGEST;

public:
    template <typename FIELD>
    PourInputNewCoin(const ProvePour<FIELD>& a,
                     const std::size_t idx)
        : PourInputNewCoin{a.commitment_cm()[idx]}
    {
        const auto& coin = a.newCoin()[idx];

        m_k = coin.commitment_k();
        m_publicHash = coin.addr().destHash();
        m_rho = coin.rho();

        m_r = coin.r();
        m_value = coin.value();
    }

    template <typename FIELD>
    PourInputNewCoin(const VerifyPour<FIELD>& a,
                     const std::size_t idx)
        : PourInputNewCoin{a.commitment_cm()[idx]}
    {}

    // public input variables to zero knowledge proof
    const DIGEST& cm() const { return m_cm; }

    // pass to proof body for convenience
    const HashDigest& k() const { return m_k; }
    const HashDigest& publicHash() const { return m_publicHash; }
    const HashDigest& rho() const { return m_rho; }
    const HashTrapdoor& r() const { return m_r; }
    const std::vector<std::uint32_t>& value() const { return m_value; }

private:
    // cm           - commitments must be consistent with proof body
    PourInputNewCoin(const HashDigest& cm) {
        snarkfront::bless(m_cm, cm);
    }

    // public input variables to zero knowledge proof
    DIGEST m_cm;

    // pass to proof body for convenience
    HashDigest m_k, m_publicHash, m_rho;
    HashTrapdoor m_r;
    std::vector<std::uint32_t> m_value;
};

////////////////////////////////////////////////////////////////////////////////
// public input variables
//

template <typename PAIRING>
class PourInput
{
public:
    // proving and verification sides
    template <template <typename> class POUR, typename FIELD>
    PourInput(const POUR<FIELD>& a)
        : m_rootSig(a)
    {
        m_oldCoin.reserve(a.oldCount());
        for (std::size_t i = 0; i < a.oldCount(); ++i) {
            m_oldCoin.emplace_back(
                PourInputOldCoin<PAIRING>(a, i));
        }

        m_newCoin.reserve(a.newCount());
        for (std::size_t i = 0; i < a.newCount(); ++i) {
            m_newCoin.emplace_back(
                PourInputNewCoin<PAIRING>(a, i));
        }
    }

    const PourInputRootSig<PAIRING>& rootSig() const {
        return m_rootSig;
    }

    const std::vector<PourInputOldCoin<PAIRING>>& oldCoin() const {
        return m_oldCoin;
    }

    const std::vector<PourInputNewCoin<PAIRING>>& newCoin() const {
        return m_newCoin;
    }

private:
    PourInputRootSig<PAIRING> m_rootSig;
    std::vector<PourInputOldCoin<PAIRING>> m_oldCoin;
    std::vector<PourInputNewCoin<PAIRING>> m_newCoin;
};

} // namespace kapital

#endif
