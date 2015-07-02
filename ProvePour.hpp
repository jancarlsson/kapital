#ifndef _KAPITAL_PROVE_POUR_HPP_
#define _KAPITAL_PROVE_POUR_HPP_

#include <cassert>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include /*cryptopp*/ <oids.h>

#include <snarkfront.hpp>

#include <kapital/PourTX.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// proving side of pouring coins transaction
// (cryptographic aspect)
//

template <typename FIELD> // CryptoPP::ECP or CryptoPP::EC2N
class ProvePour : public PourTX<FIELD>
{
    typedef snarkfront::eval::MerkleAuthPath_SHA256 AUTHPATH;

    using PourTX<FIELD>::sigMessage;

    using PourTX<FIELD>::m_signSKey;
    using PourTX<FIELD>::m_signPKey;
    using PourTX<FIELD>::m_valid;
    using PourTX<FIELD>::m_hSig;

    using PourTX<FIELD>::m_merkleRoot;

    using PourTX<FIELD>::m_zkInput;
    using PourTX<FIELD>::m_zkProof;
    using PourTX<FIELD>::m_txInfo;
    using PourTX<FIELD>::m_msgSignature;

    using PourTX<FIELD>::m_oldCount;
    using PourTX<FIELD>::m_oldSN;
    using PourTX<FIELD>::m_oldH;

    using PourTX<FIELD>::m_newCount;
    using PourTX<FIELD>::m_newEncryptedCoin;
    using PourTX<FIELD>::m_newCM;

public:
    ProvePour(const CryptoPP::OID& curve,
              const HashDigest& merkleRoot)
        : PourTX<FIELD>(curve, merkleRoot)
    {}

    // pour from old coin
    void from(const Coin<FIELD>& coin,
              const AUTHPATH& authPath,
              const SecretAddr<FIELD>& addr) {
        ++m_oldCount;

        m_oldCoin.emplace_back(coin);
        m_oldAuthPath.emplace_back(authPath);
        m_oldSecretHash.emplace_back(addr.destHash()); // secret address

#ifdef USE_ASSERT
        // authentication paths must have same root in Merkle tree
        assert(authPath.rootHash() == m_merkleRoot);

        // authentication paths must be the same length
        assert(m_oldAuthPath.front().depth() == authPath.depth());
#endif

        // these depend on the secret address
        m_oldSN.emplace_back(coin.serial_number(addr));
        m_oldH.emplace_back(
            sig_secret_addr(addr.destHash(), // secret address
                            m_oldH.size(),
                            m_hSig));
    }

    void from(const Coin<FIELD>& coin,
              const AUTHPATH& authPath,
              const AddrPair<FIELD>& addr) {
        from(coin, authPath, addr.secretAddr());
    }

    // pour into new coin
    void to(const Coin<FIELD>& coin) {
        ++m_newCount;

        m_newCoin.emplace_back(coin);
        m_newEncryptedCoin.emplace_back(coin);
        m_newCM.emplace_back(coin.commitment_cm());
    }

    // sign transaction after generating proof
    template <typename PAIRING>
    void sign(const snarklib::PPZK_Proof<PAIRING>& a,
              const std::string& txInfo) {
        // public input variables in m_zkInput
        PourTX<FIELD>::setProofInput(a);

        // zero knowledge proof
        std::stringstream ss;
        ss << a;
        m_zkProof = ss.str();

        // transaction information string
        m_txInfo = txInfo;

        // sign message
        m_msgSignature = m_signSKey(sigMessage());
    }

    // send transaction to verification side
    void marshal_out(std::ostream& os) const {
        // root hash of Merkle tree
        snarkfront::writeStream(os, m_merkleRoot);

#ifdef USE_ASSERT
        // check for signed message including the proof
        assert(!m_zkProof.empty() && !m_msgSignature.empty());
#endif

        // pour proof
        snarkfront::writeStream(os, m_zkProof);

        // transaction information string
        snarkfront::writeStream(os, m_txInfo);

        // message signature
        snarkfront::writeStream(os, m_msgSignature);

#ifdef USE_ASSERT
        // must pour one or two old coins
        assert(1 == m_oldCount || 2 == m_oldCount);
#endif

        // old coins
        os << m_oldCount << ' ';
        for (std::size_t i = 0; i < m_oldCount; ++i) {
            // old serial numbers
            snarkfront::writeStream(os, m_oldSN[i]);

            // old secret address signature hashes
            snarkfront::writeStream(os, m_oldH[i]);
        }

#ifdef USE_ASSERT
        // must pour at least one new coin
        assert(m_newCount > 0);
#endif

        // new coins
        os << m_newCount << ' ';
        for (std::size_t i = 0; i < m_newCount; ++i) {
            // new coin commitments
            snarkfront::writeStream(os, m_newCM[i]);

            // encrypted new coins
            os << m_newEncryptedCoin[i];
        }

        // signature public key
        os << m_signPKey;
    }

    // old and new coins
    const std::vector<Coin<FIELD>>& oldCoin() const { return m_oldCoin; }
    const std::vector<Coin<FIELD>>& newCoin() const { return m_newCoin; }

    // spending secrets
    const std::vector<AUTHPATH>& authPath() const { return m_oldAuthPath; }
    const std::vector<HashDigest>& secretHash() const { return m_oldSecretHash; }

private:
    std::vector<Coin<FIELD>> m_oldCoin, m_newCoin;
    std::vector<AUTHPATH> m_oldAuthPath;
    std::vector<HashDigest> m_oldSecretHash;
};

template <typename FIELD>
std::ostream& operator<< (std::ostream& os, const ProvePour<FIELD>& a) {
    a.marshal_out(os);
    return os;
}

} // namespace kapital

#endif
