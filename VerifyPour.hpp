#ifndef _KAPITAL_VERIFY_POUR_HPP_
#define _KAPITAL_VERIFY_POUR_HPP_

#include <istream>
#include <sstream>
#include <string>
#include <vector>

#include <snarkfront.hpp>

#include <kapital/PourTX.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// verification side of pouring coins transaction
// (cryptographic aspect)
//

template <typename FIELD> // CryptoPP::ECP or CryptoPP::EC2N
class VerifyPour : public PourTX<FIELD>
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
    VerifyPour()
        : PourTX<FIELD>()
    {}

    // transaction information (verification side)
    const std::string& txInfo() const { return m_txInfo; }

    // encrypted new coins (verification side)
    const std::vector<EncryptedCoin<FIELD>>& encryptedCoin() const {
        return m_newEncryptedCoin;
    }

    // first step of verification - check the signature
    template <template <typename> class POUR, typename PAIRING>
    bool verifySignature(const POUR<PAIRING>& dummy) {
        PourTX<FIELD>::setProofInput(dummy);

        return m_signPKey(m_msgSignature, sigMessage());
    }

    // second step of verification - check the zero knowledge proof
    template <typename PAIRING>
    bool verifyProof(const snarklib::PPZK_VerificationKey<PAIRING>& vk) const {
        snarklib::R1Witness<typename PAIRING::Fr> input;
        snarkfront::Proof<PAIRING> proof;
        std::stringstream ssi(m_zkInput), ssp(m_zkProof);

        return
            input.marshal_in(ssi) &&
            proof.marshal_in(ssp) &&
            snarklib::strongVerify<PAIRING>(vk, input, proof);
    }

    // receive transaction from proving side
    bool marshal_in(std::istream& is) {
        m_valid = false;

        // root hash of Merkle tree
        // transaction information string
        // message signature
        // pour proof
        if (!snarkfront::readStream(is, m_merkleRoot) ||
            !snarkfront::readStream(is, m_zkProof) ||
            !snarkfront::readStream(is, m_txInfo) ||
            !snarkfront::readStream(is, m_msgSignature)) return false;

        char c;

        // old coins
        if (!(is >> m_oldCount) || (0 == m_oldCount) || (m_oldCount > 2) ||
            !is.get(c) || (' ' != c)) return false;

        m_oldSN.clear();
        m_oldH.clear();

        m_oldSN.resize(m_oldCount);
        m_oldH.resize(m_oldCount);

        for (std::size_t i = 0; i < m_oldCount; ++i) {
            if (!snarkfront::readStream(is, m_oldSN[i]) ||
                !snarkfront::readStream(is, m_oldH[i])) return false;
        }

        // new coins
        if (!(is >> m_newCount) || (0 == m_newCount) ||
            !is.get(c) || (' ' != c)) return false;

        m_newCM.clear();
        m_newEncryptedCoin.clear();

        m_newCM.resize(m_newCount);
        m_newEncryptedCoin.resize(m_newCount);

        for (std::size_t i = 0; i < m_newCount; ++i) {
            if (!snarkfront::readStream(is, m_newCM[i]) ||
                !m_newEncryptedCoin[i].marshal_in(is)) return false;
        }

        // signature public key
        if (m_valid = m_signPKey.marshal_in(is)) {
            m_hSig = hashSig(m_signPKey);
        }

        return m_valid;
    }
};

template <typename FIELD>
std::istream& operator>> (std::istream& is, VerifyPour<FIELD>& a) {
    a.marshal_in(is);
    return is;
}

} // namespace kapital

#endif
