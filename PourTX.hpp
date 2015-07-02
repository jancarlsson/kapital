#ifndef _KAPITAL_POUR_TX_HPP_
#define _KAPITAL_POUR_TX_HPP_

#include <sstream>
#include <string>
#include <vector>

#include /*cryptopp*/ <oids.h>

#include <snarkfront.hpp>

#include <kapital/AddressKey.hpp>
#include <kapital/Coin.hpp>
#include <kapital/EncryptedCoin.hpp>
#include <kapital/HashFunctions.hpp>
#include <kapital/SignatureKey.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// base class of pouring coins transaction
// (cryptographic aspect)
//

template <typename FIELD> // CryptoPP::ECP or CryptoPP::EC2N
class PourTX
{
    typedef snarkfront::eval::MerkleAuthPath_SHA256 AUTHPATH;

public:
    virtual ~PourTX() = default;

    // validity of public signature key only, not the transaction or proof
    bool valid() const { return m_valid; }

    // public input variables
    const HashDigest& merkleRoot() const { return m_merkleRoot; }
    const HashDigest& hSig() const { return m_hSig; }
    const std::vector<HashDigest>& serial_number() const { return m_oldSN; }
    const std::vector<HashDigest>& h() const { return m_oldH; }
    const std::vector<HashDigest>& commitment_cm() const { return m_newCM; }

    // count of input and output coins
    std::size_t oldCount() const { return m_oldCount; }
    std::size_t newCount() const { return m_newCount; }

protected:
    PourTX()
        : m_valid(false),
          m_oldCount(0),
          m_newCount(0)
    {}

    PourTX(const CryptoPP::OID& curve,
           const HashDigest& merkleRoot)
        : m_signSKey(curve),
          m_signPKey(m_signSKey),
          m_valid(m_signSKey.valid() && m_signPKey.valid()),
          m_hSig(hashSig(m_signPKey)),
          m_merkleRoot(merkleRoot),
          m_oldCount(0),
          m_newCount(0)
    {}

    template <template <typename> class POUR, typename PAIRING>
    void setProofInput(const POUR<PAIRING>& dummy) {
        // zero knowledge proof inputs are part of signed message
        std::stringstream ss;
        ss << (*snarkfront::input<PAIRING>());
        m_zkInput = ss.str();
    }

    std::string sigMessage() const {
        std::stringstream ss;

        snarkfront::writeStream(ss, m_zkInput);
        snarkfront::writeStream(ss, m_zkProof);
        snarkfront::writeStream(ss, m_txInfo);
        for (const auto& a : m_newEncryptedCoin) ss << a;

        return ss.str();
    }

    // root and signature
    SecretSig<FIELD> m_signSKey;
    PublicSig<FIELD> m_signPKey;
    bool m_valid;
    HashDigest m_hSig, m_merkleRoot;

    // message to sign
    std::string m_zkInput, m_zkProof, m_txInfo, m_msgSignature;

    // old coins
    std::size_t m_oldCount;
    std::vector<HashDigest> m_oldSN, m_oldH;

    // new coins
    std::size_t m_newCount;
    std::vector<EncryptedCoin<FIELD>> m_newEncryptedCoin;
    std::vector<HashDigest> m_newCM;
};

} // namespace kapital

#endif
