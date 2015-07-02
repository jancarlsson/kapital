#ifndef _KAPITAL_ENCRYPTED_COIN_HPP_
#define _KAPITAL_ENCRYPTED_COIN_HPP_

#include <cstdint>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include /*cryptopp*/ <cryptlib.h>
#include /*cryptopp*/ <eccrypto.h>
#include /*cryptopp*/ <osrng.h>
#include /*cryptopp*/ <pubkey.h>

#include <snarkfront.hpp>

#include <kapital/AddressKey.hpp>
#include <kapital/Coin.hpp>
#include <kapital/HashFunctions.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// encrypted coin 
// (cryptographic aspect)
//

template <typename FIELD> // CryptoPP::ECP or CryptoPP::EC2N
class EncryptedCoin
{
    typedef typename CryptoPP::ECIES<FIELD>::Encryptor ENCRYPTOR;
    typedef typename CryptoPP::ECIES<FIELD>::Decryptor DECRYPTOR;
    typedef CryptoPP::AutoSeededRandomPool RANDPOOL;

public:
    EncryptedCoin() = default;

    // pour new coin
    EncryptedCoin(const Coin<FIELD>& coin) {
        ENCRYPTOR ENC(coin.addr().cryptoKey());
        RANDPOOL RNG;

        std::stringstream ss;
        coin.marshal_out(ss, false); // false means omit public address
        const std::string& ptext = ss.str();
        const std::size_t ptextLen = ptext.length() + 1;

        // encrypt message
        m_cipherText = std::vector<byte>(ENC.CiphertextLength(ptextLen), 0xfb);
        ENC.Encrypt(RNG,
                    reinterpret_cast<const byte*>(ptext.data()),
                    ptextLen,
                    m_cipherText.data());
    }

    void marshal_out(std::ostream& os) const {
        snarkfront::writeStream(os, m_cipherText);
    }

    bool marshal_in(std::istream& is) {
        return snarkfront::readStream(is, m_cipherText);
    }

    // receive coin
    Coin<FIELD> decrypt(const SecretAddr<FIELD>& secretAddr,
                        const PublicAddr<FIELD>& publicAddr) const {
        DECRYPTOR DEC(secretAddr.cryptoKey());
        RANDPOOL RNG;

        // recovered text length
        const std::size_t rtextLen = DEC.MaxPlaintextLength(m_cipherText.size());
        if (rtextLen) {
            // recovered text bytes
            std::vector<byte> rtext(rtextLen, 0xfb);
            if (DEC.Decrypt(RNG,
                            m_cipherText.data(),
                            m_cipherText.size(),
                            rtext.data()).isValidCoding) {
                // convert recovered text to stream
                std::stringstream ss(std::string(rtext.begin(), rtext.end()));

                Coin<FIELD> coin;
                if (coin.marshal_in(ss, false)) { // false means omit public address
                    // set public address of recovered coin
                    coin.addr(publicAddr);

                    // must check:
                    // 1. cm matches pour transaction cm (coin exists in ledger)
                    // 2. serial number is not in ledger (not already spent)
                    if (coin.valid()) return coin;
                }
            }
        }

        return Coin<FIELD>(); // failed
    }

    Coin<FIELD> decrypt(const AddrPair<FIELD>& addr) const {
        return decrypt(addr.secretAddr(), addr.publicAddr());
    }

private:
    std::vector<byte> m_cipherText;
};

template <typename FIELD>
std::ostream& operator<< (std::ostream& os, const EncryptedCoin<FIELD>& a) {
    a.marshal_out(os);
    return os;
}

template <typename FIELD>
std::istream& operator>> (std::istream& is, EncryptedCoin<FIELD>& a) {
    a.marshal_in(is);
    return is;
}

} // namespace kapital

#endif
