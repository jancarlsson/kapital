#ifndef _KAPITAL_SIGNATURE_KEY_HPP_
#define _KAPITAL_SIGNATURE_KEY_HPP_

#include <istream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>

#include /*cryptopp*/ <eccrypto.h>
#include /*cryptopp*/ <files.h>
#include /*cryptopp*/ <filters.h>
#include /*cryptopp*/ <oids.h>
#include /*cryptopp*/ <osrng.h>

#include <snarkfront.hpp>

#include <kapital/HashFunctions.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// signature key
//
// Note: This template is not used directly. The template typedefs
//       PublicSig and SecretSig are used. They specialize Signature.
//

template <typename KEY>
class Signature
{
    typedef CryptoPP::AutoSeededRandomPool RANDPOOL;
    typedef CryptoPP::FileSink FILESINK;
    typedef CryptoPP::FileSource FILESOURCE;

public:
    Signature()
        : m_valid(false)
    {}

    template <typename T>
    explicit Signature(const T& a) {
        RANDPOOL RNG;
        KEY::initialize(m_cryptoKey, a, RNG);
        m_valid = validateKey(RNG);
    }

    bool valid() const {
        return m_valid;
    }

    const typename KEY::KeyType& cryptoKey() const {
        return m_cryptoKey;
    }

    // DIFFERENCE FROM ZEROCASH (BAD)
    //
    // This standard ECDSA signature scheme is malleable. The original
    // Zerocash DAP design specifies a non-malleable variant.

    template <typename... Args>
    typename KEY::ResultType operator() (const Args... parameterPack) const {
        std::stringstream ss;
        bufferMessage(ss, parameterPack...);

        RANDPOOL RNG;
        return KEY::filter(m_cryptoKey, ss.str(), RNG);
    }

    void marshal_out(std::ostream& os) const {
        FILESINK sink(os);
        m_cryptoKey.Save(sink);
    }

    bool marshal_in(std::istream& is) {
        m_valid = false;

        FILESOURCE source(is, true);
        m_cryptoKey.Load(source);

        RANDPOOL RNG;
        return m_valid = validateKey(RNG);
    }

private:
    template <typename RNG>
    bool validateKey(RNG& rng) const {
        return m_cryptoKey.Validate(rng, 3);
    }

    template <typename T>
    void bufferMessage(std::ostream& os,
                       const T& a) const {
        os << a;
    }

    template <typename T, typename... Args>
    void bufferMessage(std::ostream& os,
                       const T& a,
                       const Args... parameterPack) const {
        bufferMessage(os, a);
        bufferMessage(os, parameterPack...);
    }

    typename KEY::KeyType m_cryptoKey;
    bool m_valid;
};

template <typename KEY>
std::ostream& operator<< (std::ostream& os, const Signature<KEY>& a) {
    a.marshal_out(os);
    return os;
}

template <typename KEY>
std::istream& operator>> (std::istream& is, Signature<KEY>& a) {
    a.marshal_in(is);
    return is;
}

////////////////////////////////////////////////////////////////////////////////
// signature secret key
//

template <typename FIELD>
class Sign_SKey
{
    typedef CryptoPP::ECDSA<FIELD, CryptoPP::SHA256> BASE;

public:
    typedef typename BASE::PrivateKey KeyType;
    typedef std::string ResultType;

    template <typename RNG>
    static void initialize(KeyType& key,
                           const CryptoPP::OID& curve,
                           RNG& rng) {
        key.Initialize(rng, curve);
    }

    template <typename RNG>
    static std::string filter(const KeyType& key, const std::string& msg, RNG& rng) {
        std::string signature;

        CryptoPP::StringSource(
            msg,
            true,
            new CryptoPP::SignerFilter(
                rng,
                typename BASE::Signer(key),
                new CryptoPP::StringSink(signature)));

        return signature;
    }
};

template <typename FIELD> using SecretSig = Signature<Sign_SKey<FIELD>>;

////////////////////////////////////////////////////////////////////////////////
// signature public key
//

template <typename FIELD>
class Sign_PKey
{
    typedef CryptoPP::ECDSA<FIELD, CryptoPP::SHA256> BASE;

public:
    typedef typename BASE::PublicKey KeyType;
    typedef bool ResultType;

    template <typename RNG>
    static void initialize(KeyType& key,
                           const Signature<Sign_SKey<FIELD>>& ssk,
                           RNG& rng) {
        ssk.cryptoKey().MakePublicKey(key);
    }

    template <typename RNG>
    static bool filter(const KeyType& key, const std::string& msg, RNG& rng) {
        bool valid;

        CryptoPP::StringSource(
            msg,
            true,
            new CryptoPP::SignatureVerificationFilter(
                typename BASE::Verifier(key),
                new CryptoPP::ArraySink(
                    reinterpret_cast<byte*>(std::addressof(valid)),
                    sizeof(valid))));

        return valid;
    }
};

template <typename FIELD> using PublicSig = Signature<Sign_PKey<FIELD>>;

// hash of public signature key
template <typename FIELD>
HashDigest hashSig(const PublicSig<FIELD>& a) {
    if (a.valid()) {
        std::stringstream ss;
        CryptoPP::FileSink sink(ss);
        a.cryptoKey().Save(sink);

        return CRH(ss.str());

    } else {
        return snarkfront::zero(HashDigest());
    }
}

} // namespace kapital

#endif
