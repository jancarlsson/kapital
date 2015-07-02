#ifndef _KAPITAL_ADDRESS_KEY_HPP_
#define _KAPITAL_ADDRESS_KEY_HPP_

#include <istream>
#include <ostream>

#include /*cryptopp*/ <eccrypto.h>
#include /*cryptopp*/ <files.h>
#include /*cryptopp*/ <oids.h>
#include /*cryptopp*/ <osrng.h>

#include <snarkfront.hpp>

#include <kapital/HashFunctions.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// address key pair
//
// Note: This template is not used directly. The template typedefs
//       PublicAddr and SecretAddr are used. They specialize Addr.
//

template <typename KEY>
class Addr
{
    typedef CryptoPP::AutoSeededRandomPool RANDPOOL;
    typedef CryptoPP::FileSink FILESINK;
    typedef CryptoPP::FileSource FILESOURCE;

public:
    Addr()
        : m_valid(false)
    {}

    template <typename T>
    explicit Addr(const T& a)
        : m_destHash(KEY::destHash(a))
    {
        RANDPOOL RNG;
        KEY::initialize(m_cryptoKey, a, RNG);
        m_valid = validateKey(RNG);
    }

    bool valid() const {
        return m_valid;
    }

    const HashDigest& destHash() const {
        return m_destHash;
    }

    const typename KEY::KeyType& cryptoKey() const {
        return m_cryptoKey;
    }

    void marshal_out(std::ostream& os) const {
        snarkfront::writeStream(os, m_destHash);

        FILESINK sink(os);
        m_cryptoKey.Save(sink);
    }

    bool marshal_in(std::istream& is) {
        m_valid = false;

        if (snarkfront::readStream(is, m_destHash)) {
            FILESOURCE source(is, true);
            m_cryptoKey.Load(source);

            RANDPOOL RNG;
            m_valid = validateKey(RNG);
        }

        return m_valid;
    }

private:
    template <typename RNG>
    bool validateKey(RNG& rng) const {
        return m_cryptoKey.Validate(rng, 3);
    }

    HashDigest m_destHash;
    typename KEY::KeyType m_cryptoKey;
    bool m_valid;
};

template <typename KEY>
std::ostream& operator<< (std::ostream& os, const Addr<KEY>& a) {
    a.marshal_out(os);
    return os;
}

template <typename KEY>
std::istream& operator>> (std::istream& is, Addr<KEY>& a) {
    a.marshal_in(is);
    return is;
}

////////////////////////////////////////////////////////////////////////////////
// encryption secret key
//

template <typename FIELD>
class Encrypt_SKey
{
public:
    typedef typename CryptoPP::ECIES<FIELD>::PrivateKey KeyType;

    static HashDigest destHash(const CryptoPP::OID& curve) {
        return random_array(HashDigest());
    }

    template <typename RNG>
    static void initialize(KeyType& key,
                           const CryptoPP::OID& curve,
                           RNG& rng) {
        key.Initialize(rng, curve);
    }
};

template <typename FIELD> using SecretAddr = Addr<Encrypt_SKey<FIELD>>;

////////////////////////////////////////////////////////////////////////////////
// public key
//

template <typename FIELD>
class Encrypt_PKey
{
public:
    typedef typename CryptoPP::ECIES<FIELD>::PublicKey KeyType;

    static HashDigest destHash(const Addr<Encrypt_SKey<FIELD>>& sk) {
        return addr_public_hash(sk.destHash());
    }

    template <typename RNG>
    static void initialize(KeyType& key,
                           const Addr<Encrypt_SKey<FIELD>>& sk,
                           RNG& rng) {
        sk.cryptoKey().MakePublicKey(key);
    }
};

template <typename FIELD> using PublicAddr = Addr<Encrypt_PKey<FIELD>>;

////////////////////////////////////////////////////////////////////////////////
// public/secret address key pair
//

template <typename FIELD>
class AddrPair
{
public:
    AddrPair() = default;

    AddrPair(const CryptoPP::OID& curve)
        : m_secretAddr(curve),
          m_publicAddr(m_secretAddr)
    {}

    AddrPair(const SecretAddr<FIELD>& s,
             const PublicAddr<FIELD>& p)
        : m_secretAddr(s),
          m_publicAddr(p)
    {}

    const SecretAddr<FIELD>& secretAddr() const {
        return m_secretAddr;
    }

    const PublicAddr<FIELD>& publicAddr() const {
        return m_publicAddr;
    }

    bool valid() const {
        return secretAddr().valid() && publicAddr().valid();
    }

    void marshal_out(std::ostream& os) const {
        secretAddr().marshal_out(os);
        publicAddr().marshal_out(os);
    }

    bool marshal_in(std::istream& is) {
        return
            m_secretAddr.marshal_in(is) &&
            m_publicAddr.marshal_in(is);
    }

private:
    SecretAddr<FIELD> m_secretAddr;
    PublicAddr<FIELD> m_publicAddr;
};

} // namespace kapital

#endif
