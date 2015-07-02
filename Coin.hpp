#ifndef _KAPITAL_COIN_HPP_
#define _KAPITAL_COIN_HPP_

#include <cstdint>
#include <istream>
#include <ostream>
#include <vector>

#include <snarkfront.hpp>

#include <kapital/AddressKey.hpp>
#include <kapital/HashFunctions.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// coin commitment in Merkle tree
// (cryptographic aspect)
//

template <typename FIELD> // CryptoPP::ECP or CryptoPP::EC2N
class Coin
{
public:
    // saved coin before demarshalling from disk
    // received coin before demarshalling decrypted stream from pour
    Coin()
        : m_valid(false)
    {}

    // freshly minted coin
    // newly poured coin before encryption
    Coin(const PublicAddr<FIELD>& addr)
        : m_addr(addr),
          m_rho(random_array(m_rho)),
          m_r(random_array(m_r)),
          m_valid(addr.valid())
    {}

    Coin(const AddrPair<FIELD>& addr)
        : Coin{addr.publicAddr()}
    {}

    // public address of coin
    const PublicAddr<FIELD>& addr() const { return m_addr; }
    void addr(const PublicAddr<FIELD>& a) { m_valid = (m_addr = a).valid(); }
    bool valid() const { return m_valid; }

    // random parameters
    const HashDigest& rho() const { return m_rho; }
    const HashTrapdoor& r() const { return m_r; }

    // coin value for commitment
    const std::vector<std::uint32_t>& value() const { return m_value; }
    void value(const std::uint32_t a) { m_value.push_back(a); }

    HashDigest commitment_k() const {
        return coin_commitment_k(
            r(),
            m_addr.destHash(), // public address
            rho());
    }

    HashDigest commitment_cm(const HashDigest& k) const {
        return coin_commitment_cm(
            value(),
            k);
    }

    HashDigest commitment_cm() const {
        return commitment_cm(
            commitment_k());
    }

    HashDigest serial_number(const SecretAddr<FIELD>& addr) const {
        return coin_serial_number(
            addr.destHash(), // secret address
            rho());
    }

    HashDigest serial_number(const AddrPair<FIELD>& addr) const {
        return serial_number(addr.secretAddr());
    }

    void marshal_out(std::ostream& os, const bool includeAddr = true) const {
        snarkfront::writeStream(os, value());
        snarkfront::writeStream(os, rho());
        snarkfront::writeStream(os, r());
        if (includeAddr) addr().marshal_out(os);
    }

    bool marshal_in(std::istream& is, const bool includeAddr = true) {
        return m_valid =
            snarkfront::readStream(is, m_value) &&
            snarkfront::readStream(is, m_rho) &&
            snarkfront::readStream(is, m_r) &&
            (includeAddr ? m_addr.marshal_in(is) : true);
    }

    // newly poured refund coin before encryption
    Coin refund() const {
        return Coin<FIELD>(
            m_addr,
            m_rho,             // same serial number
            random_array(r()), // different commitment
            m_valid);
    }

private:
    Coin(const PublicAddr<FIELD>& a,
         const HashDigest& b,
         const HashTrapdoor& c,
         const bool d)
        : m_addr(a),
          m_rho(b),
          m_r(c),
          m_valid(d)
    {}

    // address and commitment randomness
    PublicAddr<FIELD> m_addr;
    HashDigest m_rho;
    HashTrapdoor m_r;
    bool m_valid;

    // coin value for commitment
    std::vector<std::uint32_t> m_value;
};

template <typename FIELD>
std::ostream& operator<< (std::ostream& os, const Coin<FIELD>& a) {
    a.marshal_out(os);
    return os;
}

template <typename FIELD>
std::istream& operator>> (std::istream& is, Coin<FIELD>& a) {
    a.marshal_in(is);
    return is;
}

} // namespace kapital

#endif
