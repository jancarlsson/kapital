#ifndef _KAPITAL_VARIABLE_HPP_
#define _KAPITAL_VARIABLE_HPP_

#include <array>
#include <cstdint>
#include <istream>
#include <ostream>
#include <vector>

#include <snarkfront.hpp>

#include <kapital/Coin.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// contract variable
//
// Note: This template is not used directly.
//

template <template <typename> class T, typename PAIRING>
class Variable
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarkfront::uint32_x<FR> U32;

    typedef typename T<PAIRING>::VAL VAL;
    typedef typename T<PAIRING>::ZK ZK;

public:
    //
    // proving side - either public or coin value
    //

    // public value
    Variable(const VAL& a)
        : m_value(a),
          m_idx(-1)
    {}

    // coin value
    template <typename FIELD>
    Variable(Coin<FIELD>& coin, const VAL& a)
        : m_value(a),
          m_idx(coin.value().size())
    {
        T<PAIRING>::initialize(coin, a);
    }

    void marshal_out(std::ostream& os) const {
        snarkfront::writeStream(os, m_value);
    }

    //
    // verification side
    //

    // demarshal public value
    Variable()
        : m_idx(-1)
    {}

    // recover from coin value
    template <typename FIELD>
    Variable(const Coin<FIELD>& coin, std::size_t& idx)
        : m_value(T<PAIRING>::initialize(coin, idx)),
          m_idx(-1)
    {}

    const VAL& operator() () const {
        return m_value;
    }

    bool marshal_in(std::istream& is) {
        return snarkfront::readStream(is, m_value);
    }

    //
    // zero knowledge proof
    //

    // public input variable
    void bless() {
        snarkfront::bless(m_variable, m_value);
    }

    // non-public witness variable
    void bless(const std::vector<U32>& w) {
        bless();
        T<PAIRING>::bless(m_variable, w, m_idx);
    }

    const ZK& operator* () const {
        return m_variable;
    }

private:
    VAL m_value;
    const std::size_t m_idx;

    ZK m_variable;
};

template <template <typename> class T, typename PAIRING>
std::ostream& operator<< (std::ostream& os, const Variable<T, PAIRING>& a) {
    a.marshal_out(os);
    return os;
}

template <template <typename> class T, typename PAIRING>
std::istream& operator>> (std::istream& is, Variable<T, PAIRING>& a) {
    a.marshal_in(is);
    return is;
}

////////////////////////////////////////////////////////////////////////////////
// 64-bit unsigned int
//

template <typename PAIRING>
class Scalar64
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarkfront::uint32_x<FR> U32;

public:
    typedef std::uint64_t VAL;
    typedef snarkfront::bigint_x<FR> ZK;

    template <typename FIELD>
    static void initialize(Coin<FIELD>& coin, const VAL& a) {
        coin.value(a);
        coin.value(a >> 32);
    }

    template <typename FIELD>
    static VAL initialize(const Coin<FIELD>& coin, std::size_t& idx) {
        const auto a =
            static_cast<VAL>(coin.value()[idx]) |
            static_cast<VAL>(coin.value()[idx + 1]) << 32;

        idx += 2;

        return a;
    }

    static void bless(const ZK& a,
                      const std::vector<U32>& w,
                      const std::size_t idx)
    {
        std::array<U32, 4> b;
        snarkfront::bless(b, a);

        assert_true(w[idx] == b[0]);
        assert_true(w[idx + 1] == b[1]);
    }
};

template <typename PAIRING> using Int = Variable<Scalar64, PAIRING>;

////////////////////////////////////////////////////////////////////////////////
// hash digest or message
//

template <typename PAIRING, std::size_t N>
class Array32
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarkfront::uint32_x<FR> U32;

public:
    typedef std::array<std::uint32_t, N> VAL;
    typedef std::array<U32, N> ZK;

    template <typename FIELD>
    static void initialize(Coin<FIELD>& coin, const VAL& a) {
        for (const auto& b : a) coin.value(b);
    }

    template <typename FIELD>
    static VAL initialize(const Coin<FIELD>& coin, std::size_t& idx) {
        VAL a;
        for (auto& b : a) b = coin.value()[idx++];
        return a;
    }

    static void bless(const ZK& a,
                      const std::vector<U32>& w,
                      const std::size_t idx)
    {
        for (std::size_t i = 0; i < N; ++i)
            assert_true(w[idx + i] == a[i]);
    }
};

template <typename PAIRING> using Array256 = Array32<PAIRING, 8>;
template <typename PAIRING> using HashDig = Variable<Array256, PAIRING>;

template <typename PAIRING> using Array512 = Array32<PAIRING, 16>;
template <typename PAIRING> using HashMsg = Variable<Array512, PAIRING>;

} // namespace kapital

#endif
