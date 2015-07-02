#ifndef _KAPITAL_POUR_ZKP_HPP_
#define _KAPITAL_POUR_ZKP_HPP_

#include <array>
#include <cstdint>
#include <vector>

#include <snarkfront.hpp>

#include <kapital/PourBody.hpp>
#include <kapital/PourInput.hpp>
#include <kapital/PourTX.hpp>

namespace kapital {

////////////////////////////////////////////////////////////////////////////////
// proving and verification sides
//

template <typename PAIRING>
class PourZKP
{
    typedef typename PAIRING::Fr FR;
    typedef typename snarkfront::uint32_x<FR> U32;

public:
    template <typename FIELD>
    PourZKP(const ProvePour<FIELD>& a)
        : m_input(a)
    {
        snarkfront::end_input<PAIRING>();
        m_body = new PourBody<PAIRING>(m_input);
    }

    template <typename FIELD>
    PourZKP(const VerifyPour<FIELD>& a)
        : m_input(a),
          m_body(nullptr)
    {
        snarkfront::end_input<PAIRING>();
    }

    ~PourZKP() {
        delete m_body;
    }

    const PourInput<PAIRING>& input() const {
        return m_input;
    }

    const PourBody<PAIRING>& body() const {
        return *m_body;
    }

    const std::vector<U32>& oldValue(const std::size_t idx) const {
        return body().oldValue(idx);
    }

    const std::vector<U32>& newValue(const std::size_t idx) const {
        return body().newValue(idx);
    }

private:
    PourInput<PAIRING> m_input;
    PourBody<PAIRING>* m_body;
};

} // namespace kapital

#endif
