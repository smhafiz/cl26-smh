#ifndef TRECDSA_BICYCL_UTILS_H
#define TRECDSA_BICYCL_UTILS_H

#include <set>

#include "bicycl_compat.h"

namespace utils {

inline BICYCL::Mpz factorial(size_t n) {
    BICYCL::Mpz result("1");
    for (size_t j = 2; j <= n; ++j) {
        BICYCL::Mpz::mul(result, result, j);
    }
    return result;
}

inline BICYCL::Mpz cl_lagrange_at_zero(const std::set<size_t>& S, size_t i, const BICYCL::Mpz& delta) {
    BICYCL::Mpz numerator("1"), denominator("1"), result;
    for (size_t j : S) {
        if (j != i) {
            BICYCL::Mpz::mul(numerator, numerator, j);
            if (j > i) {
                BICYCL::Mpz::mul(denominator, denominator, j - i);
            } else {
                BICYCL::Mpz::mul(denominator, denominator, i - j);
                denominator.neg();
            }
        }
    }
    BICYCL::Mpz::divexact(result, delta, denominator);
    BICYCL::Mpz::mul(result, result, numerator);
    return result;
}

inline BICYCL::OpenSSL::BN lagrange_at_zero(const BICYCL::OpenSSL::ECGroup& E,
                                            const std::set<size_t>& S,
                                            size_t i) {
    BICYCL::OpenSSL::BN numerator, denominator, result;
    numerator = 1UL;
    denominator = 1UL;
    for (size_t j : S) {
        if (j != i) {
            E.mul_by_word_mod_order(numerator, j);
            if (j > i) {
                E.mul_by_word_mod_order(denominator, j - i);
            } else {
                E.mul_by_word_mod_order(denominator, i - j);
                denominator.neg();
            }
        }
    }
    E.inverse_mod_order(result, denominator);
    E.mul_mod_order(result, result, numerator);
    return result;
}

}

#endif
