#ifndef TRECDSA_UTILS_H
#define TRECDSA_UTILS_H

#include <set>
#include <vector>

#include <trecdsa/Types.h>

namespace trecdsa {

void randomize_message(std::vector<unsigned char>& m);
Mpz cl_lagrange_at_zero(const std::set<size_t>& S, size_t i, const Mpz& delta);
BICYCL::OpenSSL::BN lagrange_at_zero(const BICYCL::OpenSSL::ECGroup& E, const std::set<size_t>& S, size_t i);
std::set<size_t> select_parties(RandGen& rng, size_t n, size_t t);

} // namespace trecdsa

#endif // TRECDSA_UTILS_H
