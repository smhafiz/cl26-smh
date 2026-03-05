#ifndef TRECDSA_UTILS_H
#define TRECDSA_UTILS_H

#include <set>
#include <stdexcept>
#include <vector>

#include <openssl/rand.h>

namespace trecdsa {

inline void randomize_message(std::vector<unsigned char>& m) {
    unsigned char size_byte;
    if (RAND_bytes(&size_byte, 1) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    const size_t size = (size_byte < 4) ? 4 : size_byte;
    m.resize(size);
    if (RAND_bytes(m.data(), static_cast<int>(size)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
}

inline std::set<size_t> select_parties(size_t n, size_t t) {
    if (t >= n) {
        throw std::invalid_argument("t cannot be greater than n-1");
    }
    std::set<size_t> parties;
    while (parties.size() < t + 1) {
        unsigned int r;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&r), sizeof(r)) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        parties.insert(r % n + 1);
    }
    return parties;
}

}

#endif
