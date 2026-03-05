#include <chrono>
#include <iostream>
#include <set>
#include <vector>

#include <trecdsa/Protocol.h>
#include <trecdsa/Utils.h>

int main() {
    const size_t n = 5;
    const size_t t = 4;

    trecdsa::GroupParams params(trecdsa::SecurityLevel::_128, n, t);
    trecdsa::Protocol protocol(params);
    protocol.run_dkg();

    std::set<size_t> party_set = trecdsa::select_parties(n, t);
    std::vector<unsigned char> message;
    trecdsa::randomize_message(message);

    std::cout << "Selected parties: ";
    for (const auto& id : party_set) {
        std::cout << id << " ";
    }
    std::cout << std::endl;

    const auto start = std::chrono::high_resolution_clock::now();
    std::vector<trecdsa::Signature> signatures;
    protocol.run(party_set, message, signatures);
    const auto end = std::chrono::high_resolution_clock::now();

    if (protocol.verify(signatures, message)) {
        const std::chrono::duration<double> duration = end - start;
        std::cout << "run success in "
                  << duration.count() / static_cast<double>(t + 1) << " s" << std::endl;
    } else {
        std::cout << "run fail" << std::endl;
    }

    return 0;
}
