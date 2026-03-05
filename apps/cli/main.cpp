#include <sstream>
#include <iostream>
#include <chrono>

#include <trecdsa/Protocol.h>
#include <trecdsa/Utils.h>

int main()
{
    trecdsa::RandGen rng;
    size_t n = 5;
    size_t t = 4;

    trecdsa::GroupParams params(trecdsa::SecLevel::_128, n, t, rng);

    trecdsa::Protocol protocol(params);
    protocol.dkg();

    std::set<size_t> party_set = trecdsa::select_parties(rng, n, t);
    std::vector<unsigned char> message;
    trecdsa::randomize_message(message);

    std::cout << "Selected parties: ";
    for (const auto& id : party_set) {
        std::cout << id << " ";
    }
    std::cout << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    std::vector<trecdsa::Signature *> signature_set(party_set.size(), nullptr);
    protocol.run(party_set, message, signature_set);
    auto end = std::chrono::high_resolution_clock::now();

    bool ret = protocol.verify(signature_set, message);
    if (ret)
    {
        std::chrono::duration<double> duration = end - start;
        std::cout << "run success in " << duration.count() / static_cast<double>(t+1) << " s" << std::endl;
    }
    else
    {
        std::cout << "run fail" << std::endl;
    }

    for(trecdsa::Signature* ptr : signature_set) {
        delete ptr;
    }

    return 0;
}
