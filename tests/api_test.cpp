#include <set>
#include <vector>

#include <trecdsa/Errors.h>
#include <trecdsa/Protocol.h>
#include <trecdsa/Utils.h>

namespace {

bool expect_public_api_getters_work() {
    trecdsa::RandGen random_generator;
    trecdsa::GroupParams params(trecdsa::SecLevel::_128, 5, 2, random_generator);
    trecdsa::Protocol protocol(params);

    if (protocol.params().n != 5) {
        return false;
    }

    protocol.dkg();

    if (protocol.party_count() != 5) {
        return false;
    }

    return true;
}

bool expect_run_overloads_match() {
    trecdsa::RandGen random_generator;
    trecdsa::GroupParams params(trecdsa::SecLevel::_128, 5, 2, random_generator);
    trecdsa::Protocol protocol(params);
    protocol.dkg();

    const std::set<size_t> selected_parties = {1, 2, 3};
    std::vector<unsigned char> message;
    trecdsa::randomize_message(message);

    const std::vector<trecdsa::Signature> signatures_by_return = protocol.run(selected_parties, message);

    std::vector<trecdsa::Signature> signatures_by_output;
    protocol.run(selected_parties, message, signatures_by_output);

    return signatures_by_return.size() == signatures_by_output.size() &&
           signatures_by_output.size() == selected_parties.size();
}

bool expect_verify_without_dkg_throw() {
    trecdsa::RandGen random_generator;
    trecdsa::GroupParams params(trecdsa::SecLevel::_128, 5, 2, random_generator);
    trecdsa::Protocol protocol(params);

    std::vector<trecdsa::Signature> signatures;
    std::vector<unsigned char> message;
    trecdsa::randomize_message(message);

    try {
        (void) protocol.verify(signatures, message);
        return false;
    } catch (const trecdsa::ProtocolError&) {
        return true;
    }
}

} // namespace

int main() {
    if (!expect_public_api_getters_work()) return 1;
    if (!expect_run_overloads_match()) return 2;
    if (!expect_verify_without_dkg_throw()) return 3;
    return 0;
}
