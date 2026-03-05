#include <cstdlib>
#include <set>
#include <vector>

#include <trecdsa/Errors.h>
#include <trecdsa/Protocol.h>
#include <trecdsa/Utils.h>

namespace {

bool expect_public_api_getters_work() {
    trecdsa::GroupParams params(trecdsa::SecurityLevel::_128, 5, 2);
    trecdsa::Protocol protocol(params);

    if (protocol.party_count() != 5) {
        return false;
    }
    if (protocol.threshold() != 2) {
        return false;
    }

    protocol.run_dkg();

    if (protocol.party_count() != 5) {
        return false;
    }

    return true;
}

bool expect_run_overloads_match() {
    trecdsa::GroupParams params(trecdsa::SecurityLevel::_128, 5, 2);
    trecdsa::Protocol protocol(params);
    protocol.run_dkg();

    const std::set<size_t> selected_parties = {1, 2, 3};
    std::vector<unsigned char> message;
    trecdsa::randomize_message(message);

    const std::vector<trecdsa::Signature> signatures_by_return =
        protocol.run(selected_parties, message);

    std::vector<trecdsa::Signature> signatures_by_output;
    protocol.run(selected_parties, message, signatures_by_output);

    return signatures_by_return.size() == signatures_by_output.size() &&
           signatures_by_output.size() == selected_parties.size();
}

bool expect_verify_without_dkg_throw() {
    trecdsa::GroupParams params(trecdsa::SecurityLevel::_128, 5, 2);
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

}

int main() {
    try {
        if (!expect_public_api_getters_work()) { return EXIT_FAILURE; }
        if (!expect_run_overloads_match()) { return EXIT_FAILURE; }
        if (!expect_verify_without_dkg_throw()) { return EXIT_FAILURE; }
        return EXIT_SUCCESS;
    } catch (const std::exception&) {
        return EXIT_FAILURE;
    }
}
