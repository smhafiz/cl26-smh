#include <cstdlib>
#include <set>
#include <vector>

#include <trecdsa/Errors.h>
#include <trecdsa/Protocol.h>
#include <trecdsa/Utils.h>

namespace {

bool expect_insufficient_parties_throw() {
    trecdsa::GroupParams params(trecdsa::SecurityLevel::_128, 5, 2);
    trecdsa::Protocol protocol(params);
    protocol.run_dkg();

    const std::set<size_t> selected_parties = {1, 2};
    std::vector<unsigned char> message;
    trecdsa::randomize_message(message);

    try {
        (void) protocol.run(selected_parties, message);
        return false;
    } catch (const trecdsa::ProtocolError&) {
        return true;
    }
}

bool expect_out_of_range_party_throw() {
    trecdsa::GroupParams params(trecdsa::SecurityLevel::_128, 5, 2);
    trecdsa::Protocol protocol(params);
    protocol.run_dkg();

    const std::set<size_t> selected_parties = {1, 2, 6};
    std::vector<unsigned char> message;
    trecdsa::randomize_message(message);

    try {
        (void) protocol.run(selected_parties, message);
        return false;
    } catch (const trecdsa::ProtocolError&) {
        return true;
    }
}

bool expect_empty_message_throw() {
    trecdsa::GroupParams params(trecdsa::SecurityLevel::_128, 5, 2);
    trecdsa::Protocol protocol(params);
    protocol.run_dkg();

    const std::set<size_t> selected_parties = {1, 2, 3};
    const std::vector<unsigned char> empty_message;

    try {
        (void) protocol.run(selected_parties, empty_message);
        return false;
    } catch (const trecdsa::ProtocolError&) {
        return true;
    }
}

bool expect_tampered_message_fails_verify() {
    trecdsa::GroupParams params(trecdsa::SecurityLevel::_128, 5, 2);
    trecdsa::Protocol protocol(params);
    protocol.run_dkg();

    const std::set<size_t> selected_parties = {1, 2, 3};
    std::vector<unsigned char> message;
    trecdsa::randomize_message(message);

    const std::vector<trecdsa::Signature> signatures = protocol.run(selected_parties, message);

    std::vector<unsigned char> tampered_message = message;
    tampered_message[0] ^= 0x01;

    return !protocol.verify(signatures, tampered_message);
}

}

int main() {
    try {
        if (!expect_insufficient_parties_throw()) { return EXIT_FAILURE; }
        if (!expect_out_of_range_party_throw()) { return EXIT_FAILURE; }
        if (!expect_empty_message_throw()) { return EXIT_FAILURE; }
        if (!expect_tampered_message_fails_verify()) { return EXIT_FAILURE; }
        return EXIT_SUCCESS;
    } catch (const std::exception&) {
        return EXIT_FAILURE;
    }
}
