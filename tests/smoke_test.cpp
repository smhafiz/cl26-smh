#include <cstdlib>
#include <set>
#include <vector>

#include <trecdsa/Protocol.h>
#include <trecdsa/Utils.h>

int main() {
    try {
        const size_t party_count = 5;
        const size_t threshold = 2;

        trecdsa::GroupParams params(trecdsa::SecurityLevel::_128, party_count, threshold);
        trecdsa::Protocol protocol(params);
        protocol.run_dkg();

        const std::set<size_t> selected_parties = {1, 2, 3};
        std::vector<unsigned char> message;
        trecdsa::randomize_message(message);

        const std::vector<trecdsa::Signature> signatures = protocol.run(selected_parties, message);
        if (signatures.size() != selected_parties.size()) {
            return EXIT_FAILURE;
        }

        if (!protocol.verify(signatures, message)) {
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    } catch (const std::exception&) {
        return EXIT_FAILURE;
    }
}
