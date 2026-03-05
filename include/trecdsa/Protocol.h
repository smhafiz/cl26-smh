#ifndef TRECDSA_PROTOCOL_H
#define TRECDSA_PROTOCOL_H

#include <set>
#include <vector>

#include <trecdsa/Party.h>
#include <trecdsa/Types.h>

namespace trecdsa {

class Protocol {
public:
    explicit Protocol(GroupParams& params);

    void dkg();
    void run(const std::set<size_t>& party_set,
             const std::vector<unsigned char>& message,
             std::vector<Signature*>& data_set_for_offline);
    bool verify(const std::vector<Signature*>& ecdsa_sig, const std::vector<unsigned char>& message) const;

    const GroupParams& params() const noexcept;
    const BICYCL::OpenSSL::ECPoint& signature_public_key() const noexcept;
    size_t party_count() const noexcept;

private:
    GroupParams& params_;
    BICYCL::OpenSSL::ECPoint sig_public_key_;
    std::vector<Party> parties_;
};

} // namespace trecdsa

#endif // TRECDSA_PROTOCOL_H
