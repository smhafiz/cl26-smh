#ifndef TRECDSA_PROTOCOL_H
#define TRECDSA_PROTOCOL_H

#include <memory>
#include <set>
#include <vector>

#include <trecdsa/Errors.h>
#include <trecdsa/Types.h>

namespace trecdsa {

class Protocol {
public:
    explicit Protocol(GroupParams& params);
    ~Protocol();
    Protocol(Protocol&& other) noexcept;
    Protocol& operator=(Protocol&& other) noexcept;

    Protocol(const Protocol&) = delete;
    Protocol& operator=(const Protocol&) = delete;

    void dkg();
    std::vector<Signature> run(const std::set<size_t>& party_set, const std::vector<unsigned char>& message);
    void run(const std::set<size_t>& party_set, const std::vector<unsigned char>& message, std::vector<Signature>& data_set_for_offline);
    bool verify(const std::vector<Signature>& ecdsa_sig, const std::vector<unsigned char>& message) const;

    const GroupParams& params() const noexcept;
    const BICYCL::OpenSSL::ECPoint& signature_public_key() const noexcept;
    size_t party_count() const noexcept;

private:
    void validate_inputs(const std::set<size_t>& party_set, const std::vector<unsigned char>& message) const;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace trecdsa

#endif // TRECDSA_PROTOCOL_H
