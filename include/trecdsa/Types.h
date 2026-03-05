#ifndef TRECDSA_TYPES_H
#define TRECDSA_TYPES_H

#include <memory>

namespace trecdsa {

enum class SecurityLevel { _112 = 112, _128 = 128, _192 = 192, _256 = 256 };

class Party;
class Protocol;

class GroupParams {
public:
    GroupParams(SecurityLevel level, size_t n, size_t t);
    ~GroupParams();
    GroupParams(GroupParams&&) noexcept;
    GroupParams& operator=(GroupParams&&) noexcept;

    GroupParams(const GroupParams&) = delete;
    GroupParams& operator=(const GroupParams&) = delete;

    size_t party_count() const noexcept;
    size_t threshold() const noexcept;

    struct Impl;

private:
    Impl& impl() noexcept;
    const Impl& impl() const noexcept;
    std::unique_ptr<Impl> impl_;

    friend class Protocol;
    friend class Party;
};

class Signature {
public:
    Signature();
    Signature(const Signature&);
    Signature(Signature&&) noexcept;
    ~Signature();
    Signature& operator=(const Signature&);
    Signature& operator=(Signature&&) noexcept;

    struct Impl;

private:
    std::unique_ptr<Impl> impl_;

    friend class Protocol;
    friend class Party;
};

}

#endif
