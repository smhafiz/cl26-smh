#include <trecdsa/Types.h>

#include "compat/bicycl_utils.h"

namespace trecdsa {

static BICYCL::SecLevel to_bicycl_sec_level(SecurityLevel level) {
    switch (level) {
        case SecurityLevel::_112: return BICYCL::SecLevel::_112;
        case SecurityLevel::_128: return BICYCL::SecLevel::_128;
        case SecurityLevel::_192: return BICYCL::SecLevel::_192;
        case SecurityLevel::_256: return BICYCL::SecLevel::_256;
    }
    __builtin_unreachable();
}

static BICYCL::CL_HSMqk make_cl_pp(const BICYCL::OpenSSL::ECGroup& ec_group,
                                    BICYCL::SecLevel sec_level) {
    BICYCL::RandGen rng;
    return BICYCL::CL_HSMqk(ec_group.order(), 1, sec_level, rng);
}

struct GroupParams::Impl {
    BICYCL::SecLevel sec_level;
    size_t n;
    size_t t;
    BICYCL::Mpz delta;
    BICYCL::OpenSSL::ECGroup ec_group;
    BICYCL::HashAlgo H;
    BICYCL::CL_HSMqk cl_pp;

    Impl(SecurityLevel level, size_t n, size_t t)
        : sec_level(to_bicycl_sec_level(level)),
          n(n),
          t(t),
          delta(utils::factorial(n)),
          ec_group(sec_level),
          H(sec_level),
          cl_pp(make_cl_pp(ec_group, sec_level)) {}
};

GroupParams::GroupParams(SecurityLevel level, size_t n, size_t t)
    : impl_(std::make_unique<Impl>(level, n, t)) {}

GroupParams::~GroupParams() = default;
GroupParams::GroupParams(GroupParams&&) noexcept = default;
GroupParams& GroupParams::operator=(GroupParams&&) noexcept = default;

size_t GroupParams::party_count() const noexcept {
    return impl_->n;
}

size_t GroupParams::threshold() const noexcept {
    return impl_->t;
}

GroupParams::Impl& GroupParams::impl() noexcept {
    return *impl_;
}

const GroupParams::Impl& GroupParams::impl() const noexcept {
    return *impl_;
}

struct Signature::Impl {
    BICYCL::BN rx;
    BICYCL::BN s;

    Impl(const BICYCL::BN& rx, const BICYCL::BN& s) : rx(rx), s(s) {}
};

Signature::Signature() = default;

Signature::Signature(const Signature& other)
    : impl_(other.impl_ ? std::make_unique<Impl>(*other.impl_) : nullptr) {}

Signature::Signature(Signature&&) noexcept = default;
Signature::~Signature() = default;

Signature& Signature::operator=(const Signature& other) {
    impl_ = other.impl_ ? std::make_unique<Impl>(*other.impl_) : nullptr;
    return *this;
}

Signature& Signature::operator=(Signature&&) noexcept = default;

}
