//
// Created by qsang on 24-10-12.
//
#include <cmath>
#include <functional>
#include <numeric>
#include <set>
#include <vector>

#include <trecdsa/Protocol.h>
#include <trecdsa/Utils.h>

namespace trecdsa {
namespace OpenSSL = BICYCL::OpenSSL;

Protocol::Protocol(GroupParams& params) : params_(params), sig_public_key_(OpenSSL::ECPoint(params.ec_group))
{
    parties_.reserve(params.n);
}

void Protocol::dkg()
{
    RandGen randgen;

    const CL_HSMqk& cl_pp = params_.cl_pp;
    const OpenSSL::ECGroup& ec_group = params_.ec_group;
    const size_t n = params_.n;
    const size_t t = params_.t;
    const Mpz& delta = params_.delta;

    // Calculate coefficient bound
    Mpz coff_bound;
    size_t ell = cl_pp.secretkey_bound().nbits() - 124; // Bound from n = 20 and t = 19

    Mpz::mulby2k(coff_bound, Mpz("1"), ell);
    // std::cout << "Coefficient bound: " << coff_bound << std::endl;
    // std::cout << "Secret key bound: " << cl_pp.secretkey_bound() << std::endl;

    // Initialize vectors
    std::vector<CL_HSMqk::SecretKey> sk_list;
    std::vector<Mpz> sk_list_mpz;
    std::vector<CL_HSMqk::PublicKey> pk_list;
    sk_list.reserve(n);
    sk_list_mpz.reserve(n);
    pk_list.reserve(n);

    Mpz alpha(randgen.random_mpz(coff_bound));
    Mpz cl_u, sk;
    Mpz::mul(cl_u, alpha, delta);
    Mpz::mul(sk, cl_u, delta);

    CL_HSMqk::SecretKey sk_delta(cl_pp, sk);
    CL_HSMqk::PublicKey pk = cl_pp.keygen(sk_delta);

    std::vector<Mpz> cl_coefficient;
    cl_coefficient.reserve(t);
    for (size_t k = 0; k < t; ++k) {
        cl_coefficient.emplace_back(randgen.random_mpz(coff_bound));
    }

    // Shamir Secret Sharing
    for (size_t j = 0; j < n; ++j) {
        Mpz skj = cl_coefficient[t-1];
        for (size_t k = t-1; k > 0; --k) {
            Mpz::mul(skj, skj, Mpz(j+1));
            Mpz::add(skj, skj, cl_coefficient[k-1]);
        }
        Mpz::mul(skj, skj, Mpz(j+1));
        Mpz::add(skj, skj, cl_u);
        sk_list_mpz.push_back(skj);
        sk_list.emplace_back(cl_pp, skj);
        pk_list.emplace_back(cl_pp, sk_list.back());
    }

    // Verify CL
    Mpz cl_ut(0UL);
    std::set<size_t> SS = select_parties(randgen, n, t);
    for (size_t s : SS) {
        Mpz cl_l = cl_lagrange_at_zero(SS, s, delta);
        Mpz::mul(cl_l, cl_l, sk_list_mpz[s-1]);
        Mpz::add(cl_ut, cl_ut, cl_l);
    }

    // For ECDSA DKG
    std::vector<OpenSSL::BN> xi_list(n);
    OpenSSL::BN u(ec_group.random_mod_order());
    OpenSSL::ECPoint X(ec_group, u);

    std::vector<OpenSSL::BN> coefficient;
    std::vector<OpenSSL::ECPoint> coefficient_group;
    coefficient.reserve(t);
    coefficient_group.reserve(t);

    for (size_t k = 0; k < t; ++k) {
        coefficient.push_back(ec_group.random_mod_order());
        coefficient_group.emplace_back(ec_group, coefficient.back());
    }

    for (size_t j = 0; j < n; ++j) {
        xi_list[j] = coefficient[t-1];
        for (size_t k = t-1; k > 0; --k) {
            ec_group.mul_by_word_mod_order(xi_list[j], j+1);
            ec_group.add_mod_order(xi_list[j], xi_list[j], coefficient[k-1]);
        }
        ec_group.mul_by_word_mod_order(xi_list[j], j+1);
        ec_group.add_mod_order(xi_list[j], xi_list[j], u);
    }

    std::vector<OpenSSL::ECPoint> Xi_list;
    Xi_list.reserve(n);
    OpenSSL::ECPoint T(ec_group);
    for (const auto& xi : xi_list) {
        ec_group.scal_mul_gen(T, xi);
        Xi_list.emplace_back(ec_group, T);
    }


    OpenSSL::BN ut(0UL);
    for (size_t s : SS) {
        OpenSSL::BN l = lagrange_at_zero(ec_group, SS, s);
        ec_group.mul_mod_order(l, l, xi_list[s-1]);
        ec_group.add_mod_order(ut, ut, l);
    }

    // Initialize parties
    parties_.clear();
    parties_.reserve(n);
    for(size_t i = 0; i < n; ++i) {
        parties_.emplace_back(params_, i+1, pk, pk_list, sk_list[i], X, Xi_list, xi_list[i]);
    }

    sig_public_key_ = OpenSSL::ECPoint(ec_group, X);
}

std::vector<Signature> Protocol::run(const std::set<size_t>& party_set, const std::vector<unsigned char>& message) {
    std::vector<Signature> data_set_for_offline;
    run(party_set, message, data_set_for_offline);
    return data_set_for_offline;
}

void Protocol::run(const std::set<size_t>& party_set, const std::vector<unsigned char>& message, std::vector<Signature>& data_set_for_offline) {
    validate_inputs(party_set, message);

    for(auto& party : parties_)
    {
        party.setPartySet(party_set);
    }

    std::vector<RoundOneData> data_set_for_one;
    std::vector<std::reference_wrapper<const RoundOneData>> data_set_for_one_view;
    data_set_for_one.reserve(party_set.size());
    data_set_for_one_view.reserve(party_set.size());

    std::vector<RoundTwoData> data_set_for_two;
    std::vector<std::reference_wrapper<const RoundTwoData>> data_set_for_two_view;
    data_set_for_two.reserve(party_set.size());
    data_set_for_two_view.reserve(party_set.size());

    std::vector<RoundThreeData> data_set_for_three;
    std::vector<std::reference_wrapper<const RoundThreeData>> data_set_for_three_view;
    data_set_for_three.reserve(party_set.size());
    data_set_for_three_view.reserve(party_set.size());
    data_set_for_offline.clear();
    data_set_for_offline.reserve(party_set.size());

    // Execute Round 1
    for(auto& i : party_set) {
        data_set_for_one.push_back(parties_[i-1].handleRoundOne());
    }
    for(const RoundOneData& data : data_set_for_one) {
        data_set_for_one_view.push_back(std::cref(data));
    }

    // Execute Round 2
    for(auto& i : party_set) {
        data_set_for_two.push_back(parties_[i-1].handleRoundTwo(data_set_for_one_view));
    }
    for(const RoundTwoData& data : data_set_for_two) {
        data_set_for_two_view.push_back(std::cref(data));
    }

    // Execute Round 3
    for(auto& i : party_set){
        data_set_for_three.push_back(parties_[i-1].handleRoundThree(data_set_for_two_view, message));
    }
    for(const RoundThreeData& data : data_set_for_three) {
        data_set_for_three_view.push_back(std::cref(data));
    }

    // Execute Offline
    for(auto& i : party_set){
        data_set_for_offline.push_back(parties_[i-1].handleOffline(data_set_for_three_view));
    }
}

bool Protocol::verify(const std::vector<Signature>& ecdsa_sig, const std::vector<unsigned char>& message) const
{
    if (parties_.empty()) {
        throw ProtocolError("dkg must be run before verify");
    }
    if (ecdsa_sig.empty()) {
        throw ProtocolError("signature set cannot be empty");
    }
    if (message.empty()) {
        throw ProtocolError("message cannot be empty");
    }

    // Verify signatures
    OpenSSL::BN h (params_.H(message));
    OpenSSL::BN inv_s;
    OpenSSL::BN u1, u2;
    OpenSSL::ECPoint R (params_.ec_group);

    bool flag = true;
    for(const auto& signature : ecdsa_sig)
    {
        params_.ec_group.inverse_mod_order(inv_s, signature.s);
        params_.ec_group.mul_mod_order (u1, inv_s, h);
        params_.ec_group.mul_mod_order (u2, inv_s, signature.rx);
        params_.ec_group.scal_mul(R, u1, u2, sig_public_key_);

        OpenSSL::BN rx;
        params_.ec_group.x_coord_of_point (rx, R);
        params_.ec_group.mod_order (rx, rx);
        flag &= (rx == signature.rx);
    }
    return flag;
}

void Protocol::validate_inputs(const std::set<size_t>& party_set, const std::vector<unsigned char>& message) const {
    if (parties_.empty()) {
        throw ProtocolError("dkg must be run before protocol execution");
    }
    if (party_set.size() < params_.t + 1) {
        throw ProtocolError("party set must contain at least threshold + 1 parties");
    }
    for (size_t party_id : party_set) {
        if (party_id < 1 || party_id > params_.n) {
            throw ProtocolError("party id is out of range");
        }
    }
    if (message.empty()) {
        throw ProtocolError("message cannot be empty");
    }
}

const GroupParams& Protocol::params() const noexcept {
    return params_;
}

const OpenSSL::ECPoint& Protocol::signature_public_key() const noexcept {
    return sig_public_key_;
}

size_t Protocol::party_count() const noexcept {
    return parties_.size();
}

} // namespace trecdsa
