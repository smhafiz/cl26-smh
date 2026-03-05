#ifndef TRECDSA_PARTY_H
#define TRECDSA_PARTY_H

#include <functional>
#include <memory>
#include <set>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <trecdsa/Errors.h>
#include <trecdsa/Types.h>

namespace trecdsa {

class Party {
public:
    Party(GroupParams& params,
          size_t id,
          const CL_HSMqk::PublicKey& pk,
          const std::vector<CL_HSMqk::PublicKey>& pki_vector,
          const CL_HSMqk::SecretKey& ski,
          const BICYCL::OpenSSL::ECPoint& X,
          std::vector<BICYCL::OpenSSL::ECPoint>& X_v,
          const BICYCL::OpenSSL::BN& xi);

    void setPartySet(const std::set<size_t>& party_set);

    std::tuple<Commitment, CommitmentSecret> commit(const BICYCL::OpenSSL::ECPoint& Q) const;
    std::tuple<Commitment, CommitmentSecret> commit(const BICYCL::OpenSSL::ECPoint& Q1,
                                                    const BICYCL::OpenSSL::ECPoint& Q2) const;
    bool open(const Commitment& c, const BICYCL::OpenSSL::ECPoint& Q, const CommitmentSecret& r) const;
    bool open(const Commitment& c,
              const BICYCL::OpenSSL::ECPoint& Q1,
              const BICYCL::OpenSSL::ECPoint& Q2,
              const CommitmentSecret& r) const;

    RoundOneData handleRoundOne();
    RoundTwoData handleRoundTwo(const std::vector<std::reference_wrapper<const RoundOneData>>& data);
    RoundThreeData handleRoundThree(const std::vector<std::reference_wrapper<const RoundTwoData>>& data,
                                    const std::vector<unsigned char>& m);
    Signature handleOffline(const std::vector<std::reference_wrapper<const RoundThreeData>>& data);
    bool verify(const Signature& signature, const std::vector<unsigned char>& m) const;

private:
    void partial_decrypt(const CL_HSMqk::SecretKey& ski,
                         const CL_HSMqk::CipherText& encrypted_message,
                         QFI& part_dec);
    CL_HSMqk::ClearText agg_partial_ciphertext(const std::unordered_map<size_t, QFI>& pd_map,
                                               const CL_HSMqk::CipherText& c) const;

    std::unique_ptr<RoundOneLocalData> round1LocalData = nullptr;
    std::unique_ptr<RoundTwoLocalData> round2LocalData = nullptr;
    std::unique_ptr<RoundThreeLocalData> round3LocalData = nullptr;

    GroupParams& params;
    size_t id;
    CL_HSMqk::PublicKey pk;
    std::vector<CL_HSMqk::PublicKey> pki_vector;
    std::vector<BICYCL::OpenSSL::ECPoint> Xi_vector;
    BICYCL::OpenSSL::ECPoint X;

    CL_HSMqk::SecretKey ski;
    BICYCL::OpenSSL::BN xi;

    std::set<size_t> S;
};

} // namespace trecdsa

#endif // TRECDSA_PARTY_H
