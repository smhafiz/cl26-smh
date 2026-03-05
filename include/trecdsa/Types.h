#ifndef TRECDSA_TYPES_H
#define TRECDSA_TYPES_H

#include <set>
#include <unordered_map>
#include <vector>

#include <bicycl.hpp>
#include <trecdsa/compat/bicycl_compat.h>

namespace trecdsa {

using Commitment = BICYCL::OpenSSL::HashAlgo::Digest;
using CommitmentSecret = std::vector<unsigned char>;

using Mpz = BICYCL::Mpz;
using QFI = BICYCL::QFI;
using RandGen = BICYCL::RandGen;
using SecLevel = BICYCL::SecLevel;
using CL_HSMqk = BICYCL::CL_HSMqk;
using ECNIZKProof = BICYCL::ECNIZKProof;
using CL_HSMqk_ZKAoKProof = BICYCL::CL_HSMqk_ZKAoKProof;
using CL_HSMqk_DL_CL_ZKProof = BICYCL::CL_HSMqk_DL_CL_ZKProof;
using CL_HSMqk_Part_Dec_ZKProof = BICYCL::CL_HSMqk_Part_Dec_ZKProof;

Mpz factorial(size_t n);

struct RoundOneData {
    size_t id;
    CL_HSMqk::CipherText enc_phi_share;
    Commitment com_i;
    CL_HSMqk_ZKAoKProof zk_proof_cl_enc;

    RoundOneData(const size_t id,
                 const CL_HSMqk::CipherText& share,
                 const Commitment& com_i,
                 const CL_HSMqk_ZKAoKProof& proof)
        : id(id), enc_phi_share(share), com_i(com_i), zk_proof_cl_enc(proof) {}
};

struct RoundOneLocalData {
    size_t id;
    BICYCL::OpenSSL::BN phi_share;
    BICYCL::OpenSSL::BN k_share;
    BICYCL::OpenSSL::ECPoint R_share;
    CL_HSMqk::CipherText enc_phi_share;
    Commitment com_i;
    CommitmentSecret open_i;
    std::unordered_map<size_t, Commitment> com_list;
    ECNIZKProof zk_proof_dl;

    size_t data_two_size = 0;

    RoundOneLocalData(const size_t id,
                      const BICYCL::OpenSSL::ECGroup& E,
                      const BICYCL::OpenSSL::BN& phi,
                      const BICYCL::OpenSSL::BN& k,
                      const BICYCL::OpenSSL::ECPoint& R,
                      const CL_HSMqk::CipherText& ct,
                      const Commitment& com_i,
                      const CommitmentSecret& open_i,
                      const ECNIZKProof& zk_proof)
        : id(id), phi_share(phi), k_share(k), R_share(E, R), enc_phi_share(ct), com_i(com_i), open_i(open_i),
          zk_proof_dl(E, zk_proof) {
        com_list.emplace(this->id, com_i);

        data_two_size += sizeof(id);
        data_two_size += phi_share.num_bytes();
        data_two_size += k_share.num_bytes();
        data_two_size += sizeof(enc_phi_share);
        data_two_size += com_i.size() * sizeof(char);
        data_two_size += open_i.size() * sizeof(unsigned char);
    }
};

struct RoundTwoData {
    size_t id;
    CL_HSMqk::CipherText phi_x_share;
    CL_HSMqk::CipherText phi_k_share;
    BICYCL::OpenSSL::ECPoint Ri;
    CommitmentSecret open_i;
    ECNIZKProof zk_proof_dl;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_x;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_k;

    RoundTwoData(const size_t id,
                 const BICYCL::OpenSSL::ECGroup& E,
                 const CL_HSMqk::CipherText& phi_x,
                 const CL_HSMqk::CipherText& phi_k,
                 const BICYCL::OpenSSL::ECPoint& R,
                 const CommitmentSecret& open_i,
                 const ECNIZKProof& zk_proof_dl,
                 const CL_HSMqk_DL_CL_ZKProof& zk_proof_dl_cl_x,
                 const CL_HSMqk_DL_CL_ZKProof& zk_proof_dl_cl_k)
        : id(id), phi_x_share(phi_x), phi_k_share(phi_k), Ri(E, R), open_i(open_i), zk_proof_dl(E, zk_proof_dl),
          zk_proof_dl_cl_x(E, zk_proof_dl_cl_x), zk_proof_dl_cl_k(E, zk_proof_dl_cl_k) {}
};

struct RoundTwoLocalData {
    size_t id;
    CL_HSMqk::CipherText enc_phi;

    RoundTwoLocalData(const size_t id, const CL_HSMqk::CipherText& phi) : id(id), enc_phi(phi) {}
};

struct RoundThreeData {
    size_t id;
    QFI c0_dec_share;
    QFI c1_dec_share;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c0;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c1;

    RoundThreeData(const size_t id,
                   const QFI& c0_dec_share,
                   const QFI& c1_dec_share,
                   const CL_HSMqk_Part_Dec_ZKProof& zk_proof_pd_c0,
                   const CL_HSMqk_Part_Dec_ZKProof& zk_proof_pd_c1)
        : id(id), c0_dec_share(c0_dec_share), c1_dec_share(c1_dec_share), zk_proof_pd_c0(zk_proof_pd_c0),
          zk_proof_pd_c1(zk_proof_pd_c1) {}
};

struct RoundThreeLocalData {
    size_t id;
    CL_HSMqk::CipherText c0;
    CL_HSMqk::CipherText c1;
    BICYCL::OpenSSL::BN rx;

    RoundThreeLocalData(const size_t id,
                        const CL_HSMqk::CipherText& c0,
                        const CL_HSMqk::CipherText& c1,
                        const BICYCL::OpenSSL::BN& rx)
        : id(id), c0(c0), c1(c1), rx(rx) {}
};

struct Signature {
    BICYCL::OpenSSL::BN rx;
    BICYCL::OpenSSL::BN s;

    Signature(const BICYCL::OpenSSL::BN& rx, const BICYCL::OpenSSL::BN& s) : rx(rx), s(s) {}
};

class GroupParams {
public:
    SecLevel sec_level;
    size_t n;
    size_t t;
    Mpz delta;
    BICYCL::OpenSSL::ECGroup ec_group;
    BICYCL::OpenSSL::HashAlgo H;
    CL_HSMqk cl_pp;

    GroupParams(SecLevel seclevel, size_t n, size_t t, RandGen& randgen)
        : sec_level(seclevel), n(n), t(t), delta(factorial(n)), ec_group(seclevel), H(seclevel),
          cl_pp(ec_group.order(), 1, seclevel, randgen) {}
};

} // namespace trecdsa

#endif // TRECDSA_TYPES_H
