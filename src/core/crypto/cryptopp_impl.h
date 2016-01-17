#ifndef KOVRI_CORE_CRYPTO_CRYPTOPP_IMPL_H__
#define KOVRI_CORE_CRYPTO_CRYPTOPP_IMPL_H__
//
// cryptopp pimpl definitions
//

#include "Signature.h"
#include "cryptopp_rand.h"
#include <cryptopp/eccrypto.h>
#include <cryptopp/integer.h>
#include <cryptopp/dsa.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/rsa.h>

namespace i2p {
  namespace crypto {

    class DSAVerifier_Pimpl {
    public:
      DSAVerifier_Pimpl(const uint8_t* signingKey);
      bool Verify(const uint8_t* buf, size_t len, const uint8_t* signature) const;
    private:
      CryptoPP::DSA::PublicKey m_PublicKey;
    };

    class DSASigner_Pimpl {
    public:
      DSASigner_Pimpl(const uint8_t* signingPrivateKey);
      void Sign(const uint8_t* buf, size_t len, uint8_t* signature) const;
    private:
      CryptoPP::DSA::PrivateKey m_PrivateKey;
    };

        
    template<typename Hash, size_t keyLen>
    class ECDSAVerifier {
    public:
      template<typename Curve>
      ECDSAVerifier(
                    Curve curve,
                    const uint8_t* signingKey) {
      m_PublicKey.Initialize(
                             curve,
                             CryptoPP::ECP::Point(
                                                  CryptoPP::Integer(
                                                                    signingKey,
                                                                    keyLen / 2),
                                                  CryptoPP::Integer(
                                                                    signingKey + keyLen / 2, keyLen / 2)));
      }

      bool Verify(
                  const uint8_t* buf,
                  size_t len,
                  const uint8_t * signature) const {
        typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::Verifier verifier(m_PublicKey);
        return verifier.VerifyMessage(
                                      buf, len, signature, keyLen);  // signature length
      }        
  private:
    typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PublicKey m_PublicKey;
  };


  template<typename Hash>
  class ECDSASigner
    : public Signer {
  public:
    template<typename Curve>
    ECDSASigner(
                Curve curve,
                const uint8_t* signingPrivateKey,
                size_t keyLen) {
      m_PrivateKey.Initialize(
                              curve,
                              CryptoPP::Integer(
                                                signingPrivateKey,
                                                keyLen/2));  // private key length
    }
        
    void Sign(
              const uint8_t* buf,
              size_t len,
              uint8_t* signature) const {
      typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::Signer signer(m_PrivateKey);
      PRNG & rnd = GetPRNG();
      signer.SignMessage(rnd, buf, len, signature);
    }
        
  private:
    typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PrivateKey m_PrivateKey;
  };
      
  template<typename Hash, typename Curve>
  inline void CreateECDSARandomKeys(
                                    Curve curve,
                                    size_t keyLen,
                                    uint8_t* signingPrivateKey,
                                    uint8_t* signingPublicKey) {
    typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PrivateKey privateKey;
    typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PublicKey publicKey;
    i2p::crypto::PRNG & rnd = i2p::crypto::GetPRNG();
    privateKey.Initialize(rnd, curve);
    privateKey.MakePublicKey(publicKey);
    privateKey.GetPrivateExponent().Encode(signingPrivateKey, keyLen / 2);
    auto q = publicKey.GetPublicElement();
    q.x.Encode(signingPublicKey, keyLen / 2);
    q.y.Encode(signingPublicKey + keyLen / 2, keyLen / 2);
  }
  
      
  class ECDSAP256Verifier_Pimpl : public ECDSAVerifier<CryptoPP::SHA256, ECDSAP256_KEY_LENGTH> {
  public:
    ECDSAP256Verifier_Pimpl(const uint8_t* signingKey) : ECDSAVerifier(CryptoPP::ASN1::secp256r1(), signingKey) {}
    
  };
  
  class ECDSAP256Signer_Pimpl : public ECDSASigner<CryptoPP::SHA256> {
  public:
    ECDSAP256Signer_Pimpl(const uint8_t* signingPrivateKey) : ECDSASigner(CryptoPP::ASN1::secp256r1(), signingPrivateKey, ECDSAP256_KEY_LENGTH) {}
  };

      
  class ECDSAP384Verifier_Pimpl : public ECDSAVerifier<CryptoPP::SHA384, ECDSAP384_KEY_LENGTH> {
  public:
    ECDSAP384Verifier_Pimpl(const uint8_t* signingKey) : ECDSAVerifier(CryptoPP::ASN1::secp384r1(), signingKey) {}
    
  };
  
  class ECDSAP384Signer_Pimpl : public ECDSASigner<CryptoPP::SHA384> {
  public:
    ECDSAP384Signer_Pimpl(const uint8_t* signingPrivateKey) : ECDSASigner(CryptoPP::ASN1::secp384r1(), signingPrivateKey, ECDSAP384_KEY_LENGTH) {}
  };
      
  class ECDSAP521Verifier_Pimpl : public ECDSAVerifier<CryptoPP::SHA512, ECDSAP521_KEY_LENGTH> {
  public:
    ECDSAP521Verifier_Pimpl(const uint8_t* signingKey) : ECDSAVerifier(CryptoPP::ASN1::secp521r1(), signingKey) {}
  };
  
  class ECDSAP521Signer_Pimpl : public ECDSASigner<CryptoPP::SHA512> {
  public:
    ECDSAP521Signer_Pimpl(const uint8_t* signingPrivateKey) : ECDSASigner(CryptoPP::ASN1::secp521r1(), signingPrivateKey, ECDSAP521_KEY_LENGTH) {}
  };

template<typename Hash, size_t keyLen>
class RSAVerifier {
 public:
  explicit RSAVerifier(
      const uint8_t* signingKey) {
    m_PublicKey.Initialize(
        CryptoPP::Integer(
          signingKey,
          keyLen),
        CryptoPP::Integer(
          rsae));
  }

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const {
    typename CryptoPP::RSASS<CryptoPP::PKCS1v15, Hash>::Verifier verifier(m_PublicKey);
    return verifier.VerifyMessage(buf, len, signature, keyLen);  // signature length
  }

 private:
  CryptoPP::RSA::PublicKey m_PublicKey;
};


  template<typename Hash>
  class RSASigner {
  public:
    RSASigner(
       const uint8_t* signingPrivateKey,
       size_t keyLen) {
      m_PrivateKey.Initialize(
                              CryptoPP::Integer(
                                                signingPrivateKey,
                                                keyLen / 2),
                              rsae,
                               CryptoPP::Integer(
                                                signingPrivateKey + keyLen/2,
                                                keyLen/2));
    }
    
    void Sign(
              
              const uint8_t* buf,
              size_t len,
              uint8_t* signature) const {
      PRNG & rnd = GetPRNG();
      typename CryptoPP::RSASS<CryptoPP::PKCS1v15, Hash>::Signer signer(m_PrivateKey);
      signer.SignMessage(rnd, buf, len, signature);
    }

 private:
  CryptoPP::RSA::PrivateKey m_PrivateKey;
  };


    class RSASHA2562048Verifier_Pimpl : public RSAVerifier<CryptoPP::SHA256, RSASHA2562048_KEY_LENGTH> {
    public:
      explicit RSASHA2562048Verifier_Pimpl(const uint8_t* pubkey) : RSAVerifier<CryptoPP::SHA256, RSASHA2562048_KEY_LENGTH>(pubkey) {}
    };
    
    class RSASHA3843072Verifier_Pimpl : public RSAVerifier<CryptoPP::SHA384, RSASHA3843072_KEY_LENGTH> {
    public:
      explicit RSASHA3843072Verifier_Pimpl(const uint8_t* pubkey) : RSAVerifier<CryptoPP::SHA384, RSASHA3843072_KEY_LENGTH>(pubkey) {}
    };
    
    class RSASHA5124096Verifier_Pimpl : public RSAVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH> {
    public:
      RSASHA5124096Verifier_Pimpl(const uint8_t* pubkey) : RSAVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH>(pubkey) {}
    };

    class RSASHA2562048Signer_Pimpl : public RSASigner<CryptoPP::SHA256> {
    public:
      RSASHA2562048Signer_Pimpl(const uint8_t* privkey) : RSASigner<CryptoPP::SHA256>(privkey, RSASHA2562048_KEY_LENGTH * 2) {}
    };
    
    class RSASHA3843072Signer_Pimpl : public RSASigner<CryptoPP::SHA384> {
    public:
      RSASHA3843072Signer_Pimpl(const uint8_t* privkey) : RSASigner<CryptoPP::SHA384>(privkey, RSASHA3843072_KEY_LENGTH * 2) {}
    };
    
    class RSASHA5124096Signer_Pimpl : public RSASigner<CryptoPP::SHA512> {
    public:
      RSASHA5124096Signer_Pimpl(const uint8_t* privkey) : RSASigner<CryptoPP::SHA512>(privkey, RSASHA5124096_KEY_LENGTH * 2) {}
    };

template<typename Hash, size_t keyLen>
class RSARawVerifier {
 public:
  RSARawVerifier(
      const uint8_t* signingKey)
      : n(signingKey, keyLen) {}

  void Update(
      const uint8_t* buf,
      size_t len) {
    m_Hash.Update(buf, len);
  }

  bool Verify(
      const uint8_t* signature) {
    // RSA encryption first
    CryptoPP::Integer enSig(
        a_exp_b_mod_c(
          CryptoPP::Integer(
            signature,
            keyLen),
          CryptoPP::Integer(
            i2p::crypto::rsae),
          n));  // s^e mod n
    uint8_t EnSigBuf[keyLen];
    enSig.Encode(EnSigBuf, keyLen);
    uint8_t digest[Hash::DIGESTSIZE];
    m_Hash.Final(digest);
    if (static_cast<int>(keyLen) < Hash::DIGESTSIZE)
      return false;  // can't verify digest longer than key
    // we assume digest is right aligned, at least for PKCS#1 v1.5 padding
    return !memcmp(
        EnSigBuf + (keyLen - Hash::DIGESTSIZE),
        digest,
        Hash::DIGESTSIZE);
  }

 private:
  CryptoPP::Integer n;  // RSA modulus
  Hash m_Hash;
};

    
    class RSASHA5124096RawVerifier_Pimpl : public RSARawVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH> {
    public:
      RSASHA5124096RawVerifier_Pimpl(const uint8_t* signingKey) : RSARawVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH>(signingKey) {}
    };

    
    
}
}

#endif
