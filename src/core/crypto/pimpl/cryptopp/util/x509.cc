/**                                                                                           //
 * Copyright (c) 2013-2016, The Kovri I2P Router Project                                      //
 *                                                                                            //
 * All rights reserved.                                                                       //
 *                                                                                            //
 * Redistribution and use in source and binary forms, with or without modification, are       //
 * permitted provided that the following conditions are met:                                  //
 *                                                                                            //
 * 1. Redistributions of source code must retain the above copyright notice, this list of     //
 *    conditions and the following disclaimer.                                                //
 *                                                                                            //
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list     //
 *    of conditions and the following disclaimer in the documentation and/or other            //
 *    materials provided with the distribution.                                               //
 *                                                                                            //
 * 3. Neither the name of the copyright holder nor the names of its contributors may be       //
 *    used to endorse or promote products derived from this software without specific         //
 *    prior written permission.                                                               //
 *                                                                                            //
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY        //
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF    //
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL     //
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,       //
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,               //
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    //
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,          //
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF    //
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.               //
 *                                                                                            //
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project          //
 */

#include "crypto/util/x509.h"

#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/queue.h>
#include <cryptopp/rsa.h>

#include <cstdint>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "identity.h"
#include "util/log.h"

namespace i2p {
namespace crypto {
namespace util {

/// @class X509Impl
/// @brief X.509 implementation
class X509::X509Impl {
 public:
  /// @brief Retrieves signing key from processed X.509 certificate
  /// @param certificate Certificate to extract public signing key from
  /// @return Map of signer id to public signing key
  const std::map<std::string, PublicKey> GetSigningKey(
      std::stringstream& certificate) {
    if (!ProcessCert(certificate)) {
      LogPrint(eLogError, "X509: failed to process certificate");
      // Return emptied map on failure (if not already empty)
      m_SigningKeys.clear();
      return m_SigningKeys;
    }
    LogPrint(eLogDebug, "X509: successfully acquired signing key");
    return m_SigningKeys;
  }

 private:
  /// @brief Processes an X.509 certificate
  /// @param certificate Certificate to process, as string
  /// @return False on failure
  bool ProcessCert(
      std::stringstream& certificate) {
    // Find length of stream
    certificate.seekg(0, std::ios::end);
    std::size_t cert_length = certificate.tellg();
    certificate.seekg(0, std::ios::beg);
    // Read stream
    std::vector<char>buffer(cert_length);
    certificate.read(buffer.data(), cert_length);
    std::string cert(buffer.data(), cert_length);
    // Test if stream is PEM formatted
    std::unordered_map<std::string, std::string> margin {
    { "header", "-----BEGIN CERTIFICATE-----" },
    { "footer", "-----END CERTIFICATE-----" }};
    auto pos1 = cert.find(margin["header"]);
    auto pos2 = cert.find(margin["footer"]);
    if (pos1 == std::string::npos || pos2 == std::string::npos) {
      LogPrint(eLogError, "X509: certificate is not PEM");
      return false;
    }
    // Read in base64 content and decode
    pos1 += margin["header"].size();
    pos2 -= pos1;
    std::string base64 = cert.substr(pos1, pos2);
    if (!PEMDecode(base64.data(), base64.size())) {
      LogPrint(eLogError, "X509: failed to decode certificate");
      return false;
    }
    LogPrint(eLogDebug, "X509: successfully processed certificate");
    return true;
  }

  /// @brief Decodes a PEM Base64 string, stores signing key in map
  /// @param buffer A pointer to the byte buffer to process
  /// @param length Length the size of the string, in bytes
  bool PEMDecode(
      const char* buffer,
      std::size_t length) {
    try {
      CryptoPP::ByteQueue queue;
      CryptoPP::Base64Decoder decoder;  // Plain Base64 (not I2P's)
      decoder.Attach(new CryptoPP::Redirector(queue));
      decoder.Put(reinterpret_cast<const std::uint8_t*>(buffer), length);
      // Signal the end of messages to the object
      decoder.MessageEnd();
      // Extract X.509
      CryptoPP::BERSequenceDecoder x509Cert(queue);
      CryptoPP::BERSequenceDecoder tbsCert(x509Cert);
      // Version
      std::uint32_t version;
      CryptoPP::BERGeneralDecoder context(
          tbsCert,
          CryptoPP::CONTEXT_SPECIFIC | CryptoPP::CONSTRUCTED);
      CryptoPP::BERDecodeUnsigned<std::uint32_t>(
          context,
          version,
          CryptoPP::INTEGER);
      // Serial
      CryptoPP::Integer serial;
      serial.BERDecode(tbsCert);
      // Signature
      CryptoPP::BERSequenceDecoder signature(tbsCert);
      signature.SkipAll();
      // Issuer
      std::string name;
      CryptoPP::BERSequenceDecoder issuer(tbsCert); {
        CryptoPP::BERSetDecoder c(issuer);
        c.SkipAll();
        CryptoPP::BERSetDecoder st(issuer);
        st.SkipAll();
        CryptoPP::BERSetDecoder l(issuer);
        l.SkipAll();
        CryptoPP::BERSetDecoder o(issuer);
        o.SkipAll();
        CryptoPP::BERSetDecoder ou(issuer);
        ou.SkipAll();
        CryptoPP::BERSetDecoder cn(issuer); {
          CryptoPP::BERSequenceDecoder attributes(cn); {
            CryptoPP::BERGeneralDecoder ident(
                attributes,
                CryptoPP::OBJECT_IDENTIFIER);
            ident.SkipAll();
            CryptoPP::BERDecodeTextString(
                attributes,
                name,
                CryptoPP::UTF8_STRING);
          }
        }
      }
      issuer.SkipAll();
      // Validity
      CryptoPP::BERSequenceDecoder validity(tbsCert);
      validity.SkipAll();
      // Subject
      CryptoPP::BERSequenceDecoder subject(tbsCert);
      subject.SkipAll();
      // Public key
      CryptoPP::BERSequenceDecoder publicKey(tbsCert); {
        CryptoPP::BERSequenceDecoder ident(publicKey);
        ident.SkipAll();
        CryptoPP::BERGeneralDecoder key(publicKey, CryptoPP::BIT_STRING);
        key.Skip(1);  // Must skip (possibly a bug in Crypto++)
        CryptoPP::BERSequenceDecoder keyPair(key);
        CryptoPP::Integer n;
        n.BERDecode(keyPair);
        if (name.length() > 0) {
          PublicKey value;
          n.Encode(value, sizeof(PublicKey));
          m_SigningKeys[name] = value;
        } else {
          LogPrint(eLogError, "X509: unknown issuer, skipped");
        }
      }
      publicKey.SkipAll();
      tbsCert.SkipAll();
      x509Cert.SkipAll();
      return true;
    } catch (CryptoPP::Exception& e) {
      LogPrint(eLogError, "X509: PEM decoding exception '", e.what(), "'");
      return false;
    }
  }

 private:
  // Signing keys to return <signer id, signing key>
  std::map<std::string, PublicKey> m_SigningKeys;
};

X509::X509()
    : m_X509Pimpl(
          std::make_unique<X509Impl>()) {}

X509::~X509() {}

const std::map<std::string, PublicKey> X509::GetSigningKey(
    std::stringstream& certificate) {
  return m_SigningKeys = m_X509Pimpl->GetSigningKey(certificate);
}

}  // namespace util
}  // namespace crypto
}  // namespace i2p
