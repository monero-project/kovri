/**
 * Copyright (c) 2013-2016, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project
 */

#include "Reseed.h"

#include <string.h>

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "Identity.h"
#include "NetworkDatabase.h"
#include "crypto/Rand.h"
#include "crypto/CryptoConst.h"
#include "crypto/Signature.h"
#include "util/HTTP.h"
#include "util/I2PEndian.h"
#include "util/Filesystem.h"
#include "util/Log.h"

// do this AFTER other includes
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/arc4.h>
#include <cryptopp/asn.h>
#include <cryptopp/base64.h>
#include <cryptopp/crc.h>
#include <cryptopp/hmac.h>
#include <cryptopp/zinflate.h>

namespace i2p {
namespace data {

static std::vector<std::string> reseedHosts = {
  "https://i2p.mooo.com/netDb/",
  "https://reseed.i2p-projekt.de/",
  "https://reseed.i2p.vzaws.com:8443/",
  "https://uk.reseed.i2p2.no:444/",
  "https://us.reseed.i2p2.no:444/",
  "https://user.mx24.eu/",
  //"https://download.xxlspeed.com/",  // Requires SNI
  //"https://i2p-0.manas.ca:8443/",  // Requires SNI
  //"https://i2pseed.zarrenspry.info/", // Host not found (authoritative)
  //"https://netdb.i2p2.no/",  // Requires SNI
};

Reseeder::Reseeder() {}
Reseeder::~Reseeder() {}

int Reseeder::ReseedNowSU3() {
  size_t s = reseedHosts.size();
  size_t ind = i2p::crypto::RandInRange<size_t>(size_t{0}, s - size_t{1});
  std::string& reseedHost = reseedHosts[ind];
  return ReseedFromSU3(reseedHost);
}

int Reseeder::ReseedFromSU3(
    const std::string& host) {
  LogPrint(eLogInfo, "Downloading SU3 from ", host);
  std::string url = host + "i2pseeds.su3";
  std::string su3 = i2p::util::http::HttpsDownload(url);
  if (su3.length() > 0) {
    std::stringstream ss(su3);
    return ProcessSU3Stream(ss);
  } else {
    LogPrint(eLogWarning, "SU3 download failed");
    return -1;
  }
}

int Reseeder::ProcessSU3Stream(
    std::istream& s) {
  char magicNumber[7];
  s.read(magicNumber, 7);  // magic number and zero byte 6
  if (strcmp(magicNumber, SU3_MAGIC_NUMBER)) {
    LogPrint(eLogError, "Unexpected SU3 magic number");
    return -1;
  }
  // su3 file format version
  s.seekg(1, std::ios::cur);
  // signature type
  SigningKeyType signatureType;
  s.read(reinterpret_cast<char *>(&signatureType), 2);
  signatureType = be16toh(signatureType);
  // signature length
  uint16_t signatureLength;
  s.read(reinterpret_cast<char *>(&signatureLength), 2);
  signatureLength = be16toh(signatureLength);
  // unused
  s.seekg(1, std::ios::cur);
  // version length
  uint8_t versionLength;
  s.read(reinterpret_cast<char *>(&versionLength), 1);
  // unused
  s.seekg(1, std::ios::cur);
  // signer ID length
  uint8_t signerIDLength;
  s.read(reinterpret_cast<char *>(&signerIDLength), 1);
  // content length
  uint64_t contentLength;
  s.read(reinterpret_cast<char *>(&contentLength), 8);
  contentLength = be64toh(contentLength);
  // unused
  s.seekg(1, std::ios::cur);
  // file type
  uint8_t fileType;
  s.read(reinterpret_cast<char *>(&fileType), 1);
  if (fileType != 0x00) {  // zip file
    LogPrint(eLogError, "Can't handle file type ", static_cast<int>(fileType));
    return -1;
  }
  s.seekg(1, std::ios::cur);  // unused
  uint8_t contentType;
  s.read(reinterpret_cast<char *>(&contentType), 1);  // content type
  if (contentType != 0x03) {  // reseed data
    LogPrint(eLogError,
        "Unexpected content type ", static_cast<int>(contentType));
    return -1;
  }
  s.seekg(12, std::ios::cur);  // unused
  s.seekg(versionLength, std::ios::cur);  // skip version
  char signerID[256];
  s.read(signerID, signerIDLength);  // signerID
  signerID[signerIDLength] = 0;
  // try to verify signature
  auto it = m_SigningKeys.find(signerID);
  if (it != m_SigningKeys.end()) {
    // TODO(unassigned): implement all signature types
    if (signatureType == SIGNING_KEY_TYPE_RSA_SHA512_4096) {
      size_t pos = s.tellg();
      size_t tbsLen = pos + contentLength;
      uint8_t* tbs = new uint8_t[tbsLen];
      s.seekg(0, std::ios::beg);
      s.read(reinterpret_cast<char *>(tbs), tbsLen);
      uint8_t* signature = new uint8_t[signatureLength];
      s.read(reinterpret_cast<char *>(signature), signatureLength);
      // RSA-raw
      i2p::crypto::RSASHA5124096RawVerifier verifier(it->second);
      verifier.Update(tbs, tbsLen);
      bool good = verifier.Verify(signature);
      delete[] signature;
      delete[] tbs;
      s.seekg(pos, std::ios::beg);
      if (!good) {
        LogPrint(eLogError, "SU3 Signature failed");
        return -1;
      }
    } else {
      LogPrint(eLogError,
          "Signature type ", signatureType, " is not supported");
      return -1;
    }
  } else {
    LogPrint(eLogError, "Certificate for ", signerID, " not loaded");
    return -1;
  }
  // handle content
  int numFiles = 0;
  size_t contentPos = s.tellg();
  while (!s.eof()) {
    uint32_t signature;
    s.read(reinterpret_cast<char *>(&signature), 4);
    signature = le32toh(signature);
    if (signature == ZIP_HEADER_SIGNATURE) {
      // next local file
      s.seekg(2, std::ios::cur);  // version
      uint16_t bitFlag;
      s.read(reinterpret_cast<char *>(&bitFlag), 2);
      bitFlag = le16toh(bitFlag);
      uint16_t compressionMethod;
      s.read(reinterpret_cast<char *>(&compressionMethod), 2);
      compressionMethod = le16toh(compressionMethod);
      s.seekg(4, std::ios::cur);  // skip fields we don't care about
      uint32_t compressedSize, uncompressedSize;
      uint8_t crc32[4];
      s.read(reinterpret_cast<char *>(crc32), 4);
      s.read(reinterpret_cast<char *>(&compressedSize), 4);
      compressedSize = le32toh(compressedSize);
      s.read(reinterpret_cast<char *>(&uncompressedSize), 4);
      uncompressedSize = le32toh(uncompressedSize);
      uint16_t fileNameLength, extraFieldLength;
      s.read(reinterpret_cast<char *>(&fileNameLength), 2);
      fileNameLength = le16toh(fileNameLength);
      if (fileNameLength > 255) {
        // TODO: avoid overflow with longer filenames
        LogPrint(eLogError, "Reseed: SU3 fileNameLength too large: ", int(fileNameLength));
        return numFiles;
      }
      s.read(reinterpret_cast<char *>(&extraFieldLength), 2);
      extraFieldLength = le16toh(extraFieldLength);
      char localFileName[255];
      s.read(localFileName, fileNameLength);
      localFileName[fileNameLength] = 0;
      s.seekg(extraFieldLength, std::ios::cur);
      // take care about data descriptor if presented
      if (bitFlag & ZIP_BIT_FLAG_DATA_DESCRIPTOR) {
        size_t pos = s.tellg();
        if (!FindZipDataDescriptor(s)) {
          LogPrint(eLogError, "SU3 archive data descriptor not found");
          return -1;
        }
        s.read(reinterpret_cast<char *>(crc32), 4);
        s.read(reinterpret_cast<char *>(&compressedSize), 4);
        // ??? we must consider signature as part of compressed data
        compressedSize = le32toh(compressedSize) + 4;
        s.read(reinterpret_cast<char *>(&uncompressedSize), 4);
        uncompressedSize = le32toh(uncompressedSize);
        // now we know compressed and uncompressed size
        s.seekg(pos, std::ios::beg);  // back to compressed data
      }
      LogPrint(eLogDebug,
          "Processing file ", localFileName, " ", compressedSize, " bytes");
      if (!compressedSize) {
        LogPrint(eLogWarning, "Unexpected size 0. Skipped");
        continue;
      }
      std::vector<uint8_t> compressed(compressedSize);
      s.read(reinterpret_cast<char *>(compressed.data()), compressed.size());
      // TODO(anonimal): don't assume deflate.
      if (compressionMethod) {
        CryptoPP::Inflator decompressor;
        // For the reasoning behind why we need to append a null byte, see #141.
        decompressor.Put(
            compressed.data() + '\0',
            compressed.size() + 1);
        decompressor.MessageEnd();
        if (decompressor.MaxRetrievable() <= uncompressedSize) {
          uint8_t* uncompressed = new uint8_t[uncompressedSize];
          decompressor.Get(uncompressed, uncompressedSize);
          bool good =
            CryptoPP::CRC32().VerifyDigest(
              crc32,
              uncompressed,
              uncompressedSize);
          if (good) {
            i2p::data::netdb.AddRouterInfo(uncompressed, uncompressedSize);
            numFiles++;
          }
          delete[] uncompressed;
          if (!good) {
            LogPrint(eLogError, "CRC32 Failed");
            return -1;
          }
        } else {
          LogPrint(eLogError,
              "Actual uncompressed size ", decompressor.MaxRetrievable(),
              " exceeds ", uncompressedSize, " from header");
          return -1;
        }
      } else {  // Contained, but not compressed
        i2p::data::netdb.AddRouterInfo(compressed.data(), compressed.size());
        numFiles++;
      }
      if (bitFlag & ZIP_BIT_FLAG_DATA_DESCRIPTOR)
        // skip data descriptor section if presented (12 = 16 - 4)
        s.seekg(12, std::ios::cur);
    } else {
      if (signature != ZIP_CENTRAL_DIRECTORY_HEADER_SIGNATURE) {
        LogPrint(eLogWarning, "Missing zip central directory header");
        return -1;
      }
      break;  // no more files
    }
    size_t end = s.tellg();
    if (end - contentPos >= contentLength)
      break;  // we are beyond contentLength
  }
  return numFiles;
}

bool Reseeder::FindZipDataDescriptor(
    std::istream& s) {
  size_t nextInd = 0;
  while (!s.eof()) {
    uint8_t nextByte;
    s.read(reinterpret_cast<char *>(&nextByte), 1);
    if (nextByte == ZIP_DATA_DESCRIPTOR_SIGNATURE[nextInd]) {
      nextInd++;
      if (nextInd >= sizeof(ZIP_DATA_DESCRIPTOR_SIGNATURE))
        return true;
    } else {
      nextInd = 0;
    }
  }
  return false;
}

bool Reseeder::LoadSU3Certs() {
  boost::filesystem::path certsPath = i2p::util::filesystem::GetSU3CertsPath();
  if (!exists(certsPath)) {
    LogPrint(eLogError, "Reseed certificates ", certsPath, " don't exist");
    return false;
  }
  int numCerts = 0;
  boost::filesystem::directory_iterator iter(certsPath), end;
  BOOST_FOREACH(boost::filesystem::path const& cert, std::make_pair(iter, end)) {
    if (boost::filesystem::is_regular_file(cert)) {
      if (ProcessSU3Cert(cert.string()))
        numCerts++;
      else
        return false;
    }
  }
  LogPrint(eLogInfo, numCerts, " certificates loaded");
  return numCerts > 0;
}

bool Reseeder::ProcessSU3Cert(
    const std::string& filename) {
  std::ifstream s(filename, std::ifstream::binary);
  if (s.is_open()) {
    s.seekg(0, std::ios::end);
    size_t CERT_LEN = s.tellg();
    s.seekg(0, std::ios::beg);
    char buf[CERT_LEN];
    s.read(buf, CERT_LEN);
    std::string cert(buf, CERT_LEN);
    // assume file in pem format
    auto pos1 = cert.find(CERTIFICATE_HEADER);
    auto pos2 = cert.find(CERTIFICATE_FOOTER);
    if (pos1 == std::string::npos || pos2 == std::string::npos) {
      LogPrint(eLogError, "Malformed certificate file");
      return false;
    }
    pos1 += strlen(CERTIFICATE_HEADER);
    pos2 -= pos1;
    std::string base64 = cert.substr(pos1, pos2);
    CryptoPP::ByteQueue queue;
    CryptoPP::Base64Decoder decoder;  // regular base64 rather than I2P
    decoder.Attach(new CryptoPP::Redirector(queue));
    decoder.Put((const uint8_t *)base64.data(), base64.length());
    decoder.MessageEnd();
    ProcessSU3Cert(queue);
  } else {
    LogPrint(eLogError, "Can't open certificate file ", filename);
    return false;
  }
  return true;
}

std::string Reseeder::ProcessSU3Cert(
    CryptoPP::ByteQueue& queue) {
  // extract X.509
  CryptoPP::BERSequenceDecoder x509Cert(queue);
  CryptoPP::BERSequenceDecoder tbsCert(x509Cert);
  // version
  uint32_t ver;
  CryptoPP::BERGeneralDecoder context(
      tbsCert, CryptoPP::CONTEXT_SPECIFIC | CryptoPP::CONSTRUCTED);
  CryptoPP::BERDecodeUnsigned<uint32_t>(context, ver, CryptoPP::INTEGER);
  // serial
  CryptoPP::Integer serial;
  serial.BERDecode(tbsCert);
  // signature
  CryptoPP::BERSequenceDecoder signature(tbsCert);
  signature.SkipAll();

  // issuer
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
  // validity
  CryptoPP::BERSequenceDecoder validity(tbsCert);
  validity.SkipAll();
  // subject
  CryptoPP::BERSequenceDecoder subject(tbsCert);
  subject.SkipAll();
  // public key
  CryptoPP::BERSequenceDecoder publicKey(tbsCert); {
    CryptoPP::BERSequenceDecoder ident(publicKey);
    ident.SkipAll();
    CryptoPP::BERGeneralDecoder key(publicKey, CryptoPP::BIT_STRING);
    key.Skip(1);  // TODO(unassigned): FIXME: possibly a bug in crypto++?
    CryptoPP::BERSequenceDecoder keyPair(key);
    CryptoPP::Integer n;
    n.BERDecode(keyPair);
    if (name.length() > 0) {
      PublicKey value;
      n.Encode(value, 512);
      m_SigningKeys[name] = value;
    } else {
      LogPrint(eLogError, "Unknown issuer. Skipped");
    }
  }
  publicKey.SkipAll();
  tbsCert.SkipAll();
  x509Cert.SkipAll();
  return name;
}

}  // namespace data
}  // namespace i2p
