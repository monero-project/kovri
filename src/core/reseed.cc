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

#include "reseed.h"

#include <boost/filesystem.hpp>

#include <fstream>
#include <limits>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include "identity.h"
#include "net_db.h"
#include "crypto/rand.h"
#include "crypto/signature.h"
#include "util/filesystem.h"
#include "util/http.h"
#include "util/i2p_endian.h"
#include "util/log.h"
#include "util/zip.h"

namespace i2p {
namespace data {

/**
 *
 * Reseed implementation
 *
 * 1. Load/process SU3 certificates
 * 2. Fetches SU3 stream
 * 3. Implements SU3
 * 4. Inserts extracted RI's into NetDb
 *
 */
bool Reseed::ReseedImpl() {
  // Load SU3 (not SSL) certificates
  LogPrint(eLogDebug, "Reseed: processing certificates...");
  if (!ProcessCerts()) {
    LogPrint(eLogError, "Reseed: failed to load certificates");
    return false;
  }
  // Fetch SU3 stream for reseed
  std::size_t attempts = 0;
  const std::size_t max_attempts = 6;
  while (attempts != max_attempts) {
    // With default reseed, we won't break until 6 attempts are made.
    // With CLI reseed, we'll break after first failed attempt.
    if (!FetchStream()) {
      attempts++;
      LogPrint(eLogError,
          "Reseed: fetch failed after ",
          attempts, " of ", max_attempts, " attempts");
      if (!m_Stream.empty() || attempts == max_attempts)
        return false;
    } else {
      LogPrint(eLogInfo, "Reseed: fetch successful");
      break;
    }
  }
  // Implement SU3
  SU3 su3(m_Stream, m_SigningKeys);
  if (!su3.SU3Impl()) {
    LogPrint(eLogError, "Reseed: SU3 implementation failed");
    return false;
  }
  // Insert extracted RI's into NetDb
  for (auto const& router : su3.m_RouterInfos)
    if (!i2p::data::netdb.AddRouterInfo(
          router.second.data(),
          router.second.size()))
      return false;
  LogPrint(eLogInfo, "Reseed: implementation successful");
  return true;
}

bool Reseed::ProcessCerts() {
  // Test if directory exists
  boost::filesystem::path path = i2p::util::filesystem::GetSU3CertsPath();
  boost::filesystem::directory_iterator it(path), end;
  if (!boost::filesystem::exists(path)) {
    LogPrint(eLogError, "Reseed: certificates ", path, " don't exist");
    return false;
  }
  // Instantiate X.509 object
  i2p::crypto::util::X509 x509;
  // Iterate through directory and get signing key from each certificate
  std::size_t num_certs = 0;
  BOOST_FOREACH(boost::filesystem::path const& cert, std::make_pair(it, end)) {
    if (boost::filesystem::is_regular_file(cert)) {
      LogPrint(eLogDebug, "Reseed: acquiring signing key from ", cert);
      std::ifstream ifs(cert.string(), std::ifstream::binary);
      if (ifs) {
        try {
          // Prepare stream
          std::stringstream ss;
          ss << ifs.rdbuf();
          // Get signing key
          m_SigningKeys = x509.GetSigningKey(ss);
          // Close stream
          ifs.close();
        } catch (const std::exception& e) {
          LogPrint(eLogError,
              "Reseed: exception '", e.what(),
              "' caught when processing certificate", cert);
          return false;
        }
      } else {
        LogPrint(eLogError, "Reseed: ", cert, " does not exist");
        return false;
      }
      if (m_SigningKeys.empty()) {
        LogPrint(eLogError, "Reseed: failed to get signing key from ", cert);
        return false;
      }
      if (num_certs < std::numeric_limits<std::uint8_t>::max()) {
        num_certs++;
      }
    }
  }
  LogPrint(eLogInfo,
      "Reseed: successfuly loaded ", num_certs, " certificates");
  return (num_certs > 0);
}


bool Reseed::FetchStream() {
  /**
   * If user-supplied stream was given, fetch accordingly.
   * Else, fetch a random host and, on failure, clear the stream.
   */
  if (!m_Stream.empty()) {
    // TODO(unassigned): abstract downloading mechanism (see #149)
    std::regex exp("^https?://");  // We currently only support http/s
    if (std::regex_search(m_Stream, exp)) {
      return FetchStream(m_Stream);
    } else {
      // Either a local file or unsupported protocol
      std::ifstream ifs(m_Stream);
      return FetchStream(ifs);
    }
  } else {
    m_Stream =
      m_Hosts.at(
          i2p::crypto::RandInRange<std::size_t>(0, m_Hosts.size() - 1)) +
      m_Filename;
    if (FetchStream(m_Stream))
      return true;
    m_Stream.clear();
  }
  return false;
}

bool Reseed::FetchStream(
    const std::string& url) {
  LogPrint(eLogInfo, "Reseed: fetching stream from ", url);
  // TODO(unassigned): abstract our downloading mechanism (see #168)
  i2p::util::http::HTTP http;
  if (!http.Download(url))
    return false;
  // Replace our stream with downloaded stream
  m_Stream = http.m_Stream;
  // TODO(unassigned): replace with constants if this isn't rewritten by #155/#168
  return ((m_Stream.size() > 0) && (m_Stream.size() <= 128 * 1024)); // Arbitrary size in bytes
}

bool Reseed::FetchStream(
    std::ifstream& ifs) {
  LogPrint(eLogInfo, "Reseed: fetching stream from file ", m_Stream);
  if (ifs) {
    try {
      // Assign file contents to stream
      m_Stream.assign(
          (std::istreambuf_iterator<char>(ifs)),
           std::istreambuf_iterator<char>());
      ifs.close();
    } catch (const std::exception& e) {
      LogPrint(eLogError,
          "Reseed: exception '", e.what(),
          "' caught when processing ", m_Stream);
      return false;
    }
    return true;
  }
  LogPrint(eLogError, "Reseed: ", m_Stream, " does not exist");
  return false;
}

/**
 *
 * SU3 implementation
 *
 * 1. Prepares stream
 *   - Set endianness where needed
 *   - Get/set data
 *   - Perform sanity tests
 * 2. Verifies signature of stream
 *   - Verify SU3 against certs
 * 3. Unzips stream
 *   - Extract RI's for Reseed
 *
 */
bool SU3::SU3Impl() {
  /**
   * TODO(unassigned): when the --reseed-from file is a .zip, (or non-su3 type),
   * it would be nice to skip su3 all-together, decompress as appropriate, and
   * validate for RI type - then insert into NetDb.
   */
  LogPrint(eLogDebug, "SU3: preparing stream...");
  if (!PrepareStream()) {
    LogPrint(eLogError, "SU3: preparation failed");
    return false;
  }
  LogPrint(eLogDebug, "SU3: verifying stream...");
  if (!VerifySignature()) {
    LogPrint(eLogError, "SU3: verification failed");
    return false;
  }
  LogPrint(eLogDebug, "SU3: extracting content...");
  if (!ExtractContent()) {
    LogPrint(eLogError, "SU3: extraction failed");
    return false;
  }
  return true;
}

bool SU3::PrepareStream() {
  try {
    // Validate stream as an SU3
    m_Stream.Read(*m_Data->magic_number.data(), Size::magic_number);
    if (m_Data->magic_number.data() != m_MagicValue) {
      LogPrint(eLogError, "SU3: invalid magic value");
      return false;
    }
    // File format version offset (spec defines it as 0, so we don't need it)
    m_Stream.Seekg(Offset::version, std::ios::cur);
    // Prepare signature type
    m_Stream.Read(m_Data->signature_type, Size::signature_type);
    m_Data->signature_type = be16toh(m_Data->signature_type);
    if (m_Data->signature_type != SIGNING_KEY_TYPE_RSA_SHA512_4096) {  // Temporary (see #160)
      LogPrint(eLogError, "SU3: signature type not supported");
      return false;
    }
    // Prepare signature length
    m_Stream.Read(m_Data->signature_length, Size::signature_length);
    m_Data->signature_length = be16toh(m_Data->signature_length);
    if (m_Data->signature_length != sizeof(i2p::crypto::util::PublicKey)) {  // Temporary (see #160)
      LogPrint(eLogError, "SU3: invalid signature length");
      return false;
    }
    // Unused offset
    m_Stream.Seekg(Offset::unused, std::ios::cur);
    // Get version length
    m_Stream.Read(m_Data->version_length, Size::version_length);
    if (m_Data->version_length <
        static_cast<std::size_t>(Size::minimal_version)) {
      LogPrint(eLogError, "SU3: version length too short");
      return false;
    }
    // Unused offset
    m_Stream.Seekg(Offset::unused, std::ios::cur);
    // Get signer ID length
    m_Stream.Read(m_Data->signer_id_length, Size::signer_id_length);
    if (!m_Data->signer_id_length) {
      LogPrint(eLogError, "SU3: invalid signer ID length");
      return false;
    }
    // Prepare content length
    m_Stream.Read(m_Data->content_length, Size::content_length);
    m_Data->content_length = be64toh(m_Data->content_length);
    if (!m_Data->content_length) {
      LogPrint(eLogError, "SU3: invalid content length");
      return false;
    }
    // Unused offset
    m_Stream.Seekg(Offset::unused, std::ios::cur);
    // Get file type that contains non-su3 data
    m_Stream.Read(m_Data->file_type, Size::file_type);
    switch (m_Data->file_type) {
      case static_cast<std::size_t>(FileType::zip_file):
        break;
      case static_cast<std::size_t>(FileType::xml_file):
        LogPrint(eLogError, "SU3: XML not supported");
        return false;
      case static_cast<std::size_t>(FileType::html_file):
        LogPrint(eLogError, "SU3: HTML not supported");
        return false;
      case static_cast<std::size_t>(FileType::xml_gz_file):
        LogPrint(eLogError, "SU3: Gzip compressed XML not supported");
        return false;
      default:
        LogPrint(eLogError,
            "SU3: invalid file type ",
            static_cast<std::size_t>(m_Data->file_type));
        return false;
    }
    // Unused offset
    m_Stream.Seekg(Offset::unused, std::ios::cur);
    // Get content type that contains the RI's
    m_Stream.Read(m_Data->content_type, Size::content_type);
    switch (m_Data->content_type) {
      case static_cast<std::size_t>(ContentType::unknown):
        break;
      case static_cast<std::size_t>(ContentType::router_update):
        LogPrint(eLogError, "SU3: Router Update not yet supported");
        return false;
      case static_cast<std::size_t>(ContentType::plugin_related):
        LogPrint(eLogError, "SU3: Plugins not yet supported");
        return false;
      case static_cast<std::size_t>(ContentType::reseed_data):
        LogPrint(eLogDebug, "SU3: found reseed data");
        break;
      case static_cast<std::size_t>(ContentType::news_feed):
        LogPrint(eLogError, "SU3: News Feed not yet supported");
        return false;
      default:
        LogPrint(eLogError,
            "SU3: invalid content type ",
            static_cast<std::size_t>(m_Data->content_type));
        return false;
    }
    // Unused offset
    m_Stream.Seekg(static_cast<std::size_t>(Offset::unused) * 12, std::ios::cur);
    // Skip SU3 version (we *could* test against this if we want)
    m_Stream.Seekg(m_Data->version_length, std::ios::cur);
    // Get signer ID
    m_Stream.Read(*m_Data->signer_id.data(), m_Data->signer_id_length);
    // Currently enforces signer ID as an email address (not spec-defined)
    // Note: do not rely on [a-z] to catch all letters as it will fail on some locales
    const std::string alpha = "abcdefghijklmnopqrstuvwxyz";
    std::regex regex("([-"+alpha+"0-9+._']{1,254})@((?:[-"+alpha+"0-9]+.)+["+alpha+"|(i2p)]{2,})");
    if (!std::regex_search(m_Data->signer_id.data(), regex)) {
      LogPrint(eLogError, "SU3: invalid signer ID");
      return false;
    }
    // Save position
    m_Data->signature_position = m_Stream.Tellg();
    // Prepare to read in both content length + signature length
    m_Data->content_length += m_Data->signature_position;
    m_Data->content.resize(m_Data->content_length);
    m_Data->signature.resize(m_Data->signature_length);
    // Read in content and signature for verification against signer ID
    m_Stream.Seekg(0, std::ios::beg);
    m_Stream.Read(*m_Data->content.data(), m_Data->content.size());
    m_Stream.Read(*m_Data->signature.data(), m_Data->signature.size());
    // Go back to prepare for RI extraction
    m_Stream.Seekg(m_Data->signature_position, std::ios::beg);
    // Our content position is the same as signature position
    m_Data->content_position = m_Data->signature_position;
  } catch (const std::exception& e) {
    LogPrint(eLogError,
        "SU3: caught exception '", e.what(), "' during preparation");
    return false;
  }
  LogPrint(eLogDebug, "SU3: preparation successful");
  return true;
}

bool SU3::VerifySignature() {
  // Get signing keys from extracted/processed SU3 certs
  auto signing_key_it = m_SigningKeys.find(m_Data->signer_id.data());
  if (signing_key_it == m_SigningKeys.end()) {
    LogPrint(eLogError,
        "SU3: certificate for ", m_Data->signer_id.data(), " not loaded");
    return false;
  }
  // Verify hash of content data and signature
  switch (m_Data->signature_type) {
    case SIGNING_KEY_TYPE_RSA_SHA512_4096: {
      i2p::crypto::RSASHA5124096RawVerifier verifier(signing_key_it->second);
      verifier.Update(m_Data->content.data(), m_Data->content.size());
      if (!verifier.Verify(m_Data->signature.data())) {
        LogPrint(eLogError, "SU3: signature failed");
        return false;
      }
      break;
    }
    // TODO(unassigned): see #160
    // Note: this is currently redundant since signature type was
    // tested during stream preparation. We'll leave this here
    // because it will eventually be useful.
    default:
      LogPrint(eLogError,
          "SU3: signature type ", m_Data->signature_type, " is not supported");
      return false;
  }
  LogPrint(eLogDebug, "SU3: verification successful");
  return true;
}

bool SU3::ExtractContent() {
  LogPrint(eLogDebug, "SU3: unzipping stream");
  i2p::util::ZIP zip(
      m_Stream.Str(),
      m_Data->content_length,
      m_Data->content_position);
  if (!zip.Unzip()) {
    LogPrint(eLogError, "SU3: unzip failed");
    return false;
  }
  // Get unzipped RI's for Reseed
  m_RouterInfos = zip.m_Contents;
  LogPrint(eLogDebug, "SU3: extraction successful");
  return true;
}

}  // namespace data
}  // namespace i2p
