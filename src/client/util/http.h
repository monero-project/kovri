/**                                                                                           //
 * Copyright (c) 2013-2017, The Kovri I2P Router Project                                      //
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

#ifndef SRC_CLIENT_UTIL_HTTP_H_
#define SRC_CLIENT_UTIL_HTTP_H_

// cpp-netlib
#include <boost/network/include/http/client.hpp>
#include <boost/network/uri.hpp>

#include <cstdint>
#include <fstream>
#include <iosfwd>
#include <map>
#include <regex>
#include <sstream>
#include <string>

#include "client/reseed.h"
#include "core/util/log.h"

namespace kovri {
namespace client {

/// @enum Timeout
/// @brief Constants used for HTTP timeout lengths when downloading
/// @notes Scoped to prevent namespace pollution (otherwise, purely stylistic)
enum struct Timeout : std::uint8_t {
  // Seconds
  Request = 45,  // Java I2P defined
  Receive = 30,
};

/// @class HTTPStorage
/// @brief Storage for class HTTP
class HTTPStorage {
 public:
  /// @brief Set URI path to test against future downloads
  /// @param path URI path
  /// @notes Needed in conjunction with ETag
  void SetPath(
      const std::string& path) {
    m_Path.assign(path);
  }

  /// @brief Get previously set URI path
  /// @notes Needed in conjunction with ETag
  const std::string& GetPreviousPath() const
  {
    return m_Path;
  }

  /// @brief Set ETag member from response header
  void SetETag(
      const std::string& etag) {
    m_ETag.assign(etag);
  }

  /// @brief Get previously set ETag member from response header
  /// @return ETag value
  const std::string& GetPreviousETag() const
  {
    return m_ETag;
  }

  /// @brief Set Last-Modified member from response header
  void SetLastModified(
      const std::string& last_modified) {
    m_LastModified.assign(last_modified);
  }

  /// @brief Get previously set Last-Modified member from response header
  /// @return Last-Modified value
  const std::string& GetPreviousLastModified() const
  {
    return m_LastModified;
  }

  /// @brief Sets downloaded contents to stream
  /// @notes Called after completed download
  void SetDownloadedContents(
      const std::string& stream) {
    m_Stream.assign(stream);
  }

  /// @brief Gets downloaded contents after successful download
  /// @return String of downloaded contents
  /// @notes Called after completed download
  const std::string& GetDownloadedContents() const
  {
    return m_Stream;
  }

 private:
  /// @var m_Path
  /// @brief Path value from a 1st request that can be tested against later
  /// @notes If path is same as previous request, apply required header values
  std::string m_Path;

  /// @var m_ETag
  /// @brief ETag value from response header
  /// @notes Used primarily for subscriptions. Can be extended to auto-update
  std::string m_ETag;

  /// @var m_LastModified
  /// @brief Last-Modified value from response header
  /// @notes Used primarily for subscriptions. Can be extended to auto-update
  std::string m_LastModified;

  /// @var m_Stream
  /// @brief Downloaded contents
  std::string m_Stream;  // TODO(anonimal): consider refactoring into an actual stream
};

/// @class HTTP
/// @brief Provides functionality for implementing HTTP/S
/// @details URI is typically passed to ctor. Otherwise, see below.
/// @notes Vocabulary:
///   Clearnet: Connections made outside of the I2P network
///   In-net: Connections made within the I2P network
class HTTP : public HTTPStorage {
 public:
  HTTP() {}  // for HTTPProxy and tests
  ~HTTP() {}

  HTTP(const std::string& uri) : m_URI(uri)
  {
    LOG(debug) << "HTTP: constructor URI " << uri;
  }

  /// @brief Set cpp-netlib URI object if not set with ctor
  /// @param uri String URI (complete)
  void SetURI(const std::string& uri)
  {
    LOG(debug) << "HTTP: Set URI " << uri;
    // Remove existing URI if set
    if (!m_URI.string().empty()) {
      boost::network::uri::uri new_uri;
      m_URI.swap(new_uri);
    }
    // Set new URI
    m_URI.append(uri);
  }

  /// @brief Get initialized URI
  /// @return cpp-netlib URI object
  boost::network::uri::uri GetURI() const
  {
    return m_URI;
  }

  /// @brief Tests if TLD is I2P
  /// @return True if TLD is .i2p
  bool HostIsI2P() const;

  /// @brief Downloads parameter URI
  /// @param uri String URI
  /// @details Sets member URI with param uri, calls Download()
  /// @return Bool result of Download()
  /// @notes Only used if URI not initialized with ctor
  bool Download(
      const std::string& uri);

  /// @brief Download wrapper function for clearnet and in-net download
  /// @return False on failure
  bool Download();

 private:
  /// @brief Set default ports for in-net downloading
  /// @notes The default port is 80, for HTTPS it is 443
  /// @notes Removing this will require refactoring stream implementation
  void AmendURI();

  /// @brief Downloads over clearnet
  /// @return False on failure
  bool DownloadViaClearnet();

  /// @brief Downloads within I2P
  /// @return False on failure
  /// @notes Used for address book and for future in-net autoupdates
  bool DownloadViaI2P();

 private:
  /// @var m_URI
  /// @brief cpp-netlib URI instance
  boost::network::uri::uri m_URI;

  // TODO(anonimal): consider removing typedefs after refactor
  // TODO(anonimal): remove the following notes after refactor

  /// @brief HTTP client object
  /// @notes Currently only applies to clearnet download
  typedef boost::network::http::client Client;

  /// @brief HTTP client options object (timeout, SNI, etc.)
  /// @notes Currently only applies to clearnet download
  typedef boost::network::http::client::options Options;

  /// @brief HTTP client request object (header, etc.)
  /// @notes Currently only applies to clearnet download
  typedef boost::network::http::client::request Request;

  /// @brief HTTP client response object (body, status, etc.)
  /// @notes Currently only applies to clearnet download
  typedef boost::network::http::client::response Response;

 public:
  // TODO(anonimal): remove after refactor
  /// @brief Prepares header for in-net request
  void PrepareI2PRequest();

  // TODO(anonimal): remove after refactor
  /// @brief Process in-net HTTP response
  /// @return True if processing was successful
  bool ProcessI2PResponse();

  // TODO(anonimal): remove after refactor
  /// @brief Merge chunks of an in-net HTTP response
  void MergeI2PChunkedResponse(
      std::istream& response,
      std::ostream& merged);

 private:
  // TODO(anonimal): remove after refactor
  /// @brief In-net HTTP request and response
  std::stringstream m_Request, m_Response;
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_UTIL_HTTP_H_
