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

#ifndef SRC_CORE_UTIL_HTTP_H_
#define SRC_CORE_UTIL_HTTP_H_

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <fstream>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>

#include "log.h"
#include "reseed.h"

namespace i2p {
namespace util {
namespace http {

// TODO(anonimal): refactor everything in this namespace with cpp-netlib
// Will require review/refactor of AddressBook

/// @class URI
/// @brief Provides functionality for preparing a URI
class URI {
 public:
  /// @param uri The URI string to be parsed
  /// @note The default port is 80, for HTTPS it is 443
  /// @return False if URI is invalid, true if valid
  bool Parse(
      const std::string& uri);

  /// @return The decoded URI as string
  std::string Decode(
      const std::string& data);

  // TODO(anonimal): consider Get/Set functions if we keep class URI
  std::string m_Protocol, m_Host, m_Port, m_Path, m_Query;
};

/**
 * Provides functionality for implementing HTTP
 */
class HTTP {
 public:
  /**
   * @return the result of the download, or an empty string if it fails
   */
  bool Download(
      const std::string& address);

  /**
   * Header for HTTP requests.
   * @return a string of the complete header
   * @warning this function does NOT append an additional \r\n
   */
  const std::string Header(
      const std::string& path,
      const std::string& host,
      const std::string& version);

  /**
   * @return the content of the given HTTP stream without headers
   */
  const std::string GetContent(
      std::istream& response);

  /**
   * Merge chunks of an HTTP response.
   */
  void MergeChunkedResponse(
      std::istream& response,
      std::ostream& merged);

 public:
  /**
   * Used almost exclusively by Addressbook
   */
  const std::string ETAG = "ETag";
  const std::string IF_NONE_MATCH = "If-None-Match";
  const std::string IF_MODIFIED_SINCE = "If-Modified-Since";
  const std::string LAST_MODIFIED = "Last-Modified";
  const std::string TRANSFER_ENCODING = "Transfer-Encoding";

 public:
  std::string m_Stream;  // Downloaded stream
  std::uint16_t m_Status;  // HTTP Response Code
};

}  // namespace http
}  // namespace util
}  // namespace i2p

#endif  // SRC_CORE_UTIL_HTTP_H_
