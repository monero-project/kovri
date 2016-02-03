/**
 * Copyright (c) 2015-2016, The Kovri I2P Router Project
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

#include "Log.h"
#include "Reseed.h"
#include "client/util/Filesystem.h"

namespace i2p {
namespace util {
namespace http {

/**
 * @return the result of the download, or an empty string if it fails
 */
std::string HttpsDownload(const std::string& address);

/**
 * Provides functionality for parsing URIs
 */
class URI {
  /**
   * The code for ParseURI() was originally copied/pasted from
   * https://stackoverflow.com/questions/2616011/easy-way-to-parse-a-url-in-c-cross-platform
   *
   * See cpp-netlib for a better URI parsing implementation with Boost.
   *
   * Note: fragments are not parsed by this function (if they should
   * ever be needed in the future).
   *
   * @param uri the URI to be parsed
   * @warning the default port is 80, for HTTPS it is 443
   */
  void ParseURI(const std::string& uri);
 public:
  std::string m_Protocol, m_Host, m_Path, m_PortString, m_Query;
  int m_Port;
  // Parse a URI given as a string.
  explicit URI(const std::string& uri);
};

/**
 * Header for HTTP requests.
 * @return a string of the complete header
 * @warning this function does NOT append an additional \r\n
 */
std::string HttpHeader(
    const std::string& path,
    const std::string& host,
    const std::string& version);

/**
 * @return the content of the given HTTP stream without headers
 */
std::string GetHttpContent(std::istream& response);

/**
 * Merge chunks of an HTTP response.
 */
void MergeChunkedResponse(
    std::istream& response,
    std::ostream& merged);

/**
 * Used almost exclusively by Addressbook
 */
const char ETAG[] = "ETag";
const char IF_NONE_MATCH[] = "If-None-Match";
const char IF_MODIFIED_SINCE[] = "If-Modified-Since";
const char LAST_MODIFIED[] = "Last-Modified";
const char TRANSFER_ENCODING[] = "Transfer-Encoding";

/**
 * @return the decoded URI
 */
std::string DecodeURI(
    const std::string& data);

}  // namespace http
}  // namespace util
}  // namespace i2p

#endif  // SRC_CORE_UTIL_HTTP_H_
