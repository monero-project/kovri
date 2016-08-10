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

#include "http.h"

// cpp-netlib
#define BOOST_NETWORK_ENABLE_HTTPS
#include <boost/network/include/http/client.hpp>
#include <boost/network/uri.hpp>

#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "router_context.h"
#include "util/filesystem.h"

namespace i2p {
namespace util {
namespace http {

bool URI::Parse(
    const std::string& uri) {
  boost::network::uri::uri URI(uri);
  if (URI.is_valid()) {
    m_Protocol.assign(URI.scheme());
    m_Host.assign(URI.host());
    m_Port.assign(URI.port());
    m_Path.assign(URI.path());
    m_Query.assign(URI.query());
    // Set defaults for AddressBook
    // TODO(anonimal): this should disappear once we finish other refactoring
    if (!m_Port.empty())
      return true;
    if (m_Protocol == "https") {
      m_Port.assign("443");
    } else {
      m_Port.assign("80");
    }
    return true;
  } else {
    LogPrint(eLogError, "URI: invalid URI");
    return false;
  }
}

// TODO(anonimal): research if cpp-netlib can do this better
// Used by HTTPProxy
std::string URI::Decode(
    const std::string& data) {
  std::string res(data);
  for (size_t pos = res.find('%');
      pos != std::string::npos;
      pos = res.find('%', pos + 1)) {
    const char c = strtol(res.substr(pos + 1, 2).c_str(), NULL, 16);
    res.replace(pos, 3, 1, c);
  }
  return res;
}

bool HTTP::Download(
    const std::string& address) {
  // Validate URI
  URI uri;
  if (!uri.Parse(address))
    return false;
  namespace http = boost::network::http;
  namespace network = boost::network;
  http::client::options options;
  // Ensure that we only download from certified reseed servers
  if (!i2p::context.ReseedSkipSSLCheck()) {
    const std::string cert = uri.m_Host + ".crt";
    const boost::filesystem::path cert_path = i2p::util::filesystem::GetSSLCertsPath() / cert;
    if (!boost::filesystem::exists(cert_path)) {
      LogPrint(eLogError, "HTTP: certificate unavailable: ", cert_path);
      return false;
    }
    // Set SSL options
    options
      .openssl_certificate(cert_path.string())
      .openssl_sni_hostname(uri.m_Host);
  }
  try {
    // Set extra options
    options.timeout(45);  // Java I2P defined
    http::client client(options);
    // Prepare and initiate session
    http::client::request request(address);
    request << network::header("User-Agent", "Wget/1.11.4");  // Java I2P defined
    http::client::response response = client.get(request);
    // Assign stream our downloaded contents
    m_Stream.assign(http::body(response));
  } catch (const std::exception& e) {
    LogPrint(eLogError, "HTTP: unable to complete download: ", e.what());
    return false;
  }
  return true;
}

// TODO(anonimal): remove once AddressBookSubscription has been refactored
const std::string HTTP::Header(
    const std::string& path,
    const std::string& host,
    const std::string& version) {
  std::string header =
    "GET " + path + " HTTP/" + version + "\r\n" +
    "Host: " + host + "\r\n" +
    "Accept: */*\r\n" +
    "User-Agent: Wget/1.11.4\r\n" +
    "Connection: close\r\n";
  return header;
}

// TODO(anonimal): remove once AddressBookSubscription has been refactored
const std::string HTTP::GetContent(
    std::istream& response) {
  std::string version, statusMessage;
  response >> version;  // HTTP version
  response >> m_Status;  // Response code status
  std::getline(response, statusMessage);
  if (m_Status == 200) {  // OK
    bool isChunked = false;
    std::string header;
    while (!response.eof() && header != "\r") {
      std::getline(response, header);
      auto colon = header.find(':');
      if (colon != std::string::npos) {
        std::string field = header.substr(0, colon);
        if (field == TRANSFER_ENCODING)
          isChunked = (header.find("chunked", colon + 1) != std::string::npos);
      }
    }
    std::stringstream ss;
    if (isChunked)
      MergeChunkedResponse(response, ss);
    else
      ss << response.rdbuf();
    return ss.str();
  } else {
    LogPrint("HTTP response ", m_Status);
    return "";
  }
}

// TODO(anonimal): remove once AddressBookSubscription has been refactored
void HTTP::MergeChunkedResponse(
    std::istream& response,
    std::ostream& merged) {
  while (!response.eof()) {
    std::string hexLen;
    int len;
    std::getline(response, hexLen);
    std::istringstream iss(hexLen);
    iss >> std::hex >> len;
    if (!len)
      break;
    auto buf = std::make_unique<char[]>(len);
    response.read(buf.get(), len);
    merged.write(buf.get(), len);
    std::getline(response, hexLen);  // read \r\n after chunk
  }
}

}  // namespace http
}  // namespace util
}  // namespace i2p
