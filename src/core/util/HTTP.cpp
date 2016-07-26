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

#include "HTTP.h"

#include <boost/network/uri.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "RouterContext.h"
#include "util/Filesystem.h"

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
  boost::asio::io_service service;
  boost::system::error_code ec;
  URI uri;
  if (!uri.Parse(address))
    return false;
  // Ensures host is online
  auto query =
    boost::asio::ip::tcp::resolver::query(uri.m_Host, uri.m_Port);
  auto endpoint =
    boost::asio::ip::tcp::resolver(service).resolve(query, ec);
  if (ec) {
    LogPrint(eLogError,
        "HTTP: Could not resolve address ", uri.m_Host, ": ", ec.message());
    return false;
  }
  // Initialize SSL
  boost::asio::ssl::context ctx(service, boost::asio::ssl::context::sslv23);
  if (ctx.set_options(
        boost::asio::ssl::context::no_tlsv1 |
        boost::asio::ssl::context::no_sslv3,
        ec)) {
    LogPrint(eLogError,
        "HTTP: Could not initialize SSL context: ", ec.message());
    return false;
  }
  // Ensures that we only download from certified reseed servers
  if (!i2p::context.ReseedSkipSSLCheck())
    ctx.set_verify_mode(
        boost::asio::ssl::verify_peer |
        boost::asio::ssl::verify_fail_if_no_peer_cert);
  ctx.set_verify_callback(boost::asio::ssl::rfc2818_verification(uri.m_Host));
  ctx.add_verify_path(i2p::util::filesystem::GetSSLCertsPath().string());
  // Connect to host
  boost::asio::ssl::stream<boost::asio::ip::tcp::socket>socket(service, ctx);
  if (socket.lowest_layer().connect(*endpoint, ec)) {
    LogPrint(eLogError,
        "HTTP: Could not connect to ", uri.m_Host, ": ", ec.message());
    return false;
  }
  // Initiate handshake
  if (socket.handshake(boost::asio::ssl::stream_base::client, ec)) {
    LogPrint(eLogError,
        "HTTP: SSL handshake failed: ", ec.message());
    return false;
  }
  LogPrint(eLogInfo, "HTTP: Connected to ", uri.m_Host, ":", uri.m_Port);
  // Send header
  std::stringstream send_stream;
  send_stream << Header(uri.m_Path, uri.m_Host, "1.1") << "\r\n";
  socket.write_some(boost::asio::buffer(send_stream.str()));
  // Read response / download
  std::stringstream read_stream;
  std::vector<char> response(1024);  // Arbitrary amount
  std::size_t length = 0;
  do {
    length = socket.read_some(
        boost::asio::buffer(response.data(), response.size()),
        ec);
    if (length)
      read_stream.write(response.data(), length);
  } while (!ec && length);
  // Assign stream downloaded contents
  m_Stream.assign(GetContent(read_stream));
  return true;
}

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
