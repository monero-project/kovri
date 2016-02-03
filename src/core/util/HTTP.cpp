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

#include "HTTP.h"

#include "util/Filesystem.h"

#include <string>
#include <functional>

namespace i2p {
namespace util {
namespace http {

std::string HttpsDownload(
    const std::string& address) {
  // TODO(anonimal): do not use using-directive.
  using namespace boost::asio;
  io_service service;
  boost::system::error_code ec;
  URI uri(address);
  // Ensures host is online
  auto query = ip::tcp::resolver::query(uri.m_Host, std::to_string(uri.m_Port));
  auto endpoint = ip::tcp::resolver(service).resolve(query, ec);
  if (!ec) {
    // Initialize SSL
    // TODO(anonimal): deprecated constructor/
    ssl::context ctx(service, ssl::context::sslv23);
    ctx.set_options(ssl::context::no_tlsv1 | ssl::context::no_sslv3, ec);
    if (!ec) {
      // Ensures that we only download from certified reseed servers
      ctx.set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
      ctx.set_verify_callback(ssl::rfc2818_verification(uri.m_Host));
      ctx.add_verify_path(i2p::util::filesystem::GetSSLCertsPath().string());
      // Connect to host
      ssl::stream<ip::tcp::socket>socket(service, ctx);
      socket.lowest_layer().connect(*endpoint, ec);
      if (!ec) {
        // Initiate handshake
        socket.handshake(ssl::stream_base::client, ec);
        if (!ec) {
          LogPrint(eLogInfo, "Connected to ", uri.m_Host, ":", uri.m_Port);
          // Send header
          std::stringstream sendStream;
          sendStream << HttpHeader(uri.m_Path, uri.m_Host, "1.1");
          socket.write_some(buffer(sendStream.str()));
          // Read response / download
          std::stringstream readStream;
          char response[1024];
          size_t length = 0;
          do {
            length = socket.read_some(buffer(response, 1024), ec);
            if (length)
              readStream.write(response, length);
          }
          while (!ec && length);
            return GetHttpContent(readStream);
         } else {
           LogPrint(eLogError,
               "Could not initialize SSL context: ", ec.message());
         }
       } else {
         LogPrint(eLogError,
             "SSL handshake failed: ", ec.message());
       }
    } else {
      LogPrint(eLogError,
          "Could not connect to ", uri.m_Host, ": ", ec.message());
    }
  } else {
    LogPrint(eLogError,
        "Could not resolve address ", uri.m_Host, ": ", ec.message());
  }
  return "";
}

URI::URI(
    const std::string& uri) {
  m_PortString = "443";
  m_Port = 443;
  m_Path = "";
  m_Query = "";
  ParseURI(uri);
}

void URI::ParseURI(
    const std::string& uri) {
  // TODO(anonimal): do not use using-directive.
  using namespace std;
  /**
  * This is a hack since colons are a part of the URI scheme
  * and slashes aren't always needed. See RFC 7595.
  * */
  const string prot_end("://");
  // Separate scheme from authority
  string::const_iterator prot_i = search(
      uri.begin(),
      uri.end(),
      prot_end.begin(),
      prot_end.end());
  // Prepare for lowercase result and transform to lowercase
  m_Protocol.reserve(
      distance(
        uri.begin(),
        prot_i));
  transform(
      uri.begin(),
      prot_i,
      back_inserter(
        m_Protocol),
      ptr_fun<int, int>(tolower));
  // TODO(unassigned): better error checking and handling
  if (prot_i == uri.end())
    return;
  // Move onto authority. We assume it's valid and don't bother checking.
  advance(prot_i, prot_end.length());
  string::const_iterator path_i = find(prot_i, uri.end(), '/');
  // Prepare for lowercase result and transform to lowercase
  m_Host.reserve(distance(prot_i, path_i));
  transform(
      prot_i,
      path_i,
      back_inserter(m_Host),
      ptr_fun<int, int>(tolower));
  // Parse port, assuming it's valid input
  auto port_i = find(m_Host.begin(), m_Host.end(), ':');
  if (port_i != m_Host.end()) {
    m_PortString = string(port_i + 1, m_Host.end());
    m_Host.assign(m_Host.begin(), port_i);
    try {
      m_Port = boost::lexical_cast<decltype(m_Port)>(m_PortString);
    } catch (const exception& e) {
      m_Port = 443;
    }
  }
  // Parse query, assuming it's valid input
  string::const_iterator query_i = find(path_i, uri.end(), '?');
  m_Path.assign(path_i, query_i);
  if (query_i != uri.end())
    ++query_i;
  m_Query.assign(query_i, uri.end());
}

std::string HttpHeader(
    const std::string& path,
    const std::string& host,
    const std::string& version) {
  std::string header =
    "GET " + path + " HTTP/" + version + "\r\n" +
    "Host: " + host + "\r\n" +
    "Accept: */*\r\n" +
    "User-Agent: Wget/1.11.4\r\n" +
    "Connection: close\r\n\r\n";
  return header;
}

std::string GetHttpContent(
    std::istream& response) {
  std::string version, statusMessage;
  response >> version;  // HTTP version
  int status;
  response >> status;  // status
  std::getline(response, statusMessage);
  if (status == 200) {  // OK
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
    LogPrint("HTTP response ", status);
    return "";
  }
}

void MergeChunkedResponse(
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
    char* buf = new char[len];
    response.read(buf, len);
    merged.write(buf, len);
    delete[] buf;
    std::getline(response, hexLen);  // read \r\n after chunk
  }
}

// Used by HTTPProxy
std::string DecodeURI(
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

}  // namespace http
}  // namespace util
}  // namespace i2p
