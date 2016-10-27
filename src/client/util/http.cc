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

#include "client/util/http.h"

#include <boost/network/message/directives/header.hpp>
#include <boost/network/message/wrappers/body.hpp>

#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "client/address_book.h"
#include "client/context.h"

#include "core/router/context.h"

#include "core/util/filesystem.h"
#include "core/util/log.h"

namespace kovri {
namespace client {

// TODO(unassigned): currently unused but will be useful
// without needing to create a new object for each given URI
bool HTTP::Download(
    const std::string& uri) {
  SetURI(uri);
  return Download();
}

bool HTTP::Download() {
  if (!GetURI().is_valid()) {
    LogPrint(eLogError, "URI: invalid URI");
    return false;
  }
  // TODO(anonimal): ideally, we simply swapout the request/response handler
  // with cpp-netlib so we don't need two separate functions
  if (!HostIsI2P())
    return DownloadViaClearnet();
  return DownloadViaI2P();
}

bool HTTP::HostIsI2P() {
  auto uri = GetURI();
  if (!(uri.host().substr(uri.host().size() - 4) == ".i2p"))
    return false;
  if (!uri.port().empty())
    return true;
  // We must assign a port if none was assigned (for internal reasons)
  std::string port;
  if (uri.scheme() == "https")
    port.assign("443");
  else
    port.assign("80");
  // If user supplied user:password, we must append @
  std::string user_info;
  if (!uri.user_info().empty())
    user_info.assign(uri.user_info() + "@");
  // TODO(anonimal): easier way with cpp-netlib?
  std::string new_uri(
      uri.scheme() + "://" + user_info
      + uri.host() + ":" + port
      + uri.path() + uri.query() + uri.fragment());
  SetURI(new_uri);
  return true;
}

bool HTTP::DownloadViaClearnet() {
  auto uri = GetURI();
  // Create and set options
  Options options;
  options.timeout(static_cast<std::uint8_t>(Timeout::Request));
  // Ensure that we only download from certified reseed servers
  if (!kovri::context.GetOptionReseedSkipSSLCheck()) {
    const std::string cert = uri.host() + ".crt";
    const boost::filesystem::path cert_path = kovri::core::GetSSLCertsPath() / cert;
    if (!boost::filesystem::exists(cert_path)) {
      LogPrint(eLogError, "HTTP: certificate unavailable: ", cert_path);
      return false;
    }
    // Set SSL options
    options
      .always_verify_peer(true)
      .openssl_certificate(cert_path.string())
      .openssl_sni_hostname(uri.host())
      .openssl_ciphers(
          "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES"
          ":ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES"
          ":!aNULL:!MD5")
      .openssl_options(SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_ALL);
  }
  // Create client with options
  Client client(options);
  try {
    // Create request
    Request request(uri.string());  // A fully-qualified, completed URI
    // Add required Java I2P defined user-agent
    request << boost::network::header("User-Agent", "Wget/1.11.4");
    // Are we requesting the same file?
    if (uri.path() == GetPreviousPath()) {
      // Add ETag and Last-Modified headers if previously set
      if (!GetPreviousETag().empty())
        request << boost::network::header("If-None-Match", GetPreviousETag());
      if (!GetPreviousLastModified().empty())
        request << boost::network::header("If-Modified-Since", GetPreviousLastModified());
    } else {
      // Set path to test against for future download (if this is a single instance)
      SetPath(uri.path());
    }
    // Create response object, send request and receive response
    Response response = client.get(request);
    // Test HTTP response status code
    switch (response.status()) {
      // New download or cached version does not match, so re-download
      case static_cast<std::uint16_t>(ResponseCode::HTTP_OK):
        // Parse response headers for ETag and Last-Modified
        for (auto const& header : response.headers()) {
          if (header.first == "ETag") {
            if (header.second != GetPreviousETag())
              SetETag(header.second);  // Set new ETag
          }
          if (header.first == "Last-Modified") {
            if (header.second != GetPreviousLastModified())
              SetLastModified(header.second);  // Set new Last-Modified
          }
        }
        // Save downloaded content
        SetDownloadedContents(boost::network::http::body(response));
        break;
      // File requested is unchanged since previous download
      case static_cast<std::uint16_t>(ResponseCode::HTTP_NOT_MODIFIED):
        LogPrint(eLogInfo, "HTTP: no new updates available from ", uri.host());
        break;
      // Useless response code
      default:
        LogPrint(eLogWarn, "HTTP: response code: ", response.status());
        return false;
    }
  } catch (const std::exception& ex) {
    LogPrint(eLogError, "HTTP: unable to complete download: ", ex.what());
    return false;
  }
  return true;
}

// TODO(anonimal): cpp-netlib refactor: request/response handler
bool HTTP::DownloadViaI2P() {
  // Clear buffers (for when we're only using a single instance)
  m_Request.clear();
  m_Response.clear();
  // Get URI
  auto uri = GetURI();
  // Reference the only instantiated address book instance in the singleton client context
  auto& address_book = kovri::client::context.GetAddressBook();
  // For identity hash of URI host
  kovri::core::IdentHash ident;
  // Get URI host's ident hash then find its lease-set
  if (address_book.CheckAddressIdentHashFound(uri.host(), ident)
      && address_book.GetSharedLocalDestination()) {
    std::condition_variable new_data_received;
    std::mutex new_data_received_mutex;
    auto lease_set = address_book.GetSharedLocalDestination()->FindLeaseSet(ident);
    // Lease-set not available, request
    if (!lease_set) {
      std::unique_lock<std::mutex> lock(new_data_received_mutex);
      address_book.GetSharedLocalDestination()->RequestDestination(
          ident,
          [&new_data_received, &lease_set](
              std::shared_ptr<kovri::core::LeaseSet> ls) {
            lease_set = ls;
            new_data_received.notify_all();
          });
      // TODO(anonimal): request times need to be more consistent.
      //   In testing, even after integration, results vary dramatically.
      //   This could be a router issue or something amiss during the refactor.
      if (new_data_received.wait_for(
              lock,
              std::chrono::seconds(
                  static_cast<std::uint8_t>(Timeout::Request)))
          == std::cv_status::timeout)
        LogPrint(eLogError, "HTTP: lease-set request timeout expired");
    }
    // Test against requested lease-set
    if (!lease_set) {
      LogPrint(eLogError,
          "HTTP: lease-set for address ", uri.host(), " not found");
    } else {
      PrepareI2PRequest();  // TODO(anonimal): remove after refactor
      // Send request
      auto stream =
        kovri::client::context.GetAddressBook().GetSharedLocalDestination()->CreateStream(
            lease_set,
            std::stoi(uri.port()));
      stream->Send(
          reinterpret_cast<const std::uint8_t *>(m_Request.str().c_str()),
          m_Request.str().length());
      // Receive response
      std::array<std::uint8_t, 4096> buf;  // Arbitrary buffer size
      bool end_of_data = false;
      while (!end_of_data) {
        stream->AsyncReceive(
            boost::asio::buffer(
              buf.data(),
              buf.size()),
            [&](const boost::system::error_code& ecode,
              std::size_t bytes_transferred) {
                if (bytes_transferred)
                  m_Response.write(
                      reinterpret_cast<char *>(buf.data()),
                      bytes_transferred);
                if (ecode == boost::asio::error::timed_out || !stream->IsOpen())
                  end_of_data = true;
                new_data_received.notify_all();
              },
            static_cast<std::uint8_t>(Timeout::Receive));
        std::unique_lock<std::mutex> lock(new_data_received_mutex);
        // Check if we timeout
        if (new_data_received.wait_for(
                lock,
                std::chrono::seconds(
                    static_cast<std::uint8_t>(Timeout::Request)))
            == std::cv_status::timeout)
          LogPrint(eLogError,"HTTP: in-net timeout expired");
      }
      // Process remaining buffer
      while (std::size_t len = stream->ReadSome(buf.data(), buf.size()))
        m_Response.write(reinterpret_cast<char *>(buf.data()), len);
    }
  } else {
    LogPrint(eLogError, "HTTP: can't resolve I2P address: ", uri.host());
    return false;
  }
  return ProcessI2PResponse();  // TODO(anonimal): remove after refactor
}

// TODO(anonimal): remove after refactor
void HTTP::PrepareI2PRequest() {
  // Create header
  auto uri = GetURI();
  std::string header =
    "GET " + uri.path() + " HTTP/1.1\r\n" +
    "Host: " + uri.host() + "\r\n" +
    "Accept: */*\r\n" +
    "User-Agent: Wget/1.11.4\r\n" +
    "Connection: Close\r\n";
  // Add header to request
  m_Request << header;
  // Check fields
  if (!GetPreviousETag().empty())  // Send previously set ETag if available
    m_Request << "If-None-Match" << ": \"" << GetPreviousETag() << "\"\r\n";
  if (!GetPreviousLastModified().empty())  // Send previously set Last-Modified if available
    m_Request << "If-Modified-Since" << ": " << GetPreviousLastModified() << "\r\n";
  m_Request << "\r\n";  // End of header
}

// TODO(anonimal): remove after refactor
bool HTTP::ProcessI2PResponse() {
  std::string http_version;
  std::uint16_t response_code = 0;
  m_Response >> http_version;
  m_Response >> response_code;
  if (response_code == static_cast<std::uint16_t>(ResponseCode::HTTP_OK)) {
    bool is_chunked = false;
    std::string header, status_message;
    std::getline(m_Response, status_message);
    // Read response until end of header (new line)
    while (std::getline(m_Response, header) && header != "\r") {
      auto colon = header.find(':');
      if (colon != std::string::npos) {
        std::string field = header.substr(0, colon);
        header.resize(header.length() - 1);  // delete \r
        // We currently don't differentiate between strong or weak ETags
        // We currently only care if an ETag is present
        if (field == "ETag")
          SetETag(header.substr(colon + 1));
        else if (field == "Last-Modified")
          SetLastModified(header.substr(colon + 1));
        else if (field == "Transfer-Encoding")
          is_chunked = !header.compare(colon + 1, std::string::npos, "chunked");
      }
    }
    // Get content after header
    std::stringstream content;
    while (std::getline(m_Response, header)) {
      // TODO(anonimal): this can be improved but since we
      // won't need this after the refactor, it 'works' for now
      auto colon = header.find(':');
      if (colon != std::string::npos)
        continue;
      else
        content << header << std::endl;
    }
    // Test if response is chunked / save downloaded contents
    if (!content.eof()) {
      if (is_chunked) {
        std::stringstream merged;
        MergeI2PChunkedResponse(content, merged);
        SetDownloadedContents(merged.str());
      } else {
        SetDownloadedContents(content.str());
      }
    }
  } else if (response_code
             == static_cast<std::uint16_t>(ResponseCode::HTTP_NOT_MODIFIED)) {
    LogPrint(eLogInfo, "HTTP: no new updates available from ", GetURI().host());
  } else {
    LogPrint(eLogWarn, "HTTP: response code: ", response_code);
    return false;
  }
  return true;
}

// TODO(anonimal): remove after refactor
// Note: Transfer-Encoding is handled automatically by cpp-netlib
void HTTP::MergeI2PChunkedResponse(
    std::istream& response,
    std::ostream& merged) {
  // Read in hex value of length
  std::string hex;
  while (std::getline(response, hex)) {
    std::istringstream hex_len(hex);
    // Convert to integer value
    std::size_t len(0);
    // CID 146759 complains of TAINTED_SCALAR but we're guaranteed a useful value because:
    // 1. The HTTP response is chunked and prepends hex value of chunk size
    // 2. If length is null, we'll break before new buffer
    // Note: verifying the validity of stated chunk size against ensuing content size
    // will require more code (so, better to complete cpp-netlib refactor instead)
    if (!(hex_len >> std::hex >> len).fail()) {
      // If last chunk, break
      if (!len)
        break;
      // Read in chunk content of chunk size
      auto buf = std::make_unique<char[]>(len);
      response.read(buf.get(), len);
      merged.write(buf.get(), len);
      std::getline(response, hex);  // read \r\n after chunk
    } else {
      LogPrint(eLogError,
          "HTTP: stream error, unable to read line from chunked response");
      break;
    }
  }
}

// TODO(anonimal): research if cpp-netlib can do this better
std::string HTTP::HTTPProxyDecode(
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

}  // namespace client
}  // namespace kovri
