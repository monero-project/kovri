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

#ifndef SRC_CLIENT_TUNNEL_H_
#define SRC_CLIENT_TUNNEL_H_

#include <boost/asio.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <sstream>
#include <string>

#include "client/api/streaming.h"
#include "client/destination.h"
#include "client/service.h"

#include "core/router/identity.h"

namespace kovri {
namespace client {

/// @class ACL
/// @brief Access Control List for tunnel attributes
struct ACL {
  ACL() : is_white(false), is_black(false) {}
  std::string list;
  bool is_white, is_black;
};

// TODO(anonimal): signature type (see #369)
/// @class TunnelAttributes
/// @brief Attributes for client/server tunnel
/// @notes For details, see tunnels configuration key
struct TunnelAttributes {
  TunnelAttributes() : port(0), dest_port(0), in_port(0) {}
  std::string name, type, dest, address, keys;
  std::uint16_t port, dest_port, in_port;
  ACL acl{};
};

const std::size_t I2P_TUNNEL_CONNECTION_BUFFER_SIZE = 8192;
const int I2P_TUNNEL_CONNECTION_MAX_IDLE = 3600;  // in seconds
const int I2P_TUNNEL_DESTINATION_REQUEST_TIMEOUT = 10;  // in seconds

class I2PTunnelConnection
    : public I2PServiceHandler,
      public std::enable_shared_from_this<I2PTunnelConnection> {
 public:
  // To I2P
  I2PTunnelConnection(
      I2PService* owner,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket,
      std::shared_ptr<const kovri::core::LeaseSet> lease_set,
      std::uint16_t port = 0);

  // To I2P using simplified API
  I2PTunnelConnection(
      I2PService* owner,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket,
      std::shared_ptr<kovri::client::Stream> stream);

  // From I2P
  I2PTunnelConnection(
      I2PService* owner,
      std::shared_ptr<kovri::client::Stream> stream,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket,
      const boost::asio::ip::tcp::endpoint& target,
      bool quiet = true);

  ~I2PTunnelConnection();

  void I2PConnect(
      const std::uint8_t* msg = nullptr,
      std::size_t len = 0);

  void Connect();

 protected:
  void Terminate();

  void Receive();

  void HandleReceived(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  // can be overloaded
  virtual void Write(
      const std::uint8_t* buf,
      std::size_t len);

  void HandleWrite(
      const boost::system::error_code& ecode);

  void StreamReceive();

  void HandleStreamReceive(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  void HandleConnect(
      const boost::system::error_code& ecode);

 private:
  std::uint8_t m_Buffer[I2P_TUNNEL_CONNECTION_BUFFER_SIZE],
  m_StreamBuffer[I2P_TUNNEL_CONNECTION_BUFFER_SIZE];

  std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
  std::shared_ptr<kovri::client::Stream> m_Stream;
  boost::asio::ip::tcp::endpoint m_RemoteEndpoint;
  bool m_IsQuiet;  // don't send destination
};

class I2PTunnelConnectionHTTP: public I2PTunnelConnection {
 public:
  I2PTunnelConnectionHTTP(
      I2PService* owner,
      std::shared_ptr<kovri::client::Stream> stream,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket,
      const boost::asio::ip::tcp::endpoint& target,
      const std::string& host);

 protected:
  void Write(
      const std::uint8_t* buf,
      std::size_t len);

 private:
  std::string m_Host;
  std::stringstream m_InHeader, m_OutHeader;
  bool m_HeaderSent;
};

/// @class I2PClientTunnel
class I2PClientTunnel : public TCPIPAcceptor {
 public:
  I2PClientTunnel(
      const TunnelAttributes& tunnel,
      std::shared_ptr<ClientDestination> local_destination);

  ~I2PClientTunnel() {}

  /// @brief Starts TCP/IP acceptor, client tunnel startup
  void Start();

  /// @brief Stops TCP/IP acceptor, client tunnel cleanup
  void Stop();

  /// @brief Get tunnel attributes class member
  /// @return Const reference to member
  const TunnelAttributes& GetTunnelAttributes() noexcept {
    return m_TunnelAttributes;
  }

  // TODO(unassigned): must this function be virtual? Can we extend tunnel attributes?
  /// @brief Returns tunnel name
  std::string GetName() const {
    return m_TunnelAttributes.name;
  }

 protected:
  /// @brief Implements TCPIPAcceptor
  std::shared_ptr<I2PServiceHandler> CreateHandler(
      std::shared_ptr<boost::asio::ip::tcp::socket> socket);

 private:
  /// @var m_TunnelAttributes
  /// @brief Client tunnel attributes
  TunnelAttributes m_TunnelAttributes;

  /// @brief Gets ident hash of tunnel attribute remote destination
  /// @return Unique pointer to ident hash
  std::unique_ptr<const kovri::core::IdentHash> GetDestIdentHash();

  /// @brief Destination ident hash
  std::unique_ptr<const kovri::core::IdentHash> m_DestinationIdentHash;
};

// TODO(anonimal): more documentation
/// @class I2PClientTunnelHandler
/// @brief Establishes a connection with the desired destination
class I2PClientTunnelHandler
    : public I2PServiceHandler,
      public std::enable_shared_from_this<I2PClientTunnelHandler> {
 public:
  I2PClientTunnelHandler(
      I2PClientTunnel* parent,
      kovri::core::IdentHash destination,
      std::uint16_t destination_port,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket);

  void Handle();

  void Terminate();

 private:
  void HandleStreamRequestComplete(std::shared_ptr<kovri::client::Stream> stream);
  kovri::core::IdentHash m_DestinationIdentHash;
  std::uint16_t m_DestinationPort;
  std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
};

/// @class I2PServerTunnel
class I2PServerTunnel : public I2PService {
 public:
  I2PServerTunnel(
      const TunnelAttributes& tunnel,
      std::shared_ptr<ClientDestination> local_destination);

  /// @brief Starts resolver, server tunnel startup
  void Start();

  /// @brief Server tunnel shutdown, cleanup
  void Stop();

  /// @brief Updates server tunnel with new set tunnel attributes
  /// @param tunnel Tunnel attributes to update with
  void UpdateServerTunnel(
      const TunnelAttributes& tunnel);

  /// @brief Set tunnel attributes
  /// @param tunnel Initialized/populated tunnel attributes class
  void SetTunnelAttributes(
      const TunnelAttributes& tunnel) noexcept {
    m_TunnelAttributes = tunnel;
  }

  /// @brief Return tunnel attributes class member
  /// @return Const reference to member
  const TunnelAttributes& GetTunnelAttributes() noexcept {
    return m_TunnelAttributes;
  }

  /// @brief Set the Access Control List given in tunnel attributes
  void SetACL();

  /// @brief Return populated Access Control List
  /// @return Const reference to member
  const std::set<kovri::core::IdentHash>& GetACL() noexcept {
    return m_ACL;
  }

  /// @brief Enforce Access Control List: whitelist/blacklist/no list
  /// @param stream Shared pointer to client stream
  /// @return False If ACL applies to stream (and stream should be closed)
  bool EnforceACL(
    std::shared_ptr<kovri::client::Stream> stream);

  // TODO(unassigned): must this function be virtual? Can we extend tunnel attributes?
  /// @brief Returns tunnel name
  std::string GetName() const {
    return m_TunnelAttributes.name;
  }

  /// @brief Gets endpoint object
  /// @return Const reference to endpoint object
  const boost::asio::ip::tcp::endpoint& GetEndpoint() noexcept {
    return m_Endpoint;
  }

 private:
  /// @brief Handles server tunnel endpoint resolution
  void HandleResolve(
      const boost::system::error_code& ecode,
      boost::asio::ip::tcp::resolver::iterator it,
      std::shared_ptr<boost::asio::ip::tcp::resolver> resolver,
      bool accept_after = true);

  /// @brief Prepares for streaming connection handling
  void Accept();

  /// @brief Handles streaming connection
  void HandleAccept(
      std::shared_ptr<kovri::client::Stream> stream);

  /// @brief Creates Streaming connection for inbound in-net connection attempts
  /// @param stream Shared pointer to stream object
  virtual void CreateI2PConnection(
      std::shared_ptr<kovri::client::Stream> stream);

 private:
  /// @var m_TunnelAttributes
  /// @brief Server tunnel attributes
  TunnelAttributes m_TunnelAttributes;

  /// @var m_Endpoint
  /// @brief Endpoint for interface binding
  boost::asio::ip::tcp::endpoint m_Endpoint;

  /// @var m_PortDestination
  /// @brief Used to connect Streaming handling to server tunnel port handling
  std::shared_ptr<kovri::client::StreamingDestination> m_PortDestination;

  /// @var m_ACL
  /// @brief Access Control List for inbound streaming connections
  std::set<kovri::core::IdentHash> m_ACL;
};

/// @class I2PServerTunnelHTTP
class I2PServerTunnelHTTP : public I2PServerTunnel {
 public:
  I2PServerTunnelHTTP(
      const TunnelAttributes& tunnel,
      std::shared_ptr<ClientDestination> local_destination);

 private:
  void CreateI2PConnection(
      std::shared_ptr<kovri::client::Stream> stream);
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_TUNNEL_H_
