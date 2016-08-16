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

#ifndef SRC_CLIENT_I2P_TUNNEL_I2P_TUNNEL_H_
#define SRC_CLIENT_I2P_TUNNEL_I2P_TUNNEL_H_

#include <boost/asio.hpp>

#include <inttypes.h>
#include <memory>
#include <set>
#include <sstream>
#include <string>

#include "identity.h"
#include "streaming.h"
#include "client/destination.h"
#include "client/i2p_service.h"

namespace i2p {
namespace client {

const size_t I2P_TUNNEL_CONNECTION_BUFFER_SIZE = 8192;
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
      std::shared_ptr<const i2p::data::LeaseSet> lease_set,
      int port = 0);

  // To I2P using simplified API
  I2PTunnelConnection(
      I2PService* owner,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket,
      std::shared_ptr<i2p::stream::Stream> stream);

  // From I2P
  I2PTunnelConnection(
      I2PService* owner,
      std::shared_ptr<i2p::stream::Stream> stream,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket,
      const boost::asio::ip::tcp::endpoint& target,
      bool quiet = true);

  ~I2PTunnelConnection();

  void I2PConnect(
      const uint8_t* msg = nullptr,
      size_t len = 0);

  void Connect();

 protected:
  void Terminate();

  void Receive();

  void HandleReceived(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  // can be overloaded
  virtual void Write(
      const uint8_t* buf,
      size_t len);

  void HandleWrite(
      const boost::system::error_code& ecode);

  void StreamReceive();

  void HandleStreamReceive(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  void HandleConnect(
      const boost::system::error_code& ecode);

 private:
  uint8_t m_Buffer[I2P_TUNNEL_CONNECTION_BUFFER_SIZE],
  m_StreamBuffer[I2P_TUNNEL_CONNECTION_BUFFER_SIZE];

  std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
  std::shared_ptr<i2p::stream::Stream> m_Stream;
  boost::asio::ip::tcp::endpoint m_RemoteEndpoint;
  bool m_IsQuiet;  // don't send destination
};

class I2PTunnelConnectionHTTP: public I2PTunnelConnection {
 public:
  I2PTunnelConnectionHTTP(
      I2PService* owner,
      std::shared_ptr<i2p::stream::Stream> stream,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket,
      const boost::asio::ip::tcp::endpoint& target,
      const std::string& host);

 protected:
  void Write(
      const uint8_t* buf,
      size_t len);

 private:
  std::string m_Host;
  std::stringstream m_InHeader, m_OutHeader;
  bool m_HeaderSent;
};

class I2PClientTunnel : public TCPIPAcceptor {
 protected:
  // Implements TCPIPAcceptor
  std::shared_ptr<I2PServiceHandler> CreateHandler(
      std::shared_ptr<boost::asio::ip::tcp::socket> socket);

 public:
  I2PClientTunnel(
      const std::string& name,
      const std::string& destination,
      const std::string& address,
      int port,
      std::shared_ptr<ClientDestination> localDestination,
      int destinationPort = 0);

  ~I2PClientTunnel() {}

  void Start();
  void Stop();
  std::string GetName() const;

 private:
  std::unique_ptr<const i2p::data::IdentHash> GetIdentHash();
  std::string m_TunnelName;
  std::string m_Destination;
  std::unique_ptr<const i2p::data::IdentHash> m_DestinationIdentHash;
  int m_DestinationPort;
};

class I2PServerTunnel : public I2PService {
 public:
  I2PServerTunnel(
      const std::string& name,
      const std::string& address,
      int port,
      std::shared_ptr<ClientDestination> localDestination,
      int inport = 0);

  void Start();

  void Stop();

  void SetAccessList(
      const std::set<i2p::data::IdentHash>& accessList);

  // set access list given csv
  void SetAccessListString(
      const std::string& idents_str);

  std::string GetAddress() const {
    return m_Address;
  }

  // update the address of this server tunnel
  void UpdateAddress(
      const std::string& addr);

  int GetPort() const {
    return m_Port;
  }

  // update the out port of this server tunnel
  void UpdatePort(
      int port);

  // update the streaming destination's port
  void UpdateStreamingPort(
      int port) const;

  const boost::asio::ip::tcp::endpoint& GetEndpoint() const {
    return m_Endpoint;
  }

  std::string GetName() const;

 private:
  void HandleResolve(
      const boost::system::error_code& ecode,
      boost::asio::ip::tcp::resolver::iterator it,
      std::shared_ptr<boost::asio::ip::tcp::resolver> resolver,
      bool acceptAfter = true);

  void Accept();

  void HandleAccept(
      std::shared_ptr<i2p::stream::Stream> stream);

  virtual void CreateI2PConnection(
      std::shared_ptr<i2p::stream::Stream> stream);

 private:
  std::string m_Address;
  std::string m_TunnelName;
  int m_Port;
  boost::asio::ip::tcp::endpoint m_Endpoint;
  std::shared_ptr<i2p::stream::StreamingDestination> m_PortDestination;
  std::set<i2p::data::IdentHash> m_AccessList;
  bool m_IsAccessList;
};

class I2PServerTunnelHTTP: public I2PServerTunnel {
 public:
  I2PServerTunnelHTTP(
      const std::string& name,
      const std::string& address,
      int port,
      std::shared_ptr<ClientDestination> localDestination,
      int inport = 0);

 private:
  void CreateI2PConnection(
      std::shared_ptr<i2p::stream::Stream> stream);
};

}  // namespace client
}  // namespace i2p

#endif  // SRC_CLIENT_I2P_TUNNEL_I2P_TUNNEL_H_
