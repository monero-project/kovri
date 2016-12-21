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

#include "client/tunnel.h"

#include <cassert>
#include <memory>
#include <set>
#include <string>

#include "client/context.h"
#include "client/destination.h"
#include "client/util/parse.h"

#include "core/util/log.h"

namespace kovri {
namespace client {

//
// Tunnel connection implementation for all client/server tunnel types
//

I2PTunnelConnection::I2PTunnelConnection(
    I2PService* owner,
    std::shared_ptr<boost::asio::ip::tcp::socket> socket,
    std::shared_ptr<const kovri::core::LeaseSet> lease_set,
    std::uint16_t port)
    : I2PServiceHandler(owner),
      m_Socket(socket),
      m_RemoteEndpoint(socket->remote_endpoint()),
      m_IsQuiet(true) {
        m_Stream = GetOwner()->GetLocalDestination()->CreateStream(
            lease_set,
            port);
      }

I2PTunnelConnection::I2PTunnelConnection(
    I2PService* owner,
    std::shared_ptr<boost::asio::ip::tcp::socket> socket,
    std::shared_ptr<kovri::client::Stream> stream)
    : I2PServiceHandler(owner),
      m_Socket(socket),
      m_Stream(stream),
      m_RemoteEndpoint(socket->remote_endpoint()),
      m_IsQuiet(true) {}

I2PTunnelConnection::I2PTunnelConnection(
    I2PService* owner,
    std::shared_ptr<kovri::client::Stream> stream,
    std::shared_ptr<boost::asio::ip::tcp::socket> socket,
    const boost::asio::ip::tcp::endpoint& target,
    bool quiet)
    : I2PServiceHandler(owner),
      m_Socket(socket),
      m_Stream(stream),
      m_RemoteEndpoint(target),
      m_IsQuiet(quiet) {}

I2PTunnelConnection::~I2PTunnelConnection() {}

void I2PTunnelConnection::I2PConnect(
    const std::uint8_t* msg,
    std::size_t len) {
  if (m_Stream) {
    if (msg)
      m_Stream->Send(msg, len);  // connect and send
    else
      m_Stream->Send(m_Buffer, 0);  // connect
  }
  StreamReceive();
  Receive();
}

void I2PTunnelConnection::Connect() {
  if (m_Socket)
    m_Socket->async_connect(
        m_RemoteEndpoint,
        std::bind(
            &I2PTunnelConnection::HandleConnect,
            shared_from_this(),
            std::placeholders::_1));
}

void I2PTunnelConnection::Terminate() {
  if (Kill())
    return;
  if (m_Stream) {
    m_Stream->Close();
    m_Stream.reset();
  }
  m_Socket->close();
  Done(shared_from_this());
}

void I2PTunnelConnection::Receive() {
  m_Socket->async_read_some(
      boost::asio::buffer(
          m_Buffer,
          I2P_TUNNEL_CONNECTION_BUFFER_SIZE),
      std::bind(
          &I2PTunnelConnection::HandleReceived,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
}

void I2PTunnelConnection::HandleReceived(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred) {
  if (ecode) {
    LogPrint(eLogError,
        "I2PTunnelConnection: read error: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    if (m_Stream) {
      auto s = shared_from_this();
      m_Stream->AsyncSend(
          m_Buffer,
          bytes_transferred,
          [s](const boost::system::error_code& ecode) {
          if (!ecode)
            s->Receive();
          else
            s->Terminate();
        });
    }
  }
}

void I2PTunnelConnection::HandleWrite(
    const boost::system::error_code& ecode) {
  if (ecode) {
    LogPrint(eLogError,
        "I2PTunnelConnection: write error: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    StreamReceive();
  }
}

void I2PTunnelConnection::StreamReceive() {
  if (m_Stream)
    m_Stream->AsyncReceive(
        boost::asio::buffer(
            m_StreamBuffer,
            I2P_TUNNEL_CONNECTION_BUFFER_SIZE),
        std::bind(
            &I2PTunnelConnection::HandleStreamReceive,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2),
        I2P_TUNNEL_CONNECTION_MAX_IDLE);
}

void I2PTunnelConnection::HandleStreamReceive(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred) {
  if (ecode) {
    LogPrint(eLogError,
        "I2PTunnelConnection: stream read error: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    Write(m_StreamBuffer, bytes_transferred);
  }
}

void I2PTunnelConnection::Write(
    const std::uint8_t* buf,
    std::size_t len) {
  m_Socket->async_send(
      boost::asio::buffer(
          buf,
          len),
      std::bind(
          &I2PTunnelConnection::HandleWrite,
          shared_from_this(),
          std::placeholders::_1));
}

void I2PTunnelConnection::HandleConnect(
    const boost::system::error_code& ecode) {
  if (ecode) {
    LogPrint(eLogError,
        "I2PTunnelConnection: connect error: ", ecode.message());
    Terminate();
  } else {
    LogPrint(eLogDebug, "I2PTunnelConnection: connected");
    if (m_IsQuiet) {
      StreamReceive();
    } else {
      // send destination first like received from I2P
      std::string dest = m_Stream->GetRemoteIdentity().ToBase64();
      dest += "\n";
      memcpy(
          m_StreamBuffer,
          dest.c_str(),
          dest.size());
      HandleStreamReceive(
          boost::system::error_code(),
          dest.size());
    }
    Receive();
  }
}

I2PTunnelConnectionHTTP::I2PTunnelConnectionHTTP(
    I2PService* owner,
    std::shared_ptr<kovri::client::Stream> stream,
    std::shared_ptr<boost::asio::ip::tcp::socket> socket,
    const boost::asio::ip::tcp::endpoint& target,
    const std::string& host)
    : I2PTunnelConnection(
          owner,
          stream,
          socket,
          target),
      m_Host(host),
      m_HeaderSent(false) {}

void I2PTunnelConnectionHTTP::Write(
    const std::uint8_t* buf,
    std::size_t len) {
  if (m_HeaderSent) {
    I2PTunnelConnection::Write(buf, len);
  } else {
    m_InHeader.clear();
    m_InHeader.write((const char *)buf, len);
    std::string line;
    bool end_of_header = false;
    while (!end_of_header) {
      std::getline(m_InHeader, line);
      if (!m_InHeader.fail()) {
        if (line.find("Host:") != std::string::npos)
          m_OutHeader << "Host: " << m_Host << "\r\n";
        else
          m_OutHeader << line << "\n";
        if (line == "\r")
          end_of_header = true;
      } else {
        break;
      }
    }
    if (end_of_header) {
      m_OutHeader << m_InHeader.str();  // data right after header
      m_HeaderSent = true;
      I2PTunnelConnection::Write(
          (std::uint8_t *)m_OutHeader.str().c_str(),
          m_OutHeader.str().length());
    }
  }
}

//
// Client tunnel handler
//

 I2PClientTunnelHandler::I2PClientTunnelHandler(
      I2PClientTunnel* parent,
      kovri::core::IdentHash destination,
      std::uint16_t destination_port,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket)
    : I2PServiceHandler(parent),
      m_DestinationIdentHash(destination),
      m_DestinationPort(destination_port),
      m_Socket(socket) {}

void I2PClientTunnelHandler::Handle() {
  GetOwner()->GetLocalDestination()->CreateStream(
      std::bind(
          &I2PClientTunnelHandler::HandleStreamRequestComplete,
          shared_from_this(),
          std::placeholders::_1),
      m_DestinationIdentHash,
      m_DestinationPort);
}

void I2PClientTunnelHandler::HandleStreamRequestComplete(
    std::shared_ptr<kovri::client::Stream> stream) {
  if (stream) {
    if (Kill())
      return;
    LogPrint(eLogDebug, "I2PClientTunnelHandler: new I2PTunnel connection");
    auto connection =
      std::make_shared<I2PTunnelConnection>(
          GetOwner(),
          m_Socket,
          stream);
    GetOwner()->AddHandler(connection);
    connection->I2PConnect();
    Done(shared_from_this());
  } else {
    LogPrint(eLogError,
        "I2PClientTunnelHandler: stream not available ",
        "(router may need more time to integrate into the network)");
    Terminate();
  }
}

void I2PClientTunnelHandler::Terminate() {
  if (Kill())
    return;
  if (m_Socket) {
    m_Socket->close();
    m_Socket = nullptr;
  }
  Done(shared_from_this());
}

//
// Client tunnel
//

I2PClientTunnel::I2PClientTunnel(
    const TunnelAttributes& tunnel,
    std::shared_ptr<ClientDestination> local_destination)
    : TCPIPAcceptor(
          tunnel.address,
          tunnel.port,
          local_destination),
      m_TunnelAttributes(tunnel),
      m_DestinationIdentHash(nullptr) {}


void I2PClientTunnel::Start() {
  TCPIPAcceptor::Start();
  GetDestIdentHash();
}

void I2PClientTunnel::Stop() {
  TCPIPAcceptor::Stop();
  m_DestinationIdentHash.reset(nullptr);
}

// TODO(unassigned): HACK: maybe we should create a caching IdentHash provider in AddressBook?
std::unique_ptr<const kovri::core::IdentHash> I2PClientTunnel::GetDestIdentHash() {
  if (!m_DestinationIdentHash) {
    kovri::core::IdentHash ident_hash;
    AddressBook& book = kovri::client::context.GetAddressBook();
    std::string dest = GetTunnelAttributes().dest;
    if (book.CheckAddressIdentHashFound(dest, ident_hash)) {
      m_DestinationIdentHash = std::make_unique<kovri::core::IdentHash>(ident_hash);
    } else {
      LogPrint(eLogWarn,
          "I2PClientTunnel: remote destination ", dest, " not found");
    }
  }
  return std::move(m_DestinationIdentHash);
}

std::shared_ptr<I2PServiceHandler> I2PClientTunnel::CreateHandler(
    std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
  auto ident_hash = GetDestIdentHash();
  auto port = GetTunnelAttributes().dest_port;
  if (ident_hash) {
    return std::make_shared<I2PClientTunnelHandler>(this, *ident_hash, port, socket);
  } else {
    return nullptr;
  }
}

//
// Server tunnel
//

I2PServerTunnel::I2PServerTunnel(
    const TunnelAttributes& tunnel,
    std::shared_ptr<ClientDestination> local_destination)
    : I2PService(local_destination),
      m_TunnelAttributes(tunnel) {
        SetACL();
        // TODO(anonimal): assumes local_destination is not null.
        // I2PService will create a local destination if null but that has no bearing on this member.
        m_PortDestination =
          local_destination->CreateStreamingDestination(
              tunnel.in_port ? tunnel.in_port : tunnel.port);
      }

void I2PServerTunnel::Start() {
  /**
   * TODO(unassigned):
   *
   * We don't resolve the dns entry each time we connect so
   * we'd have to SIGHUP every time the entry changes
   * OR, we could resolve each time
   * BUT that would mean lots of dns queries
   * HOWEVER if when we SIGHUP something changes we SHOULD NOT throw away
   * the destination because that will discard the tunnel encryption keys which
   * causes interruption.
   *
   * Review the following options:
   * A) Get to the core of the problem and rewrite how we handle tunnels
   * B) Implement a strategy for caching and looking up hostname ip addresses
   */
  boost::system::error_code ec;
  std::string address = GetTunnelAttributes().address;
  auto ep_address = boost::asio::ip::address::from_string(address, ec);
  m_Endpoint.port(GetTunnelAttributes().port);
  if (!ec) {
    m_Endpoint.address(ep_address);
    Accept();
  } else {
    // TODO(unassigned): consider a resolver template + handler for boost resolver and other asio
    typedef boost::asio::ip::tcp::resolver tcp_resolver;
    auto resolver = std::make_shared<tcp_resolver>(GetService());
    resolver->async_resolve(
        tcp_resolver::query(
            address,
            ""),
        std::bind(
            &I2PServerTunnel::HandleResolve,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            resolver,
            true));
  }
}

void I2PServerTunnel::Stop() {
  ClearHandlers();
}

void I2PServerTunnel::HandleResolve(
    const boost::system::error_code& ecode,
    boost::asio::ip::tcp::resolver::iterator it,
    std::shared_ptr<boost::asio::ip::tcp::resolver>,
    bool accept_after) {
  if (!ecode) {
    auto addr = (*it).endpoint().address();
    LogPrint(eLogInfo,
        "I2PServerTunnel: server tunnel ",
        (*it).host_name(), " has been resolved to ", addr);
    m_Endpoint.address(addr);
    if (accept_after) {
      Accept();
    }
  } else {
    LogPrint(eLogError,
        "I2PServerTunnel: unable to resolve server tunnel address: ",
        ecode.message());
  }
}

void I2PServerTunnel::UpdateServerTunnel(
    const TunnelAttributes& tunnel) {
  // Update tunnel attributes
  SetTunnelAttributes(tunnel);
  // Update server endpoint address
  boost::system::error_code ec;
  auto ep_address = boost::asio::ip::address::from_string(tunnel.address, ec);
  if (!ec) {
    m_Endpoint.address(ep_address);
  } else {
    // TODO(unassigned): consider a resolver template + handler for boost resolver and other asio
    typedef boost::asio::ip::tcp::resolver tcp_resolver;
    auto resolver = std::make_shared<tcp_resolver>(GetService());
    resolver->async_resolve(
        tcp_resolver::query(
            tunnel.address,
            ""),
        std::bind(
            &I2PServerTunnel::HandleResolve,
            this,
            std::placeholders::_1,
            std::placeholders::_2,
            resolver,
            false));

  }
  // Update in port (streaming port)
  m_PortDestination->UpdateLocalPort(tunnel.in_port);
  // Set ACL
  SetACL();
}

void I2PServerTunnel::SetACL() {
  // Get tunnel CSV list of ACL
  std::string list = GetTunnelAttributes().acl.list;
  if (list.empty()) {
    // No CSV list given, ignore
    return;
  }
  // Get parsed CSV
  auto parsed = kovri::client::ParseCSV(list);
  // Get b32 of each value
  std::set<kovri::core::IdentHash> idents;
  for (auto const& p : parsed) {
    kovri::core::IdentHash ident;
    ident.FromBase32(p);
    idents.insert(ident);
  }
  // Set ACL
  m_ACL = idents;
}

void I2PServerTunnel::Accept() {
  if (m_PortDestination)
    m_PortDestination->SetAcceptor(
        std::bind(
            &I2PServerTunnel::HandleAccept,
            this,
            std::placeholders::_1));
  auto local_destination = GetLocalDestination();
  if (local_destination) {
    // set it as default if not set yet
    if (!local_destination->IsAcceptingStreams())
      local_destination->AcceptStreams(
          std::bind(
              &I2PServerTunnel::HandleAccept,
              this,
              std::placeholders::_1));
  } else {
    LogPrint(eLogDebug,
        "I2PServerTunnel: local destination not set for server tunnel");
  }
}

void I2PServerTunnel::HandleAccept(
    std::shared_ptr<kovri::client::Stream> stream) {
  if (stream) {
    if (!EnforceACL(stream))
      return;
    LogPrint(eLogInfo,
        "I2PServerTunnel: creating connection with ",
        stream->GetRemoteIdentity().GetIdentHash().ToBase32() + ".b32.i2p");
    CreateI2PConnection(stream);
  }
}

bool I2PServerTunnel::EnforceACL(
    std::shared_ptr<kovri::client::Stream> stream) {
  if (GetACL().empty()) {
    LogPrint(eLogDebug, "I2PServerTunnel: ACL empty, continuing");
    return true;
  }
  auto ident = stream->GetRemoteIdentity().GetIdentHash();
  bool is_on_list = GetACL().count(ident);
  auto b32 = ident.ToBase32() + ".b32.i2p";
  LogPrint(eLogInfo, "I2PServerTunnel: enforcing ACL for ", b32);
  if (GetTunnelAttributes().acl.is_white) {
    LogPrint(eLogInfo, "I2PServerTunnel: whitelist enabled");
    if (is_on_list) {
      LogPrint(eLogInfo, "I2PServerTunnel: ", b32, " is on whitelist");
      return true;
    }
    LogPrint(eLogWarn,
        "I2PServerTunnel: ", b32, "is not on whitelist, dropping connection");
  } else if (GetTunnelAttributes().acl.is_black) {
    LogPrint(eLogInfo, "I2PServerTunnel: blacklist enabled");
    if (!is_on_list) {
      LogPrint(eLogInfo, "I2PServerTunnel: ", b32, " is not on blacklist");
      return true;
    }
    LogPrint(eLogWarn,
        "I2PServerTunnel: ", b32, " is on blacklist, dropping connection");
  }
  stream->Close();
  return false;
}

void I2PServerTunnel::CreateI2PConnection(
    std::shared_ptr<kovri::client::Stream> stream) {
  auto conn =
    std::make_shared<I2PTunnelConnection>(
        this,
        stream,
        std::make_shared<boost::asio::ip::tcp::socket>(GetService()),
        GetEndpoint());
  AddHandler(conn);
  conn->Connect();
}

I2PServerTunnelHTTP::I2PServerTunnelHTTP(
    const TunnelAttributes& tunnel,
    std::shared_ptr<ClientDestination> local_destination)
    : I2PServerTunnel(
          tunnel,
          local_destination) {}

void I2PServerTunnelHTTP::CreateI2PConnection(
    std::shared_ptr<kovri::client::Stream> stream) {
  auto conn =
    std::make_shared<I2PTunnelConnectionHTTP>(
        this,
        stream,
        std::make_shared<boost::asio::ip::tcp::socket>(GetService()),
        GetEndpoint(),
        GetTunnelAttributes().address);
  AddHandler(conn);
  conn->Connect();
}

}  // namespace client
}  // namespace kovri
