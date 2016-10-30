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

#include "client/proxy/socks.h"

#include <atomic>
#include <cassert>
#include <cstring>
#include <string>

#include "client/api/streaming.h"
#include "client/context.h"
#include "client/destination.h"
#include "client/tunnel.h"

#include "core/router/identity.h"

#include "core/util/i2p_endian.h"

namespace kovri {
namespace client {

static const std::size_t SOCKS_BUFFER_SIZE = 8192;
// Limit for socks5 and bad idea to traverse
static const std::size_t MAX_SOCKS_HOSTNAME_SIZE = 255;

struct SOCKSDnsAddress {
  std::uint8_t size;
  char value[MAX_SOCKS_HOSTNAME_SIZE];
  void FromString(std::string str) {
    size = str.length();
    if (str.length() > MAX_SOCKS_HOSTNAME_SIZE)
      size = MAX_SOCKS_HOSTNAME_SIZE;
    memcpy(value, str.c_str(), size);
  }
  std::string ToString() { return std::string(value, size); }
  void push_back(char c) { value[size++] = c; }
};

class SOCKSServer;
class SOCKSHandler
    : public kovri::client::I2PServiceHandler,
      public std::enable_shared_from_this<SOCKSHandler> {
 private:
  enum state {
    GET_SOCKSV,
    GET_COMMAND,
    GET_PORT,
    GET_IPV4,
    GET4_IDENT,
    GET4A_HOST,
    GET5_AUTHNUM,
    GET5_AUTH,
    GET5_REQUESTV,
    GET5_GETRSV,
    GET5_GETADDRTYPE,
    GET5_IPV6,
    GET5_HOST_SIZE,
    GET5_HOST,
    DONE
  };
  enum authMethods {
    AUTH_NONE = 0,               // No authentication, skip to next step
    AUTH_GSSAPI = 1,             // GSSAPI authentication
    AUTH_USERPASSWD = 2,         // Username and password
    AUTH_UNACCEPTABLE = 0xff     // No acceptable method found
  };
  enum addrTypes {
    ADDR_IPV4 = 1,               // IPv4 address (4 octets)
    ADDR_DNS = 3,                // DNS name (up to 255 octets)
    ADDR_IPV6 = 4                // IPV6 address (16 octets)
  };
  enum errTypes {
    SOCKS5_OK = 0,               // No error for SOCKS5
    SOCKS5_GEN_FAIL = 1,         // General server failure
    SOCKS5_RULE_DENIED = 2,      // Connection disallowed by ruleset
    SOCKS5_NET_UNREACH = 3,      // Network unreachable
    SOCKS5_HOST_UNREACH = 4,     // Host unreachable
    SOCKS5_CONN_REFUSED = 5,     // Connection refused by the peer
    SOCKS5_TTL_EXPIRED = 6,      // TTL Expired
    SOCKS5_CMD_UNSUP = 7,        // Command unsupported
    SOCKS5_ADDR_UNSUP = 8,       // Address type unsupported
    SOCKS4_OK = 90,              // No error for SOCKS4
    SOCKS4_FAIL = 91,            // Failed establishing connecting or not allowed
    SOCKS4_IDENTD_MISSING = 92,  // Couldn't connect to the identd server
    SOCKS4_IDENTD_DIFFER = 93    // The ID reported by the application and by identd differ
  };
  enum cmdTypes {
    CMD_CONNECT = 1,             // TCP Connect
    CMD_BIND = 2,                // TCP Bind
    CMD_UDP = 3                  // UDP associate
  };
  enum socksVersions {
    SOCKS4 = 4,                  // SOCKS4
    SOCKS5 = 5                   // SOCKS5
  };
  union address {
    std::uint32_t ip;
    SOCKSDnsAddress dns;
    std::uint8_t ipv6[16];
  };

  void EnterState(
      state nstate,
      std::uint8_t parseleft = 1);

  bool HandleData(
      std::uint8_t* sock_buff,
      std::size_t len);

  bool ValidateSOCKSRequest();

  void HandleSockRecv(
      const boost::system::error_code& ecode,
      std::size_t bytes_transfered);

  void Terminate();

  void AsyncSockRead();

  boost::asio::const_buffers_1 GenerateSOCKS5SelectAuth(
      authMethods method);

  boost::asio::const_buffers_1 GenerateSOCKS4Response(
      errTypes error,
      std::uint32_t ip,
      std::uint16_t port);

  boost::asio::const_buffers_1 GenerateSOCKS5Response(
      errTypes error,
      addrTypes type,
      const address &addr,
      std::uint16_t port);

  bool Socks5ChooseAuth();

  void SocksRequestFailed(
      errTypes error);

  void SocksRequestSuccess();

  void SentSocksFailed(
      const boost::system::error_code & ecode);

  void SentSocksDone(
      const boost::system::error_code & ecode);

  void SentSocksResponse(
      const boost::system::error_code & ecode);

  void HandleStreamRequestComplete(
      std::shared_ptr<kovri::client::Stream> stream);

  std::uint8_t m_sock_buff[SOCKS_BUFFER_SIZE];
  std::shared_ptr<boost::asio::ip::tcp::socket> m_sock;
  std::shared_ptr<kovri::client::Stream> m_stream;
  std::uint8_t *m_remaining_data;  // Data left to be sent
  std::uint8_t m_response[7+MAX_SOCKS_HOSTNAME_SIZE];
  address m_address;  // Address
  std::size_t m_remaining_data_len;  // Size of the data left to be sent
  std::uint32_t m_4aip;  // Used in 4a requests
  std::uint16_t m_port;
  std::uint8_t m_command;
  std::uint8_t m_parseleft;  // Octets left to parse
  authMethods m_authchosen;  // Authentication chosen
  addrTypes m_addrtype;  // Address type chosen
  socksVersions m_socksv;  // Socks version
  cmdTypes m_cmd;  // Command requested
  state m_state;

 public:
  SOCKSHandler(
      SOCKSServer* parent,
      std::shared_ptr<boost::asio::ip::tcp::socket> sock)
      : I2PServiceHandler(parent),
        m_sock(sock),
        m_stream(nullptr),
        m_remaining_data(nullptr),
        m_remaining_data_len(0),
        m_port(0),
        m_command(0),
        m_authchosen(AUTH_UNACCEPTABLE),
        m_addrtype(ADDR_IPV4),
        m_socksv(SOCKS5),
        m_cmd(CMD_CONNECT) {
          m_address.ip = 0;
          EnterState(GET_SOCKSV);
        }
  ~SOCKSHandler() { Terminate(); }
  void Handle() { AsyncSockRead(); }
};

void SOCKSHandler::AsyncSockRead() {
  LogPrint(eLogDebug, "SOCKSHandler: async sock read");
  if (m_sock)
    m_sock->async_receive(
        boost::asio::buffer(
          m_sock_buff,
          SOCKS_BUFFER_SIZE),
        std::bind(
          &SOCKSHandler::HandleSockRecv,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
  else
    LogPrint(eLogError, "SOCKSHandler: no socket for read");
}

void SOCKSHandler::Terminate() {
  if (Kill()) return;
  if (m_sock) {
    LogPrint(eLogDebug, "SOCKSHandler: close sock");
    m_sock->close();
    m_sock = nullptr;
  }
  if (m_stream) {
    LogPrint(eLogDebug, "SOCKSHandler: close stream");
    m_stream.reset();
  }
  Done(shared_from_this());
}

boost::asio::const_buffers_1 SOCKSHandler::GenerateSOCKS4Response(
    SOCKSHandler::errTypes error,
    std::uint32_t ip,
    std::uint16_t port) {
  assert(error >= SOCKS4_OK);
  m_response[0] = '\x00';         // Version
  m_response[1] = error;          // Response code
  htobe16buf(m_response + 2, port);  // Port
  htobe32buf(m_response + 4, ip);    // IP
  return boost::asio::const_buffers_1(m_response, 8);
}

boost::asio::const_buffers_1 SOCKSHandler::GenerateSOCKS5Response(
    SOCKSHandler::errTypes error,
    SOCKSHandler::addrTypes type,
    const SOCKSHandler::address &addr,
    std::uint16_t port) {
  std::size_t size = 6;
  assert(error <= SOCKS5_ADDR_UNSUP);
  m_response[0] = '\x05';   // Version
  m_response[1] = error;    // Response code
  m_response[2] = '\x00';   // RSV
  m_response[3] = type;     // Address type
  switch (type) {
    case ADDR_IPV4:
      size = 10;
      htobe32buf(m_response + 4, addr.ip);
      break;
    case ADDR_IPV6:
      size = 22;
      memcpy(m_response + 4, addr.ipv6, 16);
      break;
    case ADDR_DNS:
      size = 7+addr.dns.size;
      m_response[4] = addr.dns.size;
      memcpy(m_response + 5, addr.dns.value, addr.dns.size);
      break;
  }
  htobe16buf(m_response + size - 2, port);  // Port
  return boost::asio::const_buffers_1(m_response, size);
}

bool SOCKSHandler::Socks5ChooseAuth() {
  m_response[0] = '\x05';  // Version
  m_response[1] = m_authchosen;  // Response code
  boost::asio::const_buffers_1 response(m_response, 2);
  if (m_authchosen == AUTH_UNACCEPTABLE) {
    LogPrint(eLogWarn,
        "SOCKSHandler: SOCKS5 authentication negotiation failed");
    boost::asio::async_write(
        *m_sock,
        response,
        std::bind(
          &SOCKSHandler::SentSocksFailed,
          shared_from_this(),
          std::placeholders::_1));
    return false;
  } else {
    LogPrint(eLogDebug,
        "SOCKSHandler: SOCKS5 choosing authentication method: ", m_authchosen);
    boost::asio::async_write(
        *m_sock,
        response,
        std::bind(
          &SOCKSHandler::SentSocksResponse,
          shared_from_this(),
          std::placeholders::_1));
    return true;
  }
}

/* All hope is lost beyond this point */
void SOCKSHandler::SocksRequestFailed(
    SOCKSHandler::errTypes error) {
  boost::asio::const_buffers_1 response(nullptr, 0);
  assert(error != SOCKS4_OK && error != SOCKS5_OK);
  switch (m_socksv) {
    case SOCKS4:
      LogPrint(eLogWarn, "SOCKSHandler: SOCKS4 failed: ", error);
      // Transparently map SOCKS5 errors
      if (error < SOCKS4_OK) error = SOCKS4_FAIL;
      response = GenerateSOCKS4Response(
          error,
          m_4aip,
          m_port);
    break;
    case SOCKS5:
      LogPrint(eLogWarn, "SOCKSHandler: SOCKS5 failed: ", error);
      response = GenerateSOCKS5Response(
          error,
          m_addrtype,
          m_address,
          m_port);
    break;
  }
  boost::asio::async_write(
      *m_sock,
      response,
      std::bind(
        &SOCKSHandler::SentSocksFailed,
        shared_from_this(),
        std::placeholders::_1));
}

void SOCKSHandler::SocksRequestSuccess() {
  boost::asio::const_buffers_1 response(nullptr, 0);
  // TODO(unassigned):
  // this should depend on things like the command type and callbacks may change
  switch (m_socksv) {
    case SOCKS4:
      LogPrint(eLogInfo, "SOCKSHandler: SOCKS4 connection success");
      response = GenerateSOCKS4Response(SOCKS4_OK, m_4aip, m_port);
    break;
    case SOCKS5:
      LogPrint(eLogInfo, "SOCKSHandler: SOCKS5 connection success");
      auto s = kovri::client::context.GetAddressBook().GetB32AddressFromIdentHash(
          GetOwner()->GetLocalDestination()->GetIdentHash());
      address ad;
      ad.dns.FromString(s);
      // HACK only 16 bits passed in port as SOCKS5 doesn't allow for more
      response = GenerateSOCKS5Response(
          SOCKS5_OK, ADDR_DNS, ad, m_stream->GetRecvStreamID());
    break;
  }
  boost::asio::async_write(
      *m_sock,
      response,
      std::bind(
        &SOCKSHandler::SentSocksDone,
        shared_from_this(),
        std::placeholders::_1));
}

void SOCKSHandler::EnterState(
    SOCKSHandler::state nstate,
    std::uint8_t parseleft) {
  switch (nstate) {
    case GET_PORT:
      parseleft = 2;
      break;
    case GET_IPV4:
      m_addrtype = ADDR_IPV4;
      m_address.ip = 0;
      parseleft = 4;
      break;
    case GET4_IDENT:
      m_4aip = m_address.ip;
      break;
    case GET4A_HOST:
    case GET5_HOST:
      m_addrtype = ADDR_DNS;
      m_address.dns.size = 0;
      break;
    case GET5_IPV6:
      m_addrtype = ADDR_IPV6;
      parseleft = 16;
      break;
    default: {}
  }
  m_parseleft = parseleft;
  m_state = nstate;
}

bool SOCKSHandler::ValidateSOCKSRequest() {
  if ( m_cmd != CMD_CONNECT ) {
    // TODO(unassigned): we need to support binds and other features!
    LogPrint(eLogError, "SOCKSHandler: unsupported command: ", m_cmd);
    SocksRequestFailed(SOCKS5_CMD_UNSUP);
    return false;
  }
  // TODO(unassigned): we may want to support other address types!
  if ( m_addrtype != ADDR_DNS ) {
    switch (m_socksv) {
      case SOCKS5:
        LogPrint(eLogError, "SOCKSHandler: SOCKS5 unsupported address type: ",
            m_addrtype);
      break;
      case SOCKS4:
        LogPrint(eLogError, "SOCKSHandler: SOCKS4a rejected because it's actually SOCKS4");
      break;
    }
    SocksRequestFailed(SOCKS5_ADDR_UNSUP);
    return false;
  }
  // TODO(unassigned): we may want to support other domains
  if (m_addrtype == ADDR_DNS &&
      m_address.dns.ToString().find(".i2p") == std::string::npos) {
    LogPrint(eLogError,
        "SOCKSHandler: invalid hostname: ", m_address.dns.ToString());
    SocksRequestFailed(SOCKS5_ADDR_UNSUP);
    return false;
  }
  return true;
}

bool SOCKSHandler::HandleData(
    std::uint8_t *sock_buff,
    std::size_t len) {
  // This should always be called with a least a byte left to parse
  assert(len);
  while (len > 0) {
    switch (m_state) {
      case GET_SOCKSV:
        m_socksv = (SOCKSHandler::socksVersions) *sock_buff;
        switch (*sock_buff) {
          case SOCKS4:
            // Initialize the parser at the right position
            EnterState(GET_COMMAND);
          break;
          case SOCKS5:
            // Initialize the parser at the right position
            EnterState(GET5_AUTHNUM);
          break;
          default:
            LogPrint(eLogError, "SOCKSHandler: rejected invalid version: ",
                (static_cast<int>(*sock_buff)));
            Terminate();
            return false;
        }
      break;
      case GET5_AUTHNUM:
        EnterState(GET5_AUTH, *sock_buff);
      break;
      case GET5_AUTH:
        m_parseleft--;
        if (*sock_buff == AUTH_NONE)
          m_authchosen = AUTH_NONE;
        if ( m_parseleft == 0 ) {
          if (!Socks5ChooseAuth()) return false;
          EnterState(GET5_REQUESTV);
        }
      break;
      case GET_COMMAND:
        switch (*sock_buff) {
          case CMD_CONNECT:
          case CMD_BIND:
          break;
          case CMD_UDP:
            if (m_socksv == SOCKS5)
              break;
          default:
            LogPrint(eLogError, "SOCKSHandler: invalid command: ",
                (static_cast<int>(*sock_buff)));
            SocksRequestFailed(SOCKS5_GEN_FAIL);
            return false;
        }
        m_cmd = (SOCKSHandler::cmdTypes)*sock_buff;
        switch (m_socksv) {
          case SOCKS5:
            EnterState(GET5_GETRSV);
            break;
          case SOCKS4:
            EnterState(GET_PORT);
            break;
        }
      break;
      case GET_PORT:
        m_port = (m_port << 8)|((std::uint16_t)*sock_buff);
        m_parseleft--;
        if (m_parseleft == 0) {
          switch (m_socksv) {
            case SOCKS5:
              EnterState(DONE);
              break;
            case SOCKS4:
              EnterState(GET_IPV4);
              break;
          }
        }
      break;
      case GET_IPV4:
        m_address.ip = (m_address.ip << 8)|((std::uint32_t)*sock_buff);
        m_parseleft--;
        if (m_parseleft == 0) {
          switch (m_socksv) {
            case SOCKS5:
              EnterState(GET_PORT);
              break;
            case SOCKS4:
              EnterState(GET4_IDENT);
              m_4aip = m_address.ip;
              break;
          }
        }
      break;
      case GET4_IDENT:
        if (!*sock_buff) {
          if (m_4aip == 0 || m_4aip > 255)
            EnterState(DONE);
          else
            EnterState(GET4A_HOST);
        }
      break;
      case GET4A_HOST:
        if (!*sock_buff) {
          EnterState(DONE);
          break;
        }
        if (m_address.dns.size >= MAX_SOCKS_HOSTNAME_SIZE) {
          LogPrint(eLogError, "SOCKSHandler: SOCKS4a destination is too large");
          SocksRequestFailed(SOCKS4_FAIL);
          return false;
        }
        m_address.dns.push_back(*sock_buff);
      break;
      case GET5_REQUESTV:
        if (*sock_buff != SOCKS5) {
          LogPrint(eLogError,
              "SOCKSHandler: SOCKS5 rejected unknown request version: ",
              (static_cast<int>(*sock_buff)));
          SocksRequestFailed(SOCKS5_GEN_FAIL);
          return false;
        }
        EnterState(GET_COMMAND);
      break;
      case GET5_GETRSV:
        if (*sock_buff != 0) {
          LogPrint(eLogError,
              "SOCKSHandler: SOCKS5 unknown reserved field: ",
              (static_cast<int>(*sock_buff)));
          SocksRequestFailed(SOCKS5_GEN_FAIL);
          return false;
        }
        EnterState(GET5_GETADDRTYPE);
      break;
      case GET5_GETADDRTYPE:
        switch (*sock_buff) {
          case ADDR_IPV4:
            EnterState(GET_IPV4);
            break;
          case ADDR_IPV6:
            EnterState(GET5_IPV6);
            break;
          case ADDR_DNS:
            EnterState(GET5_HOST_SIZE);
            break;
          default:
            LogPrint(eLogError,
                "SOCKSHandler: SOCKS5 unknown address type: ",
                (static_cast<int>(*sock_buff)));
            SocksRequestFailed(SOCKS5_GEN_FAIL);
            return false;
        }
      break;
      case GET5_IPV6:
        m_address.ipv6[16-m_parseleft] = *sock_buff;
        m_parseleft--;
        if (m_parseleft == 0) EnterState(GET_PORT);
      break;
      case GET5_HOST_SIZE:
        EnterState(GET5_HOST, *sock_buff);
      break;
      case GET5_HOST:
        m_address.dns.push_back(*sock_buff);
        m_parseleft--;
        if (m_parseleft == 0) EnterState(GET_PORT);
      break;
      default:
        LogPrint(eLogError, "SOCKSHandler: parse state?? ", m_state);
        Terminate();
        return false;
    }
    sock_buff++;
    len--;
    if (m_state == DONE) {
      m_remaining_data_len = len;
      m_remaining_data = sock_buff;
      return ValidateSOCKSRequest();
    }
  }
  return true;
}

void SOCKSHandler::HandleSockRecv(
    const boost::system::error_code& ecode,
    std::size_t len) {
  LogPrint(eLogDebug, "SOCKSHandler: sock recv: ", len);
  if (ecode) {
    LogPrint(eLogError, "SOCKSHandler: sock recv got error: ", ecode);
    Terminate();
    return;
  }
  if (HandleData(m_sock_buff, len)) {
    if (m_state == DONE) {
      LogPrint(eLogInfo, "SOCKSHandler: SOCKS requested ",
          m_address.dns.ToString(), ":" , m_port);
      GetOwner()->CreateStream(
          std::bind(
            &SOCKSHandler::HandleStreamRequestComplete,
            shared_from_this(),
            std::placeholders::_1),
          m_address.dns.ToString(),
          m_port);
    } else {
      AsyncSockRead();
    }
  }
}

void SOCKSHandler::SentSocksFailed(
    const boost::system::error_code & ecode) {
  if (!ecode) {
    Terminate();
  } else {
    LogPrint(eLogError,
        "SOCKSHandler: closing socket after sending failure: ",
        ecode.message());
    Terminate();
  }
}

void SOCKSHandler::SentSocksDone(
    const boost::system::error_code & ecode) {
  if (!ecode) {
    if (Kill())
      return;
    LogPrint(eLogInfo, "SOCKSHandler: new I2PTunnel connection");
    auto connection =
      std::make_shared<kovri::client::I2PTunnelConnection>(
          GetOwner(),
          m_sock,
          m_stream);
    GetOwner()->AddHandler(connection);
    connection->I2PConnect(
        m_remaining_data,
        m_remaining_data_len);
    Done(shared_from_this());
  } else {
    LogPrint(eLogError,
        "SOCKSHandler: closing socket after completion reply: ",
        ecode.message());
    Terminate();
  }
}

void SOCKSHandler::SentSocksResponse(
    const boost::system::error_code & ecode) {
  if (ecode) {
    LogPrint(eLogError,
        "SOCKSHandler: closing socket after sending reply: ",
        ecode.message());
    Terminate();
  }
}

void SOCKSHandler::HandleStreamRequestComplete(
    std::shared_ptr<kovri::client::Stream> stream) {
  if (stream) {
    m_stream = stream;
    SocksRequestSuccess();
  } else {
    LogPrint(eLogError,
        "SOCKSHandler: issue when creating the stream,",
        "check the previous warnings for details.");
    SocksRequestFailed(SOCKS5_HOST_UNREACH);
  }
}

SOCKSServer::SOCKSServer(
    const std::string& address, int port,
    std::shared_ptr<kovri::client::ClientDestination> local_destination)
    : TCPIPAcceptor(
        address,
        port,
        local_destination ?
        local_destination :
        kovri::client::context.GetSharedLocalDestination()) {}

std::shared_ptr<kovri::client::I2PServiceHandler> SOCKSServer::CreateHandler(
    std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
  return std::make_shared<SOCKSHandler> (this, socket);
}

}  // namespace client
}  // namespace kovri
