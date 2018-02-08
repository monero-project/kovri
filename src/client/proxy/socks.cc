/**                                                                                           //
 * Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
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

#include "client/api/streaming.h"
#include "client/context.h"
#include "client/destination.h"
#include "client/tunnel.h"

#include "core/router/identity.h"


namespace kovri {
namespace client {

static const std::size_t MAX_SOCKS_BUFFER_SIZE = 8192;
// Limit for socks5 and bad idea to traverse
static const std::size_t MAX_SOCKS_HOSTNAME_SIZE = 255;

struct SOCKSDNSAddress {
  std::uint8_t size;
  char value[MAX_SOCKS_HOSTNAME_SIZE];
  void FromString(std::string str) {
    size = str.length();
    if (str.length() > MAX_SOCKS_HOSTNAME_SIZE)
      size = MAX_SOCKS_HOSTNAME_SIZE;
    memcpy(value, str.c_str(), size);
  }
  std::string ToString() {
    return std::string(value, size);
  }

  void PushBack(char c) {
    value[size++] = c;
  }
};

class SOCKSServer;
class SOCKSHandler
    : public kovri::client::I2PServiceHandler,
      public std::enable_shared_from_this<SOCKSHandler> {
 private:
   /// @enum State
   /// @brief Enumerators used for parsing data to
   ///  fetch the corresponding variable 
  enum State {
    /// @var GetSOCKSVersion
    /// @brief Used to identify the SOCKS
    ///  version e.g. SOCKS5 
    GetSOCKSVersion,
    /// @var GetCommand
    /// @brief Used to identify which
    ///  command to execute e.g. Connect 
    GetCommand,
    /// @var GetPort
    /// @brief Used to identify which port
    ///  SOCKS is going to use e.g. 1080 
    GetPort,
    /// @var GetIPv4
    /// @brief Used to identify if SOCKS
    ///  is using an IPv4 address 
    GetIPv4,
    /// @var GetSOCKS4Ident
    /// @brief Used to identify the SOCKS4 identity 
    GetSOCKS4Ident,
    /// @var GetSOCKS4aHost
    /// @brief Used to identify the SOCKS4a hostname 
    GetSOCKS4aHost,
    /// @var GetSOCKS5AuthNum
    /// @brief Used to identify the SOCKS5
    ///  authentication number 
    GetSOCKS5AuthNum,
    /// @var GetSOCKS5Auth
    /// @brief Used to identify what kind
    ///  of authentication SOCKS is using e.g.GSSAPI 
    GetSOCKS5Auth, 
    /// @var GetSOCKS5RequestVersion
    /// @brief Retrieves SOCKS5 request version 
    GetSOCKS5RequestVersion,
    /// @var GetSOCKS5ReservedField
    /// @brief Retrieves SOCKS5 reserved
    ///  field e.g. 0x00 
    GetSOCKS5ReservedField,
    /// @var GetSOCKS5AddressType
    /// @brief Identifies the SOCKS5
    ///  address type e.g. IPv6 
    GetSOCKS5AddressType,
    /// @var GetSOCKS5IPv6
    /// @brief Used to retrieve the SOCKS5
    /// IPv6 address 
    GetSOCKS5IPv6,
    /// @var GetSOCKS5HostSize
    /// @brief Used to retrieve the SOCKS5
    ///  host size 
    GetSOCKS5HostSize,
    /// @var GetSOCKS5Host
    /// @brief Used to retrive the SOCKS5
    ///  host name 
    GetSOCKS5Host,
    /// @var Complete
    /// @brief Indicates the end of parsing data 
    Complete
  };
  /// @enum AuthMethods
  /// @brief Various authentication methods
  ///  SOCKS can utilize
  enum AuthMethods {
    /// @var None
    /// @brief No authentication, skip to next step
    None = 0,
    /// @var GSSAPI
    /// @brief GSSAPI authentication
    GSSAPI = 1,
    /// @var UserPassword
    /// @brief Username and password authentication
    UserPassword = 2,
    /// @var Invalid
    /// @brief No acceptable method found 
    Invalid = 0xff
  };
  /// @enum AddressTypes
  /// @brief Various address types SOCKS may use
  enum AddressTypes {
    /// @var IPv4
    /// @brief IPv4 address (4 octects)
    IPv4 = 1,
    /// @var DNS
    /// @brief DNS name (up to 255 octects)
    DNS = 3,
    /// @var IPv6
    /// @brief IPv6 address (16 octects)
    IPv6 = 4
  };
  /// @enum ErrorTypes
  /// @brief Various errors SOCKS may return
  enum ErrorTypes {
    /// @var SOCKS5Success
    /// @brief No errors for SOCKS5
    SOCKS5Success = 0,
    /// @var SOCKS5Fail
    /// @brief General server failure
    SOCKS5Fail = 1,
    /// @var SOCKS5RuleDenied
    /// @brief Connection denied by ruleset
    SOCKS5RuleDenied = 2,
    /// @var SOCKS5NetworkUnreachable
    /// @brief Network unreachable
    SOCKS5NetworkUnreachable = 3,
    /// @var SOCKS5HostUnreachable
    /// @brief Host unreachable
    SOCKS5HostUnreachable = 4,
    /// @var SOCKS5ConnectionRefused
    /// @brief Connection refused by peer
    SOCKS5ConnectionRefused = 5,
    /// @var SOCKS5Expired
    /// @brief Time-To-Live expired
    SOCKS5Expired = 6,
    /// @var SOCKS5UnsupportedCommand
    /// @brief Unsupported command
    SOCKS5UnsupportedCommand = 7,
    /// @var SOCKS5UnsupportedAddress
    /// @brief Unsupported address type
    SOCKS5UnsupportedAddress = 8,
    /// @var SOCKS4Success
    /// @brief No errors for SOCKS4
    SOCKS4Success = 90,
    /// @var SOCKS4Fail
    /// @brief Failed to establish a connection 
    SOCKS4Fail = 91,
    /// @var SOCKS4MissingIdent
    /// @brief Couldn't connect to the identd server
    SOCKS4MissingIdent = 92,
    /// @var SOCKS4InvalidIdent
    /// @brief Application's and identd's ID differ
    SOCKS4InvalidIdent = 93
  };
  /// @enum CommandTypes
  /// @brief Different requests directed at a SOCKS Server
  enum CommandTypes {
    /// @var Connect
    /// @brief Used to connect to SOCKS over TCP 
    Connect = 1,
    /// @var Bind
    /// @brief Used for multi-connection protocol e.g. FTP etc 
    Bind = 2,
    /// @var UDP
    /// @brief Used for UDP traffic 
    UDP = 3
  };
  /// @enum SOCKSVersions
  /// @brief Various versions of SOCKS
  enum SOCKSVersions {
    /// @var SOCKS4
    /// @brief Represents SOCKS4 version 
    SOCKS4 = 4,
    /// @var SOCKS5
    /// @brief Represents SOCKS5 version 
    SOCKS5 = 5
  };
  /// @union Address
  /// @brief Represents a variable that only 
  ///  has access to one of the variables below
  union Address {
    /// @var ip 
    /// @brief Represents an ipv4 address 
    std::uint32_t ip;
    /// @var dns
    /// @brief Represents a dns address 
    SOCKSDNSAddress dns;
    /// @var ipv6
    /// @brief Represents an ipv6 address 
    std::uint8_t ipv6[16];
  };

  void EnterState(
      State state,
      std::uint8_t parse_left = 1);

  bool HandleData(
      std::uint8_t* socket_buffer,
      std::size_t len);

  bool ValidateSOCKSRequest();

  void HandleSocketReceive(
      const boost::system::error_code& ecode,
      std::size_t bytes_transfered);

  void Terminate();

  void AsyncSocketRead();

  boost::asio::const_buffers_1 GenerateSOCKS5SelectAuth(
      AuthMethods method);

  boost::asio::const_buffers_1 GenerateSOCKS4Response(
      ErrorTypes error,
      std::uint32_t ip,
      std::uint16_t port);

  boost::asio::const_buffers_1 GenerateSOCKS5Response(
      ErrorTypes error,
      AddressTypes type,
      const Address &addr,
      std::uint16_t port);

  bool SOCKS5ChooseAuth();

  void SOCKSRequestFailed(
      ErrorTypes error);

  void SOCKSRequestSuccess();

  void SentSOCKSFailed(
      const boost::system::error_code & ecode);

  void SentSOCKSDone(
      const boost::system::error_code & ecode);

  void SentSOCKSResponse(
      const boost::system::error_code & ecode);

  void HandleStreamRequestComplete(
      std::shared_ptr<kovri::client::Stream> stream);

  std::uint8_t m_SocketBuffer[MAX_SOCKS_BUFFER_SIZE];
  std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
  std::shared_ptr<kovri::client::Stream> m_Stream;
  /// @brief Data left to be sent
  std::uint8_t *m_RemainingData;
  std::uint8_t m_Response[7 + MAX_SOCKS_HOSTNAME_SIZE];
  Address m_Address;
  /// @brief Size of the data left to be sent
  std::size_t m_RemainingDataLen;
  /// @brief Used in SOCKS4a requests
  std::uint32_t m_SOCKS4aIP;
  std::uint16_t m_Port;
  std::uint8_t m_CommandNum;
  /// @brief Octets left to parse
  std::uint8_t m_ParseLeft;
  /// @brief Authentication chosen
  AuthMethods m_AuthChosen;
  /// @brief Address type chosen
  AddressTypes m_AddressType;
  SOCKSVersions m_SOCKSVersion;
  /// @brief Command requested
  CommandTypes m_Command;
  State m_State;

 public:
  SOCKSHandler(
      SOCKSServer* parent,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket)
      : I2PServiceHandler(parent),
        m_Socket(socket),
        m_Stream(nullptr),
        m_RemainingData(nullptr),
        m_RemainingDataLen(0),
        m_Port(0),
        m_CommandNum(0),
        m_AuthChosen(Invalid),
        m_AddressType(IPv4),
        m_SOCKSVersion(SOCKS5),
        m_Command(Connect) {
          m_Address.ip = 0;
          EnterState(GetSOCKSVersion);
        }

  ~SOCKSHandler() {
    Terminate();
  }

  void Handle() {
    AsyncSocketRead();
  }
};

void SOCKSHandler::AsyncSocketRead() {
  LOG(debug) << "SOCKSHandler: async socket read";
  if (m_Socket)
    m_Socket->async_receive(
        boost::asio::buffer(
            m_SocketBuffer,
            MAX_SOCKS_BUFFER_SIZE),
        std::bind(
            &SOCKSHandler::HandleSocketReceive,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2));
  else
    LOG(error) << "SOCKSHandler: no socket read";
}

void SOCKSHandler::Terminate() {
  if (Kill()) return;
  if (m_Socket) {
    LOG(debug) << "SOCKSHandler: close socket";
    m_Socket->close();
    m_Socket = nullptr;
  }
  if (m_Stream) {
    LOG(debug) << "SOCKSHandler: close stream";
    m_Stream.reset();
  }
  Done(shared_from_this());
}

// TODO(anonimal): bytestream refactor
boost::asio::const_buffers_1 SOCKSHandler::GenerateSOCKS4Response(
    SOCKSHandler::ErrorTypes error,
    std::uint32_t ip,
    std::uint16_t port) {
  assert(error >= SOCKS4Success);
  m_Response[0] = '\x00';         // Version
  m_Response[1] = error;          // Response code
  core::OutputByteStream::Write<std::uint16_t>(m_Response + 2, port);  // Port
  core::OutputByteStream::Write<std::uint32_t>(m_Response + 4, ip);    // IP
  return boost::asio::const_buffers_1(m_Response, 8);
}

boost::asio::const_buffers_1 SOCKSHandler::GenerateSOCKS5Response(
    SOCKSHandler::ErrorTypes error,
    SOCKSHandler::AddressTypes type,
    const SOCKSHandler::Address &address,
    std::uint16_t port) {
  std::size_t size = 6;
  assert(error <= SOCKS5UnsupportedAddress);
  m_Response[0] = '\x05';   // Version
  m_Response[1] = error;    // Response code
  m_Response[2] = '\x00';   // RSV
  m_Response[3] = type;     // Address type
  switch (type) {
    case IPv4:
      size = 10;
      core::OutputByteStream::Write<std::uint32_t>(m_Response + 4, address.ip);
      break;
    case IPv6:
      size = 22;
      memcpy(m_Response + 4, address.ipv6, 16);
      break;
    case DNS:
      size = 7 + address.dns.size;
      m_Response[4] = address.dns.size;
      memcpy(m_Response + 5, address.dns.value, address.dns.size);
      break;
  }
  core::OutputByteStream::Write<std::uint16_t>(m_Response + size - 2, port);  // Port
  return boost::asio::const_buffers_1(m_Response, size);
}

bool SOCKSHandler::SOCKS5ChooseAuth() {
  m_Response[0] = '\x05';  // Version
  m_Response[1] = m_AuthChosen;  // Response code
  boost::asio::const_buffers_1 response(m_Response, 2);
  if (m_AuthChosen == Invalid) {
    LOG(warning) << "SOCKSHandler: SOCKS5 authentication negotiation failed";
    boost::asio::async_write(
        *m_Socket,
        response,
        std::bind(
            &SOCKSHandler::SentSOCKSFailed,
            shared_from_this(),
            std::placeholders::_1));
    return false;
  } else {
    LOG(debug)
      << "SOCKSHandler: SOCKS5 choosing authentication method: "
      << m_AuthChosen;
    boost::asio::async_write(
        *m_Socket,
        response,
        std::bind(
            &SOCKSHandler::SentSOCKSResponse,
            shared_from_this(),
            std::placeholders::_1));
    return true;
  }
}

/* All hope is lost beyond this point */
void SOCKSHandler::SOCKSRequestFailed(
    SOCKSHandler::ErrorTypes error) {
  boost::asio::const_buffers_1 response(nullptr, 0);
  assert(error != SOCKS4Success && error != SOCKS5Success);
  switch (m_SOCKSVersion) {
    case SOCKS4:
      LOG(warning) << "SOCKSHandler: SOCKS4 failed: " << error;
      // Transparently map SOCKS5 errors
      if (error < SOCKS4Success)
        error = SOCKS4Fail;
      response = GenerateSOCKS4Response(
          error,
          m_SOCKS4aIP,
          m_Port);
    break;
    case SOCKS5:
      LOG(warning) << "SOCKSHandler: SOCKS5 failed: " << error;
      response = GenerateSOCKS5Response(
          error,
          m_AddressType,
          m_Address,
          m_Port);
    break;
  }
  boost::asio::async_write(
      *m_Socket,
      response,
      std::bind(
          &SOCKSHandler::SentSOCKSFailed,
          shared_from_this(),
          std::placeholders::_1));
}

void SOCKSHandler::SOCKSRequestSuccess() {
  boost::asio::const_buffers_1 response(nullptr, 0);
  // TODO(unassigned):
  // this should depend on things like the command type and callbacks may change
  switch (m_SOCKSVersion) {
    case SOCKS4:
      LOG(info) << "SOCKSHandler: SOCKS4 connection success";
      response = GenerateSOCKS4Response(SOCKS4Success, m_SOCKS4aIP, m_Port);
    break;
    case SOCKS5:
      LOG(info) << "SOCKSHandler: SOCKS5 connection success";
      auto s = kovri::client::context.GetAddressBook().GetB32AddressFromIdentHash(
          GetOwner()->GetLocalDestination()->GetIdentHash());
      Address address;
      address.dns.FromString(s);
      // HACK only 16 bits passed in port as SOCKS5 doesn't allow for more
      response = GenerateSOCKS5Response(
          SOCKS5Success, DNS, address, m_Stream->GetReceiveStreamID());
    break;
  }
  boost::asio::async_write(
      *m_Socket,
      response,
      std::bind(
          &SOCKSHandler::SentSOCKSDone,
          shared_from_this(),
          std::placeholders::_1));
}

void SOCKSHandler::EnterState(
    SOCKSHandler::State state,
    std::uint8_t parse_left) {
  switch (state) {
    case GetPort:
      parse_left = 2;
      break;
    case GetIPv4:
      m_AddressType = IPv4;
      m_Address.ip = 0;
      parse_left = 4;
      break;
    case GetSOCKS4Ident:
      m_SOCKS4aIP = m_Address.ip;
      break;
    case GetSOCKS4aHost:
    case GetSOCKS5Host:
      m_AddressType = DNS;
      m_Address.dns.size = 0;
      break;
    case GetSOCKS5IPv6:
      m_AddressType = IPv6;
      parse_left = 16;
      break;
    default: {}
  }
  m_ParseLeft = parse_left;
  m_State = state;
}

bool SOCKSHandler::ValidateSOCKSRequest() {
  if (m_Command != Connect) {
    // TODO(unassigned): we need to support binds and other features!
    LOG(error) << "SOCKSHandler: unsupported command: " << m_Command;
    SOCKSRequestFailed(SOCKS5UnsupportedCommand);
    return false;
  }
  // TODO(unassigned): we may want to support other address types!
  if (m_AddressType != DNS) {
    switch (m_SOCKSVersion) {
      case SOCKS5:
        LOG(error)
          << "SOCKSHandler: SOCKS5 unsupported address type: "
          << m_AddressType;
      break;
      case SOCKS4:
        LOG(error) << "SOCKSHandler: SOCKS4a rejected because it's actually SOCKS4";
      break;
    }
    SOCKSRequestFailed(SOCKS5UnsupportedAddress);
    return false;
  }
  // TODO(unassigned): we may want to support other domains
  if (m_AddressType == DNS &&
      m_Address.dns.ToString().find(".i2p") == std::string::npos) {
    LOG(error) << "SOCKSHandler: invalid hostname: " << m_Address.dns.ToString();
    SOCKSRequestFailed(SOCKS5UnsupportedAddress);
    return false;
  }
  return true;
}

bool SOCKSHandler::HandleData(
    std::uint8_t *socket_buffer,
    std::size_t len) {
  // This should always be called with a least a byte left to parse
  assert(len);
  while (len > 0) {
    switch (m_State) {
      case GetSOCKSVersion:
        m_SOCKSVersion = (SOCKSHandler::SOCKSVersions) *socket_buffer;
        switch (*socket_buffer) {
          case SOCKS4:
            // Initialize the parser at the right position
            EnterState(GetCommand);
          break;
          case SOCKS5:
            // Initialize the parser at the right position
            EnterState(GetSOCKS5AuthNum);
          break;
          default:
            LOG(error)
              << "SOCKSHandler: rejected invalid version: "
              << static_cast<int>(*socket_buffer);
            Terminate();
            return false;
        }
      break;
      case GetSOCKS5AuthNum:
        EnterState(GetSOCKS5Auth, *socket_buffer);
      break;
      case GetSOCKS5Auth:
        m_ParseLeft--;
        if (*socket_buffer == None)
          m_AuthChosen = None;
        if ( m_ParseLeft == 0 ) {
          if (!SOCKS5ChooseAuth()) return false;
          EnterState(GetSOCKS5RequestVersion);
        }
      break;
      case GetCommand:
        switch (*socket_buffer) {
          case Connect:
          case Bind:
          break;
          case UDP:
            if (m_SOCKSVersion == SOCKS5)
              break;
            // fall-through
          default:
            LOG(error)
              << "SOCKSHandler: invalid command: "
              << static_cast<int>(*socket_buffer);
            SOCKSRequestFailed(SOCKS5Fail);
            return false;
        }
        m_Command = (SOCKSHandler::CommandTypes)*socket_buffer;
        switch (m_SOCKSVersion) {
          case SOCKS5:
            EnterState(GetSOCKS5ReservedField);
            break;
          case SOCKS4:
            EnterState(GetPort);
            break;
        }
      break;
      case GetPort:
        m_Port = (m_Port << 8)|((std::uint16_t)*socket_buffer);
        m_ParseLeft--;
        if (m_ParseLeft == 0) {
          switch (m_SOCKSVersion) {
            case SOCKS5:
              EnterState(Complete);
              break;
            case SOCKS4:
              EnterState(GetIPv4);
              break;
          }
        }
      break;
      case GetIPv4:
        m_Address.ip = (m_Address.ip << 8)|((std::uint32_t)*socket_buffer);
        m_ParseLeft--;
        if (m_ParseLeft == 0) {
          switch (m_SOCKSVersion) {
            case SOCKS5:
              EnterState(GetPort);
              break;
            case SOCKS4:
              EnterState(GetSOCKS4Ident);
              m_SOCKS4aIP = m_Address.ip;
              break;
          }
        }
      break;
      case GetSOCKS4Ident:
        if (!*socket_buffer) {
          /// @brief Checks if SOCKS4aIP has already been parsed
          if (m_SOCKS4aIP == 0 || m_SOCKS4aIP > 255)
            EnterState(Complete);
          else
            EnterState(GetSOCKS4aHost);
        }
      break;
      case GetSOCKS4aHost:
        if (!*socket_buffer) {
          EnterState(Complete);
          break;
        }
        if (m_Address.dns.size >= MAX_SOCKS_HOSTNAME_SIZE) {
          LOG(error) << "SOCKSHandler: SOCKS4a destination is too large";
          SOCKSRequestFailed(SOCKS4Fail);
          return false;
        }
        m_Address.dns.PushBack(*socket_buffer);
      break;
      case GetSOCKS5RequestVersion:
        if (*socket_buffer != SOCKS5) {
          LOG(error)
            << "SOCKSHandler: SOCKS5 rejected unknown request version: "
            << static_cast<int>(*socket_buffer);
          SOCKSRequestFailed(SOCKS5Fail);
          return false;
        }
        EnterState(GetCommand);
      break;
      case GetSOCKS5ReservedField:
        if (*socket_buffer != 0) {
          LOG(error)
            << "SOCKSHandler: SOCKS5 unknown reserved field: "
            << static_cast<int>(*socket_buffer);
          SOCKSRequestFailed(SOCKS5Fail);
          return false;
        }
        EnterState(GetSOCKS5AddressType);
      break;
      case GetSOCKS5AddressType:
        switch (*socket_buffer) {
          case IPv4:
            EnterState(GetIPv4);
            break;
          case IPv6:
            EnterState(GetSOCKS5IPv6);
            break;
          case DNS:
            EnterState(GetSOCKS5HostSize);
            break;
          default:
            LOG(error)
              << "SOCKSHandler: SOCKS5 unknown address type: "
              << static_cast<int>(*socket_buffer);
            SOCKSRequestFailed(SOCKS5Fail);
            return false;
        }
      break;
      case GetSOCKS5IPv6:
        m_Address.ipv6[16-m_ParseLeft] = *socket_buffer;
        m_ParseLeft--;
        if (m_ParseLeft == 0) EnterState(GetPort);
      break;
      case GetSOCKS5HostSize:
        EnterState(GetSOCKS5Host, *socket_buffer);
      break;
      case GetSOCKS5Host:
        m_Address.dns.PushBack(*socket_buffer);
        m_ParseLeft--;
        if (m_ParseLeft == 0) EnterState(GetPort);
      break;
      default:
        LOG(error) << "SOCKSHandler: parse state?? " << m_State;
        Terminate();
        return false;
    }
    socket_buffer++;
    len--;
    if (m_State == Complete) {
      m_RemainingDataLen = len;
      m_RemainingData = socket_buffer;
      return ValidateSOCKSRequest();
    }
  }
  return true;
}

void SOCKSHandler::HandleSocketReceive(
    const boost::system::error_code& ecode,
    std::size_t len) {
  LOG(debug) << "SOCKSHandler: socket receive: " << len;
  if (ecode) {
    LOG(error) << "SOCKSHandler: socket receive got error: " << ecode;
    Terminate();
    return;
  }
  if (HandleData(m_SocketBuffer, len)) {
    if (m_State == Complete) {
      LOG(info)
        << "SOCKSHandler: SOCKS requested "
        << m_Address.dns.ToString() << ":"  << m_Port;
      GetOwner()->CreateStream(
          std::bind(
              &SOCKSHandler::HandleStreamRequestComplete,
              shared_from_this(),
              std::placeholders::_1),
          m_Address.dns.ToString(),
          m_Port);
    } else {
      AsyncSocketRead();
    }
  }
}

void SOCKSHandler::SentSOCKSFailed(
    const boost::system::error_code & ecode) {
  if (ecode)
    LOG(error)
      << "SOCKSHandler: closing socket after sending failure: "
      << ecode.message();
  Terminate();
}

void SOCKSHandler::SentSOCKSDone(
    const boost::system::error_code & ecode) {
  if (!ecode) {
    if (Kill())
      return;
    LOG(info) << "SOCKSHandler: new I2PTunnel connection";
    auto connection =
      std::make_shared<kovri::client::I2PTunnelConnection>(
          GetOwner(),
          m_Socket,
          m_Stream);
    GetOwner()->AddHandler(connection);
    connection->I2PConnect(
        m_RemainingData,
        m_RemainingDataLen);
    Done(shared_from_this());
  } else {
    LOG(error)
      << "SOCKSHandler: closing socket after completion reply: "
      << ecode.message();
    Terminate();
  }
}

void SOCKSHandler::SentSOCKSResponse(
    const boost::system::error_code & ecode) {
  if (ecode) {
    LOG(error)
      << "SOCKSHandler: closing socket after sending reply: "
      << ecode.message();
    Terminate();
  }
}

void SOCKSHandler::HandleStreamRequestComplete(
    std::shared_ptr<kovri::client::Stream> stream) {
  if (stream) {
    m_Stream = stream;
    SOCKSRequestSuccess();
  } else {
    LOG(error)
      << "SOCKSHandler: stream not available "
      << "(router may need more time to integrate into the network)";
    SOCKSRequestFailed(SOCKS5HostUnreachable);
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
