/**                                                                                           //
 * Copyright (c) 2013-2017, The Kovri I2P Router Project                                      //
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

#ifndef SRC_CLIENT_PROXY_SOCKS_H_
#define SRC_CLIENT_PROXY_SOCKS_H_

#include <boost/asio.hpp>

#include <memory>
#include <mutex>
#include <set>
#include <string>

#include "client/service.h"

namespace kovri {
namespace client {

class SOCKSServer : public kovri::client::TCPIPAcceptor {
 public:
  SOCKSServer(
      const std::string& address,
      int port,
      std::shared_ptr<kovri::client::ClientDestination> local_destination = nullptr);
  ~SOCKSServer() {}

 protected:
  // Implements TCPIPAcceptor
  std::shared_ptr<kovri::client::I2PServiceHandler> CreateHandler(
      std::shared_ptr<boost::asio::ip::tcp::socket> socket);

  std::string GetName() const;
};

typedef SOCKSServer SOCKSProxy;

static const std::size_t MAX_SOCKS_BUFFER_SIZE = 8192;
// Limit for socks5 and bad idea to traverse
static const std::size_t MAX_SOCKS_HOSTNAME_SIZE = 255;

struct SOCKSDNSAddress {
  std::uint8_t size;
  char value[MAX_SOCKS_HOSTNAME_SIZE];

  void FromString(std::string str);

  std::string ToString();

  void PushBack(char c);
};

class SOCKSHandler
    : public kovri::client::I2PServiceHandler,
      public std::enable_shared_from_this<SOCKSHandler> {
 protected:
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

  void SOCKSRequestFailed(ErrorTypes error);

  void SOCKSRequestSuccess();

  void SentSOCKSFailed(
      const boost::system::error_code & ecode);

  void SentSOCKSDone(
      const boost::system::error_code & ecode);

  void SentSOCKSResponse(
      const boost::system::error_code & ecode);

  void HandleStreamRequestComplete(
      std::shared_ptr<kovri::client::Stream> stream);

 private:
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
      std::shared_ptr<boost::asio::ip::tcp::socket> socket);

  ~SOCKSHandler();

  void Handle();
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_PROXY_SOCKS_H_
