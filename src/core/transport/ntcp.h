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

#ifndef SRC_CORE_TRANSPORT_NTCP_H_
#define SRC_CORE_TRANSPORT_NTCP_H_

#include <boost/asio.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "identity.h"
#include "ntcp_session.h"
#include "router_info.h"
#include "transport_session.h"

namespace i2p {
namespace transport {

class NTCPServer {
 public:
  explicit NTCPServer(
      std::size_t port);

  ~NTCPServer();

  void Start();

  void Stop();

  void AddNTCPSession(
      std::shared_ptr<NTCPSession> session);

  void RemoveNTCPSession(
      std::shared_ptr<NTCPSession> session);

  std::shared_ptr<NTCPSession> FindNTCPSession(
      const i2p::data::IdentHash& ident);

  void Connect(
      const boost::asio::ip::address& address,
      std::size_t port,
      std::shared_ptr<NTCPSession> conn);

  boost::asio::io_service& GetService() {
    return m_Service;
  }

  void Ban(
      const std::shared_ptr<NTCPSession>& session);

 private:
  void Run();

  void HandleAccept(
      std::shared_ptr<NTCPSession> conn,
      const boost::system::error_code& ecode);

  void HandleAcceptV6(
      std::shared_ptr<NTCPSession> conn,
      const boost::system::error_code& ecode);

  void HandleConnect(
      std::shared_ptr<NTCPSession> conn,
      const boost::system::error_code& ecode);

 private:
  bool m_IsRunning;
  std::unique_ptr<std::thread> m_Thread;

  boost::asio::io_service m_Service;
  boost::asio::io_service::work m_Work;

  boost::asio::ip::tcp::endpoint m_NTCPEndpoint, m_NTCPEndpointV6;
  std::unique_ptr<boost::asio::ip::tcp::acceptor> m_NTCPAcceptor, m_NTCPV6Acceptor;

  std::mutex m_NTCPSessionsMutex;
  std::map<i2p::data::IdentHash, std::shared_ptr<NTCPSession>> m_NTCPSessions;

  // IP -> ban expiration time in seconds
  std::map<boost::asio::ip::address, uint32_t> m_BanList;

 public:
  // for I2PControl
  const decltype(m_NTCPSessions)& GetNTCPSessions() const {
    return m_NTCPSessions;
  }
};

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_NTCP_H_
