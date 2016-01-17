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

#ifndef SRC_CLIENT_CLIENTCONTEXT_H_
#define SRC_CLIENT_CLIENTCONTEXT_H_

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "AddressBook.h"
#include "Destination.h"
#include "api/I2PControl/I2PControlServer.h"
#include "api/I2PTunnel/HTTPProxy.h"
#include "api/I2PTunnel/I2PTunnel.h"
#include "api/I2PTunnel/SOCKS.h"

namespace i2p {
namespace client {

const char I2P_TUNNELS_SECTION_TYPE[] = "type";
const char I2P_TUNNELS_SECTION_TYPE_CLIENT[] = "client";
const char I2P_TUNNELS_SECTION_TYPE_SERVER[] = "server";
const char I2P_TUNNELS_SECTION_TYPE_HTTP[] = "http";
const char I2P_CLIENT_TUNNEL_PORT[] = "port";
const char I2P_CLIENT_TUNNEL_ADDRESS[] = "address";
const char I2P_CLIENT_TUNNEL_DESTINATION[] = "destination";
const char I2P_CLIENT_TUNNEL_KEYS[] = "keys";
const char I2P_CLIENT_TUNNEL_DESTINATION_PORT[] = "destinationport";
const char I2P_SERVER_TUNNEL_HOST[] = "host";
const char I2P_SERVER_TUNNEL_PORT[] = "port";
const char I2P_SERVER_TUNNEL_KEYS[] = "keys";
const char I2P_SERVER_TUNNEL_INPORT[] = "inport";
const char I2P_SERVER_TUNNEL_ACCESS_LIST[] = "accesslist";

class ClientContext {
 public:
  ClientContext();
  ~ClientContext();

  void Start();
  void Stop();

  std::shared_ptr<ClientDestination> GetSharedLocalDestination() const {
    return m_SharedLocalDestination;
  }

  std::shared_ptr<ClientDestination> CreateNewLocalDestination(
      bool isPublic = false,
      i2p::data::SigningKeyType sigType = i2p::data::SIGNING_KEY_TYPE_DSA_SHA1,
      const std::map<std::string,
      std::string>* params = nullptr);  // transient

  std::shared_ptr<ClientDestination> CreateNewLocalDestination(
      const i2p::data::PrivateKeys& keys,
      bool isPublic = true,
      const std::map<std::string,
      std::string>* params = nullptr);

  void DeleteLocalDestination(
      std::shared_ptr<ClientDestination> destination);

  std::shared_ptr<ClientDestination> FindLocalDestination(
      const i2p::data::IdentHash& destination) const;

  std::shared_ptr<ClientDestination> LoadLocalDestination(
      const std::string& filename, bool isPublic);

  AddressBook& GetAddressBook() { return m_AddressBook; }

  /**
     reload tunnels.cfg
     removes tunnels not in new tunnels.cfg
     adds tunnels that were previously not in tunnels.cfg
   */
  void ReloadTunnels();
  
 private:
  void ReadTunnels();

 private:
  std::mutex m_DestinationsMutex;
  std::map<i2p::data::IdentHash, std::shared_ptr<ClientDestination> >
    m_Destinations;
  std::shared_ptr<ClientDestination> m_SharedLocalDestination;

  AddressBook m_AddressBook;

  i2p::proxy::HTTPProxy* m_HttpProxy;
  i2p::proxy::SOCKSProxy* m_SocksProxy;

  std::mutex m_ClientMutex;
  std::map<int, std::unique_ptr<I2PClientTunnel> >
    m_ClientTunnels;  // port->tunnel

  std::mutex m_ServerMutex;
  std::map<i2p::data::IdentHash, std::unique_ptr<I2PServerTunnel> >
    m_ServerTunnels;  // destination->tunnel


  // types for accessing client / server tunnel map entries
  typedef std::pair<const int, std::unique_ptr<I2PClientTunnel> > ClientTunnelEntry;
  typedef std::pair<const i2p::data::IdentHash, std::unique_ptr<I2PServerTunnel> > ServerTunnelEntry;

  boost::asio::io_service m_Service;
  
  i2pcontrol::I2PControlService* m_I2PControlService;

 public:
  // for HTTP
  const decltype(m_Destinations)& GetDestinations() const {
    return m_Destinations;
  }
};

extern ClientContext context;

}  // namespace client
}  // namespace i2p

#endif  // SRC_CLIENT_CLIENTCONTEXT_H_
