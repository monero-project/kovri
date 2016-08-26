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

#include "client_context.h"

#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "identity.h"
#include "util/log.h"

namespace i2p {
namespace client {

ClientContext context;

ClientContext::ClientContext()
    : m_SharedLocalDestination(nullptr),
      m_HttpProxy(nullptr),
      m_SocksProxy(nullptr),
      m_I2PControlService(nullptr) {}

ClientContext::~ClientContext() {
  m_Service.stop();
}

void ClientContext::Start() {
  if (!m_SharedLocalDestination) {
    m_SharedLocalDestination = CreateNewLocalDestination();  // non-public, DSA
    m_Destinations[m_SharedLocalDestination->GetIdentity().GetIdentHash()] =
      m_SharedLocalDestination;
    m_SharedLocalDestination->Start();
  }
  std::shared_ptr<ClientDestination> local_destination;
  m_HttpProxy->Start();
  LogPrint(eLogInfo, "ClientContext: HTTP Proxy started");
  m_SocksProxy->Start();
  LogPrint(eLogInfo, "ClientContext: SOCKS Proxy Started");
  // Start all client tunnels
  for (auto& pair : m_ClientTunnels)
    pair.second->Start();
  // Start all server tunnels
  for (auto& pair : m_ServerTunnels)
    pair.second->Start();
  // I2P Control
  if (m_I2PControlService) {
    LogPrint(eLogInfo, "ClientContext: starting I2PControlService");
    m_I2PControlService->Start();
  }
  m_AddressBook.Start(m_SharedLocalDestination);
}

void ClientContext::Stop() {
  std::lock_guard<std::mutex> lockClient(m_ClientMutex);
  std::lock_guard<std::mutex> lockServer(m_ServerMutex);
  std::lock_guard<std::mutex> lockDest(m_DestinationsMutex);
  if (m_HttpProxy) {
    m_HttpProxy->Stop();
    m_HttpProxy.reset(nullptr);
    LogPrint(eLogInfo, "ClientContext: HTTP Proxy stopped");
  }
  if (m_SocksProxy) {
    m_SocksProxy->Stop();
    m_SocksProxy.reset(nullptr);
    LogPrint(eLogInfo, "ClientContext: SOCKS Proxy stopped");
  }
  for (auto& it : m_ClientTunnels) {
    it.second->Stop();
    LogPrint(eLogInfo,
        "ClientContext: I2P client tunnel on port ", it.first, " stopped");
  }
  m_ClientTunnels.clear();
  for (auto& it : m_ServerTunnels) {
    it.second->Stop();
    LogPrint(eLogInfo, "ClientContext: I2P server tunnel stopped");
  }
  m_ServerTunnels.clear();
  if (m_I2PControlService) {
    m_I2PControlService->Stop();
    m_I2PControlService.reset(nullptr);
    LogPrint(eLogInfo, "ClientContext: I2PControl stopped");
  }
  m_AddressBook.Stop();
  for (auto it : m_Destinations)
    it.second->Stop();
  m_Destinations.clear();
  m_SharedLocalDestination = nullptr;
}

void ClientContext::RequestShutdown() {
  Stop();
  if (m_ShutdownHandler)
    m_ShutdownHandler();
}

i2p::data::PrivateKeys ClientContext::LoadPrivateKeys(
    const std::string& file) {
  i2p::data::PrivateKeys keys;
  std::string full_path = i2p::util::filesystem::GetFullPath(file);
  std::ifstream s(full_path.c_str(), std::ifstream::binary);
  s.exceptions(std::ifstream::failbit);
  s.seekg(0, std::ios::end);
  size_t len = s.tellg();
  s.seekg(0, std::ios::beg);
  auto buf = std::make_unique<std::uint8_t[]>(len);
  s.read(reinterpret_cast<char *>(buf.get()), len);
  keys.FromBuffer(buf.get(), len);
  LogPrint(eLogInfo,
      "ClientContext: local address ",
      m_AddressBook.ToAddress(keys.GetPublic().GetIdentHash()), " loaded");
  return keys;
}

std::shared_ptr<ClientDestination> ClientContext::LoadLocalDestination(
    const std::string& filename,
    bool is_public) {
  i2p::data::PrivateKeys keys;
  try {
    keys = LoadPrivateKeys(filename);
  } catch(std::ios_base::failure&) {
    std::string full_path = i2p::util::filesystem::GetFullPath(filename);
    LogPrint(eLogError,
        "ClientContext: can't open file ", full_path, ", creating new one");
    keys = i2p::data::PrivateKeys::CreateRandomKeys(
        i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
    std::ofstream f(full_path, std::ofstream::binary | std::ofstream::out);
    size_t len = keys.GetFullLen();
    auto buf = std::make_unique<std::uint8_t[]>(len);
    len = keys.ToBuffer(buf.get(), len);
    f.write(reinterpret_cast<char *>(buf.get()), len);
    LogPrint(eLogInfo,
        "ClientContext: new private keys file ", full_path,
        " for ", m_AddressBook.ToAddress(keys.GetPublic().GetIdentHash()),
        " created");
  }
  std::shared_ptr<ClientDestination> local_destination = nullptr;
  std::unique_lock<std::mutex> l(m_DestinationsMutex);
  auto it = m_Destinations.find(keys.GetPublic().GetIdentHash());
  if (it != m_Destinations.end()) {
    LogPrint(eLogWarn,
        "ClientContext: local destination ",
        m_AddressBook.ToAddress(keys.GetPublic().GetIdentHash()),
        " already exists");
    local_destination = it->second;
  } else {
    local_destination = std::make_shared<ClientDestination>(keys, is_public);
    m_Destinations[local_destination->GetIdentHash()] = local_destination;
    local_destination->Start();
  }
  return local_destination;
}

std::shared_ptr<ClientDestination> ClientContext::CreateNewLocalDestination(
    bool is_public,
    i2p::data::SigningKeyType sig_type,
    const std::map<std::string, std::string>* params) {
  i2p::data::PrivateKeys keys =
    i2p::data::PrivateKeys::CreateRandomKeys(sig_type);
  auto local_destination =
    std::make_shared<ClientDestination>(keys, is_public, params);
  std::unique_lock<std::mutex> l(m_DestinationsMutex);
  m_Destinations[local_destination->GetIdentHash()] = local_destination;
  local_destination->Start();
  return local_destination;
}

void ClientContext::DeleteLocalDestination(
    std::shared_ptr<ClientDestination> destination) {
  if (!destination) return;
  auto it = m_Destinations.find(
      destination->GetIdentHash());
  if (it != m_Destinations.end()) {
    auto d = it->second; {
      std::unique_lock<std::mutex> l(m_DestinationsMutex);
      m_Destinations.erase(it);
    }
    d->Stop();
  }
}

std::shared_ptr<ClientDestination> ClientContext::CreateNewLocalDestination(
    const i2p::data::PrivateKeys& keys,
    bool is_public,
    const std::map<std::string, std::string>* params) {
  auto it = m_Destinations.find(keys.GetPublic().GetIdentHash());
  if (it != m_Destinations.end()) {
    LogPrint(eLogInfo,
        "ClientContext: local destination ",
        m_AddressBook.ToAddress(keys.GetPublic().GetIdentHash()),
        " already exists");
    if (!it->second->IsRunning()) {
      it->second->Start();
      return it->second;
    }
    return nullptr;
  }
  auto local_destination =
    std::make_shared<ClientDestination>(keys, is_public, params);
  std::unique_lock<std::mutex> l(m_DestinationsMutex);
  m_Destinations[keys.GetPublic().GetIdentHash()] = local_destination;
  local_destination->Start();
  return local_destination;
}

std::shared_ptr<ClientDestination> ClientContext::FindLocalDestination(
    const i2p::data::IdentHash& destination) const {
  auto it = m_Destinations.find(destination);
  if (it != m_Destinations.end())
    return it->second;
  return nullptr;
}

void ClientContext::RemoveServerTunnels(
    std::function<bool(I2PServerTunnel*)> predicate) {
  std::lock_guard<std::mutex> lock(m_ServerMutex);
  for (auto it = m_ServerTunnels.begin(); it != m_ServerTunnels.end();) {
    if (predicate(it->second.get()))
      it = m_ServerTunnels.erase(it);
    else
      ++it;
  }
}

void ClientContext::RemoveClientTunnels(
    std::function<bool(I2PClientTunnel*)> predicate) {
  std::lock_guard<std::mutex> lock(m_ClientMutex);
  for (auto it = m_ClientTunnels.begin(); it != m_ClientTunnels.end();) {
    if (predicate(it->second.get()))
      it = m_ClientTunnels.erase(it);
    else
      ++it;
  }
}

void ClientContext::UpdateServerTunnel(
    const std::string& tunnel_name,
    const std::string& key_file,
    const std::string& host_str,
    const std::string& access_list,
    int port,
    int in_port,
    bool http) {
  bool create_tunnel = false;
  try {
    i2p::data::PrivateKeys keys = LoadPrivateKeys(key_file);
    i2p::data::IdentHash i = keys.GetPublic().GetIdentHash();
    // check if it exists in existing local servers
    auto tunnel = GetServerTunnel(i);
    if (tunnel == nullptr) {
      // Server with this name does not exist, create it later
      create_tunnel = true;
    } else {
      // Server with this already exists, change the settings
      tunnel->UpdatePort(port);
      tunnel->UpdateAddress(host_str);
      tunnel->UpdateStreamingPort(in_port);
      tunnel->SetAccessListString(access_list);
      // we don't want to stop existing connections on this tunnel so
      // we DON'T call Stop() as it will call ClearHandlers()
      // this updates the server tunnel stuff
      // TODO(unassigned): fix confusing name (Apply instead of Start)
      m_ServerTunnels[i]->Start();
    }
  } catch (std::ios_base::failure&) {
      // Key file does not exist, let's say it's new, create it later
      create_tunnel = true;
  }
  if (create_tunnel) {
      // Create the server tunnel
      auto local_destination = i2p::client::context.LoadLocalDestination(
          key_file, true);
      auto server_tunnel = http ?
          std::make_unique<I2PServerTunnelHTTP>(
              tunnel_name,
              host_str,
              port,
              local_destination,
              in_port) :
          std::make_unique<I2PServerTunnel>(
              tunnel_name,
              host_str,
              port,
              local_destination,
              in_port);
      server_tunnel->SetAccessListString(access_list);
      // Add the server tunnel
      InsertServerTunnel(local_destination->GetIdentHash(), std::move(server_tunnel));
      // Start the new server tunnel
      server_tunnel->Start();
  }
}

void ClientContext::UpdateClientTunnel(
    const std::string& tunnel_name,
    const std::string& key_file,
    const std::string& destination,
    const std::string& host_str,
    int port,
    int dest_port) {
  auto client_tunnel = GetClientTunnel(tunnel_name);
  if (client_tunnel == nullptr) {
    // Client tunnel does not exist yet, create it
    auto local_destination = LoadLocalDestination(key_file, true);
    client_tunnel = std::make_unique<I2PClientTunnel>(
          tunnel_name,
          destination,
          host_str,
          port,
          local_destination,
          dest_port);
    InsertClientTunnel(port, std::move(client_tunnel));
    client_tunnel->Start();
  } else {
    // Client with this name is already locally running, update settings
    // TODO(unassigned): we MUST have a tunnel given this tunnel_name RIGHT!?
    std::string current_addr = client_tunnel->GetAddress();
    boost::system::error_code ec;
    auto next_addr = boost::asio::ip::address::from_string(host_str, ec);
    bool rebind = false;
    if (ec)  // New address is not an IP address, compare strings
      rebind = (host_str != current_addr);
    else  // New address is an IP address, compare endpoints
      rebind = (client_tunnel->GetEndpoint() == boost::asio::ip::tcp::endpoint(
          next_addr, port));
    if (rebind) {
      // The IP address has changed, rebind
      try {
        client_tunnel->Rebind(host_str, port);
      } catch (std::exception& err) {
        LogPrint(eLogError,
            "ClientContext: failed to rebind ", tunnel_name, ": ", err.what());
      }
    }
  }
}

void ClientContext::RegisterShutdownHandler(
    std::function<void(void)> handler) {
  m_ShutdownHandler = handler;
}

bool ClientContext::InsertClientTunnel(
    int port,
    std::unique_ptr<I2PClientTunnel> tunnel) {
  std::lock_guard<std::mutex> lock(m_ClientMutex);
  return m_ClientTunnels.insert(
      std::make_pair(port, std::move(tunnel))).second;
}

bool ClientContext::InsertServerTunnel(
    const i2p::data::IdentHash& id,
    std::unique_ptr<I2PServerTunnel> tunnel) {
  std::lock_guard<std::mutex> lock(m_ServerMutex);
  return m_ServerTunnels.insert(
      std::make_pair(id, std::move(tunnel))).second;
}

void ClientContext::SetI2PControlService(
    std::unique_ptr<i2p::client::i2pcontrol::I2PControlService> service) {
  m_I2PControlService = std::move(service);
}

void ClientContext::SetHTTPProxy(
    std::unique_ptr<i2p::proxy::HTTPProxy> proxy) {
  m_HttpProxy = std::move(proxy);
}

void ClientContext::SetSOCKSProxy(
    std::unique_ptr<i2p::proxy::SOCKSProxy> proxy) {
  m_SocksProxy = std::move(proxy);
}

std::unique_ptr<I2PServerTunnel> ClientContext::GetServerTunnel(
    const std::string& name) {
  std::lock_guard<std::mutex> lock(m_ServerMutex);
  auto it = std::find_if(
      m_ServerTunnels.begin(), m_ServerTunnels.end(),
      [&name](ServerTunnelEntry & e) -> bool {
        return e.second->GetName() == name;
      });
  return it == m_ServerTunnels.end() ? nullptr : std::move(it->second);
}

std::unique_ptr<I2PServerTunnel> ClientContext::GetServerTunnel(
    const i2p::data::IdentHash& id) {
  std::lock_guard<std::mutex> lock(m_ServerMutex);
  auto it = m_ServerTunnels.find(id);
  return it == m_ServerTunnels.end() ? nullptr : std::move(it->second);
}

std::unique_ptr<I2PClientTunnel> ClientContext::GetClientTunnel(
    const std::string& name) {
  std::lock_guard<std::mutex> lock(m_ClientMutex);
  auto it = std::find_if(
      m_ClientTunnels.begin(), m_ClientTunnels.end(),
      [&name](ClientTunnelEntry & e) -> bool {
        return e.second->GetName() == name;
      });
  return it == m_ClientTunnels.end() ? nullptr : std::move(it->second);
}

std::unique_ptr<I2PClientTunnel> ClientContext::GetClientTunnel(
    int port) {
  std::lock_guard<std::mutex> lock(m_ClientMutex);
  auto it = m_ClientTunnels.find(port);
  return it == m_ClientTunnels.end() ? nullptr : std::move(it->second);
}

boost::asio::io_service& ClientContext::GetIoService() {
  return m_Service;
}

}  // namespace client
}  // namespace i2p
