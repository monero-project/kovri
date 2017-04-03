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

#include "client/context.h"

#include <fstream>
#include <iostream>
#include <set>
#include <vector>

#include "core/router/identity.h"
#include "core/util/filesystem.h"
#include "core/util/log.h"

namespace kovri {
namespace client {

// Simply instantiating in namespace scope ties into, and is limited by, the current singleton design
// TODO(unassigned): refactoring this requires global work but will help to remove the singleton
ClientContext context;

ClientContext::ClientContext()
    : m_SharedLocalDestination(nullptr),
      m_HttpProxy(nullptr),
      m_SocksProxy(nullptr),
      m_I2PControlService(nullptr),
      m_Exception(__func__) {}

ClientContext::~ClientContext() {
  m_Service.stop();
}

// TODO(anonimal): nearly all Start/Stop handlers throughout the code-base should be replaced with proper RAII
void ClientContext::Start() {
  if (!m_SharedLocalDestination) {
    m_SharedLocalDestination = CreateNewLocalDestination();  // Non-public
    m_Destinations[m_SharedLocalDestination->GetIdentity().GetIdentHash()] =
      m_SharedLocalDestination;
    m_SharedLocalDestination->Start();
  }
  std::shared_ptr<ClientDestination> local_destination;
  m_HttpProxy->Start();
  LOG(debug) << "ClientContext: HTTP Proxy started";
  m_SocksProxy->Start();
  LOG(debug) << "ClientContext: SOCKS Proxy Started";
  // Start all client tunnels
  for (auto& pair : m_ClientTunnels)
    pair.second->Start();
  // Start all server tunnels
  for (auto& pair : m_ServerTunnels)
    pair.second->Start();
  // I2P Control
  if (m_I2PControlService) {
    LOG(debug) << "ClientContext: starting I2PControlService";
    m_I2PControlService->Start();
  }
  m_AddressBook.Start(m_SharedLocalDestination);
}

// TODO(anonimal): nearly all Start/Stop handlers throughout the code-base should be replaced with proper RAII
void ClientContext::Stop() {
  std::lock_guard<std::mutex> lockClient(m_ClientMutex);
  std::lock_guard<std::mutex> lockServer(m_ServerMutex);
  std::lock_guard<std::mutex> lockDest(m_DestinationsMutex);
  if (m_HttpProxy) {
    m_HttpProxy->Stop();
    m_HttpProxy.reset(nullptr);
    LOG(debug) << "ClientContext: HTTP Proxy stopped";
  }
  if (m_SocksProxy) {
    m_SocksProxy->Stop();
    m_SocksProxy.reset(nullptr);
    LOG(debug) << "ClientContext: SOCKS Proxy stopped";
  }
  for (auto& it : m_ClientTunnels) {
    it.second->Stop();
    LOG(debug)
      << "ClientContext: I2P client tunnel on port " << it.first << " stopped";
  }
  m_ClientTunnels.clear();
  for (auto& it : m_ServerTunnels) {
    it.second->Stop();
    LOG(debug) << "ClientContext: I2P server tunnel stopped";
  }
  m_ServerTunnels.clear();
  if (m_I2PControlService) {
    m_I2PControlService->Stop();
    m_I2PControlService.reset(nullptr);
    LOG(debug) << "ClientContext: I2PControl stopped";
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

kovri::core::PrivateKeys ClientContext::LoadPrivateKeys(
    const std::string& filename) {
  kovri::core::PrivateKeys keys;
  try {
    auto file_path = (kovri::core::GetClientKeysPath() / filename).string();
    std::ifstream file(file_path, std::ifstream::binary);
    if (!file) {
      LOG(debug)
        << "ClientContext: " << file_path << " does not exist, creating";
      return CreatePrivateKeys(filename);
    }
    file.seekg(0, std::ios::end);
    const std::size_t len = file.tellg();
    file.seekg(0, std::ios::beg);
    std::unique_ptr<std::uint8_t[]> buf(std::make_unique<std::uint8_t[]>(len));
    file.read(reinterpret_cast<char *>(buf.get()), len);
    keys.FromBuffer(buf.get(), len);
    // Contingency: create associated address text file if the private keys
    // filename is swapped out with another set of keys with the same filename
    CreateBaseAddressTextFile(keys, filename);
    LOG(info)
      << "ClientContext: " << file_path << " loaded: uses local address "
      << kovri::core::GetB32Address(keys.GetPublic().GetIdentHash());
  } catch (...) {
    m_Exception.Dispatch(__func__);
    throw;
  }
  return keys;
}

kovri::core::PrivateKeys ClientContext::CreatePrivateKeys(
    const std::string& filename) {
  auto path = kovri::core::EnsurePath(kovri::core::GetClientKeysPath());
  auto file_path = (path / filename).string();
  // Create binary keys file
  std::ofstream file(file_path, std::ofstream::binary);
  if (!file)
    throw std::runtime_error("ClientContext: could not open private keys for writing");
  auto keys = kovri::core::PrivateKeys::CreateRandomKeys();  // Generate default type
  std::size_t len = keys.GetFullLen();
  std::unique_ptr<std::uint8_t[]> buf(std::make_unique<std::uint8_t[]>(len));
  len = keys.ToBuffer(buf.get(), len);
  file.write(reinterpret_cast<char *>(buf.get()), len);
  // Create associated address text file
  CreateBaseAddressTextFile(keys, filename);
  LOG(info)
    << "ClientContext: created new private keys " << file_path << " for "
    << kovri::core::GetB32Address(keys.GetPublic().GetIdentHash());
  return keys;
}

void ClientContext::CreateBaseAddressTextFile(
    const kovri::core::PrivateKeys& keys,
    const std::string& filename) {
  auto path = kovri::core::EnsurePath(kovri::core::GetClientKeysPath());
  auto file_path = (path / filename).string() + ".txt";
  // Create binary keys file
  std::ofstream file(file_path);
  if (!file)
    throw std::runtime_error("ClientContext: could not open base address text file for writing");
  // Re: identity, see #366
  // Base32
  file << kovri::core::GetB32Address(keys.GetPublic().GetIdentHash()) << "\n";
  // Base64
  file << keys.GetPublic().ToBase64();
  LOG(info) << "ClientContext: created base address text file " << file_path;
}

std::shared_ptr<ClientDestination> ClientContext::LoadLocalDestination(
    const std::string& filename,
    bool is_public) {
  auto keys = LoadPrivateKeys(filename);
  std::shared_ptr<ClientDestination> local_destination = nullptr;
  std::unique_lock<std::mutex> l(m_DestinationsMutex);
  auto it = m_Destinations.find(keys.GetPublic().GetIdentHash());
  if (it != m_Destinations.end()) {
    LOG(warning)
      << "ClientContext: local destination "
      << kovri::core::GetB32Address(keys.GetPublic().GetIdentHash())
      << " already exists";
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
    kovri::core::SigningKeyType sig_type,
    const std::map<std::string, std::string>* params) {
  kovri::core::PrivateKeys keys =
    kovri::core::PrivateKeys::CreateRandomKeys(sig_type);
  auto local_destination =
    std::make_shared<ClientDestination>(keys, is_public, params);
  std::unique_lock<std::mutex> l(m_DestinationsMutex);
  m_Destinations[local_destination->GetIdentHash()] = local_destination;
  local_destination->Start();
  return local_destination;
}

void ClientContext::DeleteLocalDestination(
    std::shared_ptr<ClientDestination> destination) {
  if (!destination)
    return;
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
    const kovri::core::PrivateKeys& keys,
    bool is_public,
    const std::map<std::string, std::string>* params) {
  auto it = m_Destinations.find(keys.GetPublic().GetIdentHash());
  if (it != m_Destinations.end()) {
    LOG(debug)
      << "ClientContext: local destination "
      << kovri::core::GetB32Address(keys.GetPublic().GetIdentHash())
      << " already exists";
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
    const kovri::core::IdentHash& destination) const {
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
    const TunnelAttributes& tunnel,
    bool is_http) {
  bool create_tunnel = false;
  try {
    kovri::core::PrivateKeys keys = LoadPrivateKeys(tunnel.keys);
    kovri::core::IdentHash ident = keys.GetPublic().GetIdentHash();
    // Check if server already exists
    auto server_tunnel = GetServerTunnel(ident);
    if (server_tunnel == nullptr) {
      // Server with this name does not exist, create it later
      create_tunnel = true;
    } else {
      // Server exists, update tunnel attributes and re-bind tunnel
      // Note: all type checks, etc. are already completed in config handling
      server_tunnel->UpdateServerTunnel(tunnel);
      // TODO(unassigned): since we don't want to stop existing connections on
      // this tunnel we want to stay away from clearing any handlers
      // (e.g., not calling any stop function) but we need to ensure that
      // the previous bound port is also closed. Needs Review.
      // TODO(unassigned): consider alternative name (Apply instead of Start)
      m_ServerTunnels[ident]->Start();
    }
  } catch (const std::ios_base::failure&) {
    // Key file does not exist (assuming the tunnel is new)
    create_tunnel = true;
  } catch (const std::exception& ex) {
    throw std::runtime_error(
        "ClientContext: exception in " + std::string(__func__)
        + ": " + std::string(ex.what()));
  } catch (...) {
    throw std::runtime_error(
        "ClientContext: unknown exception in " + std::string(__func__));
  }
  if (create_tunnel)
    AddServerTunnel(tunnel, is_http);
}

void ClientContext::UpdateClientTunnel(
    const TunnelAttributes& tunnel) {
  auto client_tunnel = GetClientTunnel(tunnel.name);
  if (client_tunnel == nullptr) {
    // Client tunnel does not exist yet, create it
    AddClientTunnel(tunnel);
  } else {
    // Client with this name is already locally running, update settings
    // TODO(unassigned): use-case for remaining tunnel attributes?
    std::string current_addr = client_tunnel->GetAddress();
    boost::system::error_code ec;
    auto next_addr = boost::asio::ip::address::from_string(tunnel.address, ec);
    bool rebind = false;
    if (ec)  // New address is not an IP address, compare strings
      rebind = (tunnel.address != current_addr);
    else  // New address is an IP address, compare endpoints
      rebind =
          (client_tunnel->GetEndpoint()
           != boost::asio::ip::tcp::endpoint(next_addr, tunnel.port));
    if (rebind) {
      // The IP address has changed, rebind
      try {
        client_tunnel->Rebind(tunnel.address, tunnel.port);
      } catch (const std::exception& err) {
        LOG(error)
          << "ClientContext: failed to rebind "
          << tunnel.name << ": " << err.what();
      }
    }
  }
}

bool ClientContext::AddServerTunnel(
    const TunnelAttributes& tunnel,
    bool is_http)
{
  auto local_destination = LoadLocalDestination(tunnel.keys, true);
  auto server_tunnel =
      is_http ? std::make_unique<kovri::client::I2PServerTunnelHTTP>(
                    tunnel, local_destination)
              : std::make_unique<kovri::client::I2PServerTunnel>(
                    tunnel, local_destination);
  // Insert server tunnel
  if (!InsertServerTunnel(
          local_destination->GetIdentHash(), std::move(server_tunnel)))
    {
      LOG(error) << "Instance: server tunnel for destination "
                 << GetAddressBook().GetB32AddressFromIdentHash(
                        local_destination->GetIdentHash())
                 << " already exists";
      return false;
    }
  return true;
}

bool ClientContext::AddClientTunnel(const TunnelAttributes& tunnel)
{
  std::shared_ptr<kovri::client::ClientDestination> local_destination;
  if (!tunnel.keys.empty())
    local_destination = LoadLocalDestination(tunnel.keys, false);
  // Insert client tunnel
  auto client_tunnel = std::make_unique<kovri::client::I2PClientTunnel>(
      tunnel, local_destination);
  if (!InsertClientTunnel(tunnel.port, std::move(client_tunnel)))
    {
      LOG(error) << "Instance: failed to insert new client tunnel";
      return false;
    }
  return true;
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
    const kovri::core::IdentHash& id,
    std::unique_ptr<I2PServerTunnel> tunnel) {
  std::lock_guard<std::mutex> lock(m_ServerMutex);
  return m_ServerTunnels.insert(
      std::make_pair(id, std::move(tunnel))).second;
}

void ClientContext::SetI2PControlService(
    std::unique_ptr<kovri::client::I2PControlService> service) {
  m_I2PControlService = std::move(service);
}

void ClientContext::SetHTTPProxy(
    std::unique_ptr<HTTPProxy> proxy) {
  m_HttpProxy = std::move(proxy);
}

void ClientContext::SetSOCKSProxy(
    std::unique_ptr<kovri::client::SOCKSProxy> proxy) {
  m_SocksProxy = std::move(proxy);
}

I2PServerTunnel* ClientContext::GetServerTunnel(const std::string& name)
{
  std::lock_guard<std::mutex> lock(m_ServerMutex);
  auto it = std::find_if(
      m_ServerTunnels.begin(), m_ServerTunnels.end(),
      [&name](ServerTunnelEntry & e) -> bool {
        return e.second->GetName() == name;
      });
  return it == m_ServerTunnels.end() ? nullptr : it->second.get();
}

I2PServerTunnel* ClientContext::GetServerTunnel(
    const kovri::core::IdentHash& id)
{
  std::lock_guard<std::mutex> lock(m_ServerMutex);
  auto it = m_ServerTunnels.find(id);
  return it == m_ServerTunnels.end() ? nullptr : it->second.get();
}

I2PClientTunnel* ClientContext::GetClientTunnel(const std::string& name)
{
  std::lock_guard<std::mutex> lock(m_ClientMutex);
  auto it = std::find_if(
      m_ClientTunnels.begin(), m_ClientTunnels.end(),
      [&name](ClientTunnelEntry & e) -> bool {
        return e.second->GetName() == name;
      });
  return it == m_ClientTunnels.end() ? nullptr : it->second.get();
}

I2PClientTunnel* ClientContext::GetClientTunnel(int port)
{
  std::lock_guard<std::mutex> lock(m_ClientMutex);
  auto it = m_ClientTunnels.find(port);
  return it == m_ClientTunnels.end() ? nullptr : it->second.get();
}

boost::asio::io_service& ClientContext::GetIoService() {
  return m_Service;
}

}  // namespace client
}  // namespace kovri
