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

#include "ClientContext.h"

#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "Identity.h"
#include "util/Log.h"

namespace i2p {
namespace client {

ClientContext context;

ClientContext::ClientContext()
    : m_SharedLocalDestination(nullptr),
      m_HttpProxy(nullptr),
      m_SocksProxy(nullptr),
      m_I2PControlService(nullptr) {}

ClientContext::~ClientContext() {
  delete m_HttpProxy;
  delete m_SocksProxy;
  delete m_I2PControlService;
  m_Service.stop();
}

void ClientContext::Start() {
  if (!m_SharedLocalDestination) {
    m_SharedLocalDestination = CreateNewLocalDestination();  // non-public, DSA
    m_Destinations[m_SharedLocalDestination->GetIdentity().GetIdentHash()] =
      m_SharedLocalDestination;
    m_SharedLocalDestination->Start();
  }
  std::shared_ptr<ClientDestination> localDestination;

  // HTTP proxy
  m_HttpProxy->Start();
  LogPrint("HTTP Proxy started");

  // SOCKS proxy
    m_SocksProxy->Start();
  LogPrint("SOCKS Proxy Started");

  // Start all client tunnels
  for(auto& pair : m_ClientTunnels)
    pair.second->Start();

  // Start all server tunnels
  for(auto& pair : m_ServerTunnels)
    pair.second->Start();
  
  // I2P Control
  if (m_I2PControlService) {
    LogPrint("Starting I2PControlService ...");
    m_I2PControlService->Start();
  }
  m_AddressBook.Start(m_SharedLocalDestination.get());
}

void ClientContext::Stop() {
  std::lock_guard<std::mutex> lockClient(m_ClientMutex);
  std::lock_guard<std::mutex> lockServer(m_ServerMutex);
  std::lock_guard<std::mutex> lockDest(m_DestinationsMutex);

  if (m_HttpProxy) {
    m_HttpProxy->Stop();
    delete m_HttpProxy;
    m_HttpProxy = nullptr;
    LogPrint("HTTP Proxy stopped");
  }
  if (m_SocksProxy) {
    m_SocksProxy->Stop();
    delete m_SocksProxy;
    m_SocksProxy = nullptr;
    LogPrint("SOCKS Proxy stopped");
  }
  for (auto& it : m_ClientTunnels) {
    it.second->Stop();
    LogPrint("I2P client tunnel on port ", it.first, " stopped");
  }
  m_ClientTunnels.clear();
  for (auto& it : m_ServerTunnels) {
    it.second->Stop();
    LogPrint("I2P server tunnel stopped");
  }
  m_ServerTunnels.clear();
  if (m_I2PControlService) {
    m_I2PControlService->Stop();
    delete m_I2PControlService;
    m_I2PControlService = nullptr;
    LogPrint("I2PControl stopped");
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

i2p::data::PrivateKeys ClientContext::LoadPrivateKeys(const std::string& file) {
  i2p::data::PrivateKeys keys;
  std::string fullPath = i2p::util::filesystem::GetFullPath(file);

  std::ifstream s(fullPath.c_str(), std::ifstream::binary);
  s.exceptions(std::ifstream::failbit);

  s.seekg(0, std::ios::end);
  size_t len = s.tellg();
  s.seekg(0, std::ios::beg);
  uint8_t* buf = new uint8_t[len];
  s.read(reinterpret_cast<char *>(buf), len);
  keys.FromBuffer(buf, len);
  delete[] buf;

  LogPrint("Local address ", m_AddressBook.ToAddress(
        keys.GetPublic().GetIdentHash()), " loaded");
  return keys;
}

std::shared_ptr<ClientDestination> ClientContext::LoadLocalDestination(
    const std::string& filename, bool isPublic) {

  i2p::data::PrivateKeys keys;
  try {
    keys = LoadPrivateKeys(filename);
  } catch(std::ios_base::failure&) {
    std::string fullPath = i2p::util::filesystem::GetFullPath(filename);
    LogPrint("Can't open file ", fullPath, ", creating new one");
    keys = i2p::data::PrivateKeys::CreateRandomKeys(
        i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256);
    std::ofstream f(fullPath, std::ofstream::binary | std::ofstream::out);
    size_t len = keys.GetFullLen();
    uint8_t* buf = new uint8_t[len];
    len = keys.ToBuffer(buf, len);
    f.write(reinterpret_cast<char *>(buf), len);
    delete[] buf;
    LogPrint("New private keys file ", fullPath,
        " for ", m_AddressBook.ToAddress(keys.GetPublic().GetIdentHash()),
        " created");
  }
  std::shared_ptr<ClientDestination> localDestination = nullptr;
  std::unique_lock<std::mutex> l(m_DestinationsMutex);
  auto it = m_Destinations.find(keys.GetPublic().GetIdentHash());
  if (it != m_Destinations.end()) {
    LogPrint(eLogWarning, "Local destination ",
        m_AddressBook.ToAddress(
          keys.GetPublic().GetIdentHash()), " already exists");
    localDestination = it->second;
  } else {
    localDestination = std::make_shared<ClientDestination>(keys, isPublic);
    m_Destinations[localDestination->GetIdentHash()] = localDestination;
    localDestination->Start();
  }
  return localDestination;
}

std::shared_ptr<ClientDestination> ClientContext::CreateNewLocalDestination(
    bool isPublic, i2p::data::SigningKeyType sigType,
    const std::map<std::string, std::string>* params) {
  i2p::data::PrivateKeys keys =
    i2p::data::PrivateKeys::CreateRandomKeys(sigType);
  auto localDestination =
    std::make_shared<ClientDestination>(keys, isPublic, params);
  std::unique_lock<std::mutex> l(m_DestinationsMutex);
  m_Destinations[localDestination->GetIdentHash()] = localDestination;
  localDestination->Start();
  return localDestination;
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
    bool isPublic,
    const std::map<std::string,
    std::string>* params) {
  auto it = m_Destinations.find(keys.GetPublic().GetIdentHash());
  if (it != m_Destinations.end()) {
    LogPrint("Local destination ",
        m_AddressBook.ToAddress(keys.GetPublic().GetIdentHash()), " exists");
    if (!it->second->IsRunning()) {
      it->second->Start();
      return it->second;
    }
    return nullptr;
  }
  auto localDestination =
    std::make_shared<ClientDestination>(keys, isPublic, params);
  std::unique_lock<std::mutex> l(m_DestinationsMutex);
  m_Destinations[keys.GetPublic().GetIdentHash()] = localDestination;
  localDestination->Start();
  return localDestination;
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
    const std::string& tunnelName,
    const std::string& keyfile,
    const std::string& hostStr,
    const std::string& accessList,
    int port,
    int inPort,
    bool http) {

  bool createTunnel = false;

  try {
    i2p::data::PrivateKeys keys = LoadPrivateKeys(keyfile);
    i2p::data::IdentHash i = keys.GetPublic().GetIdentHash();
    // check if it exists in existing local servers
    I2PServerTunnel* tunnel = GetServerTunnel(i);
    if(tunnel == nullptr) {
      // Server with this name does not exist, create it later
      createTunnel = true;
    } else {
      // Server with this already exists, change the settings
      tunnel->UpdatePort(port);
      tunnel->UpdateAddress(hostStr);
      tunnel->UpdateStreamingPort(inPort);
      tunnel->SetAccessListString(accessList);
      // we don't want to stop existing connections on this tunnel so
      // we DON'T call Stop() as it will call ClearHandlers()
      // this updates the server tunnel stuff
      // TODO(unassigned): fix confusing name (Apply instead of Start)
      m_ServerTunnels[i]->Start();
    }
  } catch (std::ios_base::failure&) {
      // Key file does not exist, let's say it's new, create it later
      createTunnel = true;
  }

  if (createTunnel) {
      // Create the server tunnel 
      auto localDestination = i2p::client::context.LoadLocalDestination(keyfile, true);
      I2PServerTunnel* serverTunnel = http ? 
          new I2PServerTunnelHTTP(
              tunnelName,
              hostStr,
              port,
              localDestination,
              inPort) :
          new I2PServerTunnel(
              tunnelName,
              hostStr,
              port,
              localDestination,
              inPort);
      serverTunnel->SetAccessListString(accessList);
      // Add the server tunnel
      InsertServerTunnel(localDestination->GetIdentHash(), serverTunnel);
      // Start the new server tunnel
      serverTunnel->Start();
  }

}

void ClientContext::UpdateClientTunnel(
    const std::string& tunnelName,
    const std::string& keyfile,
    const std::string& destination,
    const std::string& hostStr,
    int port,
    int destPort) {

  I2PClientTunnel* clientTunnel = GetClientTunnel(tunnelName);
  if (clientTunnel == nullptr) {
    // Client tunnel does not exist yet, create it 
    auto localDestination = LoadLocalDestination(keyfile, true);
    clientTunnel = new I2PClientTunnel(
          tunnelName,
          destination,
          hostStr,
          port,
          localDestination,
          destPort);
    InsertClientTunnel(port, clientTunnel);
    clientTunnel->Start();
  } else {
    // Client with this name is already locally running, update settings
    // TODO(unassigned): we MUST have a tunnel given this tunnelName RIGHT!?
    std::string currentAddr = clientTunnel->GetAddress();

    boost::system::error_code ec;
    auto nextAddr = boost::asio::ip::address::from_string(hostStr, ec);

    bool rebind = false;
    if (ec) // New address is not an IP address, compare strings
      rebind = (hostStr != currentAddr);
    else // New address is an IP address, compare endpoints
      rebind = (clientTunnel->GetEndpoint() == boost::asio::ip::tcp::endpoint(
          nextAddr, port));
   
    if (rebind) { 
      // The IP address has changed, rebind  
      try {
        clientTunnel->Rebind(hostStr, port);
      } catch (std::exception& err) {
        LogPrint(eLogError, "Failed to rebind ", tunnelName, ": ", err.what());
      }
    }
  }
}

void ClientContext::RegisterShutdownHandler(std::function<void(void)> handler) {
  m_ShutdownHandler = handler; 
}

bool ClientContext::InsertClientTunnel(int port, I2PClientTunnel* tunnel) {
  std::lock_guard<std::mutex> lock(m_ClientMutex);
  return m_ClientTunnels.insert(
      std::make_pair(port, std::unique_ptr<I2PClientTunnel>(tunnel))).second;
}

bool ClientContext::InsertServerTunnel(const i2p::data::IdentHash& id,
    I2PServerTunnel* tunnel) {
  std::lock_guard<std::mutex> lock(m_ServerMutex);
  return m_ServerTunnels.insert(
      std::make_pair(id, std::unique_ptr<I2PServerTunnel>(tunnel))).second;
}

void ClientContext::SetI2PControlService(
    i2p::client::i2pcontrol::I2PControlService* service) {
  m_I2PControlService = service;
}

void ClientContext::SetHTTPProxy(i2p::proxy::HTTPProxy* proxy) {
  m_HttpProxy = proxy;
}

void ClientContext::SetSOCKSProxy(i2p::proxy::SOCKSProxy* proxy) {
  m_SocksProxy = proxy;
}

I2PServerTunnel* ClientContext::GetServerTunnel(const std::string& name) {
  std::lock_guard<std::mutex> lock(m_ServerMutex);
  auto it = std::find_if(
      m_ServerTunnels.begin(), m_ServerTunnels.end(),
      [&name](ServerTunnelEntry & e) -> bool {
        return e.second->GetName() == name;
      });
  return it == m_ServerTunnels.end() ? nullptr : it->second.get();
}

I2PServerTunnel* ClientContext::GetServerTunnel(const i2p::data::IdentHash& id) {
  std::lock_guard<std::mutex> lock(m_ServerMutex);
  auto it = m_ServerTunnels.find(id);
  return it == m_ServerTunnels.end() ? nullptr : it->second.get();
}

I2PClientTunnel* ClientContext::GetClientTunnel(const std::string& name) {
  std::lock_guard<std::mutex> lock(m_ClientMutex);
  auto it = std::find_if(
      m_ClientTunnels.begin(), m_ClientTunnels.end(),
      [&name](ClientTunnelEntry & e) -> bool {
        return e.second->GetName() == name;
      });
  return it == m_ClientTunnels.end() ? nullptr : it->second.get();
}

I2PClientTunnel* ClientContext::GetClientTunnel(int port) {
  std::lock_guard<std::mutex> lock(m_ClientMutex);
  auto it = m_ClientTunnels.find(port);
  return it == m_ClientTunnels.end() ? nullptr : it->second.get();
}

boost::asio::io_service& ClientContext::GetIoService() {
  return m_Service;
}

}  // namespace client
}  // namespace i2p
