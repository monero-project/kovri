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

#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

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
  std::string proxyKeys =
    i2p::util::config::varMap["proxykeys"].as<std::string>();
  if (proxyKeys.length() > 0)
    localDestination = LoadLocalDestination(proxyKeys, false);
  m_HttpProxy = new i2p::proxy::HTTPProxy(
      "HTTP Proxy",  // TODO(unassigned): what if we want to change the name?
      i2p::util::config::varMap["httpproxyaddress"].as<std::string>(),
      i2p::util::config::varMap["httpproxyport"].as<int>(),
      localDestination);
  m_HttpProxy->Start();
  LogPrint("HTTP Proxy started");

  // SOCKS proxy
  m_SocksProxy = new i2p::proxy::SOCKSProxy(
      i2p::util::config::varMap["socksproxyaddress"].as<std::string>(),
      i2p::util::config::varMap["socksproxyport"].as<int>(),
      localDestination);
  m_SocksProxy->Start();
  LogPrint("SOCKS Proxy Started");

  // IRC tunnel
  std::string ircDestination =
    i2p::util::config::varMap["ircdest"].as<std::string>();
  if (ircDestination.length() > 0) {  // ircdest is presented
    localDestination = nullptr;
    std::string ircKeys =
      i2p::util::config::varMap["irckeys"].as<std::string>();
    if (ircKeys.length() > 0)
      localDestination = LoadLocalDestination(ircKeys, false);
    auto ircPort = i2p::util::config::varMap["ircport"].as<int>();
    auto ircTunnel = new I2PClientTunnel(
        "IRC",  // TODO(unassigned): what happens if we name a tunnel "IRC"?
        ircDestination,
        i2p::util::config::varMap["ircaddress"].as<std::string>(),
        ircPort,
        localDestination);
    ircTunnel->Start();
    // TODO(unassigned):
    // allow multiple tunnels on the same port (but on a different address)
    m_ClientTunnels.insert(
        std::make_pair(
          ircPort,
          std::unique_ptr<I2PClientTunnel>(ircTunnel)));
    LogPrint("IRC tunnel started");
  }

  // Server tunnel
  std::string eepKeys = i2p::util::config::varMap["eepkeys"].as<std::string>();
  if (eepKeys.length() > 0) {  // eepkeys are available
    localDestination = LoadLocalDestination(eepKeys, true);
    auto serverTunnel = new I2PServerTunnel(
        "eepsite",  // TODO(unassigned): what if have a tunnel called "eepsite"?
        i2p::util::config::varMap["eepaddress"].as<std::string>(),
        i2p::util::config::varMap["eepport"].as<int>(), localDestination);
    serverTunnel->Start();
    m_ServerTunnels.insert(
        std::make_pair(
          localDestination->GetIdentHash(),
          std::unique_ptr<I2PServerTunnel>(serverTunnel)));
    LogPrint("Server tunnel started");
  }
  ReadTunnels();

  // I2P Control
  int i2pcontrolPort = i2p::util::config::varMap["i2pcontrolport"].as<int>();
  if (i2pcontrolPort) {
    LogPrint("Starting I2PControlService ...");
    m_I2PControlService =
      new i2pcontrol::I2PControlService(
        m_Service,
        i2p::util::config::varMap["i2pcontroladdress"].as<std::string>(),
        i2pcontrolPort,
        i2p::util::config::varMap["i2pcontrolpassword"].as<std::string>());
    m_I2PControlService->Start();
    LogPrint("I2PControl started");
  }
  m_AddressBook.Start(
      m_SharedLocalDestination.get());
}

void ClientContext::Stop() {
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

std::shared_ptr<ClientDestination> ClientContext::LoadLocalDestination(
    const std::string& filename,
    bool isPublic) {
  i2p::data::PrivateKeys keys;
  std::string fullPath =
    i2p::util::filesystem::GetFullPath(filename);
  std::ifstream s(fullPath.c_str(), std::ifstream::binary);
  if (s.is_open()) {
    s.seekg(0, std::ios::end);
    size_t len = s.tellg();
    s.seekg(0, std::ios::beg);
    uint8_t* buf = new uint8_t[len];
    s.read(reinterpret_cast<char *>(buf), len);
    keys.FromBuffer(buf, len);
    delete[] buf;
    LogPrint("Local address ", m_AddressBook.ToAddress(
          keys.GetPublic().GetIdentHash()), " loaded");
  } else {
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

void ClientContext::ReloadTunnels() {
  boost::property_tree::ptree pt;
  std::string tunnelsConfigFile =
    i2p::util::filesystem::GetTunnelsConfigFile().string();
  try {
    boost::property_tree::read_ini(tunnelsConfigFile, pt);
  } catch (const std::exception& ex) {
    LogPrint(eLogWarning, "Can't read ", tunnelsConfigFile,
             ": ", ex.what());
    return;
  }
  // existing tunnel names
  std::vector<std::string> existingTunnels;
  // collect existing tunnels
  {
    // lock mutex while we collect the tunnels
    std::lock_guard<std::mutex> clock(m_ServerMutex);
    std::lock_guard<std::mutex> slock(m_ClientMutex);
    for ( auto & item : m_ServerTunnels ) {
      existingTunnels.push_back(item.second->GetName());
    }
    for ( auto & item : m_ClientTunnels ) {
      existingTunnels.push_back(item.second->GetName());
    }
  }
  // a list of tunnels that exist after config update
  std::vector<std::string> updatedTunnels;
  // iterate over tunnels' ident hashes for what's in tunnels.cfg now
  for (auto& section : pt) {
    // TODO(unassigned): what if we switch a server from client to tunnel
    // or vice versa?
    bool createTunnel = false;
    std::string tunnelName = section.first;
    updatedTunnels.push_back(tunnelName);
    std::string type =
      section.second.get<std::string>(
          I2P_TUNNELS_SECTION_TYPE,
          "");
    if (type == I2P_TUNNELS_SECTION_TYPE_SERVER ||
        type == I2P_TUNNELS_SECTION_TYPE_HTTP) {
      // obtain server options
      std::string keyfile =
        section.second.get<std::string>(
            I2P_SERVER_TUNNEL_KEYS,
            "");
      std::string keysFullPath =
        i2p::util::filesystem::GetFullPath(keyfile);
      std::string hostStr =
        section.second.get<std::string>(
            I2P_SERVER_TUNNEL_HOST,
            "");
      int port =
        section.second.get<int>(
            I2P_SERVER_TUNNEL_PORT,
            0);
      int inPort =
        section.second.get(
            I2P_SERVER_TUNNEL_INPORT,
            0);
      std::string accessList =
        section.second.get(
            I2P_SERVER_TUNNEL_ACCESS_LIST,
            "");
      {
        i2p::data::PrivateKeys keys;
        // get keyfile
        std::ifstream s(keysFullPath.c_str(), std::ifstream::binary);
        if (s.is_open()) {  // keyfile exists already
          // read private keys
          s.seekg(0, std::ios::end);
          size_t len = s.tellg();
          s.seekg(0, std::ios::beg);
          uint8_t* buf = new uint8_t[len];
          s.read(reinterpret_cast<char *>(buf), len);
          keys.FromBuffer(buf, len);
          delete[] buf;
          // get key's ident hash
          i2p::data::IdentHash i = keys.GetPublic().GetIdentHash();
          // check if it exists in existing local servers
          auto itrEnd = existingTunnels.end();
          auto itr = std::find(existingTunnels.begin(), itrEnd, tunnelName);
          if (itr == itrEnd) {
            // the server with this name exists locally
            // we'll load it outside after we close the private key file when
            // we fall out if the scope it's in
            createTunnel = true;
          } else {
            // the server with this name is already locally running
            // let's update the settings of it
            // first we lock the server tunnels mutex
            std::lock_guard<std::mutex> lock(m_ServerMutex);
            // update out port for this server tunnel
            m_ServerTunnels[i]->UpdatePort(port);
            // update host for this server tunnel
            m_ServerTunnels[i]->UpdateAddress(hostStr);
            // update in port for this server tunnel
            m_ServerTunnels[i]->UpdateStreamingPort(inPort);
            // update access list
            m_ServerTunnels[i]->SetAccessListString(accessList);
            // we don't want to stop existing connections on this tunnel so
            // we DON'T call Stop() as it will call ClearHandlers()
            // this updates the server tunnel stuff,
            // it should really be called Apply() but whatever
            m_ServerTunnels[i]->Start();  // apply changes
          }
        } else {
          // key file does not exist, let's say it's new
          // after we fall out of scope of the open file for the keys,
          // we'll add it
          createTunnel = true;
        }
      }
      if (createTunnel) {
        // we're going to create a new server tunnel
        // load the destination
        auto localDestination = LoadLocalDestination(keysFullPath, true);
        I2PServerTunnel* serverTunnel =
          (type == I2P_TUNNELS_SECTION_TYPE_HTTP) ?
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
        // add the server tunnel
        {
          // lock access to server tunnels
          std::lock_guard<std::mutex> lock(m_ServerMutex);
          auto i = localDestination->GetIdentHash();
          if (m_ServerTunnels.insert(
               std::make_pair(
                   i,
                   std::unique_ptr<I2PServerTunnel>(serverTunnel))).second) {
            // we added it
            serverTunnel->Start();
          } else {
            // wtf ? it's already there?
            LogPrint(eLogError,
                "WTF! NEW I2P Server Tunnel for destination ",
                m_AddressBook.ToAddress(i), " exists?!");
          }
        }
      }
    } else if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT) {
      // get client tunnel parameters
      std::string keyfile =
        section.second.get(
            I2P_CLIENT_TUNNEL_KEYS,
            "");
      std::string keysFullPath =
        i2p::util::filesystem::GetFullPath(keyfile);
      std::string destination =
        section.second.get<std::string>(
            I2P_CLIENT_TUNNEL_DESTINATION,
            "");
      std::string hostStr =
        section.second.get(
            I2P_CLIENT_TUNNEL_ADDRESS,
            "127.0.0.1");
      int port =
        section.second.get<int>(
            I2P_CLIENT_TUNNEL_PORT,
            0);
      int destPort =
        section.second.get(
            I2P_CLIENT_TUNNEL_DESTINATION_PORT,
            0);
      {
        auto itrEnd = existingTunnels.end();
        auto itr = std::find(existingTunnels.begin(), itrEnd, tunnelName);
        createTunnel = itr == itrEnd;
      }
      // check if we have a conflicting port
      {
        // first we lock the client tunnels mutex
        std::lock_guard<std::mutex> lock(m_ClientMutex);
        // check if we have someone with this port
        auto itr = m_ClientTunnels.find(port);
        if (itr != m_ClientTunnels.end() &&
            itr->second->GetName() != tunnelName) {
          // conflicting port
          // TODO(unassigned): what if we interchange two client tunnels' ports?
          LogPrint(eLogError,
              tunnelName, " will not be updated, Conflicting Port");
          continue;
        }
      }
      // we're going to create a new client tunnel
      if (createTunnel) {
        // load the destination
        auto localDestination = LoadLocalDestination(keysFullPath, true);
        try {
          I2PClientTunnel* clientTunnel =
            new I2PClientTunnel(
                tunnelName,
                destination,
                hostStr,
                port,
                localDestination,
                destPort);
          // add the client tunnel
          {
            // lock access to server tunnels
            std::lock_guard<std::mutex> lock(m_ClientMutex);
            auto i = localDestination->GetIdentHash();
            if (m_ClientTunnels.insert(
                  std::make_pair(
                      port,
                      std::unique_ptr<I2PClientTunnel>(clientTunnel))).second) {
              // we added it
              clientTunnel->Start();
            } else {
              // wtf ? it's already there?
              LogPrint(eLogError,
                  "WTF! NEW I2P Client Tunnel for destination ",
                  m_AddressBook.ToAddress(i), " exists?!");
            }
          }
        } catch (std::exception& err) {
          // error happened while making new tunnel
          LogPrint(eLogError, "failed to create new tunnel: ", err.what());
          continue;
        }
      } else {
        // the client with this name is already locally running
        // let's update the settings of it
        // first we lock the client tunnels mutex
        std::lock_guard<std::mutex> lock(m_ClientMutex);
        // get the tunnel given the name
        auto itr = std::find_if(
          m_ClientTunnels.begin(),
          m_ClientTunnels.end(),
          [&tunnelName](ClientTunnelEntry & e) -> bool {
            return e.second->GetName() == tunnelName;
          });
        // TODO(unassigned): we MUST have a tunnel given this tunnelName RIGHT!?
        auto & tun = itr->second;
        // check what we need to rebind if anything
        auto currentEndpoint = tun->GetEndpoint();
        std::string currentAddr = tun->GetAddress();
        boost::system::error_code ec;
        auto nextAddr = boost::asio::ip::address::from_string(hostStr, ec);
        if (ec) {
          // the next address is not an ip address
          if (hostStr != currentAddr) {
            // the new address is different
            // let's rebind
            try {
              tun->Rebind(hostStr, port);
            } catch (std::exception& err) {
              LogPrint(eLogError,
                  "failed to rebind ", tunnelName, ": ", err.what());
            }
          }
        } else {
          // the next address is an ip address
          boost::asio::ip::tcp::endpoint nextEndpoint(nextAddr, port);
          if ( currentEndpoint != nextEndpoint ) {
            // the endpoints differ
            // let's rebind
            try {
              tun->Rebind(hostStr, port);
            } catch (std::exception& err) {
              LogPrint(eLogError,
                  "failed to rebind ", tunnelName, ": ", err.what());
            }
          }
        }
      }
    }
  }
  {
    // remove all non existant server tunnels
    std::vector<std::string> remove;
    std::lock_guard<std::mutex> lock(m_ServerMutex);
    for (auto& entry : m_ServerTunnels) {
      std::string tunnelName = entry.second->GetName();
      auto itrEnd = updatedTunnels.end();
      auto itr = std::find(updatedTunnels.begin(), itrEnd, tunnelName);
      if (itr == itrEnd) {
        remove.push_back(tunnelName);
      }
    }
    for (auto& tunnelName : remove) {
      auto itr =
        std::find_if(
            m_ServerTunnels.begin(),
            m_ServerTunnels.end(),
            [&tunnelName](ServerTunnelEntry & entry) -> bool {
          return entry.second->GetName() == tunnelName;
        });
      m_ServerTunnels.erase(itr);
    }
  }
  {
    // remove all non existant client tunnels
    std::vector<std::string> remove;
    std::lock_guard<std::mutex> lock(m_ClientMutex);
    for (auto& entry : m_ClientTunnels) {
      std::string tunnelName = entry.second->GetName();
      auto itrEnd = updatedTunnels.end();
      auto itr = std::find(updatedTunnels.begin(), itrEnd, tunnelName);
      if (itr == itrEnd) {
        remove.push_back(tunnelName);
      }
    }
    for (auto & tunnelName : remove) {
      LogPrint(eLogInfo, "Removing Tunnel ", tunnelName);
      auto itr =
        std::find_if(
            m_ClientTunnels.begin(),
            m_ClientTunnels.end(),
            [&tunnelName](ClientTunnelEntry & entry) -> bool {
          return entry.second->GetName() == tunnelName;
        });
      m_ClientTunnels.erase(itr);
    }
  }
}

void ClientContext::ReadTunnels() {
  boost::property_tree::ptree pt;
  std::string pathTunnelsConfigFile =
    i2p::util::filesystem::GetTunnelsConfigFile().string();
  try {
    boost::property_tree::read_ini(pathTunnelsConfigFile, pt);
  } catch(const std::exception& ex) {
    LogPrint(eLogWarning, "Can't read ",
        pathTunnelsConfigFile, ": ", ex.what());
    return;
  }
  int numClientTunnels = 0, numServerTunnels = 0;
  for (auto& section : pt) {
    std::string name = section.first;
    try {
      std::string type =
        section.second.get<std::string>(I2P_TUNNELS_SECTION_TYPE);
      if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT) {
        // mandatory params
        std::string dest =
          section.second.get<std::string>(I2P_CLIENT_TUNNEL_DESTINATION);
        int port = section.second.get<int>(I2P_CLIENT_TUNNEL_PORT);
        // optional params
        std::string address =
          section.second.get(
            I2P_CLIENT_TUNNEL_ADDRESS,
            "127.0.0.1");
        std::string keys =
          section.second.get(
            I2P_CLIENT_TUNNEL_KEYS,
            "");
        int destinationPort =
          section.second.get(
              I2P_CLIENT_TUNNEL_DESTINATION_PORT,
              0);
        std::shared_ptr<ClientDestination>localDestination = nullptr;
        if (keys.length() > 0)
          localDestination = LoadLocalDestination(keys, false);
        auto clientTunnel = new I2PClientTunnel(
            name,
            dest,
            address,
            port,
            localDestination,
            destinationPort);
        // TODO(anonimal):
        // allow multiple tunnels on the same port (but on a different address)
        if (m_ClientTunnels.insert(
              std::make_pair(
                port,
                std::unique_ptr<I2PClientTunnel>(clientTunnel))).second)
          clientTunnel->Start();
        else
          LogPrint(eLogError, "I2P client tunnel with port ",
              port, " already exists");
        numClientTunnels++;
      } else if (type == I2P_TUNNELS_SECTION_TYPE_SERVER ||
          type == I2P_TUNNELS_SECTION_TYPE_HTTP) {
        // mandatory params
        std::string host =
          section.second.get<std::string>(
              I2P_SERVER_TUNNEL_HOST);
        int port =
          section.second.get<int>(
              I2P_SERVER_TUNNEL_PORT);
        std::string keys =
          section.second.get<std::string>(
              I2P_SERVER_TUNNEL_KEYS);
        // optional params
        int inPort =
          section.second.get(
              I2P_SERVER_TUNNEL_INPORT,
              0);
        std::string accessList =
          section.second.get(
              I2P_SERVER_TUNNEL_ACCESS_LIST,
              "");
        auto localDestination = LoadLocalDestination(keys, true);
        I2PServerTunnel* serverTunnel =
          (type == I2P_TUNNELS_SECTION_TYPE_HTTP) ?
          new I2PServerTunnelHTTP(name, host, port, localDestination, inPort) :
          new I2PServerTunnel(name, host, port, localDestination, inPort);
        serverTunnel->SetAccessListString(accessList);
        if (m_ServerTunnels.insert(
              std::make_pair(
                localDestination->GetIdentHash(),
                std::unique_ptr<I2PServerTunnel>(serverTunnel))).second)
          serverTunnel->Start();
        else
          LogPrint(eLogError, "I2P server tunnel for destination ",
              m_AddressBook.ToAddress(
                localDestination->GetIdentHash()), " already exists");
        numServerTunnels++;
      } else {
        LogPrint(eLogWarning, "Unknown section type=", type,
            " of ", name, " in ", pathTunnelsConfigFile);
      }
    } catch(const std::exception& ex) {
      LogPrint(eLogError, "Can't read tunnel ", name, " params: ", ex.what());
    }
  }
  LogPrint(eLogInfo, numClientTunnels, " I2P client tunnels created");
  LogPrint(eLogInfo, numServerTunnels, " I2P server tunnels created");
}

}  // namespace client
}  // namespace i2p
