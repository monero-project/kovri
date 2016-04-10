/**
 * Copyright (c) 2013-2016, The Kovri I2P Router Project
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
 *
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project
 */

#ifndef SRC_CLIENT_CLIENTCONTEXT_H_
#define SRC_CLIENT_CLIENTCONTEXT_H_

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include "AddressBook.h"
#include "Destination.h"
#include "I2PControl/I2PControlServer.h"
#include "I2PTunnel/HTTPProxy.h"
#include "I2PTunnel/I2PTunnel.h"
#include "I2PTunnel/SOCKS.h"

namespace i2p {
namespace client {

class ClientContext {
 public:
  ClientContext();
  ~ClientContext();

  void Start();
  void Stop();

  /**
   * Shuts down the ClientContext and calls the shutdown handler.
   * This member function can be used by client components to shut down the
   *  router.
   * @note nothing happens if there is no registered shutdown handler
   * @warning not thread safe
   */
  void RequestShutdown();

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

  /// @brief Loads the private keys from the given file
  /// @param file the relative name of the private key file
  /// @return the loaded private keys
  i2p::data::PrivateKeys LoadPrivateKeys(const std::string& file);

  std::shared_ptr<ClientDestination> LoadLocalDestination(
      const std::string& filename, bool isPublic);

  AddressBook& GetAddressBook() { return m_AddressBook; }

  /// @brief Removes all server unnels satisfying the given predicate
  /// @param predicate a unary predicate used to filter server tunnels
  void RemoveServerTunnels(std::function<bool(I2PServerTunnel*)> predicate);

  /// @brief Removes all client tunnels satisfying the given predicate
  /// @param predicate a unary predicate used to filter client tunnels
  void RemoveClientTunnels(std::function<bool(I2PClientTunnel*)> predicate);

  /// @brief Updates or creates the specified server tunnel
  /// @param keyfile the relative filename of the key file
  /// @param http true if server tunnel is an HTTP tunnel
  void UpdateServerTunnel(
    const std::string& tunnelName,
    const std::string& keyfile,
    const std::string& hostStr,
    const std::string& accessList,
    int port,
    int inPort,
    bool http);

  /// @brief Updates or creates the specified client tunnel
  /// @param tunnelName the name of the client tunnel
  /// @param keyfile the relative filename of the key file
  void UpdateClientTunnel(
    const std::string& tunnelName,
    const std::string& keyfile,
    const std::string& destination,
    const std::string& hostStr,
    int port,
    int destPort);

  /// @brief Registers a shutdown handler, called by ClientContext::RequestShutdown.
  /// @param handler The handler to be called on shutdown
  void RegisterShutdownHandler(std::function<void(void)> handler);

  /// @brief Inserts a client tunnel.
  /// @return true if the tunnel was inserted, false otherwise
  /// @note takes ownership of the given pointer
  bool InsertClientTunnel(int port, I2PClientTunnel* tunnel);

  /// Inserts a server tunnel.
  /// @return true if the tunnel was inserted, false otherwise
  /// @note takes ownership of the given pointer
  bool InsertServerTunnel(
      const i2p::data::IdentHash& id,
      I2PServerTunnel* tunnel);

  /// Sets the I2PControl service
  /// @param service a pointer to the I2PControlService
  /// @note takes ownership of the given pointer
  void SetI2PControlService(
      i2p::client::i2pcontrol::I2PControlService* service);

  /// Sets the HTTP proxy.
  /// @param proxy a pointer to the HTTPProxy
  /// @note takes ownership of the given pointer
  void SetHTTPProxy(i2p::proxy::HTTPProxy* proxy);

  /// Sets the SOCKS proxy.
  /// @param proxy a pointer to the SOCKSProxy
  /// @note takes ownership of the given pointer
  void SetSOCKSProxy(i2p::proxy::SOCKSProxy* proxy);

  /// @return the client tunnel with the given name, or nullptr
  I2PServerTunnel* GetServerTunnel(const std::string& name);

  /// @return the server tunnel with the given identity hash, or nullptr
  I2PServerTunnel* GetServerTunnel(const i2p::data::IdentHash& id);

  /// @return the client tunnel with the given name, or nullptr
  I2PClientTunnel* GetClientTunnel(const std::string& name);

  /// @return the client tunnel with the given (local) port
  I2PClientTunnel* GetClientTunnel(int port);

  boost::asio::io_service& GetIoService();

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
  typedef std::pair<const int, std::unique_ptr<I2PClientTunnel> >
    ClientTunnelEntry;
  typedef std::pair<
      const i2p::data::IdentHash,
      std::unique_ptr<I2PServerTunnel>
    >ServerTunnelEntry;

  boost::asio::io_service m_Service;

  i2pcontrol::I2PControlService* m_I2PControlService;

  std::function<void(void)> m_ShutdownHandler;

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
