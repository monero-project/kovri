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

#ifndef SRC_CLIENT_CONTEXT_H_
#define SRC_CLIENT_CONTEXT_H_

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

#include "client/address_book/impl.h"
#include "client/api/i2p_control/server.h"
#include "client/destination.h"
#include "client/proxy/http.h"
#include "client/proxy/socks.h"
#include "client/tunnel.h"

#include "core/util/exception.h"

namespace kovri {
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

  // Non-public
  std::shared_ptr<ClientDestination> CreateNewLocalDestination(
      bool is_public = false,
      kovri::core::SigningKeyType sig_type = kovri::core::DEFAULT_CLIENT_SIGNING_KEY_TYPE,
      const std::map<std::string, std::string>* params = nullptr);  // transient

  // Public
  std::shared_ptr<ClientDestination> CreateNewLocalDestination(
      const kovri::core::PrivateKeys& keys,
      bool is_public = true,
      const std::map<std::string, std::string>* params = nullptr);

  void DeleteLocalDestination(
      std::shared_ptr<ClientDestination> destination);

  std::shared_ptr<ClientDestination> FindLocalDestination(
      const kovri::core::IdentHash& destination) const;

  /// @brief Creates private keys from given filename if they don't exist
  /// @param filename the relative name of the private key file
  /// @return Created private keys
  kovri::core::PrivateKeys CreatePrivateKeys(
      const std::string& filename);

  /// @brief Creates text file containing private key's public b32 address
  /// @param keys Private keys to derive b32 address from
  /// @param filename The relative name of the text address file
  void CreateBaseAddressTextFile(
      const kovri::core::PrivateKeys& keys,
      const std::string& filename);

  /// @brief Loads private keys from given filename
  /// @param filename Relative name of the private key file
  /// @return Loaded private keys
  kovri::core::PrivateKeys LoadPrivateKeys(
      const std::string& filename);

  std::shared_ptr<ClientDestination> LoadLocalDestination(
      const std::string& filename,
      bool is_public);

  AddressBook& GetAddressBook() {
    return m_AddressBook;
  }

  const AddressBook& GetAddressBook() const {
    return m_AddressBook;
  }

  /// @brief Removes all server unnels satisfying the given predicate
  /// @param predicate a unary predicate used to filter server tunnels
  void RemoveServerTunnels(
      std::function<bool(I2PServerTunnel*)> predicate);

  /// @brief Removes all client tunnels satisfying the given predicate
  /// @param predicate a unary predicate used to filter client tunnels
  void RemoveClientTunnels(
      std::function<bool(I2PClientTunnel*)> predicate);

  /// @brief Updates or creates the specified server tunnel
  /// @param tunnel Const reference to populated/initialized tunnel attributes class
  /// @param http true if server tunnel is an HTTP tunnel
  void UpdateServerTunnel(
    const TunnelAttributes& tunnel,
    bool is_http);  // TODO(anonimal): this isn't ideal

  /// @brief Updates or creates the specified client tunnel
  /// @param tunnel Const reference to populated/initialized tunnel attributes class
  void UpdateClientTunnel(
    const TunnelAttributes& tunnel);

  /// @brief Creates the specified server tunnel and tries to insert it
  /// @param tunnel Const reference to populated/initialized tunnel attributes class
  /// @param http true if server tunnel is an HTTP tunnel
  /// @return true if the tunnel was inserted, false otherwise
  bool AddServerTunnel(
      const TunnelAttributes& tunnel,
      bool is_http);  // TODO(anonimal): this isn't ideal

  /// @brief Creates the specified client tunnel and tries to insert it
  /// @param tunnel Const reference to populated/initialized tunnel attributes class
  /// @return true if the tunnel was inserted, false otherwise
  bool AddClientTunnel(const TunnelAttributes& tunnel);

  /// @brief Registers a shutdown handler, called by ClientContext::RequestShutdown.
  /// @param handler The handler to be called on shutdown
  void RegisterShutdownHandler(std::function<void(void)> handler);

  /// @brief Inserts a client tunnel.
  /// @return true if the tunnel was inserted, false otherwise
  bool InsertClientTunnel(
      int port,
      std::unique_ptr<I2PClientTunnel> tunnel);

  /// @brief Inserts a server tunnel.
  /// @return true if the tunnel was inserted, false otherwise
  bool InsertServerTunnel(
      const kovri::core::IdentHash& id,
      std::unique_ptr<I2PServerTunnel> tunnel);

  /// @brief Sets the I2PControl service
  /// @param service a pointer to the I2PControlService
  void SetI2PControlService(
      std::unique_ptr<kovri::client::I2PControlService> service);

  /// @brief Sets the HTTP proxy.
  /// @param proxy a pointer to the HTTPProxy
  void SetHTTPProxy(std::unique_ptr<HTTPProxy> proxy);

  /// @brief Sets the SOCKS proxy.
  /// @param proxy a pointer to the SOCKSProxy
  void SetSOCKSProxy(std::unique_ptr<kovri::client::SOCKSProxy> proxy);

  /// @return the client tunnel with the given name, or nullptr
  I2PServerTunnel* GetServerTunnel(const std::string& name);

  /// @return the server tunnel with the given identity hash, or nullptr
  I2PServerTunnel* GetServerTunnel(const kovri::core::IdentHash& id);

  /// @return the client tunnel with the given name, or nullptr
  I2PClientTunnel* GetClientTunnel(const std::string& name);

  /// @return the client tunnel with the given (local) port
  I2PClientTunnel* GetClientTunnel(int port);

  boost::asio::io_service& GetIoService();

 private:
  std::mutex m_DestinationsMutex;
  std::map<kovri::core::IdentHash, std::shared_ptr<ClientDestination>> m_Destinations;
  std::shared_ptr<ClientDestination> m_SharedLocalDestination;

  AddressBook m_AddressBook;

  std::unique_ptr<HTTPProxy> m_HttpProxy;
  std::unique_ptr<kovri::client::SOCKSProxy> m_SocksProxy;

  std::mutex m_ClientMutex;
  // port->tunnel
  std::map<int, std::unique_ptr<I2PClientTunnel>> m_ClientTunnels;

  std::mutex m_ServerMutex;
  // destination->tunnel
  std::map<kovri::core::IdentHash, std::unique_ptr<I2PServerTunnel>> m_ServerTunnels;


  // types for accessing client / server tunnel map entries
  typedef std::pair<const int,
                    std::unique_ptr<I2PClientTunnel>> ClientTunnelEntry;

  typedef std::pair<const kovri::core::IdentHash,
                    std::unique_ptr<I2PServerTunnel>> ServerTunnelEntry;

  boost::asio::io_service m_Service;
  std::unique_ptr<I2PControlService> m_I2PControlService;

  std::function<void(void)> m_ShutdownHandler;

  kovri::core::Exception m_Exception;
};

extern ClientContext context;

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_CONTEXT_H_
