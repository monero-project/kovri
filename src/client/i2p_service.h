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

#ifndef SRC_CLIENT_I2P_SERVICE_H_
#define SRC_CLIENT_I2P_SERVICE_H_

#include <boost/asio.hpp>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

#include "destination.h"
#include "identity.h"

namespace i2p {
namespace client {

class I2PServiceHandler;
class I2PService {
 public:
  explicit I2PService(
      std::shared_ptr<ClientDestination> localDestination = nullptr);
  explicit I2PService(
      i2p::data::SigningKeyType kt);
  virtual ~I2PService() { ClearHandlers(); }

  inline void AddHandler(
      std::shared_ptr<I2PServiceHandler> conn) {
    std::unique_lock<std::mutex> l(m_HandlersMutex);
    m_Handlers.insert(conn);
  }

  inline void RemoveHandler(
      std::shared_ptr<I2PServiceHandler> conn) {
    std::unique_lock<std::mutex> l(m_HandlersMutex);
    m_Handlers.erase(conn);
  }

  inline void ClearHandlers() {
    std::unique_lock<std::mutex> l(m_HandlersMutex);
    m_Handlers.clear();
  }

  inline std::shared_ptr<ClientDestination> GetLocalDestination() {
    return m_LocalDestination;
  }

  inline void SetLocalDestination(
      std::shared_ptr<ClientDestination> dest) {
    m_LocalDestination = dest;
  }

  void CreateStream(
      StreamRequestComplete streamRequestComplete,
      const std::string& dest,
      int port = 0);

  inline boost::asio::io_service& GetService() {
    return m_LocalDestination->GetService();
  }

  virtual void Start() = 0;
  virtual void Stop() = 0;

  // everyone must override this
  virtual std::string GetName() const = 0;

 private:
  std::shared_ptr<ClientDestination> m_LocalDestination;
  std::unordered_set<std::shared_ptr<I2PServiceHandler> > m_Handlers;
  std::mutex m_HandlersMutex;
};

/**
 * Simple interface for I2PHandlers.
 * Allows detection of finalization amongst other things.
 */
class I2PServiceHandler {
 public:
  explicit I2PServiceHandler(
      I2PService* parent)
      : m_Service(parent),
        m_Dead(false) {}
  virtual ~I2PServiceHandler() {}

  // If you override this make sure you call it from the children
  virtual void Handle() {}  // Start handling the socket

 protected:
  // Call when terminating or handing over to avoid race conditions
  inline bool Kill() { return m_Dead.exchange(true); }

  // Call to know if the handler is dead
  inline bool Dead() { return m_Dead; }

  // Call when done to clean up (make sure Kill is called first)
  inline void Done(std::shared_ptr<I2PServiceHandler> me) {
    if (m_Service)
      m_Service->RemoveHandler(me);
  }
  //  Call to talk with the owner
  inline I2PService* GetOwner() { return m_Service; }

 private:
  I2PService* m_Service;
  std::atomic<bool> m_Dead;  // To avoid cleaning up multiple times
};

/**
 * TODO(unassigned): support IPv6 too
 * This is a service that listens for connections on
 * the IP network and interacts with I2P
 */
class TCPIPAcceptor : public I2PService {
 public:
  TCPIPAcceptor(
      const std::string& address,
      int port,
      std::shared_ptr<ClientDestination> localDestination = nullptr)
      : I2PService(localDestination),
        m_Address(address),
        m_Acceptor(
            GetService(),
            boost::asio::ip::tcp::endpoint(
                boost::asio::ip::address::from_string(
                    address),
                port)),
        m_Timer(
            GetService()) {}

  TCPIPAcceptor(
      const std::string& address,
      int port,
      i2p::data::SigningKeyType kt)
    : I2PService(kt),
      m_Address(address),
      m_Acceptor(
          GetService(),
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(
                address),
              port)),
      m_Timer(GetService()) {}

  virtual ~TCPIPAcceptor() {
    TCPIPAcceptor::Stop();
  }

  // If you override this make sure you call it from the children
  void Start();

  // If you override this make sure you call it from the children
  void Stop();

  // stop tunnel, change address, start tunnel
  // will throw exception if the address is already in use
  void Rebind(
      const std::string& addr,
      uint16_t port);

  // @return the endpoint this TCPIPAcceptor is bound on
  boost::asio::ip::tcp::endpoint GetEndpoint() const {
    return m_Acceptor.local_endpoint();
  }

 protected:
  virtual std::shared_ptr<I2PServiceHandler> CreateHandler(
      std::shared_ptr<boost::asio::ip::tcp::socket> socket) = 0;

  std::string GetName() const { return "generic TCP/IP accepting daemon"; }

 protected:
  std::string m_Address;

 private:
  void Accept();
  void HandleAccept(
      const boost::system::error_code& ecode,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket);

  boost::asio::ip::tcp::acceptor m_Acceptor;
  boost::asio::deadline_timer m_Timer;

 public:
  // get our current address
  std::string GetAddress() const {
    return m_Address;
  }
};

}  // namespace client
}  // namespace i2p

#endif  // SRC_CLIENT_I2P_SERVICE_H_
