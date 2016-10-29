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

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

#include <boost/asio.hpp>
#include "destination.h"
#include "identity.h"
#include "client_context.h"


namespace i2p {
namespace client {

class I2PServiceHandler;
/// @class I2PService abstract class for service
/// @brief base class for i2p service
class I2PService {
 public:
  /// @brief  constructor takes ClientDestination, defaults to null ptr
  /// @param localDestination pointer to local destination
  explicit I2PService(
      std::shared_ptr<ClientDestination> localDestination = nullptr);
  /// @brief  constructor takes a type of signing key
  /// @param kt key type
  explicit I2PService(
      i2p::data::SigningKeyType kt);
  /// @brief Destructor to clean up Handlers virtual
  virtual ~I2PService() { ClearHandlers(); }
  /// @brief add a hander to set
  /// @param conn I2pService pointer handler to addd
  inline void AddHandler(
      std::shared_ptr<I2PServiceHandler> conn) {
    std::unique_lock<std::mutex> l(m_HandlersMutex);
    m_Handlers.insert(conn);
  }
  /// @brief remove handler from set
  /// @param conn I2PServiceHandler pointer to remove
  inline void RemoveHandler(
      std::shared_ptr<I2PServiceHandler> conn) {
    std::unique_lock<std::mutex> l(m_HandlersMutex);
    m_Handlers.erase(conn);
  }
  /// @brief  clear out handlers from set
  inline void ClearHandlers() {
    std::unique_lock<std::mutex> l(m_HandlersMutex);
    m_Handlers.clear();
  }
  /// @brief returns pointer to member m_LocalDestination
  inline std::shared_ptr<ClientDestination> GetLocalDestination() {
    return m_LocalDestination;
  }
  /// @brief Set new member m_LocationDestination
  /// @param dest pointer of type ClientDestination
  inline void SetLocalDestination(
      std::shared_ptr<ClientDestination> dest) {
    m_LocalDestination = dest;
  }
  /// @brief Create a Stream to a destination
  /// @param streamRequestComplete
  void CreateStream(
      StreamRequestComplete streamRequestComplete,
      const std::string& dest,
      int port = 0);
  /// @brief return io_service refernce of member m_LocalDestination
  inline boost::asio::io_service& GetService() {
    return m_LocalDestination->GetService();
  }
  /// @brief virtual start service
  virtual void Start() = 0;
  /// @brief virtual stop service
  virtual void Stop() = 0;

  /// @brief return name of service. must override
  virtual std::string GetName() const = 0;

 private:
  /// pointer to localDestination
  std::shared_ptr<ClientDestination> m_LocalDestination;
  /// set of handlers
  std::unordered_set<std::shared_ptr<I2PServiceHandler> > m_Handlers;
  std::mutex m_HandlersMutex;
};

/**
  * @class I2PServiceHandler
  * @brief Simple interface for I2PHandlers. abstract class for handler
  * Simple interface for I2PHandlers. abstract class for handler
  * Handler will take listener away from server and process message;
  * thus allowing server to continue listening.
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


  /// @brief Start the handler; If you override this make sure you call it from
  /// the children
  void Start();

  /// @brief stop the handler;  If you override this make sure you call it from
  /// the children
  void Stop();

  /// @brief stop tunnel, change address, start tunnel will throw exception if
  /// the address is already in use
  void Rebind(
      const std::string& addr,
      uint16_t port);

  /// @brief return the endpoint
  /// @return the endpoint this TCPIPAcceptor is bound on
  boost::asio::ip::tcp::endpoint GetEndpoint() const {
    return m_Acceptor.local_endpoint();
  }

 protected:
  /// @brief  create handler object
  /// @param  socket pointer to transfer   
  /// @return return a shared pointer to the base class of this handler;
  virtual std::shared_ptr<I2PServiceHandler> CreateHandler(
      std::shared_ptr<boost::asio::ip::tcp::socket> socket) = 0;
  /// @brief get name of service
  /// @return std::string name of service
  std::string GetName() const { return "generic TCP/IP accepting daemon"; }

 protected:
  std::string m_Address;

 private:
  /// @brief accept connection ; create socket for  handler
  void Accept();
  /// @brief  callback function to handle a requested connection ;
  /// @param ecode
  /// @param socket socket creted by accept
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
