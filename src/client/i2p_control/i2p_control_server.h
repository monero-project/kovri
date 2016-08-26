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

#ifndef SRC_CLIENT_I2P_CONTROL_I2P_CONTROL_SERVER_H_
#define SRC_CLIENT_I2P_CONTROL_I2P_CONTROL_SERVER_H_

#include <inttypes.h>

#include <boost/asio.hpp>

#include <array>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include "i2p_control.h"

namespace i2p {
namespace client {
namespace i2pcontrol {

const size_t I2P_CONTROL_MAX_REQUEST_SIZE = 1024;
typedef std::array<char, I2P_CONTROL_MAX_REQUEST_SIZE> I2PControlBuffer;

class I2PControlService {
 public:
  I2PControlService(
      boost::asio::io_service& service,
      const std::string& address,
      int port,
      const std::string& password);

  ~I2PControlService();

  void Start();
  void Stop();

 private:
  void Run();
  void Accept();

  void HandleAccept(
      const boost::system::error_code& ecode,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket);

  void ReadRequest(
      std::shared_ptr<boost::asio::ip::tcp::socket> socket);

  void HandleRequestReceived(
      const boost::system::error_code& ecode,
      size_t bytes_transferred,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket,
      std::shared_ptr<I2PControlBuffer> buf);

  void SendResponse(
      std::shared_ptr<boost::asio::ip::tcp::socket> socket,
      std::shared_ptr<I2PControlBuffer> buf,
      const std::string& response,
      bool isHtml);

  void HandleResponseSent(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket,
      std::shared_ptr<I2PControlBuffer> buf);

 private:
  std::shared_ptr<I2PControlSession> m_Session;

  bool m_IsRunning;
  std::unique_ptr<std::thread> m_Thread;

  boost::asio::io_service& m_Service;
  boost::asio::ip::tcp::acceptor m_Acceptor;
};

}  // namespace i2pcontrol
}  // namespace client
}  // namespace i2p

#endif  // SRC_CLIENT_I2P_CONTROL_I2P_CONTROL_SERVER_H_
