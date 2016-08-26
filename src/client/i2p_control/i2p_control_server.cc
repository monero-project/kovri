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

#include "i2p_control_server.h"

#include <boost/date_time/local_time/local_time.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <sstream>
#include <string>
#include <memory>

#include "core/version.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace client {
namespace i2pcontrol {

I2PControlService::I2PControlService(
  boost::asio::io_service& service,
  const std::string& address,
  int port,
  const std::string& password)
    : m_Session(std::make_shared<I2PControlSession>(service, password)),
      m_IsRunning(false),
      m_Thread(nullptr),
      m_Service(service),
      m_Acceptor(
          service,
          boost::asio::ip::tcp::endpoint(
              boost::asio::ip::address::from_string(address),
              port)) {}

I2PControlService::~I2PControlService() {
  Stop();
}

void I2PControlService::Start() {
  if (!m_IsRunning) {
    Accept();
    m_Session->Start();
    m_IsRunning = true;
    m_Thread = std::make_unique<std::thread>(
        std::bind(
            &I2PControlService::Run,
            this));
  }
}

void I2PControlService::Stop() {
  if (m_IsRunning) {
    m_IsRunning = false;
    m_Acceptor.cancel();
    m_Session->Stop();
    // Release ownership before the io_service is stopped and destroyed
    m_Session.reset();
    if (m_Thread) {
      m_Thread->join();
      m_Thread.reset(nullptr);
    }
  }
}

void I2PControlService::Run() {
  while (m_IsRunning) {
    try {
      m_Service.run();
    } catch (const std::exception& ex) {
      LogPrint(eLogError, "I2PControlService::Run() exception: ", ex.what());
    }
  }
}

void I2PControlService::Accept() {
  auto new_socket =
    std::make_shared<boost::asio::ip::tcp::socket>(m_Service);
  m_Acceptor.async_accept(
      *new_socket,
      std::bind(
          &I2PControlService::HandleAccept,
          this,
          std::placeholders::_1,
          new_socket));
}

void I2PControlService::HandleAccept(
    const boost::system::error_code& ecode,
    std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
  if (ecode != boost::asio::error::operation_aborted)
    Accept();
  if (!ecode) {
    LogPrint(eLogInfo,
        "I2PControlService: new I2PControl request from ",
        socket->remote_endpoint());
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    ReadRequest(socket);
  } else {
    LogPrint(eLogError,
        "I2PControlService: accept error: ",  ecode.message());
  }
}

void I2PControlService::ReadRequest(
    std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
  auto request = std::make_shared<I2PControlBuffer>();
  socket->async_read_some(
#if BOOST_VERSION >= 104900
  boost::asio::buffer(*request),
#else
  boost::asio::buffer(request->data(), request->size()),
#endif
  std::bind(
      &I2PControlService::HandleRequestReceived,
      this,
      std::placeholders::_1,
      std::placeholders::_2,
      socket,
      request));
}

void I2PControlService::HandleRequestReceived(
    const boost::system::error_code& ecode,
    size_t bytes_transferred,
    std::shared_ptr<boost::asio::ip::tcp::socket> socket,
    std::shared_ptr<I2PControlBuffer> buf) {
  if (ecode) {
    LogPrint(eLogError, "I2PControlService: read error: ", ecode.message());
    return;
  }
  try {
    bool is_html = !memcmp(buf->data(), "POST", 4);
    std::stringstream ss;
    ss.write(buf->data(), bytes_transferred);
    if (is_html) {
      std::string header;
      while (!ss.eof() && header != "\r")
        std::getline(ss, header);
      if (ss.eof()) {
        LogPrint(eLogError,
            "I2PControlService: malformed I2PControl request."
            "HTTP header expected");
        return;  // TODO(unassigned): implement
      }
    }
    I2PControlSession::Response response =
      m_Session->HandleRequest(ss);
    SendResponse(socket, buf, response.ToJsonString(), is_html);
  } catch (const std::exception& ex) {
    LogPrint(eLogError,
        "I2PControlService: handle request exception: ", ex.what());
  } catch (...) {
    LogPrint(eLogError,
        "I2PControlService: handle request unknown exception");
  }
}

void I2PControlService::SendResponse(
    std::shared_ptr<boost::asio::ip::tcp::socket> socket,
    std::shared_ptr<I2PControlBuffer> buf,
    const std::string& response,
    bool is_html) {
  size_t len = response.length(), offset = 0;
  if (is_html) {
    std::ostringstream header;
    header << "HTTP/1.1 200 OK\r\n";
    header << "Connection: close\r\n";
    header << "Content-Length: "
           << boost::lexical_cast<std::string>(len) << "\r\n";
    header << "Content-Type: application/json\r\n";
    header << "Date: ";
    auto facet = new boost::local_time::local_time_facet(
        "%a, %d %b %Y %H:%M:%S GMT");
    header.imbue(std::locale(header.getloc(), facet));
    header << boost::posix_time::second_clock::local_time() << "\r\n";
    header << "\r\n";
    offset = header.str().size();
    memcpy(buf->data(), header.str().c_str(), offset);
  }
  memcpy(buf->data() + offset, response.c_str(), len);
  boost::asio::async_write(
      *socket,
      boost::asio::buffer(
          buf->data(),
          offset + len),
      boost::asio::transfer_all(),
      std::bind(
          &I2PControlService::HandleResponseSent,
          this,
          std::placeholders::_1,
          std::placeholders::_2,
          socket,
          buf));
}

void I2PControlService::HandleResponseSent(
    const boost::system::error_code& ecode,
    std::size_t,
    std::shared_ptr<boost::asio::ip::tcp::socket> socket,
    std::shared_ptr<I2PControlBuffer>) {
  if (ecode)
    LogPrint(eLogError, "I2PControlService: write error: ", ecode.message());
  socket->close();
}

}  // namespace i2pcontrol
}  // namespace client
}  // namespace i2p
