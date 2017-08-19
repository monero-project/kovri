/**                                                                                           //
 * Copyright (c) 2015-2017, The Kovri I2P Router Project                                      //
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
 */

#ifndef SRC_UTIL_I2PCONTROL_H_
#define SRC_UTIL_I2PCONTROL_H_

#include <boost/asio/io_service.hpp>

#include <memory>
#include <string>
#include <vector>
#include "util/command.h"
#include "util/i2pcontrol_client.h"

namespace bpo = boost::program_options;
namespace client = kovri::client;

/**
 * @class I2PControlCommand
 * @brief specialization of Command for I2PControl
 */

class I2PControlCommand : public Command
{
 public:
  I2PControlCommand();
  virtual void PrintUsage(const std::string& cmd_name) const;
  virtual bool Impl(const std::string&, const std::vector<std::string>&);
  virtual std::string GetName(void) const
  {
    return "control";
  }

 protected:
  typedef client::I2PControlRequest Request;
  typedef client::I2PControlResponse Response;
  typedef Request::Method Method;

  // @brief Populate request from variable map
  // @param map User parameters
  // @param request Request to populate
  virtual void ProcessConfig(
      const bpo::variables_map& map,
      std::shared_ptr<Request> request);

  // @brief Process received response
  // @param request Original request
  // @param response Parsed response from an I2PControl server
  virtual void HandleResponse(
      std::shared_ptr<Request> request,
      std::unique_ptr<Response> response);

  bpo::options_description m_Options;
  std::string m_Command;
  std::shared_ptr<boost::asio::io_service> m_Service;
  std::unique_ptr<client::I2PControlClient> m_Client;

 private:
  void ProcessRouterManager(
      const Response& response,
      const std::string& name,
      std::uint8_t key);
};

#endif  // SRC_UTIL_I2PCONTROL_H_
