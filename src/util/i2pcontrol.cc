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

#include "util/i2pcontrol.h"
#include <assert.h>
#include <functional>
#include <memory>
#include <utility>

#include "core/util/exception.h"
#include "core/util/log.h"

namespace core = kovri::core;

/**
 * @class PrintVisitor
 * @brief Print value to string
 **/
struct PrintVisitor final : public boost::static_visitor<std::string>
{
  std::string operator()(bool value) const
  {
    return value ? "true" : "false";
  }

  std::string operator()(const std::size_t& value) const
  {
    return std::to_string(value);
  }

  std::string operator()(const double& value) const
  {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << value;
    return oss.str();
  }

  std::string operator()(const std::string& value) const
  {
    return value;
  }

  std::string operator()(const client::JsonObject& value) const
  {
    return value.ToString();
  }
};

I2PControlCommand::I2PControlCommand()
{
  bpo::options_description options("Connection options");
  options.add_options()(
      "host", bpo::value<std::string>()->default_value("127.0.0.1"))(
      "port", bpo::value<int>()->default_value(7650))(
      "password", bpo::value<std::string>()->default_value("itoopie"));
  m_Options.add(options);

  bpo::options_description shortcuts("Shortcuts");
  shortcuts.add_options()(
      "command", bpo::value<std::string>()->default_value(""));
  m_Options.add(shortcuts);

  bpo::options_description raw_options("Low level options");
  raw_options.add_options()(
      "method,m", bpo::value<std::string>()->default_value("RouterInfo"))(
      "key,k", bpo::value<std::string>()->default_value(""))(
      "value,v", bpo::value<std::string>()->default_value(""));
  m_Options.add(raw_options);
}

void I2PControlCommand::PrintUsage(const std::string& name) const
{
  LOG(info) << "Syntax: " << name << m_Options;
  LOG(info) << "Available commands: ";
  LOG(info) << "\tstatus";
  LOG(info) << "\tversion";
  LOG(info) << "\tuptime";
  LOG(info) << "\treseed";
  LOG(info) << "\tshutdown";
  LOG(info) << "\tforce-shutdown";
  LOG(info) << "\tstats";
}

bool I2PControlCommand::Impl(
    const std::string&,
    const std::vector<std::string>& args)
{
  m_Service = std::make_shared<boost::asio::io_service>();
  m_Client = std::make_unique<client::I2PControlClient>(m_Service);
  try
    {
      std::vector<std::string> inputs;
      bpo::positional_options_description pos;
      pos.add("command", -1);

      bpo::variables_map vm;
      bpo::parsed_options parsed = bpo::command_line_parser(args)
                                       .options(m_Options)
                                       .positional(pos)
                                       .run();
      bpo::store(parsed, vm);
      bpo::notify(vm);

      // Host connection params
      auto request = std::make_shared<client::I2PControlRequest>();
      ProcessConfig(vm, request);

      // Authenticate
      m_Client->AsyncConnect(
          [this,
           request](std::unique_ptr<client::I2PControlResponse> auth_response) {
            // Received response of authentication
            if (auth_response->GetError() != Response::ErrorCode::None)
              {
                throw std::runtime_error(
                    "Authentification failed : "
                    + auth_response->GetErrorMsg());
              }
            // Successfully authenticated, send request
            m_Client->AsyncSendRequest(
                request,
                [this, request](
                    std::unique_ptr<client::I2PControlResponse> response) {
                  // Received response
                  HandleResponse(request, std::move(response));
                  // Nothing more to do
                  m_Service->stop();
                });
          });
      m_Service->run();
    }
  catch (...)
    {
      core::Exception ex(GetName().c_str());
      ex.Dispatch(__func__);
      return false;
    }
  return true;
}

void I2PControlCommand::ProcessConfig(
    const bpo::variables_map& vm,
    std::shared_ptr<Request> request)
{
  typedef Request::MethodRouterInfo RouterInfo;
  typedef Request::MethodRouterManager RouterManager;

  // Connection parameters
  m_Client->SetHost(vm["host"].as<std::string>());
  m_Client->SetPort(vm["port"].as<int>());
  m_Client->SetPassword(vm["password"].as<std::string>());

  // Process Shortcuts first
  m_Command = vm["command"].as<std::string>();
  if (m_Command == "status")
    {
      request->SetMethod(Method::RouterInfo);
      request->SetParam(RouterInfo::Status, std::string());
      return;
    }
  else if (m_Command == "version")
    {
      request->SetMethod(Method::RouterInfo);
      request->SetParam(RouterInfo::Version, std::string());
      return;
    }
  else if (m_Command == "uptime")
    {
      request->SetMethod(Method::RouterInfo);
      request->SetParam(RouterInfo::Uptime, std::string());
      return;
    }
  else if (m_Command == "reseed")
    {
      request->SetMethod(Method::RouterManager);
      request->SetParam(RouterManager::Reseed, std::string());
      return;
    }
  else if (m_Command == "shutdown")
    {
      request->SetMethod(Method::RouterManager);
      request->SetParam(RouterManager::ShutdownGraceful, std::string());
      return;
    }
  else if (m_Command == "force-shutdown")
    {
      request->SetMethod(Method::RouterManager);
      request->SetParam(RouterManager::Shutdown, std::string());
      return;
    }
  else if (m_Command == "stats")
    {
      request->SetMethod(Method::RouterInfo);
      std::string empty;
      request->SetParam(RouterInfo::BWIn1S, empty);
      request->SetParam(RouterInfo::BWOut1S, empty);
      request->SetParam(RouterInfo::NetStatus, empty);
      request->SetParam(RouterInfo::TunnelsParticipating, empty);
      request->SetParam(RouterInfo::ActivePeers, empty);
      request->SetParam(RouterInfo::KnownPeers, empty);
      request->SetParam(RouterInfo::Floodfills, empty);
      request->SetParam(RouterInfo::LeaseSets, empty);
      request->SetParam(RouterInfo::TunnelsCreationSuccessRate, empty);
      return;
    }
  else if (!m_Command.empty())
    {
      throw std::runtime_error("Invalid command " + m_Command);
    }

  // If no shortcut, try low level options
  auto method_string = vm["method"].as<std::string>();
  auto method = request->GetMethodFromString(method_string);
  request->SetMethod(method);

  auto key = vm["key"].as<std::string>();
  auto value = vm["value"].as<std::string>();

  switch (method)
    {
      case Method::Authenticate:
        throw std::invalid_argument("Invalid method: use option password");

      case Method::Echo:
        if (!key.empty())
          throw std::invalid_argument("Invalid key: leave empty");
        request->SetParam(Request::MethodEcho::Echo, value);
        break;

      case Method::GetRate:
        request->SetParam(Request::MethodGetRate::Stat, key);
        request->SetParam(
            Request::MethodGetRate::Period, std::size_t(std::stoi(value)));
        break;

      case Method::I2PControl:
      case Method::RouterManager:
      case Method::NetworkSetting:
        request->SetParam(key, value);
        break;

      case Method::RouterInfo:
        {
          if (!value.empty())
            throw std::invalid_argument("Command RouterInfo takes no value");
          request->SetParam(key, std::string());
        }
        break;

      case Method::Unknown:
        throw std::invalid_argument(
            "Invalid method " + vm["method"].as<std::string>());
    }
}

void I2PControlCommand::ProcessRouterManager(
    const Response& response,
    const std::string& name,
    std::uint8_t key)
{
  auto const& params = response.GetParams();
  auto end = params.end();
  if (params.find(key) == end)
    LOG(error) << "ControlCommand: no " << name << " key in response";
  else
    LOG(info) << "ControlCommand: " << name << " initiated";
}

void I2PControlCommand::HandleResponse(
    std::shared_ptr<Request> request,
    std::unique_ptr<Response> response)
{
  typedef Request::MethodRouterInfo RouterInfo;
  typedef Request::MethodRouterManager RouterManager;
  typedef Request::MethodI2PControl I2PControl;

  LOG(debug) << "I2PControlCommand: response received";
  if (response->GetError() != Response::ErrorCode::None)
    {
      LOG(error) << "I2PControlCommand: server responded with error: "
                 << response->GetErrorMsg();
      return;
    }

  // Process shortucts responses
  if (m_Command == "status")
    {
      LOG(info) << "Status: "
                << response->GetParam<std::string>(RouterInfo::Status);
      return;
    }
  else if (m_Command == "version")
    {
      LOG(info) << "Version: "
                << response->GetParam<std::string>(RouterInfo::Version);
      return;
    }
  else if (m_Command == "uptime")
    {
      LOG(info) << "Server uptime: "
                << std::to_string(
                       response->GetParam<std::size_t>(RouterInfo::Uptime)
                       / 1000)
                << " seconds";
      return;
    }
  else if (m_Command == "reseed")
    {
      return ProcessRouterManager(*response, m_Command, RouterManager::Reseed);
    }
  else if (m_Command == "shutdown")
    {
      return ProcessRouterManager(
          *response, m_Command, RouterManager::ShutdownGraceful);
    }
  else if (m_Command == "force-shutdown")
    {
      return ProcessRouterManager(
          *response, m_Command, RouterManager::Shutdown);
    }
  else if ((m_Command != "stats") && !m_Command.empty())
    {
      throw std::runtime_error("Missing implementation");
    }

  // Process raw responses
  switch (request->GetMethod())
    {
      case Method::Echo:
        LOG(info) << "Echo: "
                  << response->GetParam<std::string>(
                         Request::MethodEcho::Result);
        break;

      case Method::I2PControl:
        for (const auto& pair : response->GetParams())
          {
            switch (pair.first)
              {
                case I2PControl::Address:
                  LOG(info) << "Address changed";
                  break;
                case I2PControl::Password:
                  LOG(info) << "Password changed";
                  break;
                case I2PControl::Port:
                  LOG(info) << "Port changed";
                  break;

                case I2PControl::SettingsSaved:
                case I2PControl::RestartNeeded:
                  LOG(info)
                      << response->KeyToString(pair.first) << " : "
                      << boost::apply_visitor(PrintVisitor(), pair.second);
                  break;

                default:
                  throw std::runtime_error("Invalid I2PControl key");
              }
          }
        break;

      case Method::GetRate:
      case Method::RouterInfo:
      case Method::RouterManager:
      case Method::NetworkSetting:
        for (const auto& pair : response->GetParams())
          {
            LOG(info) << response->KeyToString(pair.first) << " : "
                      << boost::apply_visitor(PrintVisitor(), pair.second);
          }
        break;

      default:
        throw std::runtime_error("Missing implementation");
    }
}
