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

#include "app/instance.h"  // includes "app/config.h"

// Config parsing
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

// Logging
#include <boost/core/null_deleter.hpp>
#include <boost/log/expressions/formatters/date_time.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>

#include <stdexcept>
#include <memory>

#include "client/util/parse.h"

#include "core/crypto/aes.h"
#include "core/crypto/rand.h"

// TODO(anonimal): instance configuration should probably be moved to libcore

namespace kovri {
namespace app {

namespace bpo = boost::program_options;

void Configuration::ParseKovriConfig() {
  // Default visible option
  bpo::options_description help("\nhelp");
  help.add_options()("help,h", "");  // Blank so we can use custom message above
  // Map options values from command-line and config
  bpo::options_description system("\nsystem");
  system.add_options()(
      "host", bpo::value<std::string>()->default_value("127.0.0.1"))(
      "port,p", bpo::value<int>()->default_value(0))(
      "data-dir",
      bpo::value<std::string>()
          ->default_value(kovri::core::GetDefaultDataPath().string())
          ->value_name("path"))(
      "daemon,d", bpo::value<bool>()->default_value(false)->value_name("bool"))(
      "service,s", bpo::value<std::string>()->default_value(""))(
      "log-to-console",
      bpo::value<bool>()->default_value(true)->value_name("bool"))(
      "log-to-file",
      bpo::value<bool>()->default_value(true)->value_name("bool"))(
      "log-file-name",
      bpo::value<std::string>()->default_value("")->value_name("path"))(
      // TODO(anonimal): use only 1 log file?
      // Log levels
      // 0 = fatal
      // 1 = error fatal
      // 2 = warn error fatal
      // 3 = info warn error fatal
      // 4 = debug info warn error fatal
      // 5 = trace debug info warn error fatal
      "log-level",
      bpo::value<std::uint16_t>()->default_value(3))(
      "log-auto-flush",
      bpo::value<bool>()->default_value(false)->value_name("bool"))(
      "kovriconf,c",
      bpo::value<std::string>()->default_value("")->value_name("path"))(
      "tunnelsconf,t",
      bpo::value<std::string>()->default_value("")->value_name("path"));
  // This is NOT our default values for port, log-file-name, kovriconf and tunnelsconf

  bpo::options_description network("\nnetwork");
  network.add_options()(
      "v6,6", bpo::value<bool>()->default_value(false)->value_name("bool"))(
      "floodfill,f",
      bpo::value<bool>()->default_value(false)->value_name("bool"))(
      "bandwidth,b", bpo::value<std::string>()->default_value("L"))(
      "enable-ssu",
      bpo::value<bool>()->default_value(true)->value_name("bool"))(
      "enable-ntcp",
      bpo::value<bool>()->default_value(true)->value_name("bool"))(
      "reseed-from,r", bpo::value<std::string>()->default_value(""))(
      "enable-ssl",
      bpo::value<bool>()->default_value(true)->value_name("bool"))(
      "disable-su3-verification",
      bpo::value<bool>()->default_value(false)->value_name("bool"));

  bpo::options_description client("\nclient");
  client.add_options()
    ("httpproxyport", bpo::value<int>()->default_value(4446))
    ("httpproxyaddress", bpo::value<std::string>()->default_value("127.0.0.1"))
    ("socksproxyport", bpo::value<int>()->default_value(4447))
    ("socksproxyaddress", bpo::value<std::string>()->default_value("127.0.0.1"))
    ("proxykeys", bpo::value<std::string>()->default_value(""))
    ("i2pcontrolport", bpo::value<int>()->default_value(0))
    ("i2pcontroladdress", bpo::value<std::string>()->default_value("127.0.0.1"))
    ("i2pcontrolpassword", bpo::value<std::string>()->default_value("itoopie"));
    //("reseed-to", bpo::value<std::string>()->default_value(""),
    // "Creates a reseed file for you to share\n"
    // "Example: ~/path/to/new/i2pseeds.su3\n")
  // Available command-line options
  bpo::options_description cli_options;
  cli_options
    .add(help)
    .add(system)
    .add(network)
    .add(client);
  // Available config file options
  bpo::options_description config_options;
  config_options
    .add(system)
    .add(network)
    .add(client);
  // Map and store command-line options
  bpo::store(
      bpo::command_line_parser(m_Args).options(cli_options).run(),
      m_KovriConfig);
  bpo::notify(m_KovriConfig);
  // Help options
  if (m_KovriConfig.count("help")) {
    std::cout << config_options << std::endl;
    throw std::runtime_error("for more details, see user-guide or config file");
  }
  // Parse config file after mapping command-line
  // TODO(anonimal): we want to be able to reload config file without original
  // cli args overwriting any *new* config file options
  SetupGlobalPath();
  std::string kovri_config = GetConfigFile().string();
  ParseKovriConfigFile(kovri_config, config_options, m_KovriConfig);
}

// TODO(unassigned): improve this function and use-case
void Configuration::ParseKovriConfigFile(
    const std::string& file,
    const bpo::options_description& options,
    bpo::variables_map& var_map) {
  std::ifstream filename(file.c_str());
  if (!filename)
    throw std::runtime_error("Could not open " + file + "!\n");
  bpo::store(bpo::parse_config_file(filename, options), var_map);
  bpo::notify(var_map);
  // Check host syntax
  boost::system::error_code ec;
  boost::asio::ip::address::from_string(
      m_KovriConfig["host"].as<std::string>(), ec);
  if (ec)
    throw std::runtime_error("Invalid host: " + ec.message());
  // Ensure port in valid range
  if (!m_KovriConfig["port"].defaulted())
    {
      int port = m_KovriConfig["port"].as<int>();
      if ((port < core::RouterInfo::MinPort)
          || (port > core::RouterInfo::MaxPort))
        throw std::runtime_error(
            "Port not in range [" + std::to_string(core::RouterInfo::MinPort)
            + ","
            + std::to_string(core::RouterInfo::MaxPort)
            + "], see user-guide or config file");
    }
}

void Configuration::SetupGlobalPath()
{
  context.SetCustomDataDir(
      m_KovriConfig["data-dir"].defaulted()
          ? kovri::core::GetDefaultDataPath().string()
          : m_KovriConfig["data-dir"].as<std::string>());
}

void Configuration::SetupAESNI() {
  // TODO(anonimal): implement user-option to disable AES-NI auto-detection
  kovri::core::SetupAESNI();
}

void Configuration::ParseTunnelsConfig() {
  auto file = GetTunnelsConfigFile().string();
  boost::property_tree::ptree pt;
  // Read file
  try {
    boost::property_tree::read_ini(file, pt);
  } catch (const std::exception& ex) {
    throw std::runtime_error(
        "Configuration: can't read " + file + ": " + ex.what());
    return;
  } catch (...) {
    throw std::runtime_error(
        "Configuration: can't read " + file + ": unknown exception");
    return;
  }
  // Parse on a per-section basis, store in tunnels config vector
  m_TunnelsConfig.clear();
  for (auto& section : pt) {
    kovri::client::TunnelAttributes tunnel{};
    try {
      // Get tunnel name and container for remaining attributes
      tunnel.name = section.first;
      const auto& value = section.second;
      // Get remaining attributes
      tunnel.type = value.get<std::string>(GetAttribute(Key::Type));
      tunnel.address = value.get<std::string>(GetAttribute(Key::Address), "127.0.0.1");
      tunnel.port = value.get<std::uint16_t>(GetAttribute(Key::Port));
      // Test which type of tunnel (client or server), add unique attributes
      if (tunnel.type == GetAttribute(Key::Client)
          || tunnel.type == GetAttribute(Key::IRC)) {
        tunnel.dest = value.get<std::string>(GetAttribute(Key::Dest));
        tunnel.dest_port = value.get<std::uint16_t>(GetAttribute(Key::DestPort), 0);
        tunnel.keys = value.get<std::string>(GetAttribute(Key::Keys), "");
        // Parse for CSV destinations + dest:port, then set appropriately
        ParseClientDestination(&tunnel);
        // Check for conflicting port
        if (std::find_if(
                m_TunnelsConfig.begin(),
                m_TunnelsConfig.end(),
                [&tunnel](
                    kovri::client::TunnelAttributes const& tunnel_attribute) {
                  return tunnel.port == tunnel_attribute.port;
                })
            != m_TunnelsConfig.end())
          {
            LOG(error) << "Config: " << tunnel.name
                       << " will not be loaded, conflicting port";
            continue;
          }
      } else if (tunnel.type == GetAttribute(Key::Server)
                || tunnel.type == GetAttribute(Key::HTTP)) {
        tunnel.in_port = value.get<std::uint16_t>(GetAttribute(Key::InPort), 0);
        tunnel.keys = value.get<std::string>(GetAttribute(Key::Keys));  // persistent private key
        // Test/Get/Set for ACL
        auto white = value.get<std::string>(GetAttribute(Key::Whitelist), "");
        auto black = value.get<std::string>(GetAttribute(Key::Blacklist), "");
        // Ignore blacklist if whitelist is given
        if (!white.empty()) {
          tunnel.acl.list = white;
          tunnel.acl.is_white = true;
        } else if (!black.empty()) {
          tunnel.acl.list = black;
          tunnel.acl.is_black = true;
        }
      } else {
        throw std::runtime_error(
            "Configuration: unknown tunnel type="
            + tunnel.type + " of " + tunnel.name + " in " + file);
      }
    } catch (const std::exception& ex) {
      throw std::runtime_error(
          "Configuration: can't read tunnel "
          + tunnel.name + " params: " + ex.what());
    } catch (...) {
      throw std::runtime_error(
          "Configuration: can't read tunnel "
          + tunnel.name + " unknown exception");
    }
    // Save section for later client insertion
    m_TunnelsConfig.push_back(tunnel);
  }
}

const std::string Configuration::GetAttribute(Key key) const {
  switch (key) {
    // Section types
    case Key::Type:
      return "type";
      break;
    case Key::Client:
      return "client";
      break;
    case Key::IRC:
      return "irc";
      break;
    case Key::Server:
      return "server";
      break;
    case Key::HTTP:
      return "http";
      break;
    // Client-tunnel specific
    case Key::Dest:
      return "dest";
      break;
    case Key::DestPort:
      return "dest_port";
      break;
    // Server-tunnel specific
    case Key::InPort:
      return "in_port";
      break;
    case Key::Whitelist:
      return "white_list";
      break;
    case Key::Blacklist:
      return "black_list";
      break;
    // Tunnel-agnostic
    case Key::Address:
      return "address";
      break;
    case Key::Port:
      return "port";
      break;
    case Key::Keys:
      return "keys";
      break;
    default:
      return "";  // not needed (avoids nagging -Wreturn-type)
      break;
  };
}

}  // namespace app
}  // namespace kovri
