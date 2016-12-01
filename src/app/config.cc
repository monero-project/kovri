/**                                                                                           //
 * Copyright (c) 2015-2016, The Kovri I2P Router Project                                      //
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

#include "app/instance.h"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/program_options.hpp>

#include <cstdint>
#include <stdexcept>
#include <memory>
#include <vector>

#include "core/crypto/rand.h"

#include "core/util/log.h"

namespace kovri {
namespace app {

namespace bpo = boost::program_options;

void Configuration::ParseKovriConfig() {
  // Random generated port if none is supplied via CLI or config
  // See: i2p.i2p/router/java/src/net/i2p/router/transport/udp/UDPEndpoint.java
  // TODO(unassigned): move this elsewhere (outside of ParseArgs()) when possible
  std::size_t port = kovri::core::RandInRange<std::size_t>(9111, 30777);
  // Configuration files
  std::string kovri_config, tunnels_config;
  // Default visible option
  bpo::options_description help("\nhelp");
  help.add_options()("help,h", "");  // Blank so we can use custom message above
  // Map options values from command-line and config
  bpo::options_description system("\nsystem");
  system.add_options()
    ("host", bpo::value<std::string>()->default_value("127.0.0.1"))
    ("port,p", bpo::value<int>()->default_value(port))
    ("daemon,d", bpo::value<bool>()->default_value(false))
    ("service,s", bpo::value<std::string>()->default_value(""))
    ("log-to-console", bpo::value<bool>()->default_value(true))
    ("log-to-file", bpo::value<bool>()->default_value(true))
    ("log-file-name", bpo::value<std::string>()->default_value(
        (kovri::core::GetLogsPath() / "kovri_%1N.log").string()))  // TODO(anonimal): #330
    ("log-levels", bpo::value<std::vector<std::string>>()->
                   // Note: we set a default value during validation and
                   // leave blank here to prevent bad_any_cast exception.
                   default_value(std::vector<std::string>(), "")->multitoken())
    ("kovriconf,c", bpo::value<std::string>(&kovri_config)->default_value(
        kovri::core::GetFullPath("kovri.conf")))  // TODO(anonimal): #330
    ("tunnelsconf,t", bpo::value<std::string>(&tunnels_config)->default_value(
        kovri::core::GetFullPath("tunnels.conf")));  // TODO(anonimal): #330

  bpo::options_description network("\nnetwork");
  network.add_options()
    ("v6,6", bpo::value<bool>()->default_value(false))
    ("floodfill,f", bpo::value<bool>()->default_value(false))
    ("bandwidth,b", bpo::value<std::string>()->default_value("L"))
    ("enable-ssu", bpo::value<bool>()->default_value(true))
    ("enable-ntcp", bpo::value<bool>()->default_value(true))
    ("reseed-from,r", bpo::value<std::string>()->default_value(""))
    ("reseed-skip-ssl-check", bpo::value<bool>()->default_value(false));

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
      bpo::command_line_parser(m_Args).options(cli_options).run(), m_KovriConfig);
  bpo::notify(m_KovriConfig);

  // TODO(anonimal): we want to be able to reload config file without original
  // cli args overwriting any *new* config file options

  // Parse config file after mapping command-line
  ParseKovriConfigFile(kovri_config, config_options, m_KovriConfig);
  // Set logging options
  if (!SetLoggingOptions())
    throw std::runtime_error("Configuration: could not set logging options");
  if (m_KovriConfig.count("help")) {
    std::cout << config_options << std::endl;
    throw std::runtime_error("for more details, see user-guide documentation");
  }
}

// TODO(unassigned): improve this function and use-case
void Configuration::ParseKovriConfigFile(
    std::string& file,
    bpo::options_description& options,
    bpo::variables_map& var_map) {
  std::ifstream filename(file.c_str());
  if (!filename) {
    std::cout << "Could not open " << file << "!\n";
  } else {
    bpo::store(bpo::parse_config_file(filename, options), var_map);
    bpo::notify(var_map);
  }
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
  for (auto& section : pt) {
    TunnelsConfigSection tunnel;
    tunnel.name = section.first;
    const auto& value = section.second;
    try {
      tunnel.type = value.get<std::string>(GetTunnelParam(Key::Type));
      // Test which type of tunnel (client or server)
      if (tunnel.type == GetTunnelParam(Key::Client)) {
        tunnel.dest = value.get<std::string>(GetTunnelParam(Key::Dest));
        tunnel.port = value.get<std::uint16_t>(GetTunnelParam(Key::Port));
        // Sets default if missing in file
        tunnel.address = value.get<std::string>(GetTunnelParam(Key::Address), "127.0.0.1");
        tunnel.keys = value.get<std::string>(GetTunnelParam(Key::Keys), "");
        tunnel.dest_port = value.get<std::uint16_t>(GetTunnelParam(Key::DestPort), 0);
      } else if (tunnel.type == GetTunnelParam(Key::Server)
                || tunnel.type == GetTunnelParam(Key::HTTP)) {
        tunnel.host = value.get<std::string>(GetTunnelParam(Key::Host));
        tunnel.port = value.get<std::uint16_t>(GetTunnelParam(Key::Port));
        tunnel.keys = value.get<std::string>(GetTunnelParam(Key::Keys));
        // Sets default if missing in file
        tunnel.in_port = value.get<std::uint16_t>(GetTunnelParam(Key::InPort), 0);
        tunnel.access_list = value.get<std::string>(GetTunnelParam(Key::ACL), "");
      } else {
        throw std::runtime_error(
            "Configuration: unknown tunnel type="
            + tunnel.type + " of " + tunnel.name + " in " + file);
	return;
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

bool Configuration::SetLoggingOptions() {
  namespace core = kovri::core;
  /**
   * TODO(unassigned): write custom validator for log-levels
   * so we can set values via config file.
   */
  // Test for valid log-levels input
  auto arg_levels = m_KovriConfig["log-levels"].as<std::vector<std::string>>();
  auto global_levels = core::GetGlobalLogLevels();
  if (arg_levels.size()) {
    if (arg_levels.size() > global_levels.size()) {
      std::cout << "Invalid number of log levels. Maximum allowed: "
                << global_levels.size() << std::endl;
      return false;
    }
    // Verify validity of log levels
    for (auto& level : arg_levels) {
      auto result = global_levels.find(level);
      if (result == global_levels.end()) {
        std::cout << "Invalid log-level(s). See help for options" << std::endl;
        return false;
      }
    }
  } else {
    // Set default log-levels if none present
    for (auto& level : global_levels)
      arg_levels.push_back(level.first);
  }
  // Set new global log-levels
  core::SetGlobalLogLevels(arg_levels);
  // Set other logging options
  core::SetOptionLogToConsole(m_KovriConfig["log-to-console"].as<bool>());
  // TODO(unassigned): the following daemon test is a HACK to ensure that
  // log-to-console is enabled in daemon mode (or else we'll boost.log segfault)
  // See #469
  if (m_KovriConfig["daemon"].as<bool>())
    core::SetOptionLogToConsole(true);
  core::SetOptionLogToFile(m_KovriConfig["log-to-file"].as<bool>());
  core::SetOptionLogFileName(m_KovriConfig["log-file-name"].as<std::string>());
  return true;
}

const std::string Configuration::GetTunnelParam(Key key) {
  switch (key) {
    // Section types
    case Key::Type:
      return "type";
      break;
    case Key::Client:
      return "client";
      break;
    case Key::Server:
      return "server";
      break;
    case Key::HTTP:
      return "http";
      break;
    // Client-tunnel specific
    case Key::Address:
      return "address";
      break;
    case Key::Dest:
      return "destination";
      break;
    case Key::DestPort:
      return "destinationport";
      break;
    // Server-tunnel specific
    case Key::Host:
      return "host";
      break;
    case Key::InPort:
      return "inport";
      break;
    case Key::ACL:
      return "accesslist";
      break;
    // Tunnel-agnostic
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
