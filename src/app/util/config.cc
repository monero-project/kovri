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

#include "config.h"

#include <string>
#include <vector>

#include "core/util/log.h"
#include "crypto/rand.h"

namespace i2p {
namespace util {
namespace config {

namespace bpo = boost::program_options;
bpo::variables_map var_map;

bool ParseArgs(
    int argc,
    char* argv[]) {
  // Random generated port if none is supplied via CLI or config
  // See: i2p.i2p/router/java/src/net/i2p/router/transport/udp/UDPEndpoint.java
  // TODO(unassigned): move this elsewhere (outside of ParseArgs()) when possible
  size_t port = i2p::crypto::RandInRange<size_t>(9111, 30777);
  // Configuration files
  std::string kovri_config, tunnels_config;
  // Default visible option
  const std::string kovri_help =
    "\n- Read kovri.conf for details on cli/config options\n"
    "- Read tunnels.conf on how to configure tunnels\n"
    "- Below is a listing of all available options:";
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
        (i2p::util::filesystem::GetLogsPath() / "kovri_%1N.log").string()))
    ("log-levels", bpo::value<std::vector<std::string>>()->
                   // Note: we set a default value during validation and
                   // leave blank here to prevent bad_any_cast exception.
                   default_value(std::vector<std::string>(), "")->multitoken())
    ("kovriconf,c", bpo::value<std::string>(&kovri_config)->default_value(
        i2p::util::filesystem::GetFullPath("kovri.conf")))
    ("tunnelsconf,t", bpo::value<std::string>(&tunnels_config)->default_value(
        i2p::util::filesystem::GetFullPath("tunnels.conf")));

  bpo::options_description network("\nnetwork");
  network.add_options()
    ("v6,6", bpo::value<bool>()->default_value(false))
    ("floodfill,f", bpo::value<bool>()->default_value(false))
    ("bandwidth,b", bpo::value<std::string>()->default_value("L"))
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
  bpo::store(bpo::parse_command_line(argc, argv, cli_options), var_map);
  bpo::notify(var_map);
  // Parse config file after mapping command-line
  ParseConfigFile(kovri_config, config_options, var_map);
  // Set logging options
  if (!SetLoggingOptions())
    return false;
  if (var_map.count("help")) {
    std::cout << kovri_help << config_options; // we don't need to print .add(help)
    return false;
  }
  return true;
}

// TODO(unassigned): improve this function and use-case for it
void ParseConfigFile(
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

bool SetLoggingOptions() {
  namespace log = i2p::util::log;
  /**
   * TODO(unassigned): write custom validator for log-levels
   * so we can set values via config file.
   */
  // Test for valid log-levels input
  auto arg_levels = var_map["log-levels"].as<std::vector<std::string>>();
  auto global_levels = log::GetGlobalLogLevels();
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
  log::SetGlobalLogLevels(arg_levels);
  // Set other logging options
  log::SetOptionLogToConsole(var_map["log-to-console"].as<bool>());
  log::SetOptionLogToFile(var_map["log-to-file"].as<bool>());
  log::SetOptionLogFileName(var_map["log-file-name"].as<std::string>());
  return true;
}

}  // namespace config
}  // namespace util
}  // namespace i2p
