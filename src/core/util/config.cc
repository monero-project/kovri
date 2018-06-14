/**                                                                                           //
 * Copyright (c) 2015-2018, The Kovri I2P Router Project                                      //
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

#include "core/util/config.h"

// Logging
#include <boost/core/null_deleter.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/expressions/formatters/date_time.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>

#include <memory>
#include <stdexcept>

#include "core/router/context.h"
#include "core/router/info.h"

#include "core/crypto/aes.h"  // For AES-NI detection/initialization
#include "core/crypto/rand.h"

namespace kovri
{
namespace core
{
namespace bpo = boost::program_options;

/// @brief Safely initialize exception member
/// @details Complies with CERT secure coding rule ERR53-CPP, and resolves build warnings
/// @notes Initializing the member with class name was/is a hack until our logger is improved
core::Exception Configuration::m_Exception("Configuration");

Configuration::Configuration(const std::vector<std::string>& args) try
    : m_Args(args)
  {
    ParseConfig();
  }
catch (...)
  {
    m_Exception.Dispatch();
  }

Configuration::~Configuration() {}

void Configuration::ParseConfig()
{
  // Default visible option
  bpo::options_description help("\nhelp");
  help.add_options()("help,h", "");  // Blank so we can use custom message above
  // Map options values from command-line and config
  bpo::options_description system("\nsystem");
  system.add_options()(
      "host",
        bpo::value<ListParameter<std::string, 2>>()->default_value(
            ListParameter<std::string, 2>("127.0.0.1")))(  // TODO(anonimal): fix default host
      "port,p", bpo::value<int>()->default_value(0))(
      "data-dir",
      bpo::value<std::string>()
          ->default_value(core::GetPath(core::Path::DefaultData).string())
          ->value_name("path"))(
      "service,s", bpo::value<std::string>()->default_value(""))(

      "enable-daemon,d",
      bpo::bool_switch()->default_value(false))(

      "disable-console-log",
      bpo::bool_switch()->default_value(false))(

      "disable-file-log",
      bpo::bool_switch()->default_value(false))(

      "disable-color-log",
      bpo::bool_switch()->default_value(false))(

      "enable-auto-flush-log",
      bpo::bool_switch()->default_value(false))(

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

      "log-file-name",
      bpo::value<std::string>()->default_value("")->value_name("path"))(

      "kovriconf,c",
      bpo::value<std::string>()->default_value("")->value_name("path"))(

      "tunnelsconf,t",
      bpo::value<std::string>()->default_value("")->value_name("path"));
  // This is NOT our default values for port, log-file-name, kovriconf and tunnelsconf

  bpo::options_description network("\nnetwork");
  network.add_options()(
      "enable-upnp",
      bpo::bool_switch()->default_value(false))(

      "enable-ipv6",
      bpo::bool_switch()->default_value(false))(

      "enable-floodfill",
      bpo::bool_switch()->default_value(false))(

      // TODO(anonimal): refine bandwidth + update packaged default config file
      "bandwidth,b",
      bpo::value<std::string>()->default_value("L"))(

      "disable-ssu",
      bpo::bool_switch()->default_value(false))(

      "disable-ntcp",
      bpo::bool_switch()->default_value(false))(

      "reseed-from,r", bpo::value<std::string>()->default_value(""))(

      "disable-https",
      bpo::bool_switch()->default_value(false))(

      "disable-su3-verification",
      bpo::bool_switch()->default_value(false));

  bpo::options_description client("\nclient");
  client.add_options()("httpproxyport", bpo::value<int>()->default_value(4446))(
      "httpproxyaddress",
      bpo::value<std::string>()->default_value("127.0.0.1"))(
      "socksproxyport", bpo::value<int>()->default_value(4447))(
      "socksproxyaddress",
      bpo::value<std::string>()->default_value("127.0.0.1"))(
      "proxykeys", bpo::value<std::string>()->default_value(""))(
      "i2pcontrolport", bpo::value<int>()->default_value(0))(
      "i2pcontroladdress",
      bpo::value<std::string>()->default_value("127.0.0.1"))(
      "i2pcontrolpassword",
      bpo::value<std::string>()->default_value("itoopie"));
  //("reseed-to", bpo::value<std::string>()->default_value(""),
  // "Creates a reseed file for you to share\n"
  // "Example: ~/path/to/new/i2pseeds.su3\n")
  // Available command-line options
  bpo::options_description cli_options;
  cli_options.add(help).add(system).add(network).add(client);
  // Available config file options
  bpo::options_description config_options;
  config_options.add(system).add(network).add(client);
  // Map and store command-line options
  bpo::store(
      bpo::command_line_parser(m_Args).options(cli_options).run(), m_Map);
  bpo::notify(m_Map);
  // Help options
  if (m_Map.count("help"))
    {
      LOG(info) << config_options;
      throw std::runtime_error(
          "for more details, see user-guide or config file");
    }
  // Parse config file after mapping command-line
  // TODO(anonimal): we want to be able to reload config file without original
  // cli args overwriting any *new* config file options
  SetupGlobalPath();
  ParseConfigFile(GetConfigPath().string(), config_options, m_Map);
}

// TODO(unassigned): improve this function and use-case
void Configuration::ParseConfigFile(
    const std::string& file,
    const bpo::options_description& options,
    bpo::variables_map& var_map)
{
  std::ifstream filename(file.c_str());
  if (!filename)
    throw std::runtime_error("Could not open " + file + "!\n");

  bpo::store(bpo::parse_config_file(filename, options), var_map);
  bpo::notify(var_map);

  auto hosts = m_Map["host"].as<ListParameter<std::string, 2>>();
  // TODO(anonimal): move to sanity check function for namespace use
  // Check host syntax

  // Ensure host parameter is what we expect.
  // TODO(brbzull): If default?
  if (!hosts.IsExpectedSize())
    throw std::invalid_argument(
        "host parameter contains more than expected(2)");

  // We will store the first address just after we run the basic validation.
  boost::optional<boost::asio::ip::address> first_address;
  bool valid_host = true;
  for (const auto& host : hosts.values)
    {
      boost::system::error_code ec;
      auto address = boost::asio::ip::address::from_string(host, ec);
      if (ec)
        {
          valid_host = false;
          break;
        }

      // only for the second host.
      if (first_address)
        {
          // same one?
          if (*first_address == address)
            {
              valid_host = false;
              break;
            }

          // should be different.
          if (first_address.get().is_v4() == address.is_v4()
              || first_address.get().is_v6() == address.is_v6())
            {
              valid_host = false;
              break;
            }
        }
      else
        first_address = std::move(address);
    }

  if (!valid_host)
    throw std::invalid_argument("Invalid host parameter");
  // TODO(brbzull): Check for rfc1918.

  // Ensure port in valid range
  if (!m_Map["port"].defaulted())
    {
      int port = m_Map["port"].as<int>();
      if ((port < RouterInfo::MinPort) || (port > RouterInfo::MaxPort))
        throw std::runtime_error(
            "Port not in range [" + std::to_string(RouterInfo::MinPort) + ","
            + std::to_string(RouterInfo::MaxPort)
            + "], see user-guide or config file");
    }

  // Ensure valid transport
  if (m_Map["disable-ntcp"].as<bool>() && m_Map["disable-ssu"].as<bool>())
    throw std::invalid_argument("at least one transport is required");
}

void Configuration::SetupGlobalPath()
{
  context.SetCustomDataDir(
      m_Map["data-dir"].defaulted()
          ? core::GetPath(core::Path::DefaultData).string()
          : m_Map["data-dir"].as<std::string>());
}

void Configuration::SetupAESNI()
{
  // TODO(anonimal): implement user-option to disable AES-NI auto-detection
  core::SetupAESNI();
}

}  // namespace core
}  // namespace kovri
