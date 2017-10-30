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

#ifndef SRC_CLIENT_UTIL_CONFIG_H_
#define SRC_CLIENT_UTIL_CONFIG_H_

#include "core/util/config.h"

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "client/tunnel.h"

#include "core/util/exception.h"
#include "core/util/filesystem.h"

namespace kovri
{
namespace client
{
/// @enum Key
/// @brief Tunnels config attribute key for const tunnel param string
enum struct Key : std::uint8_t
{
  /// @var Type
  /// @brief Key for type of tunnel  (client/server/HTTP, etc.)
  Type,
  /// @var Client
  /// @brief Key for client tunnel
  Client,
  /// @var IRC
  /// @brief Key for IRC tunnel
  IRC,
  /// @var Server
  /// @brief Key for server tunnel
  Server,
  /// @var HTTP
  /// @brief Key for HTTP tunnel
  HTTP,
  /// @var Address
  /// @brief Key for local listening address that you or service connects to
  /// @notes Should default to 127.0.0.1
  Address,
  /// @var Dest
  /// @brief Key for I2P hostname or .b32 address
  Dest,
  /// @var DestPort
  /// @brief Key for I2P destination port used in destination
  DestPort,
  /// @var InPort
  /// @brief Key for I2P service port. If unset, should be the same as 'port'
  InPort,
  /// @var Whitelist
  /// @brief Key for Access Control whitelist of I2P addresses for server tunnel
  Whitelist,
  /// @var Blackslist
  /// @brief Key for Access Control blacklist of I2P addresses for server tunnel
  Blacklist,
  /// @var Port
  /// @brief Key for port of our listening client or server tunnel
  ///   (example: port 80 if you are hosting website)
  Port,
  /// @var Keys
  /// @brief Key for client tunnel identity
  ///   or file with LeaseSet of local service I2P address
  Keys,
};

/// @class Configuration
/// @brief Client configuration implementation
/// @note Core configuration SHOULD be initialized first
class Configuration
{
 public:
  explicit Configuration(const core::Configuration& core_config);

  // TODO(anonimal): overload ctor
  ~Configuration();

  /// @brief Parses tunnel configuration file
  /// @warning Logging must be setup to see any debug output
  void ParseConfig();

  /// @brief Gets pre-defined tunnel attribute from tunnel config
  /// @param key Key for tunnels config attribute
  const std::string GetAttribute(Key key) const;

  /// @brief Gets tunnels config member
  /// @return Reference to tunnels attributes vector member
  const std::vector<TunnelAttributes>& GetParsedTunnelsConfig() const noexcept
  {
    return m_TunnelsConfig;
  }

  /// @brief Gets complete path + name of tunnels config
  /// @return Boost filesystem path of file
  /// @warning Config file must first be parsed
  const boost::filesystem::path GetConfigPath() const
  {
    std::string tunnels_config =
        m_CoreConfig.GetMap()["tunnelsconf"].defaulted()
            ? "tunnels.conf"
            : m_CoreConfig.GetMap()["tunnelsconf"].as<std::string>();
    boost::filesystem::path file(tunnels_config);
    if (!file.is_complete())
      file = core::GetConfigPath() / file;
    return file;
  }

  /// @brief Get core configuration object
  const core::Configuration& GetCoreConfig() const noexcept
  {
    return m_CoreConfig;
  }

 private:
  /// @brief Exception dispatcher
  core::Exception m_Exception;

  /// @var m_TunnelsConfig
  /// @brief Vector of all sections in a tunnel configuration
  std::vector<TunnelAttributes> m_TunnelsConfig{};

  /// @brief Core configuration
  core::Configuration m_CoreConfig;
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_UTIL_CONFIG_H_
