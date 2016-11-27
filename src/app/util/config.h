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

#ifndef SRC_APP_UTIL_CONFIG_H_
#define SRC_APP_UTIL_CONFIG_H_

#include <boost/filesystem/fstream.hpp>
#include <boost/program_options.hpp>

#include <iostream>
#include <map>
#include <string>

#include "core/version.h"
#include "filesystem.h"

namespace kovri {
namespace app {

/// @class Configuration
/// @brief Config file class for daemon
struct Configuration {
  /// @enum Key
  /// @brief Configuration const keys for tunnel config map
  enum struct Key : std::uint8_t {
    /// @var Type
    /// @brief Key for type of tunnel  (client/server/HTTP, etc.)
    Type,

    /// @var Client
    /// @brief Key for client tunnel
    Client,

    /// @var Server
    /// @brief Key for server tunnel
    Server,

    /// @var HTTP
    /// @brief Key for HTTP tunnel
    HTTP,

    /// @var Address
    /// @brief Key for local client listening address that you'll connect to
    /// @notes Should default to 127.0.0.1
    Address,

    /// @var Dest
    /// @brief Key for I2P hostname or .b32 address
    Dest,

    /// @var DestPort
    /// @brief Key for I2P destination port used in destination
    DestPort,

    /// @var Host
    /// @brief Key for IP address of our local server (that we host)
    /// @notes Should default to 127.0.0.1
    Host,

    /// @var InPort
    /// @brief Key for I2P service port. If unset, should be the same as 'port'
    InPort,

    /// @var ACL
    /// @brief Key for access control list of I2P addresses for server tunnel
    ACL,

    /// @var Port
    /// @brief Key for port of our listening client or server tunnel
    ///   (example: port 80 if you are hosting website)
    Port,

    /// @var Keys
    /// @brief Key for client tunnel identity
    ///   or file with LeaseSet of local service I2P address
    Keys,
  };

  /// @var TunnelConfig
  /// @brief Map of tunnel config keys to string const
  const std::map<Key, std::string> TunnelConfig {
    // Section types
    { Key::Type, "type" },
    { Key::Client, "client" },
    { Key::Server, "server" },
    { Key::HTTP, "http" },

    // Client-tunnel specific
    { Key::Address, "address" },
    { Key::Dest, "destination" },
    { Key::DestPort, "destinationport" },

    // Server-tunnel specific
    { Key::Host, "host" },
    { Key::InPort, "inport" },
    { Key::ACL, "accesslist" },

    // Tunnel-agnostic
    { Key::Port, "port" },
    { Key::Keys, "keys" },
  };
};

// TODO(unassigned): not ideal, we can create a useful class
/// @var VarMap
/// @brief Variable map for command-line and config file args
extern boost::program_options::variables_map VarMap;

/// @brief Parse command line arguments
/// @return False on failure
bool ParseArgs(
    int argc,
    char* argv[]);

/// @brief Parses configuration file and maps options
/// @param config File name
/// @param config_options Reference to instantiated options_description
/// @param var_map Reference to instantiated variables map
/// @notes command-line opts take precedence over config file opts)
void ParseConfigFile(
    std::string& config,
    boost::program_options::options_description& config_options,
    boost::program_options::variables_map& var_map);

/// @brief Sets logging options after validating user input
/// @return False on failure
/// @notes We set here instead of router context because we start logging
///   before router context and client context are initialized
bool SetLoggingOptions();

}  // namespace app
}  // namespace kovri

#endif  // SRC_APP_UTIL_CONFIG_H_
