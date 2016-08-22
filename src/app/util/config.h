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

#include <string>
#include <iostream>

#include "core/version.h"
#include "filesystem.h"

namespace i2p {
namespace util {

const char I2P_TUNNELS_SECTION_TYPE[] = "type";
const char I2P_TUNNELS_SECTION_TYPE_CLIENT[] = "client";
const char I2P_TUNNELS_SECTION_TYPE_SERVER[] = "server";
const char I2P_TUNNELS_SECTION_TYPE_HTTP[] = "http";
const char I2P_CLIENT_TUNNEL_PORT[] = "port";
const char I2P_CLIENT_TUNNEL_ADDRESS[] = "address";
const char I2P_CLIENT_TUNNEL_DESTINATION[] = "destination";
const char I2P_CLIENT_TUNNEL_KEYS[] = "keys";
const char I2P_CLIENT_TUNNEL_DESTINATION_PORT[] = "destinationport";
const char I2P_SERVER_TUNNEL_HOST[] = "host";
const char I2P_SERVER_TUNNEL_PORT[] = "port";
const char I2P_SERVER_TUNNEL_KEYS[] = "keys";
const char I2P_SERVER_TUNNEL_INPORT[] = "inport";
const char I2P_SERVER_TUNNEL_ACCESS_LIST[] = "accesslist";

namespace config {

/// @var var_map
/// @brief Variable map for command-line and config file args
extern boost::program_options::variables_map var_map;

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

}  // namespace config
}  // namespace util
}  // namespace i2p

#endif  // SRC_APP_UTIL_CONFIG_H_
