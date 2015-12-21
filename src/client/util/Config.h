/**
 * Copyright (c) 2015-2016, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SRC_CLIENT_UTIL_CONFIG_H_
#define SRC_CLIENT_UTIL_CONFIG_H_

#include <boost/filesystem/fstream.hpp>
#include <boost/program_options.hpp>

#include <string>
#include <iostream>

#include "core/Version.h"
#include "Filesystem.h"

namespace i2p {
namespace util {
namespace config {

// Our configuration files
extern std::string kovriConfig, tunnelsConfig;

// Config option descriptions
extern boost::program_options::options_description confOpts;

// Variable map for CLI and conf args
extern boost::program_options::variables_map varMap;

/**
 * Note: CLI args override config file args but
 * args that are not overridden will stay mapped
 */
void ParseConfigFile(
    std::string& kovriConfig,
    boost::program_options::options_description& confOpts,
    boost::program_options::variables_map& varMap);

/**
 * @return 1 on failure/help, 0 on success
 */
bool ParseArgs(int argc, char* argv[]);

}  // namespace config
}  // namespace util
}  // namespace i2p

#endif  // SRC_CLIENT_UTIL_CONFIG_H_
