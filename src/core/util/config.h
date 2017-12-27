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

#ifndef SRC_CORE_UTIL_CONFIG_H_
#define SRC_CORE_UTIL_CONFIG_H_

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "core/util/exception.h"
#include "core/util/filesystem.h"

namespace kovri
{
namespace core
{
/// @class Configuration
/// @brief Core configuration implementation
class Configuration
{
 public:
  /// @param args Taken as standard argv arguments (element = "space delimited" arg)
  explicit Configuration(
      const std::vector<std::string>& args = std::vector<std::string>());

  ~Configuration();

  /// @brief Parse config arguments
  void ParseConfig();

  /// @details This configures/sets up the global path.
  /// @warning Kovri config must first be parsed and this must be called before anything else
  void SetupGlobalPath();

  /// @brief Tests/Configures AES-NI if available
  /// @warning Kovri config must first be parsed
  void SetupAESNI();

  /// @brief Gets complete path + name of core config
  /// @return Boost filesystem path of file
  /// @warning Config file must first be parsed
  const boost::filesystem::path GetConfigPath() const
  {
    std::string kovri_config = m_Map["kovriconf"].defaulted()
                                   ? "kovri.conf"
                                   : m_Map["kovriconf"].as<std::string>();
    boost::filesystem::path file(kovri_config);
    if (!file.is_complete())
      file = core::GetPath(core::Path::Config) / file;
    return file;
  }

  /// @brief Gets core config variable map
  /// @return Reference to kovri config member variable map
  const boost::program_options::variables_map& GetMap() const noexcept
  {
    return m_Map;
  }

 private:
  /// @brief Exception dispatcher
  core::Exception m_Exception;

  /// @brief Vector of string arguments passed to configuration
  std::vector<std::string> m_Args;

  /// @brief Variable map for command-line and core config file data
  boost::program_options::variables_map m_Map{};

 private:
  // TODO(unassigned): improve this function and use-case
  /// @brief Parses configuration file and maps options
  /// @param config File name
  /// @param config_options Reference to instantiated options_description
  /// @param var_map Reference to instantiated variables map
  /// @notes command-line opts take precedence over config file opts
  void ParseConfigFile(
      const std::string& config,
      const boost::program_options::options_description& config_options,
      boost::program_options::variables_map& var_map);
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_UTIL_CONFIG_H_
