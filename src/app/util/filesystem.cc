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

#include "filesystem.h"

#ifdef __MINGW32__
#include <minwindef.h>
#include <shlobj.h>
#endif

#include <string>

#include "config.h"

namespace i2p {
namespace util {
namespace filesystem {

std::string app_name("kovri");

void SetAppName(
    const std::string& name) {
  app_name = name;
}

std::string GetAppName() {
  return app_name;
}

boost::filesystem::path GetConfigFile() {
  boost::filesystem::path kovri_conf(
      i2p::util::config::var_map["kovriconf"].as<std::string>());
  if (!kovri_conf.is_complete())
        kovri_conf = GetDataPath() / kovri_conf;
  return kovri_conf;
}

boost::filesystem::path GetTunnelsConfigFile() {
  boost::filesystem::path tunnels_conf(
      i2p::util::config::var_map["tunnelsconf"].as<std::string>());
  if (!tunnels_conf.is_complete())
    tunnels_conf = GetDataPath() / tunnels_conf;
  return tunnels_conf;
}

boost::filesystem::path GetSU3CertsPath() {
  return GetDataPath() / "certificates" / "su3";
}

boost::filesystem::path GetSSLCertsPath() {
  return GetDataPath() / "certificates" / "ssl";
}

const boost::filesystem::path GetLogsPath() {
  return GetDataPath() / "logs";
}

std::string GetFullPath(
    const std::string& filename) {
  std::string full_path = GetDataPath().string();
#ifdef _WIN32
  full_path.append("\\");
#else
  full_path.append("/");
#endif
  full_path.append(filename);
  return full_path;
}

const boost::filesystem::path& GetDataPath() {
  static boost::filesystem::path path;
  path = GetDefaultDataPath();
  if (!boost::filesystem::exists(path)) {
    // Create data directory
    if (!boost::filesystem::create_directory(path)) {
      LogPrint(eLogError, "Filesystem: failed to create data directory!");
      path = "";
      return path;
    }
  }
  if (!boost::filesystem::is_directory(path))
    path = GetDefaultDataPath();
  return path;
}

boost::filesystem::path GetDefaultDataPath() {
  // Custom path, or default path:
  // Windows < Vista: C:\Documents and Settings\Username\Application Data\kovri
  // Windows >= Vista: C:\Users\Username\AppData\Roaming\kovri
  // Mac: ~/Library/Application Support/kovri
  // Unix: ~/.kovri
#ifdef KOVRI_CUSTOM_DATA_PATH
  return boost::filesystem::path(std::string(KOVRI_CUSTOM_DATA_PATH));
#else
#ifdef _WIN32
  // Windows
  char local_app_data[MAX_PATH];
  SHGetFolderPath(NULL, CSIDL_APPDATA, 0, NULL, local_app_data);
  return boost::filesystem::path(std::string(local_app_data) + "\\" + app_name);
#else
  boost::filesystem::path path_ret;
  char* home = getenv("HOME");
  if (home == NULL || strlen(home) == 0)
      path_ret = boost::filesystem::path("/");
  else
      path_ret = boost::filesystem::path(home);
#ifdef __APPLE__
  // Mac
  path_ret /= "Library/Application Support";
  create_directory(path_ret);
  return path_ret / app_name;
#else
  // Unix
  return path_ret / (std::string(".") + app_name);
#endif
#endif
#endif
}

}  // namespace filesystem
}  // namespace util
}  // namespace i2p
