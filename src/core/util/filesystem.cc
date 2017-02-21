/**                                                                                           //
 * Copyright (c) 2013-2017, The Kovri I2P Router Project                                      //
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

#include "core/util/filesystem.h"

#ifdef __MINGW32__
#define WIN32_LEAN_AND_MEAN
#include <minwindef.h>
#include <shlobj.h>
#endif

#include <string>

#include "core/router/context.h"

#include "core/util/log.h"

namespace kovri {
namespace core {

/// @var g_AppName
/// @brief Global name for data directory on all platforms
std::string g_AppName("kovri");

const boost::filesystem::path EnsurePath(
    const boost::filesystem::path& path) {
  if (!boost::filesystem::exists(path)) {
    boost::system::error_code ec;
    if (!boost::filesystem::create_directory(path, ec)) {
      throw std::runtime_error(
          "Filesystem: failed to create " + std::string(path.string() + ": " + ec.message()));
    }
  }
  return path;
}

/// TODO(anonimal): we can refactor all path getter functions, consolidate with key

/// Client paths

const boost::filesystem::path GetSU3CertsPath() {
  return GetClientPath() / "certificates" / "su3";
}

const boost::filesystem::path GetSSLCertsPath() {
  return GetClientPath() / "certificates" / "ssl";
}

const boost::filesystem::path GetAddressBookPath() {
  return GetClientPath() / "address_book";
}

const boost::filesystem::path GetClientKeysPath() {
  return GetClientPath() / "keys";
}

/// Core paths

const boost::filesystem::path GetNetDbPath() {
  return GetCorePath() / "network_database";
}

const boost::filesystem::path GetProfilesPath() {
  return GetCorePath() / "peer_profiles";
}

/// Data paths

const boost::filesystem::path GetLogsPath() {
  return GetDataPath() / "logs";
}

const boost::filesystem::path GetConfigPath() {
  return GetDataPath() / "config";
}

const boost::filesystem::path GetCorePath() {
  return GetDataPath() / "core";
}

const boost::filesystem::path GetClientPath() {
  return GetDataPath() / "client";
}

/// Root data directory

const boost::filesystem::path& GetDataPath() {
  static boost::filesystem::path path =
      context.GetCustomDataDir().empty()
          ? GetDefaultDataPath()
          : boost::filesystem::path(context.GetCustomDataDir());
  if (!boost::filesystem::exists(path)) {
    // Create data directory
    if (!boost::filesystem::create_directory(path)) {
      LOG(error) << "Filesystem: failed to create data directory!";
      path = "";
      return path;
    }
  }
  if (!boost::filesystem::is_directory(path))
    path = context.GetCustomDataDir().empty()
               ? GetDefaultDataPath()
               : boost::filesystem::path(context.GetCustomDataDir());
  return path;
}

boost::filesystem::path GetDefaultDataPath() {
  // Custom path, or default path:
  // Windows < Vista: C:\Documents and Settings\Username\Application Data\Kovri
  // Windows >= Vista: C:\Users\Username\AppData\Roaming\Kovri
  // Mac: ~/Library/Application Support/Kovri
  // Unix: ~/.kovri
#ifdef KOVRI_CUSTOM_DATA_PATH
  return boost::filesystem::path(std::string(KOVRI_CUSTOM_DATA_PATH));
#else
#ifdef _WIN32
  // Windows
  char local_app_data[MAX_PATH];
  SHGetFolderPath(NULL, CSIDL_APPDATA, 0, NULL, local_app_data);
  return boost::filesystem::path(std::string(local_app_data) + "\\" + g_AppName);
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
  return path_ret / g_AppName;
#else
  // Unix
  return path_ret / (std::string(".") + g_AppName);
#endif
#endif
#endif
}

}  // namespace core
}  // namespace kovri
