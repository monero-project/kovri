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

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <minwindef.h>
#include <shlobj.h>
#endif

#include <tuple>

#include "core/router/context.h"

namespace kovri {
namespace core {

StringStream::StringStream()
{
}

StringStream::~StringStream()
{
}

StringStream::StringStream(const std::string& stream)
{
  m_Stream.str(stream);
}

StringStream::StringStream(std::string& stream)
{
  m_Stream.str(stream);
}

StringStream::StringStream(
    const std::string& delimiter,
    const std::string& terminator)
{
  m_Delimiter = delimiter;
  m_Terminator = terminator;
}

std::tuple<std::string, std::string, std::size_t>
StringStream::ReadKeyPair()
{
  std::uint16_t read_size(0);  // TODO(anonimal): member for stream read size

  // Read key
  std::string key(ReadStringFromByte());
  read_size += key.size();

  // Skip delimiter
  read_size++;
  m_Stream.seekg(1, std::ios_base::cur);
  read_size++;

  // Read value
  std::string value(ReadStringFromByte());
  read_size += value.size();

  // Skip terminator
  read_size++;
  m_Stream.seekg(1, std::ios_base::cur);
  read_size++;

  // TODO(anonimal): debug logging; include delimiter/terminator

  return std::make_tuple(std::move(key), std::move(value), read_size);
}

std::string StringStream::ReadStringFromByte()
{
  // Get stated length amount
  std::uint8_t len;
  m_Stream.read(reinterpret_cast<char*>(&len), 1);

  std::string string(len, '\0');

  // Read given amount
  m_Stream.read(const_cast<char*>(string.data()), string.size());

  return string;
}

void StringStream::WriteKeyPair(
    const std::string& key,
    const std::string& value)
{
  WriteByteAndString(key);
  m_Stream.write(GetDelimiter().c_str(), GetDelimiter().size());
  WriteByteAndString(value);
  m_Stream.write(GetTerminator().c_str(), GetTerminator().size());
}

void StringStream::WriteByteAndString(const std::string& string)
{
  if (string.size() > std::numeric_limits<std::uint8_t>::max())
    throw std::length_error(
        "StringStream: " + std::string(__func__) + "invalid length");
  std::uint8_t len = string.size();
  m_Stream.write(reinterpret_cast<char*>(&len), 1);
  m_Stream.write(string.c_str(), len);
}

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

boost::filesystem::path GetPath(Path path)
{
  auto get_data_path = [](bool const is_default = false) {

    auto get_default_data_path = []() {
      static std::string data_dir("kovri");
#ifdef KOVRI_CUSTOM_DATA_PATH
      return boost::filesystem::path(std::string(KOVRI_CUSTOM_DATA_PATH));
#else
#ifdef _WIN32
      char local_app_data[MAX_PATH];
      SHGetFolderPath(NULL, CSIDL_APPDATA, 0, NULL, local_app_data);
      return boost::filesystem::path(std::string(local_app_data) + "\\" + data_dir);
#else
      boost::filesystem::path path_ret;
      char* home = getenv("HOME");
      if (home == NULL || strlen(home) == 0)
        path_ret = boost::filesystem::path("/");
      else
        path_ret = boost::filesystem::path(home);
#ifdef __APPLE__
      path_ret /= "Library/Application Support";
      create_directory(path_ret);
      return path_ret / data_dir;
#else
      return path_ret / (std::string(".") + data_dir);
#endif
#endif
#endif
    };

    // Return default if set
    if (is_default)
      return get_default_data_path();

    // Create data directory
    static boost::filesystem::path path =
        context.GetCustomDataDir().empty()
            ? get_default_data_path()
            : boost::filesystem::path(context.GetCustomDataDir());

    if (!boost::filesystem::exists(path))
      {
        if (!boost::filesystem::create_directory(path))
          {
            LOG(error) << "Filesystem: failed to create data directory!";
            path = "";
            return path;
          }
      }

    if (!boost::filesystem::is_directory(path))
      path = context.GetCustomDataDir().empty()
                 ? get_default_data_path()
                 : boost::filesystem::path(context.GetCustomDataDir());

    return path;
  };

  // Return specific data paths
  switch (path)
    {
      case Path::DefaultData:
        return get_data_path(true);

      case Path::Data:
        return get_data_path();

      case Path::Core:
        return get_data_path() / "core";

      case Path::Client:
        return get_data_path() / "client";

      case Path::Config:
        return get_data_path() / "config";

      case Path::Logs:
        return get_data_path() / "logs";

      case Path::NetDb:
        return GetPath(Path::Core) / "network_database";

      case Path::Profiles:
        return GetPath(Path::Core) / "peer_profiles";

      case Path::TLS:
        return GetPath(Path::Client) / "certificates" / "tls";

      case Path::SU3:
        return GetPath(Path::Client) / "certificates" / "su3";

      case Path::AddressBook:
        return GetPath(Path::Client) / "address_book";

      case Path::ClientKeys:
        return GetPath(Path::Client) / "keys";

      default:
        throw std::invalid_argument("Filesystem: invalid path");
    }
}

}  // namespace core
}  // namespace kovri
