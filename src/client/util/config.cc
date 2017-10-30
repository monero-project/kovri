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

#include "client/util/config.h"

#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <memory>
#include <stdexcept>

#include "client/util/parse.h"

#include "core/util/config.h"

namespace kovri
{
namespace client
{
Configuration::Configuration(const core::Configuration& core_config) try
    : m_Exception(__func__),
      m_CoreConfig(core_config)
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
  auto const file = GetConfigPath().string();
  boost::property_tree::ptree pt;
  // Read file
  try
    {
      boost::property_tree::read_ini(file, pt);
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      return;
    }

  // Parse on a per-section basis, store in tunnels config vector
  m_TunnelsConfig.clear();
  for (auto& section : pt)
    {
      TunnelAttributes tunnel{};
      try
        {
          // Get tunnel name and container for remaining attributes
          tunnel.name = section.first;
          const auto& value = section.second;

          // Get remaining attributes
          tunnel.type = value.get<std::string>(GetAttribute(Key::Type));
          tunnel.address =
              value.get<std::string>(GetAttribute(Key::Address), "127.0.0.1");
          tunnel.port = value.get<std::uint16_t>(GetAttribute(Key::Port));

          // Test which type of tunnel (client or server), add unique attributes
          if (tunnel.type == GetAttribute(Key::Client)
              || tunnel.type == GetAttribute(Key::IRC))
            {
              tunnel.dest = value.get<std::string>(GetAttribute(Key::Dest));
              tunnel.dest_port =
                  value.get<std::uint16_t>(GetAttribute(Key::DestPort), 0);
              tunnel.keys = value.get<std::string>(GetAttribute(Key::Keys), "");

              // Parse for CSV destinations + dest:port, then set appropriately
              ParseClientDestination(&tunnel);

              // Check for conflicting port
              if (std::find_if(
                      m_TunnelsConfig.begin(),
                      m_TunnelsConfig.end(),
                      [&tunnel](TunnelAttributes const& tunnel_attribute) {
                        return tunnel.port == tunnel_attribute.port;
                      })
                  != m_TunnelsConfig.end())
                {
                  LOG(error) << "Config: " << tunnel.name
                             << " will not be loaded, conflicting port";
                  continue;
                }
            }
          else if (
              tunnel.type == GetAttribute(Key::Server)
              || tunnel.type == GetAttribute(Key::HTTP))
            {
              tunnel.in_port =
                  value.get<std::uint16_t>(GetAttribute(Key::InPort), 0);
              tunnel.keys = value.get<std::string>(
                  GetAttribute(Key::Keys));  // persistent private key

              // Test/Get/Set for ACL
              auto white =
                  value.get<std::string>(GetAttribute(Key::Whitelist), "");
              auto black =
                  value.get<std::string>(GetAttribute(Key::Blacklist), "");

              // Ignore blacklist if whitelist is given
              if (!white.empty())
                {
                  tunnel.acl.list = white;
                  tunnel.acl.is_white = true;
                }
              else if (!black.empty())
                {
                  tunnel.acl.list = black;
                  tunnel.acl.is_black = true;
                }
            }
          else
            {
              throw std::runtime_error(
                  "Configuration: unknown tunnel type=" + tunnel.type + " of "
                  + tunnel.name + " in " + file);
            }
        }
      catch (...)
        {
          std::string message =
              std::string(__func__) + ": tunnel name " + tunnel.name;
          m_Exception.Dispatch(message.data());
          throw;
        }

      // Save section for later client insertion
      m_TunnelsConfig.push_back(tunnel);
    }
}

const std::string Configuration::GetAttribute(Key key) const
{
  switch (key)
    {
      // Section types
      case Key::Type:
        return "type";
        break;
      case Key::Client:
        return "client";
        break;
      case Key::IRC:
        return "irc";
        break;
      case Key::Server:
        return "server";
        break;
      case Key::HTTP:
        return "http";
        break;
      // Client-tunnel specific
      case Key::Dest:
        return "dest";
        break;
      case Key::DestPort:
        return "dest_port";
        break;
      // Server-tunnel specific
      case Key::InPort:
        return "in_port";
        break;
      case Key::Whitelist:
        return "white_list";
        break;
      case Key::Blacklist:
        return "black_list";
        break;
      // Tunnel-agnostic
      case Key::Address:
        return "address";
        break;
      case Key::Port:
        return "port";
        break;
      case Key::Keys:
        return "keys";
        break;
      default:
        return "";  // not needed (avoids nagging -Wreturn-type)
        break;
    };
}

}  // namespace client
}  // namespace kovri
