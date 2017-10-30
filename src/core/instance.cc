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
 *                                                                                            //
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project          //
 */

#include "core/instance.h"

#include <cstdint>
#include <stdexcept>
#include <memory>

// TODO(anonimal): we musn't use client code in core...
#include "client/reseed.h"

#include "core/router/context.h"
#include "core/router/net_db/impl.h"
#include "core/router/transports/impl.h"
#include "core/router/tunnel/impl.h"

#include "core/util/log.h"

#include "version.h"

namespace kovri {
namespace core {

Instance::Instance(const std::vector<std::string>& args) try
    : m_Exception(__func__),
      m_Config(args)
  {
    // TODO(anonimal): Initializing of sources/streams/sinks must come after we've properly configured the logger.
    //   we do this here so we can catch debug logging before instance "initialization". This is not ideal
    core::SetupLogging(m_Config.GetMap());

    // Log the banner
    LOG(info) << "The Kovri I2P Router Project";
    LOG(info) << KOVRI_VERSION << "-" << KOVRI_GIT_REVISION << " \""
              << KOVRI_CODENAME << "\"";

    // Continue with configuration/setup
    m_Config.SetupAESNI();
  }
catch (...)
  {
    m_Exception.Dispatch();
  }

Instance::~Instance() {}

// Note: we'd love Instance RAII but singleton needs to be daemonized (if applicable) before initialization
void Instance::Initialize() {
  // TODO(unassigned): see TODO's for router context and singleton
  LOG(debug) << "Instance: initializing core context";
  auto map = m_Config.GetMap();
  auto host = map["host"].as<std::string>();
  // Random generated port if none is supplied via CLI or config
  // See: i2p.i2p/router/java/src/net/i2p/router/transport/udp/UDPEndpoint.java
  auto port = map["port"].defaulted()
                  ? kovri::core::RandInRange32(
                        core::RouterInfo::MinPort, core::RouterInfo::MaxPort)
                  : map["port"].as<int>();
  // TODO(unassigned): context should be in core namespace (see TODO in router context)
  kovri::context.Init(host, port);
  kovri::context.UpdatePort(port);
  LOG(info) << "Instance: listening on port " << map["port"].as<int>();
  kovri::context.UpdateAddress(boost::asio::ip::address::from_string(host));
  kovri::context.SetSupportsV6(map["v6"].as<bool>());
  kovri::context.SetFloodfill(map["floodfill"].as<bool>());
  auto bandwidth = map["bandwidth"].as<std::string>();
  if (!bandwidth.empty()) {
    if (bandwidth[0] > 'L')
      kovri::context.SetHighBandwidth();
    else
      kovri::context.SetLowBandwidth();
  }
  // Set reseed options
  kovri::context.SetOptionReseedFrom(map["reseed-from"].as<std::string>());
  kovri::context.SetOptionDisableSU3Verification(
      map["disable-su3-verification"].as<bool>());
  // Set transport options
  kovri::context.SetSupportsNTCP(map["enable-ntcp"].as<bool>());
  kovri::context.SetSupportsSSU(map["enable-ssu"].as<bool>());
  // Set SSL option
  kovri::context.SetOptionEnableSSL(map["enable-ssl"].as<bool>());
}

void Instance::Start()
{
  try
    {
      // NetDb
      LOG(debug) << "Instance: starting NetDb";
      if (!kovri::core::netdb.Start())
        throw std::runtime_error("Instance: NetDb failed to start");

      // Reseed
      if (core::netdb.GetNumRouters() < core::NetDb::Size::MinRequiredRouters)
        {
          LOG(debug) << "Instance: reseeding NetDb";
          // TODO(anonimal): we musn't use client code in core...
          kovri::client::Reseed reseed;
          if (!reseed.Start())
            throw std::runtime_error("Instance: reseed failed");
        }

      LOG(debug) << "Instance: starting transports";
      kovri::core::transports.Start();

      LOG(debug) << "Instance: starting tunnels";
      kovri::core::tunnels.Start();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }

  LOG(info) << "Instance: successfully started";
}

void Instance::Stop()
{
  try
    {
      LOG(debug) << "Instance: stopping tunnels";
      kovri::core::tunnels.Stop();

      LOG(debug) << "Instance: stopping transports";
      kovri::core::transports.Stop();

      LOG(debug) << "Instance: stopping NetDb";
      kovri::core::netdb.Stop();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }

  LOG(info) << "Instance: successfully stopped";
}

}  // namespace core
}  // namespace kovri
