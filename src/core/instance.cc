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
#include <memory>
#include <stdexcept>

// TODO(anonimal): we musn't use client code in core...
#include "client/reseed.h"

#include "core/router/context.h"
#include "core/router/net_db/impl.h"
#include "core/router/transports/impl.h"
#include "core/router/tunnel/impl.h"

#include "core/util/log.h"

#include "version.h"

namespace kovri
{
namespace core
{
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

    // Log args (if applicable)
    for (auto const& arg : args)
      LOG(debug) << __func__ << ": arg=" << arg;

    // Continue with configuration/setup
    m_Config.SetupAESNI();
  }
catch (...)
  {
    m_Exception.Dispatch();
  }

Instance::~Instance() {}

// Note: we'd love Instance RAII but singleton needs to be daemonized (if applicable) before initialization
void Instance::Initialize()
{
  LOG(debug) << "Instance: initializing core";
  // TODO(unassigned): see TODOs for router context and singleton
  context.Initialize(m_Config.GetMap());
}

void Instance::Start()
{
  try
    {
      // NetDb
      LOG(debug) << "Instance: starting NetDb";
      if (!netdb.Start())
        throw std::runtime_error("Instance: NetDb failed to start");

      // Reseed
      if (netdb.GetNumRouters() < NetDb::Size::MinRequiredRouters)
        {
          LOG(debug) << "Instance: reseeding NetDb";
          // TODO(anonimal): we musn't use client code in core...
          client::Reseed reseed;
          if (!reseed.Start())
            throw std::runtime_error("Instance: reseed failed");
        }

      LOG(debug) << "Instance: starting transports";
      transports.Start();

      LOG(debug) << "Instance: starting tunnels";
      tunnels.Start();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }

  LOG(info) << "Instance: core successfully started";
}

void Instance::Stop()
{
  try
    {
      LOG(debug) << "Instance: stopping tunnels";
      tunnels.Stop();

      LOG(debug) << "Instance: stopping transports";
      transports.Stop();

      LOG(debug) << "Instance: stopping NetDb";
      netdb.Stop();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }

  LOG(info) << "Instance: core successfully stopped";
}

}  // namespace core
}  // namespace kovri
