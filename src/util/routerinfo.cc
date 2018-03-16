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

#include "util/routerinfo.h"
#include <assert.h>
#include <memory>
#include <tuple>
#include <utility>

#include "core/crypto/rand.h"
#include "core/router/info.h"
#include "core/util/exception.h"
#include "core/util/filesystem.h"
#include "core/util/log.h"
#include "version.h"  // NOLINT(build/include)

namespace bpo = boost::program_options;
namespace core = kovri::core;

RouterInfoCommand::RouterInfoCommand()
{
  bpo::options_description read_options("Read options");
  read_options.add_options()(
      "args", bpo::value<std::vector<std::string>>()->multitoken());

  bpo::options_description create_options("Create options");
  create_options.add_options()(
      "create,c", bpo::bool_switch()->default_value(false))(
      "host", bpo::value<std::string>()->default_value("127.0.0.1"))(
      "port", bpo::value<int>()->default_value(0))(
      "floodfill,f",
      bpo::value<bool>()->default_value(false)->value_name("bool"))(
      "bandwidth,b", bpo::value<std::string>()->default_value("L"))(
      "enable-ssu",
      bpo::value<bool>()->default_value(true)->value_name("bool"))(
      "enable-ntcp",
      bpo::value<bool>()->default_value(true)->value_name("bool"))(
      "ssuintroducer,i",
      bpo::value<bool>()->default_value(true)->value_name("bool"))(
      "ssutesting,t",
      bpo::value<bool>()->default_value(true)->value_name("bool"));

  m_Options.add(create_options).add(read_options);
}

void RouterInfoCommand::PrintUsage(const std::string& name) const
{
  LOG(info) << "Syntax: " << name << m_Options;
  LOG(info) << "Example: " << name << " routerInfo-(...).dat";
  LOG(info) << "or: " << name << " --create --host 192.168.1.1 --port 10100 "
                                 "--floodfill 1 --bandwidth P";
}

bool RouterInfoCommand::Impl(
    const std::string& cmd_name,
    const std::vector<std::string>& args)
{
  try
    {
      std::vector<std::string> inputs;
      bpo::positional_options_description pos;
      pos.add("args", -1);

      bpo::variables_map vm;
      bpo::parsed_options parsed = bpo::command_line_parser(args)
                                       .options(m_Options)
                                       .positional(pos)
                                       .run();
      bpo::store(parsed, vm);
      bpo::notify(vm);

      if (vm.count("args"))
        inputs = vm["args"].as<std::vector<std::string>>();

      if (vm["create"].as<bool>())  // Create new router info + keys
        {
          // Sanity checks
          if (inputs.size() > 1)
            {
              LOG(error) << "routerinfo: Too many arguments";
              PrintUsage(cmd_name);
              return false;
            }
          auto filename = inputs.empty() ? std::string() : inputs.at(0);
          if (filename == "-")
            {
              // Need to output 2 files : RI + key
              LOG(error) << "routerinfo: output to console is not supported "
                            "for creation";
              return false;
            }
          auto host = vm["host"].as<std::string>();
          auto port = vm["port"].defaulted() ? core::RandInRange32(
                                                   core::RouterInfo::MinPort,
                                                   core::RouterInfo::MaxPort)
                                             : vm["port"].as<int>();

          // Set transports
          bool const has_ntcp = vm["enable-ntcp"].as<bool>();
          bool const has_ssu = vm["enable-ssu"].as<bool>();

          if (!has_ntcp && !has_ssu)
            throw std::invalid_argument(
                "routerinfo: at least one transport is required");

          std::uint8_t caps(core::RouterInfo::Cap::Reachable);
          // Generate private key
          core::PrivateKeys keys = core::PrivateKeys::CreateRandomKeys(
              core::DEFAULT_ROUTER_SIGNING_KEY_TYPE);
          // Create router info
          core::RouterInfo routerInfo(
              keys,
              std::make_pair(host, port),
              std::make_pair(has_ntcp, has_ssu),
              caps);
          // Set capabilities after creation to allow for disabling
          if (vm["ssuintroducer"].as<bool>())
            caps |= core::RouterInfo::Cap::SSUIntroducer;
          if (vm["ssutesting"].as<bool>())
            caps |= core::RouterInfo::Cap::SSUTesting;
          if (vm["floodfill"].as<bool>())
            caps |= core::RouterInfo::Cap::Floodfill;
          auto bandwidth = vm["bandwidth"].as<std::string>();
          if (!bandwidth.empty() && (bandwidth[0] > 'L'))
            caps |= core::RouterInfo::Cap::HighBandwidth;

          // Set filename if none provided
          if (filename.empty())
            filename = std::string("routerInfo-")
                       + routerInfo.GetIdentHash().ToBase64()
                       + std::string(".dat");
          // Write key to file
          core::OutputFileStream output_key(
              filename + ".key", std::ofstream::binary);
          if (output_key.Fail())
            {
              LOG(error) << "routerinfo: Failed to open file " << filename
                         << ".key";
              return false;
            }
          const std::size_t len = keys.GetFullLen();
          std::unique_ptr<std::uint8_t[]> buf(
              std::make_unique<std::uint8_t[]>(len));
          keys.ToBuffer(buf.get(), len);
          output_key.Write(buf.get(), len);
          if (output_key.Fail())
            {
              LOG(error) << "routerinfo: Failed to write to file " << filename
                         << ".key";
              return false;
            }
          // Write RI to file
          routerInfo.SaveToFile(filename);
          return true;
        }

      if (inputs.size() == 0)
        {
          LOG(error) << "routerinfo: Not enough arguments";
          PrintUsage(cmd_name);
          return false;
        }

      // for each file : read and print description
      for (const auto& arg : inputs)
        {
          core::InputFileStream input(arg, std::ios::in | std::ios::binary);
          if (input.Fail())
            {
              LOG(error) << "routerinfo: Failed to open input " << arg;
              return false;
            }
          // Read all input
          std::size_t length(0);
          std::unique_ptr<std::uint8_t[]> buffer =
              input.ReadAll<std::uint8_t, std::size_t>(&length);
          if (!buffer)
            {
              LOG(error) << "routerinfo: Failed to read input " << arg;
              return false;
            }
          LOG(trace) << "routerinfo: read OK length " << length;
          core::RouterInfo ri(buffer.get(), length);
          LOG(info) << ri.GetDescription();
        }
    }
  catch (...)
    {
      core::Exception ex(GetName().c_str());
      ex.Dispatch(__func__);
      return false;
    }
  return true;
}
