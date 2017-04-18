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
#include "core/router/info.h"
#include "core/util/exception.h"
#include "core/util/filesystem.h"
#include "core/util/log.h"

namespace bpo = boost::program_options;

RouterInfoCommand::RouterInfoCommand()
{
}

void RouterInfoCommand::PrintUsage(const std::string& name) const
{
  LOG(info) << "Syntax: " << name << " routerInfo-(...).dat";
}

bool RouterInfoCommand::Impl(
    const std::string& cmd_name,
    const std::vector<std::string>& args)
{
  std::vector<std::string> inputs;
  bpo::options_description options("Specific options");
  options.add_options()(
      "args", bpo::value<std::vector<std::string>>(&inputs)->multitoken());

  bpo::positional_options_description pos;
  pos.add("args", -1);

  bpo::variables_map vm;
  try
    {
      bpo::parsed_options parsed =
          bpo::command_line_parser(args).options(options).positional(pos).run();
      bpo::store(parsed, vm);
      bpo::notify(vm);
    }
  catch (...)
    {
      kovri::core::Exception ex(GetName().c_str());
      ex.Dispatch(__func__);
      return false;
    }

  if (inputs.size() == 0)
    {
      LOG(error) << "routerinfo: Not enough arguments";
      PrintUsage(cmd_name);
      return false;
    }

  for (const auto& arg : inputs)
    {
      kovri::core::InputFileStream input(arg, std::ios::in | std::ios::binary);
      if (input.Fail())
        {
          LOG(error) << "routerinfo: Failed to open input " << arg;
          return false;
        }
      // Read all input
      std::size_t length(0);
      std::unique_ptr<std::uint8_t> buffer =
          input.ReadAll<std::uint8_t, std::size_t>(&length);
      if (!buffer)
        {
          LOG(error) << "routerinfo: Failed to read input " << arg;
          return false;
        }
      LOG(trace) << "routerinfo: read OK length " << length;
      try
        {
          kovri::core::RouterInfo ri(buffer.get(), length);
          LOG(info) << ri.GetDescription();
        }
      catch (...)
        {
          kovri::core::Exception ex(GetName().c_str());
          ex.Dispatch(__func__);
          return false;
        }
    }

  return true;
}
