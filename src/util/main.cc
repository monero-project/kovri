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

#include "core/util/exception.h"
#include "core/util/log.h"
#include "util/base.h"
#include "util/command.h"

namespace bpo = boost::program_options;
typedef std::map<std::string, Command*> ListCommands;

void PrintUsage(
    const std::string& name,
    const bpo::options_description& desc,
    const ListCommands& list_cmd)
{
  LOG(info) << "Syntax: " << name << " <options> command";
  LOG(info) << desc;
  LOG(info) << "Available commands : ";
  for (const auto& c : list_cmd)
    LOG(info) << "\t" << c.first;
}

int main(int argc, const char* argv[])
{
  ListCommands list_cmd;
  Base32Command base32_cmd;
  Base64Command base64_cmd;
  list_cmd[base32_cmd.GetName()] = &base32_cmd;
  list_cmd[base64_cmd.GetName()] = &base64_cmd;

  bpo::options_description general_desc("General options");
  std::string opt_type, opt_infile, opt_outfile;
  general_desc.add_options()("help,h", "produce this help message")(
      "all,a", "print all options");

  bpo::variables_map vm;
  try
    {
      bpo::parsed_options parsed = bpo::command_line_parser(argc, argv)
                                       .options(general_desc)
                                       .allow_unregistered()
                                       .run();
      bpo::store(parsed, vm);
      bpo::notify(vm);
    }
  catch (...)
    {
      kovri::core::Exception ex;
      ex.Dispatch(__func__);
      return EXIT_FAILURE;
    }

  if (argc < 2)
    {
      LOG(error) << "Error : Not enough arguments !";
      PrintUsage(argv[0], general_desc, list_cmd);
      return EXIT_FAILURE;
    }

  // If the first argument is not a command
  if (list_cmd.find(std::string(argv[1])) == list_cmd.end())
    {
      if (vm.count("all"))
        {
          for (const auto& cmd : list_cmd)
            cmd.second->PrintUsage(std::string(argv[0]) + " " + cmd.first);
          return EXIT_SUCCESS;
        }
      if (vm.count("help"))
        {
          if (argc > 2)
            {
              const auto& c = list_cmd.find(std::string(argv[2]));
              if (c != list_cmd.end())
                {  // print only sub command help
                  list_cmd[c->first]->PrintUsage(
                      std::string(argv[0]) + " " + c->first);
                  return EXIT_SUCCESS;
                }
            }
          PrintUsage(argv[0], general_desc, list_cmd);
          return EXIT_SUCCESS;
        }
      LOG(error) << "Error : Invalid command or option \"" << argv[1] << "\"";
      PrintUsage(argv[0], general_desc, list_cmd);
      return EXIT_FAILURE;
    }
  // Process
  if (list_cmd[argv[1]]->Impl(
          std::string(argv[0]) + " " + std::string(argv[1]),
          argc - 1,
          argv + 1))
    return EXIT_SUCCESS;
  return EXIT_FAILURE;
}
