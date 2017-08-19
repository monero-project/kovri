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

#include "util/fuzz.h"

#include <FuzzerDefs.h>
#include <memory>

#include "core/util/log.h"

#include "tests/fuzz_tests/i2pcontrol.h"
#include "tests/fuzz_tests/lease_set.h"
#include "tests/fuzz_tests/routerinfo.h"
#include "tests/fuzz_tests/su3.h"
#include "tests/fuzz_tests/target.h"

namespace bpo = boost::program_options;

// Helper for conversion from std::vector to (int, char**)
struct ArgvDeleter
{
  explicit ArgvDeleter(std::size_t size) : m_Size(size)
  {
  }
  void operator()(char** ptr)
  {
    for (std::size_t i(0); i < m_Size; i++)
      delete[] ptr[i];
    delete[] ptr;
  }
  std::size_t m_Size;
};

typedef std::unique_ptr<char* [], ArgvDeleter> UniqueCharArrayPtr;

UniqueCharArrayPtr VectorToArgcArgv(
    const std::vector<std::string> args,
    int* argc)
{
  UniqueCharArrayPtr argv(new char*[args.size()], ArgvDeleter(args.size()));
  for (std::size_t i(0); i < args.size(); i++)
    {
      argv.get()[i] = new char[args.at(i).size() + 1];
      snprintf(argv.get()[i], args.at(i).size() + 1, "%s", args.at(i).c_str());
    }
  for (int i(0); i < *argc; i++)
    LOG(info) << "i " << i << " " << argv.get()[i];
  *argc = args.size();
  return argv;
}

kovri::fuzz::FuzzTarget* CurrentTarget = nullptr;

// Fuzz callbacks

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  if (!CurrentTarget)
    return 0;
  return CurrentTarget->Initialize(argc, argv);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  return CurrentTarget->Impl(data, size);
}

// Fuzz command
FuzzCommand::FuzzCommand()
{
}

void FuzzCommand::PrintAvailableTargets() const
{
  LOG(info) << "Available targets : ";
  LOG(info) << "\ti2pcontrol";
  LOG(info) << "\tleaseset";
  LOG(info) << "\trouterinfo";
  LOG(info) << "\tsu3";
}

void FuzzCommand::PrintUsage(const std::string& name) const
{
  LOG(info) << "Syntax: " << name;
  LOG(info) << "\t--help";
  LOG(info) << "\t--list";
  LOG(info) << "\t--target=TARGET -merge=1 CORPUS_DIR RAW_CORPUS_DIR";
  LOG(info) << "\t--target=TARGET <libfuzzer_options> CORPUS_DIR";
  PrintAvailableTargets();

  // Print libFuzzer options
  LOG(info) << "LibFuzzer options:";
  std::vector<std::string> fuzz_args;
  fuzz_args.push_back(name);
  fuzz_args.push_back("-help=1");
  int argc = {};
  UniqueCharArrayPtr argv = VectorToArgcArgv(fuzz_args, &argc);
  char** argv_ptr = argv.get();
  fuzzer::FuzzerDriver(&argc, &argv_ptr, LLVMFuzzerTestOneInput);
}

bool FuzzCommand::Impl(
    const std::string& cmd_name,
    const std::vector<std::string>& args)
{
  std::string target;
  bpo::options_description desc("Options");
  desc.add_options()("list,l", "list available targets")(
      "target,t", bpo::value<std::string>(&target), "fuzz target");

  bpo::variables_map vm;
  std::vector<std::string> fuzz_options;
  try
    {
      bpo::parsed_options parsed = bpo::command_line_parser(args)
                                       .options(desc)
                                       .allow_unregistered()
                                       .run();
      fuzz_options =
          bpo::collect_unrecognized(parsed.options, bpo::include_positional);
      bpo::store(parsed, vm);
      bpo::notify(vm);
    }
  catch (...)
    {
      kovri::core::Exception ex(GetName().c_str());
      ex.Dispatch(__func__);
      return false;
    }

  if (vm.count("list"))
    {
      PrintAvailableTargets();
      return false;
    }

  // Handle target
  if (target.empty())
    {
      LOG(error) << "Fuzz: Empty target !";
      PrintUsage(cmd_name);
      return false;
    }
  else if (target == "su3")
    {
      CurrentTarget = new kovri::fuzz::SU3();
    }
  else if (target == "routerinfo")
    {
      CurrentTarget = new kovri::fuzz::RouterInfo();
    }
  else if (target == "leaseset")
    {
      CurrentTarget = new kovri::fuzz::LeaseSet();
    }
  else if (target == "i2pcontrol")
    {
      CurrentTarget = new kovri::fuzz::I2PControl();
    }
  else
    {
      LOG(error) << "Fuzz: Invalid target " << target;
      PrintUsage(cmd_name);
      return false;
    }
  // Prepend with --target=target
  fuzz_options.insert(fuzz_options.begin(), std::string("--target=") + target);
  // Prepend with program name
  fuzz_options.insert(fuzz_options.begin(), cmd_name);
  // Transform fuzz_options to (argc,argv)
  int argc = {};
  UniqueCharArrayPtr argv = VectorToArgcArgv(fuzz_options, &argc);
  char** argv_ptr = argv.get();
  // Start fuzzing
  return fuzzer::FuzzerDriver(&argc, &argv_ptr, LLVMFuzzerTestOneInput);
}
