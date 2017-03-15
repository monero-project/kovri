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

#ifndef SRC_UTIL_BENCHMARK_H_
#define SRC_UTIL_BENCHMARK_H_

#include <chrono>
#include <iostream>
#include <string>
#include <vector>

#include "util/command.h"
#include "core/crypto/rand.h"
#include "core/crypto/signature.h"

class Benchmark : public Command
{
 public:
  typedef void (*KeyGenerator)(uint8_t*, uint8_t*);
  static const std::size_t BenchmarkCount = 1000;
  Benchmark();
  boost::program_options::options_description m_Desc;
  std::string m_OptType;

  /// @brief implemation of command
  /// @param command name
  /// @param number of arguments
  /// @param arguments
  /// @return boolean on success failure
  //
  bool Impl(const std::string& path, const std::vector<std::string> & args);

  /// @brief Name of the sub command
  /// @return name of the sub command

  /// @brief Print the help message of the sub command
  void PrintUsage(const std::string& cmd_name) const;
  void PerformTests();

  template <class Verifier, class Signer>
  void BenchmarkTest(
      std::size_t count,
      uint8_t * public_key_size,
      uint8_t * private_key_size,
      uint8_t * output,
      KeyGenerator generator);

  std::string GetName(void) const
  {
    return "benchmark";
  }
};

#endif  // SRC_UTIL_BENCHMARK_H_
