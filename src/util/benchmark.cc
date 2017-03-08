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
 */


#include "util/benchmark.h"

#include "core/util/exception.h"
#include "core/util/log.h"


namespace bpo = boost::program_options;
/// @brief perfrom all benchmark tests
void Benchmark::PerformTests()
{
  uint8_t private_key_DSA[kovri::core::DSA_PRIVATE_KEY_LENGTH];
  uint8_t public_key_DSA[kovri::core::DSA_PUBLIC_KEY_LENGTH];
  uint8_t output_DSA[kovri::core::DSA_SIGNATURE_LENGTH];
  LOG(info) << "--------DSA---------";
  BenchmarkTest<kovri::core::DSAVerifier, kovri::core::DSASigner>(
      Benchmark::BenchmarkCount,
      private_key_DSA,
      public_key_DSA,
      output_DSA,
      kovri::core::CreateDSARandomKeys);

  uint8_t private_key_ECDSAP256[kovri::core::ECDSAP256_KEY_LENGTH];
  uint8_t public_key_ECDSAP256[kovri::core::ECDSAP256_KEY_LENGTH/ 2];
  uint8_t output_ECDSAP256[kovri::core::ECDSAP256_KEY_LENGTH];
  LOG(info) << "-----ECDSAP256------";
  BenchmarkTest<kovri::core::ECDSAP256Verifier, kovri::core::ECDSAP256Signer>(
      Benchmark::BenchmarkCount,
      private_key_ECDSAP256,
      public_key_ECDSAP256,
      output_ECDSAP256,
      kovri::core::CreateECDSAP256RandomKeys);

  LOG(info) << "-----ECDSAP384------";
  uint8_t private_key_ECDSAP384[kovri::core::ECDSAP384_KEY_LENGTH];
  uint8_t public_key_ECDSAP384[kovri::core::ECDSAP384_KEY_LENGTH / 2];
  uint8_t output_ECDSAP384[kovri::core::ECDSAP384_KEY_LENGTH];
  BenchmarkTest<kovri::core::ECDSAP384Verifier, kovri::core::ECDSAP384Signer>(
      Benchmark::BenchmarkCount,
      private_key_ECDSAP384,
      public_key_ECDSAP384,
      output_ECDSAP384,
      kovri::core::CreateECDSAP384RandomKeys);

  LOG(info) << "-----ECDSAP521------";
  uint8_t private_key_ECDSAP521[kovri::core::ECDSAP521_KEY_LENGTH];
  uint8_t public_key_ECDSAP521[kovri::core::ECDSAP521_KEY_LENGTH / 2];
  uint8_t output_ECDSAP521[kovri::core::ECDSAP521_KEY_LENGTH];
  BenchmarkTest<kovri::core::ECDSAP521Verifier, kovri::core::ECDSAP521Signer>(
      Benchmark::BenchmarkCount,
      private_key_ECDSAP521,
      public_key_ECDSAP521,
      output_ECDSAP521,
      kovri::core::CreateECDSAP521RandomKeys);

  LOG(info) << "-----EDDSA25519-----";
  uint8_t private_key_EDDSA25519[kovri::core::EDDSA25519_PRIVATE_KEY_LENGTH];
  uint8_t public_key_EDDSA25519[kovri::core::EDDSA25519_PUBLIC_KEY_LENGTH];
  uint8_t output_EDDSA25519[ kovri::core::EDDSA25519_SIGNATURE_LENGTH];
  BenchmarkTest<kovri::core::EDDSA25519Verifier, kovri::core::EDDSA25519Signer>(
      Benchmark::BenchmarkCount,
      private_key_EDDSA25519,
      public_key_EDDSA25519,
      output_EDDSA25519,
      kovri::core::CreateEDDSARandomKeys);
}

Benchmark::Benchmark() : m_Desc("Options")
{
  m_Desc.add_options()("help,h", "produce this help message")
     ("test,t", bpo::bool_switch()->default_value(false), "all tests");
}
/// @brief parse options and perform action
bool Benchmark::Impl(const std::string& cmd_name,
    const std::vector<std::string>& args)
{
  bpo::variables_map vm;
  try
    {
      bpo::parsed_options parsed =
          bpo::command_line_parser(args).options(m_Desc).run();
      bpo::store(parsed, vm);
      bpo::notify(vm);
    }
  catch (...)
    {
      kovri::core::Exception ex(GetName().c_str());
      ex.Dispatch(__func__);
      return false;
    }

  if (args.size() == 0)  // no arguments
    {
      PrintUsage(cmd_name);
      return false;
    }
  if (vm.count("help"))  // help
    {
      PrintUsage(cmd_name);
      return false;
    }
  if (vm["test"].as<bool>() == true)  // run all tests
    {
      PerformTests();
    }
  return true;
}
/// @brief perform single benchmark test
template <class Verifier, class Signer>
void Benchmark::BenchmarkTest(
    std::size_t count,
    uint8_t * public_key,
    uint8_t * private_key,
    uint8_t * output,
    KeyGenerator generator)
{
  typedef std::chrono::time_point<std::chrono::high_resolution_clock> TimePoint;
  generator(private_key, public_key);
  Verifier verifier(public_key);
  Signer signer(private_key);
  uint8_t message[512] = {};
  std::chrono::nanoseconds sign_duration(0);
  std::chrono::nanoseconds verify_duration(0);
  for (std::size_t i = 0; i < count; ++i)
    {
      try
        {
          kovri::core::RandBytes(message, 512);
          TimePoint begin1 = std::chrono::high_resolution_clock::now();
          signer.Sign(message, 512, output);
          TimePoint end1 = std::chrono::high_resolution_clock::now();
          sign_duration += std::chrono::duration_cast<std::chrono::nanoseconds>(
              end1 - begin1);
          TimePoint begin2 = std::chrono::high_resolution_clock::now();
          verifier.Verify(message, 512, output);
          TimePoint end2 = std::chrono::high_resolution_clock::now();
          verify_duration +=
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  end2 - begin2);
        }
      catch (...)
        {
          kovri::core::Exception ex(GetName().c_str());
          ex.Dispatch(__func__);
          break;
        }
    }
  LOG(info) << "Conducted " << count << " experiments.";
  LOG(info) << "Total sign time: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(
                   sign_duration)
                   .count();
  LOG(info) << "Total verify time: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(
                   verify_duration)
                   .count();
}

void Benchmark::PrintUsage(const std::string& name) const
{
  LOG(info) << name << ": "<< m_Desc << std::endl;
}
