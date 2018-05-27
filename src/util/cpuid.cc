/**                                                                                           //
 * Copyright (c) 2015-2018, The Kovri I2P Router Project                                      //
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

#include "util/cpuid.h"

#ifdef WITH_CRYPTOPP
#include <cryptopp/cpu.h>
#endif

#include "core/util/log.h"

// Cpuid command
CpuidCommand::CpuidCommand() {}

#if defined(__x86_64__) || defined(__i386__)
std::string CpuidCommand::GetCpuVendor()
{
  unsigned int cpuid[4]{};
  if (!CryptoPP::CpuId(0, 0, cpuid))
    {
      return "";
    }

  std::stringstream cpu_vendor_id;
  cpu_vendor_id << (char)(cpuid[1] & 0xFF);
  cpu_vendor_id << (char)(cpuid[1] >> 8 & 0xFF);
  cpu_vendor_id << (char)(cpuid[1] >> 16 & 0xFF);
  cpu_vendor_id << (char)(cpuid[1] >> 24 & 0xFF);
  cpu_vendor_id << (char)(cpuid[3] & 0xFF);
  cpu_vendor_id << (char)(cpuid[3] >> 8 & 0xFF);
  cpu_vendor_id << (char)(cpuid[3] >> 16 & 0xFF);
  cpu_vendor_id << (char)(cpuid[3] >> 24 & 0xFF);
  cpu_vendor_id << (char)(cpuid[2] & 0xFF);
  cpu_vendor_id << (char)(cpuid[2] >> 8 & 0xFF);
  cpu_vendor_id << (char)(cpuid[2] >> 16 & 0xFF);
  cpu_vendor_id << (char)(cpuid[2] >> 24 & 0xFF);
  return cpu_vendor_id.str();
}

std::string CpuidCommand::GetCpuModelName()
{
  unsigned int cpuid[4]{};
  if (!CryptoPP::CpuId(0x80000000, 0, cpuid))
    {
      return "";
    }

  unsigned int max_supported = cpuid[0] & 0xFFFFFFFF;
  if (max_supported < 0x80000004)
    {
      return "";
    }

  std::stringstream cpu_model_name;
  for (unsigned int i = 0x80000002; i <= 0x80000004; i++)
    {
      if (!CryptoPP::CpuId(i, 0, cpuid))
        {
          return "";
        }

      for (int j = 0; j < 4; j++)
        {
          cpu_model_name << (char)(cpuid[j] & 0xFF);
          cpu_model_name << (char)(cpuid[j] >> 8 & 0xFF);
          cpu_model_name << (char)(cpuid[j] >> 16 & 0xFF);
          cpu_model_name << (char)(cpuid[j] >> 24 & 0xFF);
        }
    }
  return cpu_model_name.str();
}

unsigned int CpuidCommand::GetCpuFamily()
{
  unsigned int cpuid[4]{};
  if (!CryptoPP::CpuId(1, 0, cpuid))
    {
      return 0;
    }

  unsigned int cpu_family = (cpuid[0] >> 8) & 0xf;
  return cpu_family;
}

unsigned int CpuidCommand::GetCpuExtendedFamily()
{
  unsigned int cpuid[4]{};
  if (!CryptoPP::CpuId(1, 0, cpuid))
    {
      return 0;
    }

  unsigned int cpu_family = (cpuid[0] >> 20) & 0xff;
  return cpu_family;
}

unsigned int CpuidCommand::GetCpuModel()
{
  unsigned int cpuid[4]{};
  if (!CryptoPP::CpuId(1, 0, cpuid))
    {
      return 0;
    }

  unsigned int cpu_model = (cpuid[0] >> 4) & 0xf;
  return cpu_model;
}

unsigned int CpuidCommand::GetCpuExtendedModel()
{
  unsigned int cpuid[4]{};
  if (!CryptoPP::CpuId(1, 0, cpuid))
    {
      return 0;
    }

  unsigned int cpu_model = (cpuid[0] >> 16) & 0xf;
  return cpu_model;
}

unsigned int CpuidCommand::GetCpuStepping()
{
  unsigned int cpuid[4]{};
  if (!CryptoPP::CpuId(1, 0, cpuid))
    {
      return 0;
    }

  return cpuid[0] & 0xf;
}
#endif

void CpuidCommand::PrintUsage(const std::string& name) const
{
  LOG(info) << "Syntax: " << name;
}

bool CpuidCommand::Impl(
    const std::string& /*cmd_name*/,
    const std::vector<std::string>& /*args*/)
{
#if defined(__x86_64__) || defined(__i386__)
  LOG(info) << "CPU Vendor: " << GetCpuVendor();
  LOG(info) << "CPU Model Name: " << GetCpuModelName();
  const int extended_val = 15;
  const int extended_intel_val = 6;
  int cpu_family = GetCpuFamily();
  int cpu_model = GetCpuModel();
  if (cpu_family == extended_val
      || (cpu_family == extended_intel_val
          && GetCpuVendor().compare("GenuineIntel") == 0))
    {
      cpu_model += (GetCpuExtendedModel() << 4);
    }
  if (cpu_family == extended_val)
    {
      cpu_family += GetCpuExtendedFamily();
    }
  LOG(info) << "CPU Family: " << cpu_family;
  LOG(info) << "CPU Model: " << cpu_model;
  LOG(info) << "CPU Stepping: " << GetCpuStepping();
  LOG(info) << "CacheLineSize: " << CryptoPP::GetCacheLineSize();
  LOG(info) << "Has SSE2: " << CryptoPP::HasSSE2();
  LOG(info) << "Has SSSE3: " << CryptoPP::HasSSSE3();
  LOG(info) << "Has SSE4.1: " << CryptoPP::HasSSE41();
  LOG(info) << "Has SSE4.2: " << CryptoPP::HasSSE42();
  LOG(info) << "Has AESNI: " << CryptoPP::HasAESNI();
  LOG(info) << "Has CLMUL: " << CryptoPP::HasCLMUL();
  LOG(info) << "Has SHA: " << CryptoPP::HasSHA();
  LOG(info) << "Is P4: " << CryptoPP::IsP4();
  LOG(info) << "Has RDRAND: " << CryptoPP::HasRDRAND();
  LOG(info) << "Has RDSEED: " << CryptoPP::HasRDSEED();
  LOG(info) << "Has PadlockRNG: " << CryptoPP::HasPadlockRNG();
  LOG(info) << "Has PadlockACE: " << CryptoPP::HasPadlockACE();
  LOG(info) << "Has PadlockACE2: " << CryptoPP::HasPadlockACE2();
  LOG(info) << "Has PadlockPHE: " << CryptoPP::HasPadlockPHE();
  LOG(info) << "Has PadlockPMM: " << CryptoPP::HasPadlockPMM();
#elif defined(__arm__)
  LOG(info) << "Has NEON: " << CryptoPP::HasNEON();
  LOG(info) << "Has PMULL: " << CryptoPP::HasPMULL();
  LOG(info) << "Has CRC32: " << CryptoPP::HasCRC32();
  LOG(info) << "Has AES: " << CryptoPP::HasAES();
  LOG(info) << "Has SHA1: " << CryptoPP::HasSHA1();
  LOG(info) << "Has SHA2: " << CryptoPP::HasSHA2();
#else
  LOG(warning) << GetName() << " is unsupported by this CPU";
#endif
  return true;
}
