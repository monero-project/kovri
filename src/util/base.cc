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

#include "util/base.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <memory>
#include <vector>

#include "core/crypto/radix.h"

#include "core/util/exception.h"
#include "core/util/log.h"

namespace bpo = boost::program_options;

BaseCommand::BaseCommand() : m_Desc("General options")
{
  m_Desc.add_options()("help,h", "produce this help message")(
      "type,t", bpo::value<std::string>(&m_OptType), "encode/decode")(
      "infile,i",
      bpo::value<std::string>(&m_OptInfile)->value_name("path"),
      "input file")(
      "outfile,o",
      bpo::value<std::string>(&m_OptOutfile)->value_name("path"),
      "output file");
}

void BaseCommand::PrintUsage(const std::string& name) const
{
  LOG(info) << "Syntax: " << name << " encode <inFile> <outfile>";
  LOG(info) << "or    : " << name << " decode <inFile> <outfile>";
}

template <typename Encoder, typename Decoder>
bool process(
    Encoder encoder,
    Decoder decoder,
    bool encode,
    kovri::core::InputFileStream* input,
    kovri::core::OutputFileStream* output)
{
  std::vector<std::uint8_t> in_buffer;
  std::vector<std::uint8_t> out_buffer;

  do
    {
      input->Seekg(0, std::ios::end);
      in_buffer.resize(input->Tellg());
      input->Seekg(0, std::ios::beg);

      if (!input->Read(in_buffer.data(), in_buffer.size()))
        return false;

      try
        {
          if (encode)
            {
              std::string const encoded =
                  encoder(in_buffer.data(), in_buffer.size());
              out_buffer.resize(encoded.size());
              std::copy(encoded.begin(), encoded.end(), out_buffer.begin());
            }
          else
            {
              out_buffer = decoder(
                  reinterpret_cast<const char*>(in_buffer.data()),
                  in_buffer.size());
            }
        }
      catch (...)
        {
          kovri::core::Exception ex;
          ex.Dispatch(__func__);
          return false;
        }

      if (input->Count() && out_buffer.empty())
        {
          LOG(error) << "Error : Stream processing failed !";
          return false;
        }

      if (!output->Write(out_buffer.data(), out_buffer.size()))
        return false;
    }
  while (input->Good() && out_buffer.empty());

  return true;
}

bool BaseCommand::Impl(
    const std::string& cmd_name,
    const std::vector<std::string>& args)
{
  bpo::variables_map vm;
  bpo::positional_options_description pos;
  pos.add("type", 1).add("infile", 1).add("outfile", 1);
  try
    {
      bpo::parsed_options parsed =
          bpo::command_line_parser(args).options(m_Desc).positional(pos).run();
      bpo::store(parsed, vm);
      bpo::notify(vm);
    }
  catch (...)
    {
      kovri::core::Exception ex(GetName().c_str());
      ex.Dispatch(__func__);
      return false;
    }

  // TODO(anonimal): fix args size
  if (vm.count("help") || (args.size() < 1) || (args.size() > 3))
    {
      if (args.size() < 2)
        LOG(error) << "Not enough arguments !";
      else if (args.size() > 4)
        LOG(error) << "Too many arguments !";
      PrintUsage(cmd_name);
      return false;
    }

  // encode or decode or error
  bool encode = true;
  if (m_OptType == "decode")
    {
      encode = false;
    }
  else if (m_OptType != "encode")
    {
      LOG(error) << "Invalid option : \"" << m_OptType << "\"";
      LOG(error) << "Should be \"encode\" or \"decode\"";
      PrintUsage(cmd_name);
      return false;
    }

  kovri::core::InputFileStream input(
      m_OptInfile, std::ios::in | std::ios::binary);
  if (input.Fail())
    {
      LOG(error) << "Failed to open input file \"" << m_OptInfile.c_str()
                 << "\"";
      return false;
    }

  kovri::core::OutputFileStream output(
      m_OptOutfile, std::ios::out | std::ios::binary);
  if (output.Fail())
    {
      LOG(error) << "Failed to open output file \"" << m_OptOutfile.c_str()
                 << "\"";
      return false;
    }

  // Process
  if (!do_process(encode, &input, &output))
    {
      LOG(error) << "Error : Operation Failed !";
      return false;
    }

  return true;
}

bool Base32Command::do_process(
    bool encode,
    kovri::core::InputFileStream* input,
    kovri::core::OutputFileStream* output)
{
  return process(
      kovri::core::Base32::Encode,
      kovri::core::Base32::Decode,
      encode,
      input,
      output);
}

bool Base64Command::do_process(
    bool encode,
    kovri::core::InputFileStream* input,
    kovri::core::OutputFileStream* output)
{
  return process(
      kovri::core::Base64::Encode,
      kovri::core::Base64::Decode,
      encode,
      input,
      output);
}
