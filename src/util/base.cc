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
#include <assert.h>
#include <memory>
#include "core/util/base64.h"
#include "core/util/exception.h"
#include "core/util/log.h"

namespace bpo = boost::program_options;

static_assert(
    Base32Command::m_BufferSize % 40 == 0,
    "Invalid BASE32 buffer size");
static_assert(
    Base64Command::m_BufferSize % 12 == 0,
    "Invalid BASE64 buffer size");

BaseCommand::BaseCommand() : m_Desc("General options")
{
  m_Desc.add_options()("help,h", "produce this help message")(
      "type,t", bpo::value<std::string>(&m_OptType), "encode/decode")(
      "infile,i", bpo::value<std::string>(&m_OptInfile), "input file")(
      "outfile,o", bpo::value<std::string>(&m_OptOutfile), "output file");
}

void BaseCommand::PrintUsage(const std::string& name) const
{
  LOG(info) << "Syntax: " << name << " encode <inFile> <outfile>";
  LOG(info) << "or    : " << name << " decode <inFile> <outfile>";
}

template <typename ToBase, typename ToByte, typename SizeConst>
bool process(
    ToBase ByteStreamToBase,
    ToByte BaseToByteStream,
    SizeConst Size,
    bool encode,
    kovri::core::InputFileStream* input,
    kovri::core::OutputFileStream* output)
{
  std::uint8_t in_buffer[Size + 1];
  std::uint8_t out_buffer[Size * 2 + 1];
  std::size_t ret(0);
  memset(in_buffer, 0, sizeof(in_buffer));
  memset(out_buffer, 0, sizeof(out_buffer));
  do
    {
      if (!input->Read(in_buffer, Size))
        return false;

      if (encode)
        ret = ByteStreamToBase(
            in_buffer,
            input->Count(),
            reinterpret_cast<char*>(out_buffer),
            Size * 2);
      else
        ret = BaseToByteStream(
            reinterpret_cast<char*>(in_buffer),
            input->Count(),
            out_buffer,
            Size * 2);

      if (input->Count() && !ret)
        {
          LOG(error) << "Error : Stream processing failed !";
          return false;
        }

      if (!output->Write(out_buffer, ret))
        return false;
    } while (input->Good());
  return true;
}

bool BaseCommand::Impl(
    const std::string& cmd_name,
    int argc,
    const char* argv[])
{
  bpo::variables_map vm;
  bpo::positional_options_description pos;
  pos.add("type", 1).add("infile", 1).add("outfile", 1);
  try
    {
      bpo::parsed_options parsed = bpo::command_line_parser(argc, argv)
                                       .options(m_Desc)
                                       .positional(pos)
                                       .run();
      bpo::store(parsed, vm);
      bpo::notify(vm);
    }
  catch (...)
    {
      kovri::core::Exception ex(GetName().c_str());
      ex.Dispatch(__func__);
      return false;
    }

  if (vm.count("help") || (argc < 2) || (argc > 4))
    {
      if (argc < 2)
        LOG(error) << "Not enough arguments !";
      else if (argc > 4)
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
      kovri::core::ByteStreamToBase32,
      kovri::core::Base32ToByteStream,
      m_BufferSize,
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
      kovri::core::ByteStreamToBase64,
      kovri::core::Base64ToByteStream,
      m_BufferSize,
      encode,
      input,
      output);
}
