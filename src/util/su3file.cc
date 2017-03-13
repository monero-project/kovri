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

#include "util/su3file.h"
#include <assert.h>
#include <map>
#include <memory>
#include <regex>  // NOLINT(build/c++11)
#include <unordered_map>

#include "client/reseed.h"
#include "core/crypto/rand.h"
#include "core/crypto/signature.h"
#include "core/router/identity.h"
#include "core/util/exception.h"
#include "core/util/filesystem.h"
#include "core/util/log.h"

namespace bpo = boost::program_options;

SU3FileCommand::SU3FileCommand()
{
}

void SU3FileCommand::PrintUsage(const std::string& name) const
{
  LOG(info) << "Syntax: " << name;
  LOG(info) << "\tshowversion [-k file.crt] [-d cert-dir] signedFile.su3";
  LOG(info) << "\tverifysig [-k file.crt] [-d cert-dir] signedFile.su3";
  LOG(info) << "\textract [-k file.crt] [-d cert-dir] signedFile.su3 outFile";
}

bool SU3FileCommand::Impl(
    const std::string& cmd_name,
    const std::vector<std::string>& args)
{
  std::string sub_cmd, input_name, output_name;
  bpo::options_description desc("General options");
  desc.add_options()("help,h", "produce this help message")(
      ",k", bpo::value<std::string>(), "crlFile.crt")(
      "cert-dir,d", bpo::value<std::string>(), "certificate directory")(
      "command,c", bpo::value<std::string>(&sub_cmd), "sub command")(
      "input,i", bpo::value<std::string>(&input_name), "file.su3")(
      "output,o", bpo::value<std::string>(&output_name), "outputFile");

  bpo::positional_options_description pos;
  pos.add("command", 1).add("input", 1).add("output", 1);

  bpo::variables_map vm;
  try
    {
      bpo::parsed_options parsed =
          bpo::command_line_parser(args).options(desc).positional(pos).run();
      bpo::store(parsed, vm);
      bpo::notify(vm);
    }
  catch (...)
    {
      kovri::core::Exception ex(GetName().c_str());
      ex.Dispatch(__func__);
      return false;
    }

  if (vm.count("help"))
    {
      PrintUsage(cmd_name);
      return false;
    }

  if (input_name.empty())  // minimum sub command + file.su3
    {
      LOG(error) << "su3file: Not enough arguments !";
      PrintUsage(cmd_name);
      return false;
    }

  // Check supported sub command
  if ((sub_cmd != "showversion") && (sub_cmd != "verifysig")
      && (sub_cmd != "extract"))
    {
      LOG(error) << "su3file: Unknown command : " << sub_cmd;
      PrintUsage(cmd_name);
      return false;
    }
  // Get trusted certificates
  std::map<std::string, kovri::core::PublicKey> keys;
  if (vm.count("-k"))
    {
      kovri::core::X509 x509;
      boost::filesystem::path path(vm["-k"].as<std::string>());
      LOG(debug) << "su3file: Using cutom certificate " << path;
      // Sanity check
      if (!boost::filesystem::is_regular_file(path))
        {
          LOG(error) << "su3file: Certificate is not a regular file " << path;
          return false;
        }
      // Prepare stream
      std::ifstream ifs(path.string(), std::ifstream::binary);
      if (ifs.fail())
        {
          LOG(error) << "su3file: Failed to read certificate " << path.string();
          return false;
        }
      // Extract content
      std::stringstream ss;
      ss << ifs.rdbuf();
      ifs.close();
      // Get signing keys
      keys = x509.GetSigningKey(ss);
      if (keys.empty())
        {
          LOG(error) << "su3file: No keys in " << path.string();
          return false;
        }
    }
  else
    {
      boost::filesystem::path cert_dir_path =
          vm.count("cert-dir")
              ? boost::filesystem::path(vm["cert-dir"].as<std::string>())
              : kovri::core::GetSU3CertsPath();
      LOG(debug) << "su3file: Using certificates path " << cert_dir_path;
      if (!kovri::client::Reseed::ProcessCerts(&keys, cert_dir_path))
        {
          LOG(error) << "su3file: Failed to get trusted certificates !";
          return false;
        }
    }

  // Open input
  LOG(trace) << "su3file: input " << input_name;
  kovri::core::InputFileStream input(
      input_name, std::ios::in | std::ios::binary);
  if (input.Fail())
    {
      LOG(error) << "su3file: Failed to open input " << input_name;
      return false;
    }
  if (input.EndOfFile())
    {
      LOG(error) << "su3file: Empty input " << input_name;
      return false;
    }
  // Read all input
  std::size_t length(0);
  std::unique_ptr<std::uint8_t> buffer_ptr =
      input.ReadAll<std::uint8_t, std::size_t>(&length);
  if (!buffer_ptr)
    {
      LOG(error) << "su3file: Failed to read input " << input_name;
      return false;
    }
  // Process SU3
  std::string su3_str(buffer_ptr.get(), buffer_ptr.get() + length);
  kovri::client::SU3 su3(su3_str, keys);
  if (!su3.SU3Impl())
    {
      LOG(error) << "su3file: Failed to process input !";
      return false;
    }

  // sub command specific
  if (sub_cmd == "showversion")
    {
      LOG(info) << "Version: " << su3.GetVersion();
      LOG(info) << "Signer: " << su3.GetSignerId();
      LOG(info) << "SigType: "
                << kovri::core::GetSigningKeyTypeName(su3.GetSignatureType());
      LOG(info) << "Content: " << su3.ContentTypeToString(su3.GetContentType());
      LOG(info) << "FileType: " << su3.FileTypeToString(su3.GetFileType());
    }
  else if (sub_cmd == "verifysig")
    {
      LOG(info) << "su3file: Signer " << su3.GetSignerId();
    }
  else if (sub_cmd == "extract")
    {
      kovri::core::OutputFileStream output(
          output_name, std::ios::out | std::ios::binary);
      if (output.Fail())
        {
          LOG(error) << "su3file: Failed to open output : " << output_name;
          return false;
        }
      if (!su3.Extract(&output))
        {
          LOG(error) << "su3file: Failed to Extract ";
          return false;
        }
      LOG(debug) << "su3file: Extraction successfull ";
    }

  return true;
}
