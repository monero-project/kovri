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

#ifndef SRC_UTIL_BASE_H_
#define SRC_UTIL_BASE_H_

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "core/util/filesystem.h"
#include "util/command.h"

/**
 * @class BaseCommand
 * @brief base class for base32 and base64
 */

class BaseCommand : public Command
{
 public:
  BaseCommand();
  void PrintUsage(const std::string& cmd_name) const;
  bool Impl(const std::string&, const std::vector<std::string>& args);

 protected:
  virtual bool do_process(
      bool encode,
      kovri::core::InputFileStream* input,
      kovri::core::OutputFileStream* output) = 0;
  boost::program_options::options_description m_Desc;
  std::string m_OptType;
  std::string m_OptInfile;
  std::string m_OptOutfile;
};

/**
 * @class Base32Command
 * @brief command base32
 */

class Base32Command : public BaseCommand
{
 public:
  Base32Command() : BaseCommand()
  {
  }
  std::string GetName(void) const
  {
    return "base32";
  }

 protected:
  bool do_process(
      bool encode,
      kovri::core::InputFileStream* input,
      kovri::core::OutputFileStream* output);
};

/**
 * @class Base64Command
 * @brief command base64
 */

class Base64Command : public BaseCommand
{
 public:
  Base64Command() : BaseCommand()
  {
  }
  std::string GetName(void) const
  {
    return "base64";
  }

 protected:
  bool do_process(
      bool encode,
      kovri::core::InputFileStream* input,
      kovri::core::OutputFileStream* output);
};

#endif  // SRC_UTIL_BASE_H_
