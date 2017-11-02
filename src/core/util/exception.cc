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

#ifdef WITH_CRYPTOPP
#include <cryptopp/cryptlib.h>
#endif

#include <exception>

#include <boost/program_options.hpp>
#include "core/util/log.h"

namespace kovri {
namespace core {

Exception::Exception(const char* message) : m_Message(message) {}

// TODO(anonimal): exception error codes to replace strings?
void Exception::Dispatch(const char* message)
{
  // Message to log
  std::string log;

  // Begin formatting. Ctor string is usually a class name.
  if (!m_Message.empty())
    {
      log += m_Message + ": ";
    }

  // Complete the dispatched message
  std::string msg(message);
  if (!msg.empty())
    {
      log += msg;
      log += ": ";
    }

  // Throw original exception
  try {
    throw;
#ifdef WITH_CRYPTOPP
  // Note: CryptoPP::Exception inherits std::exception
  } catch (const CryptoPP::Exception& ex) {
    LOG(error) << log << "cryptopp exception" << ": '" << ex.what() << "'";
#endif
  // TODO(anonimal): boost exception/exception_ptr
  } catch (const boost::program_options::error& ex) {
    LOG(error) << log << "program option exception"
               << ": '" << ex.what() << "'";
  } catch (const std::exception& ex) {
    LOG(error) << log << "standard exception" << ": '" << ex.what() << "'";
  } catch (...) {
    LOG(error) << log << "unknown exception";
  }
}

}  // namespace core
}  // namespace kovri
