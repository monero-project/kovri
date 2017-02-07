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
#include <string>

#include "core/util/log.h"

namespace kovri {
namespace core {

Exception::Exception(const char* message) : m_CtorMessage(message) {}

// TODO(anonimal): exception error codes to replace strings?
void Exception::Dispatch(const char* message) {
  // Reset previous Message
  m_Message.clear();
  // Set new message with formatting
  if (!m_CtorMessage.empty())
    m_Message += m_CtorMessage + ": ";
  m_Message += message;
  m_Message += ": ";
  // Throw original exception
  try {
    throw;
#ifdef WITH_CRYPTOPP
  // Note: CryptoPP::Exception inherits std::exception
  } catch (const CryptoPP::Exception& ex) {
    LOG(error) << m_Message << "cryptopp exception" << ": '" << ex.what() << "'";
#endif
  // TODO(anonimal): boost exception/exception_ptr
  } catch (const std::exception& ex) {
    LOG(error) << m_Message << "standard exception" << ": '" << ex.what() << "'";
  } catch (...) {
    LOG(error) << m_Message << "unknown exception";
  }
}

}  // namespace core
}  // namespace kovri
