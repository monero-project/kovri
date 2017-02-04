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

#ifndef SRC_CORE_UTIL_EXCEPTION_H_
#define SRC_CORE_UTIL_EXCEPTION_H_

#include <string>

namespace kovri {
namespace core {

/// TODO(anonimal): not yet a true exception class; could be more useful as a polymorphic class
/// @class Exception
/// @brief Exception dispatcher class
/// @notes A global exception class, kept in core namespace (for now)
class Exception final {
 public:
  /// @brief Constructs exception message
  /// TODO(anonimal): this is a semi-useful hack to get caller's class name until class-name logging attribute is implemented
  explicit Exception(const char* message = "");

  /// @brief Exception class dispatcher
  /// @details Set optional exception message, concats messages, adds trivial formatting
  /// @param message String message to log for exception
  void Dispatch(const char* message = "");

 private:
  std::string m_CtorMessage, m_Message;
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_UTIL_EXCEPTION_H_
