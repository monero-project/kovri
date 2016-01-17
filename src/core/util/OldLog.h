/**
 * Copyright (c) 2015-2016, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SRC_CORE_UTIL_OLDLOG_H_
#define SRC_CORE_UTIL_OLDLOG_H_

// Old Logging API

#include <iostream>
#include <sstream>
#include <string>

#define eLogDebug kovri::log::eLogLevelDebug
#define eLogInfo kovri::log::eLogLevelInfo
#define eLogWarning kovri::log::eLogLevelWarning
#define eLogError kovri::log::eLogLevelError

void DeprecatedStartLog(
    const std::string& fullFilePath);

void DeprecatedStartLog(
    std::ostream* s);

void DeprecatedStopLog();

template<typename TValue>
void DeprecatedLog(
    std::ostream& s,
    TValue arg) {
  s << arg;
}


template<typename TValue, typename... TArgs>
void DeprecatedLog(
    std::ostream& s,
    TValue arg,
    TArgs... args) {
  DeprecatedLog(s, arg);
  DeprecatedLog(s, args...);
}


template<typename... TArgs>
void DeprecatedLogPrint(
    kovri::log::LogLevel level,
    TArgs... args) {
  auto l = kovri::log::Log::Get();
  if (l == nullptr) {
    // fallback logging to std::clog
    std::clog << "!!! ";
    DeprecatedLog(std::clog, args...);
    std::clog << std::endl;
  } else {
    auto log = l->Default();
    if (level == eLogDebug) {
      auto & s = log->Debug();
      DeprecatedLog(s, args...);
      s << std::flush;
    } else if (level == eLogInfo) {
      auto & s = log->Info();
      DeprecatedLog(s, args...);
      s << std::flush;
    } else if (level == eLogWarning) {
      auto & s = log->Warning();
      DeprecatedLog(s, args...);
      s << std::flush;
    } else  {
      auto & s = log->Error();
      DeprecatedLog(s, args...);
      s << std::flush;
    }
  }
}

template<typename... TArgs>
void DeprecatedLogPrint(
    TArgs... args) {
  DeprecatedLogPrint(eLogInfo, args...);
}
#define StopLog DeprecatedStopLog
#define StartLog DeprecatedStartLog
#define LogPrint DeprecatedLogPrint

#endif  // SRC_CORE_UTIL_OLDLOG_H_
