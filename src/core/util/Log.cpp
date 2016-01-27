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

#include "Log.h"

#include <memory>
#include <string>

namespace i2p {
namespace util {
namespace log {

static std::shared_ptr<Log> g_Log = nullptr;
sink_ptr g_LogSink;

//
// LogStreamImpl <- LogStream
//
LogStreamImpl::LogStreamImpl(
    std::mutex& mtx,
    log_t& l,
    LogLevel level)
    : m_Str(new std::stringbuf),
      m_Access(mtx),
      m_Log(l),
      m_Level(level),
      m_Enable(true) {
      // m_Log.add_global_attribute("Logger", m_ParentName);
}

LogStreamImpl::~LogStreamImpl() {
  delete m_Str;
}

void LogStreamImpl::WaitForReady() {
  {
    std::lock_guard<std::mutex> lock(m_Access);
  }
}

LogStreamImpl::int_type LogStreamImpl::overflow(
    int_type ch) {
  return std::streambuf::overflow(ch);
}

int LogStreamImpl::sync() {
  int ret = 0;
  ret = m_Str->pubsync();
  Flush();
  m_Access.unlock();
  return ret;
}

// not thread safe
std::streamsize LogStreamImpl::xsputn(
    const LogStreamImpl::char_type* s,
    std::streamsize count) {
  return m_Str->sputn(s, count);
}

// not thread safe
void LogStreamImpl::Flush() {
  if (g_Log->Silent()) {
    // don't log if we are silent
    return;
  }
  BOOST_LOG_SEV(m_Log, m_Level) << m_Str;
  delete m_Str;
  m_Str = new std::stringbuf;
  g_LogSink->flush();
}

//
// LogStream
//
LogStream::LogStream(
    LogStreamImpl* impl)
    : std::ostream(impl),
      m_Impl(impl) {}

LogStream::~LogStream() {
  delete m_Impl;
}

LogStream& LogStream::Flush() {
  g_LogSink->flush();
  return *this;
}

bool LogStream::IsEnabled() {
  return m_Impl->IsEnabled();
}

void LogStream::Disable() {
  m_Impl->Disable();
}

void LogStream::Enable() {
  m_Impl->Enable();
}

/**
 * TODO(unassigned): implement
 * LogStream& LogStream::Meta(
 *     const std::string& key,
 *     std::string value) {
 *   //TODO(unassigned): this doesn't do anything yet
 *   m_Impl->MetaImpl(key, value);
 *   return *this;
 * }
*/

//
// LoggerImpl <- Logger
//
LoggerImpl::LoggerImpl(
    const std::string& name,
    const std::string& channel)
    : log(boost::log::keywords::channel = channel),
      m_Debug(new LogStreamImpl(m_DebugMtx, log, eLogDebug)),
      m_Info(new LogStreamImpl(m_InfoMtx, log, eLogInfo)),
      m_Warn(new LogStreamImpl(m_WarnMtx, log, eLogWarning)),
      m_Error(new LogStreamImpl(m_ErrorMtx, log, eLogError)) {
  log.add_attribute(
      "LogName",
      boost::log::attributes::constant< std::string >(name));
}

LoggerImpl::LoggerImpl()
    : LoggerImpl("default", "default") {}

LogStream& LoggerImpl::Debug() {
  return GetLogger(m_Debug, m_DebugMtx);
}

LogStream& LoggerImpl::Info() {
  return GetLogger(m_Info, m_InfoMtx);
}

LogStream& LoggerImpl::Warning() {
  return GetLogger(m_Warn, m_WarnMtx);
}

LogStream& LoggerImpl::Error() {
  return GetLogger(m_Error, m_ErrorMtx);
}

LogStream& LoggerImpl::GetLogger(
    LogStream& l,
    std::mutex & mtx) {
  mtx.lock();
  return l;
}

//
// Logger
//
Logger::Logger(
    LoggerImpl* impl)
    : m_Impl(impl) {}

Logger::~Logger() {
  delete m_Impl;
}

LogStream& Logger::Error() {
  return m_Impl->Error();
}

LogStream& Logger::Warning() {
  return m_Impl->Warning();
}

LogStream& Logger::Info() {
  return m_Impl->Info();
}

LogStream& Logger::Debug() {
  return m_Impl->Debug();
}

void Logger::Flush() {
  g_LogSink->flush();
}

//
// LogImpl <- Log
//
LogImpl::LogImpl(
    LogLevel minlev,
    std::ostream* out) {
  m_LogCore = boost::log::core::get();
  m_LogBackend = boost::make_shared<backend_t>();
  m_LogBackend->add_stream(
      boost::shared_ptr<std::ostream>(
        out,
        boost::null_deleter()));
  g_LogSink = boost::shared_ptr<sink_t>(
      new sink_t(
        m_LogBackend));
  g_LogSink->set_filter(
      boost::log::expressions::attr<LogLevel>(
        "Severity") >= minlev);
  g_LogSink->set_formatter(&LogImpl::Format);
  m_LogCore->add_sink(g_LogSink);
  m_LogCore->add_global_attribute(
      "Timestamp",
      boost::log::attributes::local_clock());
}

void LogImpl::Format(
    boost::log::record_view const& rec,
    boost::log::formatting_ostream &s) {
  // const boost::log::attribute_value_set& attrs = rec.attribute_values();
  static std::locale loc(
      std::clog.getloc(),
      new boost::posix_time::time_facet("%Y:%m:%d|%T.%f"));
  std::stringstream ss;
  ss.imbue(loc);
  ss << boost::log::extract<boost::posix_time::ptime>("Timestamp", rec) << ' ';
  s << ss.str();
  s << boost::log::extract<std::string>("Channel", rec) << ":";
  s << boost::log::extract<std::string>("LogName", rec) << "\t\t";
  s << boost::log::extract<LogLevel>("Severity", rec) << "\t\t";
  s << rec[boost::log::expressions::smessage];
}

void LogImpl::Flush() {
  g_LogSink->flush();
}

void LogImpl::Stop() {
  m_Silent = true;
}

bool LogImpl::IsSilent() {
  return m_Silent;
}

//
// Log
//
Log::Log(
    LogLevel minlev,
    std::ostream* out) {
  m_LogImpl = std::make_shared<LogImpl>(minlev, out);
  m_DefaultLogger = std::make_shared<Logger>(new LoggerImpl);
}

std::shared_ptr<Log> Log::Get() {
  // make default logger if we don't have a logger
  if (g_Log == nullptr)
    g_Log = std::make_shared<Log>(eLogDebug, &std::clog);
  return g_Log;
}

std::shared_ptr<Logger> Log::Default() {
  return m_DefaultLogger;
}

std::unique_ptr<Logger> Log::New(
    const std::string& name,
    const std::string& channel) {
  return std::unique_ptr<Logger>(
      new Logger(
          new LoggerImpl(
              name,
              channel)));
}

void Log::Stop() {
  m_LogImpl->Stop();
}

bool Log::Silent() {
  return m_LogImpl->IsSilent();
}

std::ostream& operator<<(
    std::ostream& out,
    LogLevel lev) {
  static const char* levels[] = {
    "DBG",  // debug
    "NFO",  // info
    "WRN",  // warning
    "ERR"   // error
  };
  if (static_cast<std::size_t>(lev) < sizeof(levels) / sizeof(*levels)) {
    out << levels[lev];
  } else {
    out << "?" << static_cast<int>(lev) << "?";
  }
  return out;
}

}  // namespace log
}  // namespace util
}  // namespace i2p

//
// Deprecated
//
void DeprecatedStartLog(
    const std::string& fullFilePath) {
  std::cerr << "Not opening log file: " << fullFilePath << std::endl;
}

void DeprecatedStartLog(
    std::ostream* s) {
  *s << "Deprecated Logging not implemented" << std::endl;
}

void DeprecatedStopLog() {}
