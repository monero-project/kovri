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

//
// std::ostream logging backend
//
#include "PrintLog.h"

namespace kovri
{
namespace log
{

    std::shared_ptr<Log> g_Log =  nullptr;

    Logger::~Logger() { delete m_Impl; }
    Logger::Logger(LoggerImpl * impl) : m_Impl(impl) {}
    
    LogStream::LogStream(LogStreamImpl * impl) : std::ostream(impl),  m_Impl(impl) {}
    LogStream::~LogStream() { delete m_Impl; }

    LogStream & LogStream::Flush()
    {
        // we don't want to flush anything here
        return *this;
    }
    
    LogStream & LoggerImpl::GetLogStream(const std::string & name)
    {
        m_LogMtx.lock();
        m_LogStream << m_LogName << "\t" << name << "\t";
        return m_LogStream;
    }

    LogStreamImpl::int_type LogStreamImpl::overflow(int_type ch)
    {
        return std::streambuf::overflow(ch);
    }
    // called when we get std::flush
    int LogStreamImpl::sync()
    {
        int ret;
        // sync out std::stringbuf
        ret = m_Str.pubsync();
        // flush to std::ostream
        m_Out << &m_Str;
        m_Out << std::endl;
        m_Str = std::stringbuf();
        // unlock our access mutex so that others can now acquire the log stream
        m_Access.unlock();
        return ret;
    }

    // not thread safe
    std::streamsize LogStreamImpl::xsputn(const LogStreamImpl::char_type * s, std::streamsize count)
    {
        return m_Str.sputn(s, count);
    }

    bool LogStream::IsEnabled()
    {
        return m_Impl->IsEnabled();
    }

    void LogStream::Disable()
    {
        m_Impl->Disable();
    }

    void LogStream::Enable()
    {
        m_Impl->Enable();
    }    
    
    LogStream & Logger::Debug()
    {
        return m_Impl->GetLogStream("DBG");
    }
    
    LogStream & Logger::Info()
    {
        return m_Impl->GetLogStream("NFO");
    }
    
    LogStream & Logger::Warning()
    {
        return m_Impl->GetLogStream("WRN");
    }

    LogStream & Logger::Error()
    {
        return m_Impl->GetLogStream("ERR");
    }

    void Logger::Flush()
    {
    }

    Log::Log(LogLevel minLev, std::ostream * out)
    {
        m_LogImpl = std::make_shared<LogImpl>(minLev, *out);
        m_DefaultLogger = std::make_shared<Logger>(new LoggerImpl(minLev, "default", *out));
    }

    LogImpl::LogImpl(LogLevel minLev, std::ostream & out) : m_LogLevel(minLev), m_Out(out) 
    {
    }

    std::shared_ptr<Log> Log::Get()
    {
        // make default logger if we don't have a logger
        if(g_Log == nullptr) g_Log = std::make_shared<Log>(eLogDebug, &std::clog);
        return g_Log;
    }
    
    std::shared_ptr<Logger> Log::Default()
    {
        return m_DefaultLogger;
    }

    std::unique_ptr<Logger> Log::New(const std::string & name, const std::string & channel)
    {
        return std::unique_ptr<Logger>(new Logger(new LoggerImpl(m_LogImpl->CurrentLevel(), name, m_LogImpl->Out())));
    }
    
}
}
