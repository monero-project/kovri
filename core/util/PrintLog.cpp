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
        auto log = Log::Get();
        return log->m_DefaultLogger;
    }

    std::shared_ptr<Logger> Log::New(const std::string & name, const std::string & channel)
    {
        auto log = Log::Get();
        return std::make_shared<Logger>(new LoggerImpl(log->m_LogImpl->CurrentLevel(), name, log->m_LogImpl->Out()));
    }
    
}
}
