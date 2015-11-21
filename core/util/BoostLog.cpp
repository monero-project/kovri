//
// boost::log logging implementation
//
#include "BoostLog.h"
#include <memory>
#include <boost/core/null_deleter.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks.hpp>
#include <boost/log/sources/channel_feature.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/sources/severity_feature.hpp>
namespace kovri
{
namespace log
{
    std::shared_ptr<Log> g_Log = nullptr;
    sink_ptr g_LogSink;
    
    LogImpl::LogImpl(LogLevel minlev, std::ostream * out)
    {
        auto core = boost::log::core::get();
        m_LogBackend = boost::make_shared<backend_t>();
        m_LogBackend->add_stream(boost::shared_ptr<std::ostream> (out, boost::null_deleter()));
        g_LogSink = boost::shared_ptr<sink_t>(new sink_t(m_LogBackend));
        g_LogSink->set_filter(boost::log::expressions::attr<LogLevel>("Severity") >= minlev);
        g_LogSink->set_formatter(&LogImpl::Format);
        core->add_sink(g_LogSink);
        core->add_global_attribute("Timestamp", boost::log::attributes::local_clock());
        
    }

   
    Log::Log(LogLevel minlev, std::ostream * out)
    {
        m_LogImpl = std::make_shared<LogImpl>(minlev, out);
        m_DefaultLogger = std::make_shared<Logger>(new LoggerImpl);
    }

    LoggerImpl::LoggerImpl(const std::string & name, const std::string & channel) : log(boost::log::keywords::channel = channel),
                                                                                    m_Debug(new LogStreamImpl(log, eLogDebug)),
                                                                                    m_Info(new LogStreamImpl(log, eLogInfo)),
                                                                                    m_Warn(new LogStreamImpl(log, eLogWarning)),
                                                                                    m_Error(new LogStreamImpl(log, eLogError))
    {
    }
    
    LoggerImpl::LoggerImpl() : LoggerImpl("default", "default")
    {
    }    

    LogStreamImpl::LogStreamImpl(log_t & l, LogLevel level) :
        log(l),
        m_Level(level),
        m_Enable(true)

    {
        //m_Log.add_global_attribute("Logger", m_ParentName);
    }


    LogStream & Logger::Error()
    {
        return m_Impl->Error();
    }

    LogStream & Logger::Warning()
    {
        return m_Impl->Warning();
    }

    LogStream & Logger::Info()
    {
        return m_Impl->Info();
    }

    LogStream & Logger::Debug()
    {
        return m_Impl->Debug();
    }

    void Logger::Flush()
    {
        g_LogSink->flush();
    }

    Logger::Logger(LoggerImpl * impl) : m_Impl(impl) {}
    
    Logger::~Logger()
    {
        delete m_Impl;
    }
    
    LogStream::LogStream(LogStreamImpl * impl) : m_Impl(impl) {}
    LogStream::~LogStream() { delete m_Impl; }
    
    const LogStream & LogStream::Meta(const std::string & key, std::string value)
    {
        // this doesn't do anything yet
        // m_Impl->MetaImpl(key, value);
        return *this;
    }

    void LogStream::operator << (const std::string & str)
    {
        m_Impl->LogStr(m_Impl->log, str);

    }
    
    void LogStreamImpl::LogStr (log_t & log, const std::string & str) 
    {
        /*
        auto rec = m_Log.open_record(boost::log::keywords::severity = m_Level);
        if (rec)
        {
            boost::log::record_ostream s(rec);
            s << str;
            s.flush();
            m_Log.push_record(boost::move(rec));
        }
        */
        BOOST_LOG_SEV(log, m_Level) << str;
        Flush();
    }

    void LogStreamImpl::Flush()
    {
        g_LogSink->flush();
    }

    void LogStream::Flush()
    {
        m_Impl->Flush();
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
    
    std::ostream & operator<<(std::ostream & out, LogLevel lev)
    {
        static const char * levels[] =
        {
            "DBG", // debug
            "NFO", // info
            "WRN", // warning
            "ERR"  // error
        };
        if (static_cast<std::size_t>(lev) < sizeof(levels) / sizeof(*levels))
        {
            out << levels[lev];
        } else
        {
            out << "?" << static_cast<int>(lev) << "?";
        }
        return out;
    }
    
    void LogImpl::Format(boost::log::record_view const & rec, boost::log::formatting_ostream &s)
    {
        //const boost::log::attribute_value_set& attrs = rec.attribute_values();
        static std::locale loc(std::clog.getloc(), new boost::posix_time::time_facet("%Y:%m:%d:%T.%f"));
        std::stringstream ss;
        ss.imbue(loc);
        ss << boost::log::extract<boost::posix_time::ptime>("Timestamp", rec) << ' ';
        s << ss.str();
        s << boost::log::extract<std::string>("Channel", rec) << "::";
        s << boost::log::extract<LogLevel>("Severity", rec) << "\t\t";
        s << rec[boost::log::expressions::smessage];
    }
    
    void LogImpl::Flush()
    {
        g_LogSink->flush();
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
    
}
}
