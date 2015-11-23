#ifndef BOOST_LOG_H__
#define BOOST_LOG_H__
#include "Log.h"
#include <boost/log/core/core.hpp>
#include <boost/log/sinks/async_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/sources/severity_channel_logger.hpp>
#include <memory>
#include <mutex>

namespace kovri
{
namespace log
{
    typedef boost::log::core_ptr core_ptr;
    
    typedef boost::log::sinks::text_ostream_backend backend_t;
    typedef boost::shared_ptr<backend_t> backend_ptr;
    
    typedef boost::log::sinks::asynchronous_sink< backend_t > sink_t;
    typedef boost::shared_ptr<sink_t> sink_ptr;
    
    typedef boost::log::sources::severity_channel_logger_mt<LogLevel, std::string> log_t;
    
    class LogStreamImpl 
    {
    public:
        LogStreamImpl(std::mutex & access, log_t & l, LogLevel levelno);
        ~LogStreamImpl() {}
        void MetaImpl(const std::string & key, std::string value);
        void Flush();
        bool IsEnabled() { return m_Enable; };
        void Disable() { m_Enable = false; };
        void Enable() { m_Enable = true; };
        std::stringbuf * Stream() { return &m_Str; }
    private:
        std::mutex & m_Access;
        log_t & m_Log;
        LogLevel m_Level;
        bool m_Enable;
        std::stringbuf m_Str;
    };

    class BoostEventStream : public EventStream
    {
    public:
        virtual EventStream & Flush() const {};
        virtual EventStream & operator << (const std::vector<std::string> & strs ) const {};
    };
    
    class LoggerImpl
    {
    public:
        /**
           Construct default Logger
         */
        LoggerImpl();
        /**
           Construct logger with a name that belongs in 1 log channel
         */
        LoggerImpl(const std::string & name, const std::string & channel);
        LogStream & Debug(); 
        LogStream & Info(); 
        LogStream & Warning(); 
        LogStream & Error();
        EventStream & UI() { return m_Events; }
        log_t log;
    private:
        std::mutex m_DebugMtx, m_InfoMtx, m_WarnMtx, m_ErrorMtx;
        LogStream m_Debug, m_Info, m_Warn, m_Error;
        BoostEventStream m_Events;
    };

    class LogImpl
    {
    public:
        LogImpl(LogLevel minLevel, std::ostream * out);
        LogImpl() : LogImpl(eLogWarning, &std::clog) {}
        void Flush();
    private:
        backend_ptr m_LogBackend;
        core_ptr m_LogCore;
        static void Format(boost::log::record_view const & rec, boost::log::formatting_ostream &s);
    };
}
}

#endif
