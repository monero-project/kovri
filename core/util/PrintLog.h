#ifndef PRINT_LOG_H__
#define PRINT_LOG_H__
#include "Log.h"
#include <mutex>

/* TODO: implement */

namespace kovri
{
namespace log
{
    class LogStreamImpl : public std::streambuf
    {
    public:
        LogStreamImpl(std::ostream & out, std::mutex & mtx) : m_Out(out), m_Access(mtx), m_Enable(true) {}
        ~LogStreamImpl() {}
        void MetaImpl(const std::string & key, std::string & value) {}
        bool IsEnabled() { return m_Enable; };
        void Disable() { m_Enable = false; };
        void Enable() { m_Enable = true; };
        int_type overflow(int_type ch);
    protected:
        using char_type = typename std::streambuf::char_type;
        int sync();
        std::streamsize xsputn( const char_type* s, std::streamsize count );
    private:
        std::stringbuf m_Str;
        std::ostream & m_Out;
        std::mutex & m_Access;
        bool m_Enable;
    };

    class LoggerImpl
    {
    public:
        LoggerImpl(LogLevel minlev, const std::string & name, std::ostream & out) : m_MinLevel(minlev), m_LogName(name), m_Out(out), m_LogStream(new LogStreamImpl(m_Out, m_LogMtx)) {}
        LogStream & GetLogStream(const std::string & name);
        void SetMinLevel(LogLevel lev) { m_MinLevel = lev; }
    private:
        LogLevel m_MinLevel;
        std::string m_LogName;
        std::mutex m_LogMtx;
        std::ostream & m_Out;
        LogStream m_LogStream;
    };

    class LogImpl
    {
    public:
        LogImpl(LogLevel minLevel, std::ostream & out);
        LogImpl() : LogImpl(eLogDebug, std::clog) {}
        std::ostream & Out() { return m_Out; }
        LogLevel CurrentLevel() { return m_LogLevel; }
    private:
        LogLevel m_LogLevel;
        std::ostream & m_Out;
    };
}
}

#endif
