#ifndef LOG_H__
#define LOG_H__

#include <iostream>
#include <string>
#include <memory>
#include <vector>

namespace kovri
{
namespace log
{

    enum LogLevel
    {
        eLogLevelDebug,
        eLogLevelInfo,
        eLogLevelWarning,
        eLogLevelError
    };

    // private implemenation of LogStream
    class LogStreamImpl;

    
    /**
       Generic Log stream
    */
    class LogStream : public std::ostream
    {
    public:

        LogStream(LogStreamImpl * impl);
        ~LogStream();
        
        /**
           attach metadata to the current logger's next entries until flushed
         */
        LogStream & Meta(const std::string & key, std::string value);
        /**
           flush this log stream
         */
        LogStream & Flush();
        
        /**
           check if this stream is enabled
           return true if it is
         */
        bool IsEnabled();

        /**
           disable logging on this stream
         */
        void Disable();

        /**
           enable logging on this stream
         */
        void Enable();
        
    private:
        LogStreamImpl * m_Impl;
    };

    /**
       Stream for sending events to live UI
       TODO: implement
     */
    class EventStream
    {
    public:
        /**
           flush events
         */
        virtual EventStream & Flush() const = 0;

        /**
           operator overload for <<
           queue an event
         */
        virtual EventStream & operator << (const std::vector<std::string> & strs) const = 0;
    };

    // private implementation of Logger
    class LoggerImpl;
    
    class Logger
    {
    public:

        Logger(LoggerImpl * impl);
        ~Logger();
        
        /**
           get error level log stream
         */
        LogStream & Error();
        /**
           get warning level log stream
         */
        LogStream & Warning();
        /**
           get info level log stream
         */
        LogStream & Info();
        /**
           get debug level log stream
         */
        LogStream & Debug();
        /**
           get EventStream to send events to UI
         */
        EventStream & UI();

        /**
           flush pending log events
         */
        void Flush();
    private:
        LoggerImpl * m_Impl;
    };

    class LogImpl;
    
    class Log
    {
    public:
        Log(LogLevel minLev, std::ostream * out);
        Log() : Log(eLogLevelWarning, &std::clog) {}
        
        /**
           Get global log engine
         */
        static std::shared_ptr<Log> Get();
        /**
           get default logger
         */
        static std::shared_ptr<Logger> Default();
        
        /**
           create new logger
         */
        static std::shared_ptr<Logger> New(const std::string & name, const std::string & channel);
    private:
        std::shared_ptr<LogImpl> m_LogImpl;
        std::shared_ptr<Logger> m_DefaultLogger;
    };
}    
}

#include "util/OldLog.h"

#endif
