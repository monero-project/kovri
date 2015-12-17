#pragma once
#include <string>

#ifdef _WIN32
#define Daemon i2p::util::DaemonWin32::Instance()
#else
#define Daemon i2p::util::DaemonLinux::Instance()
#endif
#include "util/Log.h"

namespace i2p
{
    namespace util
    {
        class Daemon_Singleton
        {
        public:
            virtual bool Init();
            virtual bool Start();
            virtual bool Stop();

            bool m_isDaemon, m_isLogging, m_isRunning;

        protected:
            Daemon_Singleton();
            virtual ~Daemon_Singleton();

            bool IsService() const;

            std::shared_ptr<kovri::log::Log> m_log;
        };

#ifdef _WIN32
        class DaemonWin32 : public Daemon_Singleton
        {
        public:
            static DaemonWin32& Instance()
            {
                static DaemonWin32 instance;
                return instance;
            }

            virtual bool Init();
            virtual bool Start();
            virtual bool Stop();
        };
#else
        class DaemonLinux : public Daemon_Singleton
        {
        public:
            DaemonLinux() = default;

            static DaemonLinux& Instance()
            {
                static DaemonLinux instance;
                return instance;
            }

            virtual bool Start();
            virtual bool Stop();

         private:
                std::string m_pidfile;
                int m_pidFilehandle;

        };
#endif
    }
}
