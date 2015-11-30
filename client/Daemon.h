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
        class Daemon_Singleton_Private;
        class Daemon_Singleton
        {
        public:
            virtual bool init();
            virtual bool start();
            virtual bool stop();

            bool m_isDaemon, m_isLogging, m_isRunning;

        protected:
            Daemon_Singleton();
            virtual ~Daemon_Singleton();

            bool IsService() const;

            // d-pointer for httpServer, httpProxy, etc.
            class Daemon_Singleton_Private;
            Daemon_Singleton_Private &m_dsp;
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

            virtual bool init();
            virtual bool start();
            virtual bool stop();
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

            virtual bool start();
            virtual bool stop();

         private:
                std::string m_pidfile;
                int m_pidFilehandle;

        };
#endif
    }
}
