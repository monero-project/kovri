#include <thread>
#include "ClientContext.h"
#include "Daemon.h"
#include "Destination.h"
#include "Garlic.h"
#include "NetworkDatabase.h"
#include "RouterContext.h"
#include "RouterInfo.h"
#include "Streaming.h"
#include "transport/NTCPSession.h"
#include "transport/Transports.h"
#include "tunnel/Tunnel.h"
#include "Version.h"

namespace i2p
{
    namespace util
    {
        Daemon_Singleton::Daemon_Singleton() :
		m_isRunning(1),
		m_log(kovri::log::Log::Get()) {};
        Daemon_Singleton::~Daemon_Singleton() {};

        bool Daemon_Singleton::IsService () const
        {
#ifndef _WIN32
            return i2p::util::config::varMap["service"].as<bool>();
#else
            return false;
#endif
        }

        bool Daemon_Singleton::Init()
        {
            i2p::context.Init();

	    m_isDaemon = i2p::util::config::varMap["daemon"].as<bool>();
	    m_isLogging = i2p::util::config::varMap["log"].as<bool>();

            int port = i2p::util::config::varMap["port"].as<int>();
            i2p::context.UpdatePort(port);

            i2p::context.UpdateAddress(
                boost::asio::ip::address::from_string(
                    i2p::util::config::varMap["host"].as<std::string>()
                )
            );

            i2p::context.SetSupportsV6(i2p::util::config::varMap["v6"].as<bool>());
            i2p::context.SetFloodfill(i2p::util::config::varMap["floodfill"].as<bool>());
            auto bandwidth = i2p::util::config::varMap["bandwidth"].as<std::string>();

            if(bandwidth.length() > 0)
            {
                if (bandwidth[0] > 'L')
                    i2p::context.SetHighBandwidth();
                else
                    i2p::context.SetLowBandwidth();
            }   

            return true;
        }
            
        bool Daemon_Singleton::Start()
        {
            LogPrint("The Kovri I2P Router Project");
            LogPrint("Version ", KOVRI_VERSION);
            LogPrint("Listening on port ", i2p::util::config::varMap["port"].as<int>());

            if (m_isLogging) {
                if (m_isDaemon) {
                    std::string logfile_path = IsService() ? "/var/log" :
			i2p::util::filesystem::GetDataPath().string();
#ifndef _WIN32
                    logfile_path.append("/kovri.log");
#else
                    logfile_path.append("\\kovri.log");
#endif
                    StartLog (logfile_path);
                }
                else
                    StartLog (""); // write to stdout
            }
            
            try {
                LogPrint("Starting NetDB...");
                if(i2p::data::netdb.Start()) {
                    LogPrint("NetDB started");
                } else {
                    LogPrint("NetDB failed to start");
                    return false;
                }

                LogPrint("Starting transports...");
                i2p::transport::transports.Start();
                LogPrint("Transports started");

                LogPrint("Starting tunnels...");
                i2p::tunnel::tunnels.Start();
                LogPrint("Tunnels started");

                LogPrint("Starting client...");
                i2p::client::context.Start ();
                LogPrint("Client started");

            } catch (std::runtime_error & e) {
                LogPrint(eLogError, e.what());
                return false;
            }
            return true;
        }

        bool Daemon_Singleton::Stop()
        {
            LogPrint("Stopping client...");
            i2p::client::context.Stop();
            LogPrint("Client stopped");

            LogPrint("Stopping tunnels...");
            i2p::tunnel::tunnels.Stop();
            LogPrint("Tunnels stopped");

            LogPrint("Stopping transports...");
            i2p::transport::transports.Stop();
            LogPrint("Transports stopped");

            LogPrint("Stopping NetDB...");
            i2p::data::netdb.Stop();
            LogPrint("NetDB stopped");

	    LogPrint("Goodbye!");
            StopLog();
            return true;
        }
    }
}
