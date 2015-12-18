#include <fstream>
#include <iostream>

#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "ClientContext.h"
#include "Identity.h"
#include "util/Log.h"

namespace i2p
{
namespace client
{
    ClientContext context;  

    ClientContext::ClientContext () :
        m_SharedLocalDestination (nullptr),
        m_HttpProxy (nullptr),
        m_SocksProxy (nullptr),
        m_I2PControlService (nullptr) {}
    
    ClientContext::~ClientContext () 
    {
        delete m_HttpProxy;
        delete m_SocksProxy;
        delete m_I2PControlService;
    }
    
    void ClientContext::Start ()
    {
        if (!m_SharedLocalDestination)
        {   
            m_SharedLocalDestination = CreateNewLocalDestination (); // non-public, DSA
            m_Destinations[m_SharedLocalDestination->GetIdentity ().GetIdentHash ()] = m_SharedLocalDestination;
            m_SharedLocalDestination->Start ();
        }

        std::shared_ptr<ClientDestination> localDestination;    
        // proxies  
        std::string proxyKeys = i2p::util::config::varMap["proxykeys"].as<std::string>();
        if (proxyKeys.length () > 0)
            localDestination = LoadLocalDestination(proxyKeys, false);
        m_HttpProxy = new i2p::proxy::HTTPProxy(
	    i2p::util::config::varMap["httpproxyaddress"].as<std::string>(),
	    i2p::util::config::varMap["httpproxyport"].as<int>(),
            localDestination
        );
        m_HttpProxy->Start();
        LogPrint("HTTP Proxy started");

        m_SocksProxy = new i2p::proxy::SOCKSProxy(
	    i2p::util::config::varMap["socksproxyaddress"].as<std::string>(),
	    i2p::util::config::varMap["socksproxyport"].as<int>(),
            localDestination
        );
        m_SocksProxy->Start();
        LogPrint("SOCKS Proxy Started");
    
        // I2P tunnels
        std::string ircDestination = i2p::util::config::varMap["ircdest"].as<std::string>();
        if (ircDestination.length () > 0) // ircdest is presented
        {
            localDestination = nullptr;
            std::string ircKeys = i2p::util::config::varMap["irckeys"].as<std::string>();
            if (ircKeys.length () > 0)
                localDestination = LoadLocalDestination(ircKeys, false);
            auto ircPort = i2p::util::config::varMap["ircport"].as<int>();
            auto ircTunnel = new I2PClientTunnel(
                ircDestination, i2p::util::config::varMap["ircaddress"].as<std::string>(),
                ircPort, localDestination
            );
            ircTunnel->Start ();
            // TODO: allow multiple tunnels on the same port (but on a different address)
            m_ClientTunnels.insert(std::make_pair(
                ircPort, std::unique_ptr<I2PClientTunnel>(ircTunnel)
            ));
            LogPrint("IRC tunnel started");
        }   

        std::string eepKeys = i2p::util::config::varMap["eepkeys"].as<std::string>();
        if (eepKeys.length () > 0) // eepkeys file is presented
        {
            localDestination = LoadLocalDestination(eepKeys, true);
            auto serverTunnel = new I2PServerTunnel(i2p::util::config::varMap["eepaddress"].as<std::string>(),
                i2p::util::config::varMap["eepport"].as<int>(), localDestination);
            serverTunnel->Start ();
            m_ServerTunnels.insert(std::make_pair(localDestination->GetIdentHash(),
                std::unique_ptr<I2PServerTunnel>(serverTunnel))
	    );
            LogPrint("Server tunnel started");
        }

        ReadTunnels ();

        // I2P Control
        int i2pcontrolPort = i2p::util::config::varMap["i2pcontrolport"].as<int>();
        if(i2pcontrolPort) {
            m_I2PControlService = new i2pcontrol::I2PControlService(
                i2p::util::config::varMap["i2pcontroladdress"].as<std::string>(),
                i2pcontrolPort,
		i2p::util::config::varMap["i2pcontrolpassword"].as<std::string>()
            );
            m_I2PControlService->Start();
            LogPrint("I2PControl started");
        }
        m_AddressBook.Start (m_SharedLocalDestination.get());
    }
        
    void ClientContext::Stop ()
    {
        if (m_HttpProxy)
        {
            m_HttpProxy->Stop();
            delete m_HttpProxy;
            m_HttpProxy = nullptr;
            LogPrint("HTTP Proxy stopped");
        }
        if (m_SocksProxy)
        {
            m_SocksProxy->Stop();
            delete m_SocksProxy;
            m_SocksProxy = nullptr;
            LogPrint("SOCKS Proxy stopped");
        }
        for (auto& it: m_ClientTunnels)
        {
            it.second->Stop ();
            LogPrint("I2P client tunnel on port ", it.first, " stopped");   
        }
        m_ClientTunnels.clear ();   
        for (auto& it: m_ServerTunnels)
        {
            it.second->Stop ();
            LogPrint("I2P server tunnel stopped");  
        }
        m_ServerTunnels.clear ();   
        if (m_I2PControlService)
        {
            m_I2PControlService->Stop ();
            delete m_I2PControlService; 
            m_I2PControlService = nullptr;
            LogPrint("I2PControl stopped"); 
        }
        m_AddressBook.Stop ();    
        for (auto it: m_Destinations)
            it.second->Stop ();
        m_Destinations.clear ();
        m_SharedLocalDestination = nullptr; 
    }   
    
    std::shared_ptr<ClientDestination> ClientContext::LoadLocalDestination (const std::string& filename, bool isPublic)
    {
        i2p::data::PrivateKeys keys;
        std::string fullPath = i2p::util::filesystem::GetFullPath (filename);
        std::ifstream s(fullPath.c_str (), std::ifstream::binary);
        if (s.is_open ())   
        {   
            s.seekg (0, std::ios::end);
            size_t len = s.tellg();
            s.seekg (0, std::ios::beg);
            uint8_t * buf = new uint8_t[len];
            s.read ((char *)buf, len);
            keys.FromBuffer (buf, len);
            delete[] buf;
            LogPrint ("Local address ", m_AddressBook.ToAddress(keys.GetPublic ().GetIdentHash ()), " loaded");
        }   
        else
        {
            LogPrint ("Can't open file ", fullPath, " Creating new one");
            keys = i2p::data::PrivateKeys::CreateRandomKeys (i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256); 
            std::ofstream f (fullPath, std::ofstream::binary | std::ofstream::out);
            size_t len = keys.GetFullLen ();
            uint8_t * buf = new uint8_t[len];
            len = keys.ToBuffer (buf, len);
            f.write ((char *)buf, len);
            delete[] buf;
            
            LogPrint ("New private keys file ", fullPath, " for ", m_AddressBook.ToAddress(keys.GetPublic ().GetIdentHash ()), " created");
        }   

        std::shared_ptr<ClientDestination> localDestination = nullptr;  
        std::unique_lock<std::mutex> l(m_DestinationsMutex);    
        auto it = m_Destinations.find (keys.GetPublic ().GetIdentHash ()); 
        if (it != m_Destinations.end ())
        {
            LogPrint (eLogWarning, "Local destination ",  m_AddressBook.ToAddress(keys.GetPublic ().GetIdentHash ()), " alreday exists");
            localDestination = it->second;
        }
        else
        {
            localDestination = std::make_shared<ClientDestination> (keys, isPublic);
            m_Destinations[localDestination->GetIdentHash ()] = localDestination;
            localDestination->Start ();
        }
        return localDestination;
    }

    std::shared_ptr<ClientDestination> ClientContext::CreateNewLocalDestination (bool isPublic, i2p::data::SigningKeyType sigType,
        const std::map<std::string, std::string> * params)
    {
        i2p::data::PrivateKeys keys = i2p::data::PrivateKeys::CreateRandomKeys (sigType);
        auto localDestination = std::make_shared<ClientDestination> (keys, isPublic, params);
        std::unique_lock<std::mutex> l(m_DestinationsMutex);
        m_Destinations[localDestination->GetIdentHash ()] = localDestination;
        localDestination->Start ();
        return localDestination;
    }

    void ClientContext::DeleteLocalDestination (std::shared_ptr<ClientDestination> destination)
    {
        if (!destination) return;
        auto it = m_Destinations.find (destination->GetIdentHash ());
        if (it != m_Destinations.end ())
        {
            auto d = it->second;
            {
                std::unique_lock<std::mutex> l(m_DestinationsMutex);
                m_Destinations.erase (it);
            }   
            d->Stop ();
        }
    }

    std::shared_ptr<ClientDestination> ClientContext::CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic,
        const std::map<std::string, std::string> * params)
    {
        auto it = m_Destinations.find (keys.GetPublic ().GetIdentHash ());
        if (it != m_Destinations.end ())
        {
            LogPrint ("Local destination ", m_AddressBook.ToAddress(keys.GetPublic ().GetIdentHash ()), " exists");
            if (!it->second->IsRunning ())
            {   
                it->second->Start ();
                return it->second;
            }   
            return nullptr;
        }   
        auto localDestination = std::make_shared<ClientDestination> (keys, isPublic, params);
        std::unique_lock<std::mutex> l(m_DestinationsMutex);
        m_Destinations[keys.GetPublic ().GetIdentHash ()] = localDestination;
        localDestination->Start ();
        return localDestination;
    }
    
    std::shared_ptr<ClientDestination> ClientContext::FindLocalDestination (const i2p::data::IdentHash& destination) const
    {
        auto it = m_Destinations.find (destination);
        if (it != m_Destinations.end ())
            return it->second;
        return nullptr;
    }   

    void ClientContext::ReadTunnels ()
    {
        boost::property_tree::ptree pt;
        std::string pathTunnelsConfigFile = i2p::util::filesystem::GetTunnelsConfigFile().string();
        try {
            boost::property_tree::read_ini(
                pathTunnelsConfigFile,
                pt
            );
        } catch(const std::exception& ex) {
            LogPrint(eLogWarning, "Can't read ", pathTunnelsConfigFile, ": ", ex.what ());
            return;
        }
            
        int numClientTunnels = 0, numServerTunnels = 0;
        for(auto& section: pt) {
            std::string name = section.first;           
            try {
                std::string type = section.second.get<std::string> (I2P_TUNNELS_SECTION_TYPE);
                if(type == I2P_TUNNELS_SECTION_TYPE_CLIENT) {
                    // mandatory params
                    std::string dest = section.second.get<std::string> (I2P_CLIENT_TUNNEL_DESTINATION);
                    int port = section.second.get<int> (I2P_CLIENT_TUNNEL_PORT);
                    // optional params
                    std::string address = section.second.get(
                        I2P_CLIENT_TUNNEL_ADDRESS, "127.0.0.1"
                    );
                    std::string keys = section.second.get(I2P_CLIENT_TUNNEL_KEYS, "");
                    int destinationPort = section.second.get(I2P_CLIENT_TUNNEL_DESTINATION_PORT, 0);

                    std::shared_ptr<ClientDestination> localDestination = nullptr;
                    if(keys.length () > 0)
                        localDestination = LoadLocalDestination (keys, false);

                    auto clientTunnel = new I2PClientTunnel(
                        dest, address, port, localDestination, destinationPort
                    );
                    // TODO: allow multiple tunnels on the same port (but on a different address)
                    if(m_ClientTunnels.insert(std::make_pair(port, std::unique_ptr<I2PClientTunnel>(clientTunnel))).second)
                        clientTunnel->Start ();
                    else
                        LogPrint (eLogError, "I2P client tunnel with port ", port, " already exists");
                    numClientTunnels++;
                } else if(type == I2P_TUNNELS_SECTION_TYPE_SERVER || type == I2P_TUNNELS_SECTION_TYPE_HTTP)
                {   
                    // mandatory params
                    std::string host = section.second.get<std::string> (I2P_SERVER_TUNNEL_HOST);
                    int port = section.second.get<int> (I2P_SERVER_TUNNEL_PORT);
                    std::string keys = section.second.get<std::string> (I2P_SERVER_TUNNEL_KEYS);
                    // optional params
                    int inPort = section.second.get (I2P_SERVER_TUNNEL_INPORT, 0);
                    std::string accessList = section.second.get (I2P_SERVER_TUNNEL_ACCESS_LIST, "");                    

                    auto localDestination = LoadLocalDestination (keys, true);
                    I2PServerTunnel * serverTunnel = (type == I2P_TUNNELS_SECTION_TYPE_HTTP) ? new I2PServerTunnelHTTP (host, port, localDestination, inPort) : new I2PServerTunnel (host, port, localDestination, inPort);
                    if (accessList.length () > 0) {
                        std::set<i2p::data::IdentHash> idents;
                        size_t pos = 0, comma;
                        do {
                            comma = accessList.find (',', pos);
                            i2p::data::IdentHash ident;
                            ident.FromBase32 (accessList.substr (pos, comma != std::string::npos ? comma - pos : std::string::npos));   
                            idents.insert (ident);
                            pos = comma + 1;
                        } while (comma != std::string::npos);
                        serverTunnel->SetAccessList (idents);
                    }
                    if (m_ServerTunnels.insert (std::make_pair (localDestination->GetIdentHash (), std::unique_ptr<I2PServerTunnel>(serverTunnel))).second)
                        serverTunnel->Start ();
                    else
                        LogPrint (eLogError, "I2P server tunnel for destination ",   m_AddressBook.ToAddress(localDestination->GetIdentHash ()), " already exists");    
                    numServerTunnels++;
                } else
                    LogPrint (eLogWarning, "Unknown section type=", type, " of ", name, " in ", pathTunnelsConfigFile);
                
            } catch (const std::exception& ex) {
                LogPrint (eLogError, "Can't read tunnel ", name, " params: ", ex.what ());
            }
        }   
        LogPrint (eLogInfo, numClientTunnels, " I2P client tunnels created");
        LogPrint (eLogInfo, numServerTunnels, " I2P server tunnels created");
    }   
}       
}   
