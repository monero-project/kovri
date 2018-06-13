/**                                                                                           //
 * Copyright (c) 2015-2017, The Kovri I2P Router Project                                      //
 *                                                                                            //
 * All rights reserved.                                                                       //
 *                                                                                            //
 * Redistribution and use in source and binary forms, with or without modification, are       //
 * permitted provided that the following conditions are met:                                  //
 *                                                                                            //
 * 1. Redistributions of source code must retain the above copyright notice, this list of     //
 *    conditions and the following disclaimer.                                                //
 *                                                                                            //
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list     //
 *    of conditions and the following disclaimer in the documentation and/or other            //
 *    materials provided with the distribution.                                               //
 *                                                                                            //
 * 3. Neither the name of the copyright holder nor the names of its contributors may be       //
 *    used to endorse or promote products derived from this software without specific         //
 *    prior written permission.                                                               //
 *                                                                                            //
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY        //
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF    //
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL     //
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,       //
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,               //
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    //
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,          //
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF    //
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.               //
 *                                                                                            //
 */

#include "client/api/i2p_control/data.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <iomanip>
#include <stdexcept>

namespace kovri
{
namespace client
{
/**
 * @class SerializeVisitor
 * @brief JSON formatted output of a ValueType
 **/
struct SerializeVisitor final : public boost::static_visitor<std::string>
{
  std::string operator()(bool value) const
  {
    return value ? "true" : "false";
  }

  std::string operator()(const std::size_t& value) const
  {
    return std::to_string(value);
  }

  std::string operator()(const double& value) const
  {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << value;
    return oss.str();
  }

  std::string operator()(const std::string& value) const
  {
    return (value.empty() ? "null" : "\"" + value + "\"");
  }

  std::string operator()(const JsonObject& value) const
  {
    auto str = value.ToString();
    if (str.empty())
      return "null";
    return str;
  }
};

/**
 * Method
 **/
const std::string I2PControlDataTraits::GetTrait(Method method) const
{
  switch (method)
    {
      case Method::Authenticate:
        return "Authenticate";
      case Method::Echo:
        return "Echo";
      case Method::GetRate:
        return "GetRate";
      case Method::I2PControl:
        return "I2PControl";
      case Method::RouterInfo:
        return "RouterInfo";
      case Method::RouterManager:
        return "RouterManager";
      case Method::NetworkSetting:
        return "NetworkSetting";
      case Method::Unknown:
        return "";
    }
  throw std::domain_error(
      "Invalid method " + std::to_string(core::GetType(method)));
}

I2PControlDataTraits::Method I2PControlDataTraits::GetMethodFromString(
    const std::string& value) const
{
  if (value == GetTrait(Method::Authenticate))
    return Method::Authenticate;

  else if (value == GetTrait(Method::Echo))
    return Method::Echo;

  else if (value == GetTrait(Method::GetRate))
    return Method::GetRate;

  else if (value == GetTrait(Method::I2PControl))
    return Method::I2PControl;

  else if (value == GetTrait(Method::RouterInfo))
    return Method::RouterInfo;

  else if (value == GetTrait(Method::RouterManager))
    return Method::RouterManager;

  else if (value == GetTrait(Method::NetworkSetting))
    return Method::NetworkSetting;

  else
    return Method::Unknown;
}

std::string I2PControlDataTraits::AbstractMethod::ToJsonString() const
{
  SerializeVisitor visitor;
  std::ostringstream oss;
  for (auto it = m_Params.begin(); it != m_Params.end(); ++it)
    {
      if (it != m_Params.begin())
        oss << ',';
      oss << '"' << GetTrait(it->first)
          << "\":" << boost::apply_visitor(visitor, it->second);
    }
  return oss.str();
}

/**
 * Authenticate
 **/
const std::string I2PControlDataTraits::MethodAuthenticate::GetTrait(
    std::uint8_t value) const
{
  switch (value)
    {
      case API:
        return "API";
      case Password:
        return "Password";
      case Token:
        return "Token";
      default:
        throw std::domain_error("Invalid key " + std::to_string(value));
    };
}

std::uint8_t I2PControlDataTraits::MethodAuthenticate::GetTrait(
    const std::string& value) const
{
  if (value == GetTrait(API))
    return API;

  else if (value == GetTrait(Password))
    return Password;

  else if (value == GetTrait(Token))
    return Token;

  return Unknown;
}

void I2PControlDataTraits::MethodAuthenticate::ParseRequest(const ptree& tree)
{
  Set(API, tree.get<std::size_t>(GetTrait(API)));
  Set(Password, tree.get<std::string>(GetTrait(Password)));
}

void I2PControlDataTraits::MethodAuthenticate::ParseResponse(const ptree& tree)
{
  Set(API, tree.get<std::size_t>(GetTrait(API)));
  Set(Token, tree.get<std::string>(GetTrait(Token)));
}

/**
 * Echo
 **/
const std::string I2PControlDataTraits::MethodEcho::GetTrait(
    std::uint8_t value) const
{
  switch (value)
    {
      case Echo:
        return "Echo";
      case Result:
        return "Result";
      default:
        throw std::domain_error("Invalid key " + std::to_string(value));
    };
}

std::uint8_t I2PControlDataTraits::MethodEcho::GetTrait(
    const std::string& value) const
{
  if (value == GetTrait(Echo))
    return Echo;

  else if (value == GetTrait(Result))
    return Result;

  return Unknown;
}

void I2PControlDataTraits::MethodEcho::ParseRequest(const ptree& tree)
{
  Set(Echo, tree.get<std::string>(GetTrait(Echo)));
}

void I2PControlDataTraits::MethodEcho::ParseResponse(const ptree& tree)
{
  Set(Result, tree.get<std::string>(GetTrait(Result)));
}

/**
 * GetRate
 **/
const std::string I2PControlDataTraits::MethodGetRate::GetTrait(
    std::uint8_t value) const
{
  switch (value)
    {
      case Stat:
        return "Stat";
      case Period:
        return "Period";
      case Result:
        return "Result";
      case Unknown:
        return "";
    }
  throw std::domain_error("Invalid GetRate key " + std::to_string(value));
}

std::uint8_t I2PControlDataTraits::MethodGetRate::GetTrait(
    const std::string& value) const
{
  if (value == GetTrait(Stat))
    return Stat;

  else if (value == GetTrait(Period))
    return Period;

  else if (value == GetTrait(Result))
    return Result;

  return Unknown;
}

void I2PControlDataTraits::MethodGetRate::ParseRequest(const ptree& tree)
{
  Set(Stat, tree.get<std::string>(GetTrait(Stat)));
  Set(Period, tree.get<std::size_t>(GetTrait(Period)));
}

void I2PControlDataTraits::MethodGetRate::ParseResponse(const ptree& tree)
{
  Set(Result, tree.get<double>(GetTrait(Result)));
}

/**
 * I2PControl
 **/
const std::string I2PControlDataTraits::MethodI2PControl::GetTrait(
    std::uint8_t value) const
{
  switch (value)
    {
      case Address:
        return "i2pcontrol.address";
      case Password:
        return "i2pcontrol.password";
      case Port:
        return "i2pcontrol.port";
      case SettingsSaved:
        return "SettingsSaved";
      case RestartNeeded:
        return "RestartNeeded";
      case Unknown:
        return "";
    }
  throw std::domain_error("Invalid control value " + std::to_string(value));
}

std::uint8_t I2PControlDataTraits::MethodI2PControl::GetTrait(
    const std::string& value) const
{
  if (value == GetTrait(Address))
    return Address;

  else if (value == GetTrait(Password))
    return Password;

  else if (value == GetTrait(Port))
    return Port;

  else if (value == GetTrait(SettingsSaved))
    return SettingsSaved;

  else if (value == GetTrait(RestartNeeded))
    return RestartNeeded;

  return Unknown;
}

void I2PControlDataTraits::MethodI2PControl::ParseRequest(const ptree& tree)
{
  for (const auto& pair : tree)
    {
      if (pair.first == "Token")
        continue;
      auto option = GetTrait(pair.first);
      switch (option)
        {
          case Address:
          case Password:
          case Port:
            Set(option, pair.second.get_value<std::string>());
            break;
          default:
            throw std::domain_error("Invalid key " + pair.first);
        }
    }
}

void I2PControlDataTraits::MethodI2PControl::ParseResponse(const ptree& tree)
{
  for (const auto& pair : tree)
    {
      auto option = GetTrait(pair.first);
      switch (option)
        {
          case Address:
          case Password:
          case Port:
            Set(option, std::string());
            break;
          case SettingsSaved:
          case RestartNeeded:
            Set(option, pair.second.get_value<bool>());
            break;
          default:
            throw std::domain_error("Invalid key " + pair.first);
        }
    }
}

/**
 * RouterInfo
 **/
const std::string I2PControlDataTraits::MethodRouterInfo::GetTrait(
    std::uint8_t info) const
{
  switch (info)
    {
      case Status:
        return "i2p.router.status";
      case Uptime:
        return "i2p.router.uptime";
      case Version:
        return "i2p.router.version";
      case BWIn1S:
        return "i2p.router.net.bw.inbound.1s";
      case BWIn15S:
        return "i2p.router.net.bw.inbound.15s";
      case BWOut1S:
        return "i2p.router.net.bw.outbound.1s";
      case BWOut15S:
        return "i2p.router.net.bw.outbound.15s";
      case NetStatus:
        return "i2p.router.net.status";
      case TunnelsParticipating:
        return "i2p.router.net.tunnels.participating";
      case ActivePeers:
        return "i2p.router.netdb.activepeers";
      case FastPeers:
        return "i2p.router.netdb.fastpeers";
      case HighCapacityPeers:
        return "i2p.router.netdb.highcapacitypeers";
      case IsReseeding:
        return "i2p.router.netdb.isreseeding";
      case KnownPeers:
        return "i2p.router.netdb.knownpeers";
      // Extra options
      case DataPath:
        return "i2p.router.datapath";
      case Floodfills:
        return "i2p.router.netdb.floodfills";
      case LeaseSets:
        return "i2p.router.netdb.leasesets";
      // TODO(unassigned): Probably better to use the standard GetRate instead
      case TunnelsCreationSuccessRate:
        return "i2p.router.net.tunnels.creationsuccessrate";
      case TunnelsInList:
        return "i2p.router.net.tunnels.inbound.list";
      case TunnelsOutList:
        return "i2p.router.net.tunnels.outbound.list";
      case Unknown:
        return "";
    }
  throw std::domain_error("Invalid router info " + std::to_string(info));
}

std::uint8_t I2PControlDataTraits::MethodRouterInfo::GetTrait(
    const std::string& value) const
{
  if (value == GetTrait(Status))
    return Status;

  else if (value == GetTrait(Uptime))
    return Uptime;

  else if (value == GetTrait(Version))
    return Version;

  else if (value == GetTrait(BWIn1S))
    return BWIn1S;

  else if (value == GetTrait(BWIn15S))
    return BWIn15S;

  else if (value == GetTrait(BWOut1S))
    return BWOut1S;

  else if (value == GetTrait(BWOut15S))
    return BWOut15S;

  else if (value == GetTrait(NetStatus))
    return NetStatus;

  else if (value == GetTrait(TunnelsParticipating))
    return TunnelsParticipating;

  else if (value == GetTrait(ActivePeers))
    return ActivePeers;

  else if (value == GetTrait(FastPeers))
    return FastPeers;

  else if (value == GetTrait(HighCapacityPeers))
    return HighCapacityPeers;

  else if (value == GetTrait(IsReseeding))
    return IsReseeding;

  else if (value == GetTrait(KnownPeers))
    return KnownPeers;

  else if (value == GetTrait(DataPath))
    return DataPath;

  else if (value == GetTrait(Floodfills))
    return Floodfills;

  else if (value == GetTrait(LeaseSets))
    return LeaseSets;

  else if (value == GetTrait(TunnelsCreationSuccessRate))
    return TunnelsCreationSuccessRate;

  else if (value == GetTrait(TunnelsInList))
    return TunnelsInList;

  else if (value == GetTrait(TunnelsOutList))
    return TunnelsOutList;

  return Unknown;
}

void I2PControlDataTraits::MethodRouterInfo::ParseRequest(const ptree& tree)
{
  for (const auto& pair : tree)
    {
      if (pair.first == "Token")
        continue;

      auto info = GetTrait(pair.first);
      if (info == Unknown)
        throw std::domain_error("Invalid key " + pair.first);

      Set(info, std::string());
    }
}

void I2PControlDataTraits::MethodRouterInfo::ParseResponse(const ptree& tree)
{
  for (const auto& pair : tree)
    {
      auto option(GetTrait(pair.first));
      switch (option)
        {
          // String values
          case Status:
          case Version:
          case DataPath:
            Set(option, pair.second.get_value<std::string>());
            break;

          // Long values
          case Uptime:
          case NetStatus:
          case TunnelsParticipating:
          case ActivePeers:
          case FastPeers:
          case HighCapacityPeers:
          case KnownPeers:
          case Floodfills:
          case LeaseSets:
            Set(option, pair.second.get_value<std::size_t>());
            break;

          // float values
          case BWIn1S:
          case BWIn15S:
          case BWOut1S:
          case BWOut15S:
          case TunnelsCreationSuccessRate:
            Set(option, pair.second.get_value<double>());
            break;

          // boolean
          case IsReseeding:
            Set(option, pair.second.get_value<bool>());
            break;

          // JsonObject
          case TunnelsInList:
          case TunnelsOutList:
            Set(option, JsonObject(pair.second));
            break;

          // Other
          case Unknown:
            throw std::domain_error("Invalid key " + pair.first);
        }
    }
}

/**
 * RouterManager
 **/
const std::string I2PControlDataTraits::MethodRouterManager::GetTrait(
    std::uint8_t command) const
{
  switch (command)
    {
      case FindUpdates:
        return "FindUpdates";
      case Reseed:
        return "Reseed";
      case Restart:
        return "Restart";
      case RestartGraceful:
        return "RestartGraceful";
      case Shutdown:
        return "Shutdown";
      case ShutdownGraceful:
        return "ShutdownGraceful";
      case Update:
        return "Update";
      case Unknown:
        return "";
    }
  throw std::domain_error(
      "Invalid router manager command " + std::to_string(command));
}
std::uint8_t I2PControlDataTraits::MethodRouterManager::GetTrait(
    const std::string& value) const
{
  if (value == GetTrait(FindUpdates))
    return FindUpdates;

  else if (value == GetTrait(Reseed))
    return Reseed;

  else if (value == GetTrait(Restart))
    return Restart;

  else if (value == GetTrait(RestartGraceful))
    return RestartGraceful;

  else if (value == GetTrait(Shutdown))
    return Shutdown;

  else if (value == GetTrait(ShutdownGraceful))
    return ShutdownGraceful;

  else if (value == GetTrait(Update))
    return Update;

  return Unknown;
}

void I2PControlDataTraits::MethodRouterManager::ParseRequest(const ptree& tree)
{
  for (const auto& pair : tree)
    {
      if (pair.first == "Token")
        continue;

      auto info = GetTrait(pair.first);
      if (info == Unknown)
        throw std::domain_error("Invalid key " + pair.first);

      Set(info, std::string());
    }
}

void I2PControlDataTraits::MethodRouterManager::ParseResponse(const ptree& tree)
{
  for (const auto& pair : tree)
    {
      auto option(GetTrait(pair.first));
      switch (option)
        {
          case FindUpdates:
            Set(option, pair.second.get_value<bool>());
            break;

          case Reseed:
          case Restart:
          case RestartGraceful:
          case Shutdown:
          case ShutdownGraceful:
            Set(option, std::string());
            break;

          case Update:
            Set(option, pair.second.get_value<std::string>());
            break;

          case Unknown:
            throw std::domain_error("Invalid key " + pair.first);
        }
    }
}

/**
 * NetworkSetting
 **/
const std::string I2PControlDataTraits::MethodNetworkSetting::GetTrait(
    std::uint8_t setting) const
{
  switch (setting)
    {
      case NTCPPort:
        return "i2p.router.net.ntcp.port";
      case NTCPHostName:
        return "i2p.router.net.ntcp.hostname";
      case NTCPAutoIP:
        return "i2p.router.net.ntcp.autoip";
      case SSUPort:
        return "i2p.router.net.ssu.port";
      case SSUHostName:
        return "i2p.router.net.ssu.hostname";
      case SSUAutoIP:
        return "i2p.router.net.ssu.autoip";
      case SSUDetectedIP:
        return "i2p.router.net.ssu.detectedip";
      case UPnP:
        return "i2p.router.net.upnp";
      case BWShare:
        return "i2p.router.net.bw.share";
      case BWIn:
        return "i2p.router.net.bw.in";
      case BWOut:
        return "i2p.router.net.bw.out";
      case LaptopMode:
        return "i2p.router.net.laptopmode";
      case SettingsSaved:
        return "SettingsSaved";
      case RestartNeeded:
        return "RestartNeeded";
      case Unknown:
        return "";
    }
  throw std::domain_error("Invalid network setting " + std::to_string(setting));
}

std::uint8_t I2PControlDataTraits::MethodNetworkSetting::GetTrait(
    const std::string& value) const
{
  if (value == GetTrait(NTCPPort))
    return NTCPPort;

  else if (value == GetTrait(NTCPHostName))
    return NTCPHostName;

  else if (value == GetTrait(NTCPAutoIP))
    return NTCPAutoIP;

  else if (value == GetTrait(SSUPort))
    return SSUPort;

  else if (value == GetTrait(SSUHostName))
    return SSUHostName;

  else if (value == GetTrait(SSUAutoIP))
    return SSUAutoIP;

  else if (value == GetTrait(SSUDetectedIP))
    return SSUDetectedIP;

  else if (value == GetTrait(UPnP))
    return UPnP;

  else if (value == GetTrait(BWShare))
    return BWShare;

  else if (value == GetTrait(BWIn))
    return BWIn;

  else if (value == GetTrait(BWOut))
    return BWOut;

  else if (value == GetTrait(LaptopMode))
    return LaptopMode;

  else if (value == GetTrait(SettingsSaved))
    return SettingsSaved;

  else if (value == GetTrait(RestartNeeded))
    return RestartNeeded;

  return Unknown;
}

void I2PControlDataTraits::MethodNetworkSetting::ParseRequest(const ptree& tree)
{
  for (const auto& pair : tree)
    {
      if (pair.first == "Token")
        continue;

      auto setting = GetTrait(pair.first);
      if (setting == Unknown)
        throw std::domain_error("Invalid key " + pair.first);

      const std::string value = pair.second.get_value<std::string>();
      Set(setting, value == "null" ? std::string() : value);
    }
}

void I2PControlDataTraits::MethodNetworkSetting::ParseResponse(
    const ptree& tree)
{
  for (const auto& pair : tree)
    {
      auto setting(GetTrait(pair.first));
      if (setting == Unknown)
        throw std::domain_error("Invalid key " + pair.first);

      if ((setting == SettingsSaved) || (setting == RestartNeeded))
        Set(setting, pair.second.get_value<bool>());
      else
        Set(setting, pair.second.get_value<std::string>());
    }
}

/**
 * ErrorCode
 **/
const std::string I2PControlDataTraits::GetTrait(ErrorCode error) const
{
  switch (error)
    {
      case ErrorCode::None:
        return "";
      case ErrorCode::InvalidRequest:
        return "Invalid request.";
      case ErrorCode::MethodNotFound:
        return "Method not found.";
      case ErrorCode::InvalidParameters:
        return "Invalid parameters.";
      case ErrorCode::InternalError:
        return "Internal error.";
      case ErrorCode::ParseError:
        return "Json parse error.";
      case ErrorCode::InvalidPassword:
        return "Invalid password.";
      case ErrorCode::NoToken:
        return "No authentication token given.";
      case ErrorCode::NonexistentToken:
        return "Nonexistent authentication token given.";
      case ErrorCode::ExpiredToken:
        return "Expired authentication token given.";
      case ErrorCode::UnspecifiedVersion:
        return "Version not specified.";
      case ErrorCode::UnsupportedVersion:
        return "Version not supported.";
    }
  throw std::domain_error(
      "Invalid error " + std::to_string(core::GetType(error)));
}

I2PControlDataTraits::ErrorCode I2PControlDataTraits::ErrorFromInt(
    int error) const
{
  switch ((ErrorCode)error)
    {
      case ErrorCode::None:
      case ErrorCode::InvalidRequest:
      case ErrorCode::MethodNotFound:
      case ErrorCode::InvalidParameters:
      case ErrorCode::InternalError:
      case ErrorCode::ParseError:
      case ErrorCode::InvalidPassword:
      case ErrorCode::NoToken:
      case ErrorCode::NonexistentToken:
      case ErrorCode::ExpiredToken:
      case ErrorCode::UnspecifiedVersion:
      case ErrorCode::UnsupportedVersion:
        return static_cast<ErrorCode>(error);

      default:
        throw std::domain_error("Invalid error " + std::to_string(error));
    }
}

/**
 * NetStatus
 **/
const std::string I2PControlDataTraits::GetTrait(NetStatus status) const
{
  switch (status)
    {
      case NetStatus::Ok:
        return "OK";
      case NetStatus::Testing:
        return "TESTING";
      case NetStatus::Firewalled:
        return "FIREWALLED";
      case NetStatus::Hidden:
        return "HIDDEN";
      case NetStatus::WarnFirewalledAndFast:
        return "WARN_FIREWALLED_AND_FAST";
      case NetStatus::WarnFirewalledAndFloodfill:
        return "WARN_FIREWALLED_AND_FLOODFILL";
      case NetStatus::WarnFirewalledAndInboundTcp:
        return "WARN_FIREWALLED_WITH_INBOUND_TCP";
      case NetStatus::WarnFirewalledWithUDPDisabled:
        return "WARN_FIREWALLED_WITH_UDP_DISABLED";
      case NetStatus::ErrorI2CP:
        return "ERROR_I2CP";
      case NetStatus::ErrorClockSkew:
        return "ERROR_CLOCK_SKEW";
      case NetStatus::ErrorPrivateTcpAddress:
        return "ERROR_PRIVATE_TCP_ADDRESS";
      case NetStatus::ErrorSymmetricNat:
        return "ERROR_SYMMETRIC_NAT";
      case NetStatus::ErrorUDPPortInUse:
        return "ERROR_UDP_PORT_IN_USE";
      case NetStatus::ErrorNoActivePeers:
        return "ERROR_NO_ACTIVE_PEERS_CHECK_CONNECTION_AND_FIREWALL";
      case NetStatus::ErrorUDPDisabledAndTcpUnset:
        return "ERROR_UDP_DISABLED_AND_TCP_UNSET";
    }
  throw std::domain_error(
      "Invalid net status " + std::to_string(core::GetType(status)));
}

I2PControlDataTraits::NetStatus I2PControlDataTraits::NetStatusFromLong(
    std::size_t status) const
{
  switch ((NetStatus)status)
    {
      case NetStatus::Ok:
      case NetStatus::Testing:
      case NetStatus::Firewalled:
      case NetStatus::Hidden:
      case NetStatus::WarnFirewalledAndFast:
      case NetStatus::WarnFirewalledAndFloodfill:
      case NetStatus::WarnFirewalledAndInboundTcp:
      case NetStatus::WarnFirewalledWithUDPDisabled:
      case NetStatus::ErrorI2CP:
      case NetStatus::ErrorClockSkew:
      case NetStatus::ErrorPrivateTcpAddress:
      case NetStatus::ErrorSymmetricNat:
      case NetStatus::ErrorUDPPortInUse:
      case NetStatus::ErrorNoActivePeers:
      case NetStatus::ErrorUDPDisabledAndTcpUnset:
        return static_cast<NetStatus>(status);

      default:
        throw std::domain_error("Invalid net status " + std::to_string(status));
    }
}

/**
 * I2PControlData
 **/
void I2PControlData::SetID(const ValueType& id)
{
  m_ID = id;
}

const I2PControlData::ValueType& I2PControlData::GetID() const
{
  return m_ID;
}

void I2PControlData::SetVersion(const std::string& version)
{
  m_Version = version;
}

const std::string& I2PControlData::GetVersion() const
{
  return m_Version;
}

void I2PControlData::SetMethod(Method method)
{
  switch (method)
    {
      case Method::Authenticate:
        m_Method.reset(new MethodAuthenticate());
        break;
      case Method::Echo:
        m_Method.reset(new MethodEcho());
        break;
      case Method::GetRate:
        m_Method.reset(new MethodGetRate());
        break;
      case Method::I2PControl:
        m_Method.reset(new MethodI2PControl());
        break;
      case Method::RouterInfo:
        m_Method.reset(new MethodRouterInfo());
        break;
      case Method::RouterManager:
        m_Method.reset(new MethodRouterManager());
        break;
      case Method::NetworkSetting:
        m_Method.reset(new MethodNetworkSetting());
        break;
      default:
        throw std::runtime_error("Invalid method");
    }
}

void I2PControlData::SetParam(std::uint8_t key, const ValueType& value)
{
  CheckInitialized();
  m_Method->Set(key, value);
}

void I2PControlData::SetParam(std::string key, const ValueType& value)
{
  CheckInitialized();
  m_Method->Set(m_Method->GetTrait(key), value);
}

const std::string I2PControlData::KeyToString(std::uint8_t key)
{
  CheckInitialized();
  return m_Method->GetTrait(key);
}

void I2PControlData::Parse(const ptree& tree)
{
  auto id = tree.get<std::string>("id");
  if (boost::starts_with(id, "\""))
    SetID(id);
  else
    SetID(tree.get<std::size_t>("id"));
  // Parse common parameter jsonrpc
  SetVersion(tree.get<std::string>("jsonrpc"));
}

/**
 * I2PControlRequest
 **/
void I2PControlRequest::SetToken(const std::string& token)
{
  m_Token = token;
}

std::string I2PControlRequest::GetToken() const
{
  return m_Token;
}

std::string I2PControlRequest::ToJsonString() const
{
  std::ostringstream oss;
  SerializeVisitor visitor;

  oss << "{\"id\":" << boost::apply_visitor(visitor, m_ID) << ",\"method\":\""
      << GetTrait(m_Method->Which()) << "\",\"params\":{";

  if (!m_Token.empty())
    oss << "\"Token\":\"" << m_Token << "\",";

  if (m_Method)
    oss << m_Method->ToJsonString();

  oss << "},\"jsonrpc\":\"" << m_Version << "\"}";
  return oss.str();
}

void I2PControlRequest::Parse(std::stringstream& stream)
{
  boost::property_tree::ptree tree;
  boost::property_tree::read_json(stream, tree);
  I2PControlData::Parse(tree);
  // Check for error
  auto method(GetMethodFromString(tree.get<std::string>("method")));
  if (method == Method::Unknown)
    throw std::logic_error("Invalid method");
  SetMethod(method);

  auto params = tree.get_child("params");
  auto token = params.get_child_optional("Token");
  if (token)
    SetToken(token->get_value<std::string>());
  m_Method->ParseRequest(params);
}

/**
 * I2PControlResponse
 **/
I2PControlResponse::ErrorCode I2PControlResponse::GetError() const
{
  return m_Error;
}

std::string I2PControlResponse::GetErrorMsg() const
{
  return GetTrait(m_Error);
}

void I2PControlResponse::SetError(ErrorCode code)
{
  m_Error = code;
}

std::string I2PControlResponse::ToJsonString() const
{
  std::ostringstream oss;
  SerializeVisitor visitor;

  oss << "{\"id\":" << boost::apply_visitor(visitor, m_ID);

  if (m_Method)
    oss << ",\"result\":{" << m_Method->ToJsonString() << "}";

  oss << ",\"jsonrpc\":\"" << m_Version << "\"";

  if (m_Error != ErrorCode::None)
    oss << ",\"error\":{\"code\":" << static_cast<int>(m_Error)
        << ",\"message\":\"" << GetTrait(m_Error) << "\""
        << "}";

  oss << "}";
  return oss.str();
}

void I2PControlResponse::Parse(Method method, std::stringstream& stream)
{
  boost::property_tree::ptree tree;
  boost::property_tree::read_json(stream, tree);
  I2PControlData::Parse(tree);
  SetMethod(method);
  // Check for error
  auto error = tree.get_child_optional("error");
  if (error)
    {
      LOG(debug)
          << "I2PControlResponseParser: server responded with explicit error";
      SetError(ErrorFromInt(error->get<int>("code")));
      return;
    }
  m_Method->ParseResponse(tree.get_child("result"));
}

}  // namespace client
}  // namespace kovri
