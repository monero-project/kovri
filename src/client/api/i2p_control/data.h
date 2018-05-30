/**                                                                                           //
 * Copyright (c) 2015-2018, The Kovri I2P Router Project                                      //
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

#ifndef SRC_CLIENT_API_I2P_CONTROL_DATA_H_
#define SRC_CLIENT_API_I2P_CONTROL_DATA_H_

#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/variant.hpp>

#include <map>
#include <memory>
#include <sstream>
#include <string>

#include "client/util/json.h"
#include "core/util/byte_stream.h"
#include "core/util/log.h"

// Note: Spec at https://geti2p.net/en/docs/api/i2pcontrol

namespace kovri
{
namespace client
{
struct I2PControlDataTraits
{
  // For convenience
  typedef boost::variant<bool, std::size_t, double, std::string, JsonObject>
      ValueType;
  typedef boost::property_tree::ptree ptree;

  /// @enum Method
  /// @brief I2PControl supported methods
  enum struct Method : std::uint8_t
  {
    Authenticate,
    Echo,
    GetRate,
    I2PControl,
    RouterInfo,
    RouterManager,
    NetworkSetting,
    Unknown
  };

  /// @return String value of given enumerated method
  /// @param trait key used for trait string value
  /// @throw std::domain_error on invalid value
  const std::string GetTrait(Method method) const;

  /// @return Enumerated method trait
  /// @param value String value of potential trait given
  Method GetMethodFromString(const std::string& value) const noexcept;

  /// @class AbstractMethod
  /// @brief Base class for specific methods
  class AbstractMethod
  {
   public:
    virtual ~AbstractMethod() = default;

    /// @return String value of given enumerated method
    /// @param trait key used for trait string value
    /// @throw std::domain_error if invalid key
    virtual const std::string GetTrait(std::uint8_t trait) const = 0;

    /// @return Enumerated key trait
    /// @param value String value of potential trait given
    virtual std::uint8_t GetTrait(const std::string& value) const noexcept = 0;

    /// @return Enumerated Method implemented
    virtual Method Which(void) const = 0;

    /// @brief Parse an I2P Control request
    virtual void ParseRequest(const ptree&) = 0;

    /// @brief Parse an I2P Control response
    virtual void ParseResponse(const ptree&) = 0;

    /// @return param with specific type
    /// @param key container's key
    /// @throw std::domain_error if invalid key
    /// @throw std::out_of_range if value not present
    /// @throw boost::bad_get if type mismatch
    template <typename Type>
    Type Get(std::uint8_t key) const
    {
      return boost::get<Type>(m_Params.at(key));
    }

    /// @brief Insert value with associated key
    void Set(std::uint8_t key, const ValueType& value)
    {
      m_Params[key] = value;
    }

    /// @return Json serialization of m_Params
    std::string ToJsonString() const;

   private:
    std::map<std::uint8_t, ValueType> m_Params{};

   public:
    /// @return all stored params
    const decltype(m_Params)& Get() const
    {
      return m_Params;
    }
  };

  struct MethodAuthenticate final : public AbstractMethod
  {
    enum Trait : std::uint8_t
    {
      API,
      Password,
      Token,
      Unknown
    };
    Method Which() const
    {
      return Method::Authenticate;
    }
    const std::string GetTrait(std::uint8_t value) const;
    std::uint8_t GetTrait(const std::string& value) const noexcept;
    void ParseRequest(const ptree& tree);
    void ParseResponse(const ptree& tree);
  };

  struct MethodEcho final : public AbstractMethod
  {
    enum Trait : std::uint8_t
    {
      Echo,
      Result,
      Unknown
    };
    Method Which() const
    {
      return Method::Echo;
    }
    const std::string GetTrait(std::uint8_t value) const;
    std::uint8_t GetTrait(const std::string& value) const noexcept;
    void ParseRequest(const ptree& tree);
    void ParseResponse(const ptree& tree);
  };

  struct MethodGetRate final : public AbstractMethod
  {
    enum Trait : std::uint8_t
    {
      Stat,
      Period,
      Result,
      Unknown
    };
    Method Which() const
    {
      return Method::GetRate;
    }
    const std::string GetTrait(std::uint8_t value) const;
    std::uint8_t GetTrait(const std::string& value) const noexcept;
    void ParseRequest(const ptree& tree);
    void ParseResponse(const ptree& tree);
  };

  struct MethodI2PControl final : public AbstractMethod
  {
    enum Trait : std::uint8_t
    {
      Address,
      Password,
      Port,
      SettingsSaved,
      RestartNeeded,
      Unknown
    };
    Method Which() const
    {
      return Method::I2PControl;
    }
    const std::string GetTrait(std::uint8_t value) const;
    std::uint8_t GetTrait(const std::string& value) const noexcept;
    void ParseRequest(const ptree& tree);
    void ParseResponse(const ptree& tree);
  };

  struct MethodRouterInfo final : public AbstractMethod
  {
    enum Trait : std::uint8_t
    {
      // Options in spec
      Status,
      Uptime,
      Version,
      BWIn1S,
      BWIn15S,
      BWOut1S,
      BWOut15S,
      NetStatus,
      TunnelsParticipating,
      ActivePeers,
      FastPeers,
      HighCapacityPeers,
      IsReseeding,
      KnownPeers,
      // Extra options
      DataPath,
      Floodfills,
      LeaseSets,
      TunnelsCreationSuccessRate,
      TunnelsInList,
      TunnelsOutList,
      Unknown,
    };
    Method Which() const
    {
      return Method::RouterInfo;
    }
    const std::string GetTrait(std::uint8_t value) const;
    std::uint8_t GetTrait(const std::string& value) const noexcept;
    void ParseRequest(const ptree& tree);
    void ParseResponse(const ptree& tree);
  };

  struct MethodRouterManager final : public AbstractMethod
  {
    enum Trait : std::uint8_t
    {
      FindUpdates,
      Reseed,
      Restart,
      RestartGraceful,
      Shutdown,
      ShutdownGraceful,
      Update,
      Unknown
    };
    Method Which() const
    {
      return Method::RouterManager;
    }
    const std::string GetTrait(std::uint8_t value) const;
    std::uint8_t GetTrait(const std::string& value) const noexcept;
    void ParseRequest(const ptree& tree);
    void ParseResponse(const ptree& tree);
  };

  struct MethodNetworkSetting final : public AbstractMethod
  {
    enum Trait : std::uint8_t
    {
      NTCPPort,
      NTCPHostName,
      NTCPAutoIP,
      SSUPort,
      SSUHostName,
      SSUAutoIP,
      SSUDetectedIP,
      UPnP,
      BWShare,
      BWIn,
      BWOut,
      LaptopMode,
      SettingsSaved,
      RestartNeeded,
      Unknown
    };
    Method Which() const
    {
      return Method::NetworkSetting;
    }
    const std::string GetTrait(std::uint8_t value) const;
    std::uint8_t GetTrait(const std::string& value) const noexcept;
    void ParseRequest(const ptree& tree);
    void ParseResponse(const ptree& tree);
  };

  /// @enum ErrorCode
  /// @brief Error codes
  enum struct ErrorCode : std::int16_t
  {
    None = 0,
    // JSON-RPC2
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    InvalidParameters = -32602,
    InternalError = -32603,
    ParseError = -32700,
    // I2PControl specific
    InvalidPassword = -32001,
    NoToken = -32002,
    NonexistentToken = -32003,
    ExpiredToken = -32004,
    UnspecifiedVersion = -32005,
    UnsupportedVersion = -32006
  };

  /// @return String value of given router manager trait
  /// @param trait key used for trait string value
  /// @throw std::domain_error on invalid value
  const std::string GetTrait(ErrorCode error) const;

  /// @return ErrorCode from integer as specified in protocol
  /// @throw std::domain_error on invalid value
  ErrorCode ErrorFromInt(int error) const;

  /// @enum NetStatus
  /// @brief Network status
  enum struct NetStatus : std::uint8_t
  {
    Ok = 0,
    Testing = 1,
    Firewalled = 2,
    Hidden = 3,
    WarnFirewalledAndFast = 4,
    WarnFirewalledAndFloodfill = 5,
    WarnFirewalledAndInboundTcp = 6,
    WarnFirewalledWithUDPDisabled = 7,
    ErrorI2CP = 8,
    ErrorClockSkew = 9,
    ErrorPrivateTcpAddress = 10,
    ErrorSymmetricNat = 11,
    ErrorUDPPortInUse = 12,
    ErrorNoActivePeers = 13,
    ErrorUDPDisabledAndTcpUnset = 14,
  };

  /// @return String value of given NetStatus
  /// @param trait key used for trait string value
  /// @throw std::domain_error on invalid value
  const std::string GetTrait(NetStatus status) const;

  /// @return NetStatus from integer as specified in protocol
  /// @throw std::domain_error on invalid value
  NetStatus NetStatusFromLong(std::size_t error) const;
};

/// @class I2PControlData
/// @brief Base class for a request and a response
class I2PControlData : public I2PControlDataTraits
{
 public:
  /// @brief Set current ID
  void SetID(const ValueType& id);

  /// @return Current ID
  const ValueType& GetID() const;

  /// @brief Set json rpc version
  void SetVersion(const std::string& version);

  /// @return Json rpc version
  const std::string& GetVersion() const;

  /// @brief Sets current method
  void SetMethod(Method method);

  /// @return name of the method
  Method GetMethod(void) const
  {
    return m_Method ? m_Method->Which() : Method::Unknown;
  }

  /// @return param associated with enumerated key
  template <typename Type>
  Type GetParam(std::uint8_t key) const
  {
    CheckInitialized();
    return m_Method->Get<Type>(key);
  }

  /// @return param associated with string key
  template <typename Type>
  Type GetParam(const std::string& key) const
  {
    CheckInitialized();
    return m_Method->Get<Type>(m_Method->GetTrait(key));
  }

  /// @brief Insert value associated with enumerated key
  void SetParam(std::uint8_t key, const ValueType& value);

  /// @brief Insert value associated with string key
  void SetParam(std::string key, const ValueType& value);

  /// @return String representation of key
  const std::string KeyToString(std::uint8_t key);

 protected:
  /// @brief Parse common parameters
  void Parse(const ptree&);

  std::unique_ptr<AbstractMethod> m_Method;
  ValueType m_ID{std::size_t(0)};
  std::string m_Version{"2.0"};

 private:
  /// @brief Ensure method has been initialized
  void CheckInitialized() const
  {
    if (!m_Method)
      throw std::runtime_error("Method not initialized");
  }

 public:
  /// @return all stored params
  decltype(m_Method->Get()) GetParams() const
  {
    CheckInitialized();
    return m_Method->Get();
  }
};

/// @class I2PControlRequest
/// @brief represents an I2PControl request
class I2PControlRequest final : public I2PControlData
{
 public:
  /// @brief Sets the current token
  void SetToken(const std::string& token);

  /// @return current token
  std::string GetToken(void) const;

  /// @return Json serialization
  std::string ToJsonString() const;

  /// @brief Parse an I2P control request
  void Parse(std::stringstream& message);

 private:
  std::string m_Token;
};

/// @class I2PControlResponse
/// @brief represents an I2PControl response
class I2PControlResponse final : public I2PControlData
{
 public:
  /// @brief Sets current error code
  void SetError(ErrorCode code);

  /// @return Current error code
  ErrorCode GetError(void) const;

  /// @return Message associated with current error
  std::string GetErrorMsg() const;

  /// @return Json serialization
  std::string ToJsonString() const;

  /// @brief Parse an I2P control response
  void Parse(Method, std::stringstream& message);

 private:
  ErrorCode m_Error{ErrorCode::None};
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_API_I2P_CONTROL_DATA_H_
