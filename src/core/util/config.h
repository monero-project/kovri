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
 */

#ifndef SRC_CORE_UTIL_CONFIG_H_
#define SRC_CORE_UTIL_CONFIG_H_

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <boost/tokenizer.hpp>

#include "core/util/exception.h"
#include "core/util/filesystem.h"

namespace kovri
{
namespace core
{

/// @class ConfigInternal
/// @brief Internal Core base configuration implementation
class ConfigInternal {
 public:
  /// @class ListParameter
  /// @brief Class used to handle custom data out of the boost::program_options.
  /// @details Template class which accepts string, integral and floating point types.
  ///          This class can perform a parse of a string with ',' (comma) separated
  ///          character and split the token sinto the internal values (std::vector<T>)
  ///          member which can be accessed directly (public member).
  /// @param   T: string, integral and floating point types. (future anytype ie: boost::asio::ip::address)
  /// @param   MAX: define the max expected number of item to be inserted in the internal
  ///          values. This size can be exceed with no issue, but the IsExpectedSize will fail
  ///          once checked.
  template <typename T, int MAX>
  struct ListParameter
  {
   private:
    /// @return The value converted from the string value into T.
    /// @brief We apply a lexical_cast only for integral or floating point types.
    template <typename U>
    U GetValue(
        const std::string& string_value,
        typename std::enable_if<std::is_integral<U>::value
                                || std::is_floating_point<U>::value>::type*
            value = 0)
    {
      try
        {
          (void) value;  // TODO(anonimal): no
          return boost::lexical_cast<U>(string_value);
        }
      catch (const boost::bad_lexical_cast& ex)
        {
          throw std::runtime_error(ex.what());
        }
    }

    /// @return The original values as it was passed, no modifications are made.
    /// @brief Overload of @GetValue to handle the string case.
    template <typename U>
    U GetValue(
        const std::string& string_value,
        typename std::enable_if<std::is_same<std::string,
                                             typename std::decay<U>::type>::
                                    value>::type* value = 0) noexcept
    {
      (void) value;  // Silence compiler warning about unused parameters.
      return string_value;
    }

   public:
    static constexpr int limit = MAX;
    // This is what is only allowed for now.
    static_assert(
        std::is_same<std::string, typename std::decay<T>::type>::value
            || std::is_integral<T>::value
            || std::is_floating_point<T>::value,
        "Type not supported.");

    /// @brief we should handle default values also through the default_value() function.
    explicit ListParameter(const std::string& plain_params)
        : raw_data(plain_params)
    {
      // May not make a big diff if we do not expect a large collection.
      values.reserve(MAX);
      // Parse the default value.
      ParseFrom(raw_data);
    }

    // We need the default constructor as the boost::program_options::value should
    // be default constructible.
    ListParameter() = default;
    // We want to enable move/copy semantic on this helper class. Previous declaration
    // force us to define the following.
    ListParameter(const ListParameter&) = default;
    ListParameter& operator=(const ListParameter&) = default;
    ListParameter(ListParameter&&) = default;
    ListParameter& operator=(ListParameter&&) = default;

    /// @return true if the internal list size is what we expect. Defined by the template param.
    inline bool IsExpectedSize() const noexcept
    {
      return values.size() <= MAX;
    }

    /// @brief Parse and fill the internal values.
    void ParseFrom(const std::string& parameter_data)
    {
      if (parameter_data.empty())
        return;
      try
        {
          // TODO(unassigned): Make the separator configurable.
          boost::char_separator<char> token_separator{","};
          boost::tokenizer<boost::char_separator<char>> tokens{parameter_data,
                                                               token_separator};
          for (const auto& token : tokens)
            {
              // We can be in the case where we need to insert a plain string which
              // is what we get from the token in this case. This type can be inserted
              // into the values straigh away *only* if T is a std:string, any other
              // type must be converted to T, that's why we use the helper function
              // config_internal::GetValue<T>() which in the case of not a std::string
              // will perform a boost::lexical_cast<T> from the given string token.
              // If the token is invalid or is there any issue during the cast, a
              // std::runtime_error exception will be fired.
              values.push_back(GetValue<T>(token));
            }
        }
      catch (const std::runtime_error& re)
        {
          // Mind exceptions from the lexical_cast done in config_internal::GetValue<T>
          throw boost::program_options::validation_error(
              boost::program_options::validation_error::invalid_option_value);
        }
      // save the original data
      raw_data = parameter_data;
    }
    // values will hold the result list after parsing.
    std::vector<T> values;
    // In case you need the raw data passed by bpo.
    // TODO(unassigned): Check default constructor.
    std::string raw_data;
  };
};

/// @class Configuration
/// @brief Core configuration implementation
class Configuration final: public ConfigInternal
{
 public:
  /// @param args Taken as standard argv arguments (element = "space delimited" arg)
  explicit Configuration(
      const std::vector<std::string>& args = std::vector<std::string>());

  ~Configuration();

  /// @brief Parse config arguments
  void ParseConfig();

  /// @details This configures/sets up the global path.
  /// @warning Kovri config must first be parsed and this must be called before anything else
  void SetupGlobalPath();

  /// @brief Tests/Configures AES-NI if available
  /// @warning Kovri config must first be parsed
  void SetupAESNI();

  /// @brief Gets complete path + name of core config
  /// @return Boost filesystem path of file
  /// @warning Config file must first be parsed
  const boost::filesystem::path GetConfigPath() const
  {
    std::string kovri_config = m_Map["kovriconf"].defaulted()
                                   ? "kovri.conf"
                                   : m_Map["kovriconf"].as<std::string>();
    boost::filesystem::path file(kovri_config);
    if (!file.is_complete())
      file = core::GetPath(core::Path::Config) / file;
    return file;
  }

  /// @brief Gets core config variable map
  /// @return Reference to kovri config member variable map
  const boost::program_options::variables_map& GetMap() const noexcept
  {
    return m_Map;
  }

 private:
  /// @brief Exception dispatcher
  core::Exception m_Exception;

  /// @brief Vector of string arguments passed to configuration
  std::vector<std::string> m_Args;

  /// @brief Variable map for command-line and core config file data
  boost::program_options::variables_map m_Map{};

 private:
  // TODO(unassigned): improve this function and use-case
  /// @brief Parses configuration file and maps options
  /// @param config File name
  /// @param config_options Reference to instantiated options_description
  /// @param var_map Reference to instantiated variables map
  /// @notes command-line opts take precedence over config file opts
  void ParseConfigFile(
      const std::string& config,
      const boost::program_options::options_description& config_options,
      boost::program_options::variables_map& var_map);
};

/// @brief stream in conversion implementation to be used by the boost program
///        options library. This function is needed so the boost::program_options
///        delegates the construction and parsing of the Listparameter object.
template <typename T, int MAX>
std::istream& operator>>(std::istream& in, ConfigInternal::ListParameter<T, MAX>& value)
{
  std::string parameter_data;
  in >> parameter_data;
  value.ParseFrom(parameter_data);
  return in;
}

/// @brief Stream out conversion implementation to be used by the boost program
///        options.
///        This function is needed so the boost::program_options delegates the
///        construction and parsing the expected object.
template <typename T, int MAX>
std::ostream& operator<<(std::ostream& os, const ConfigInternal::ListParameter<T, MAX>& value)
{
  os << value.raw_data;
  return os;
}

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_UTIL_CONFIG_H_
