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

#ifndef SRC_APP_INSTANCE_H_
#define SRC_APP_INSTANCE_H_

#include <string>
#include <vector>

#include "app/config.h"

namespace kovri {
namespace app {

/// @class Instance
/// @brief Instance implementation for client / router contexts
/// @notes It is currently implied that only a single configuration object will
///   be used by a single instance object.
class Instance {
 public:
   // TODO(unassigned): see note and TODO in main about multiple instances
   explicit Instance(
       const std::vector<std::string>& args);

   ~Instance();

  /// @brief Configures instance
  void Configure();

  /// @brief Initializes instance (client/router contexts)
  void Initialize();

  /// @brief Reloads configuration
  /// @notes TODO(unassigned): should also reload client/router contexts
  void Reload();

  /// @brief Get configuration object
  /// @return Reference to configuration object
  Configuration& GetConfig() noexcept {
    return m_Config;
  }

 private:
  /// @brief Initializes router context / core settings
  void InitRouterContext();

  /// @brief Initializes the router's client context object
  /// @details Creates tunnels, proxies and I2PControl service
  void InitClientContext();

  /// @brief Sets up (or reloads) client/server tunnels
  /// @warning Configuration files must be parsed prior to setup
  void SetupTunnels();

  /// @brief Should remove old tunnels after tunnels config is updated
  /// TODO(unassigned): not fully implemented
  void RemoveOldTunnels(
      std::vector<std::string>& updated_tunnels);

 private:
  /// @var m_Config
  /// @brief Configuration implementation
  Configuration m_Config;

  /// @var m_IsReloading
  /// @brief Are tunnels configuration in the process of reloading?
  /// TODO(unassigned): expand types of reloading
  bool m_IsReloading;
};

}  // namespace app
}  // namespace kovri

#endif  // SRC_APP_INSTANCE_H_
