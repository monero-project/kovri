/**                                                                                           //
 * Copyright (c) 2013-2016, The Kovri I2P Router Project                                      //
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
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project          //
 */

#ifndef SRC_APP_WIN32_SERVICE_H_
#define SRC_APP_WIN32_SERVICE_H_

#include <winsock2.h>
#include <windows.h>
#define WIN32_LEAN_AND_MEAN
#include <memory>
#include <thread>

#ifdef _WIN32
// Internal name of the service
#define SERVICE_NAME             "Kovri"

// Displayed name of the service
#define SERVICE_DISPLAY_NAME     "Kovri I2P Router"

// Service start options.
#define SERVICE_START_TYPE       SERVICE_DEMAND_START

// List of service dependencies - "dep1\0dep2\0\0"
#define SERVICE_DEPENDENCIES     ""

// The name of the account under which the service should run
#define SERVICE_ACCOUNT          "NT AUTHORITY\\LocalService"

// The password to the service account name
#define SERVICE_PASSWORD         NULL
#endif


class I2PService {
 public:
  I2PService(
      PSTR service_name,
      BOOL can_stop = TRUE,
      BOOL can_shutdown = TRUE,
      BOOL can_pause_continue = FALSE);

  virtual ~I2PService(void);

  static BOOL IsService();
  static BOOL Run(I2PService& service);
  void Stop();

 protected:
  virtual void OnStart(
      DWORD argc,
      PSTR *argv);
  virtual void OnStop();
  virtual void OnPause();
  virtual void OnContinue();
  virtual void OnShutdown();
  void SetServiceStatus(
      DWORD current_state,
      DWORD win32_exit_code = NO_ERROR,
      DWORD wait_hint = 0);

 private:
  static void WINAPI ServiceMain(
      DWORD argc,
      LPSTR *argv);
  static void WINAPI ServiceCtrlHandler(
      DWORD ctrl);
  void WorkerThread();
  void Start(
      DWORD argc,
      PSTR *argv);
  void Pause();
  void Continue();
  void Shutdown();
  static I2PService* m_Service;
  PSTR m_Name;
  SERVICE_STATUS m_Status;
  SERVICE_STATUS_HANDLE m_StatusHandle;

  BOOL m_Stopping;
  HANDLE m_StoppedEvent;

  std::unique_ptr<std::thread> m_Worker;
};

void InstallService(
    PSTR service_name,
    PSTR display_name,
    DWORD start_type,
    PSTR dependencies,
    PSTR account,
    PSTR password);

void UninstallService(PSTR service_name);

#endif  // SRC_APP_WIN32_SERVICE_H_
