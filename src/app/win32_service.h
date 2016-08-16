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
      PSTR pszServiceName,
      BOOL fCanStop = TRUE,
      BOOL fCanShutdown = TRUE,
      BOOL fCanPauseContinue = FALSE);

  virtual ~I2PService(void);

  static BOOL isService();
  static BOOL Run(I2PService& service);
  void Stop();

 protected:
  virtual void OnStart(
      DWORD dwArgc,
      PSTR *pszArgv);
  virtual void OnStop();
  virtual void OnPause();
  virtual void OnContinue();
  virtual void OnShutdown();
  void SetServiceStatus(
      DWORD dwCurrentState,
      DWORD dwWin32ExitCode = NO_ERROR,
      DWORD dwWaitHint = 0);

 private:
  static void WINAPI ServiceMain(
      DWORD dwArgc,
      LPSTR *lpszArgv);
  static void WINAPI ServiceCtrlHandler(
      DWORD dwCtrl);
  void WorkerThread();
  void Start(
      DWORD dwArgc,
      PSTR *pszArgv);
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
    PSTR pszServiceName,
    PSTR pszDisplayName,
    DWORD dwStartType,
    PSTR pszDependencies,
    PSTR pszAccount,
    PSTR pszPassword);

void UninstallService(PSTR pszServiceName);

#endif  // SRC_APP_WIN32_SERVICE_H_
