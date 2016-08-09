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

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS  // to use freopen
#endif

#include "win32_service.h"

#include <assert.h>

#include <memory>

#include "daemon.h"
#include "core/util/log.h"

I2PService *I2PService::m_Service = NULL;

BOOL I2PService::isService() {
  BOOL bIsService = FALSE;
  HWINSTA hWinStation = GetProcessWindowStation();
  if (hWinStation != NULL) {
    USEROBJECTFLAGS uof = { 0 };
    if (GetUserObjectInformation(hWinStation, UOI_FLAGS, &uof,
      sizeof(USEROBJECTFLAGS), NULL) && ((uof.dwFlags & WSF_VISIBLE) == 0)) {
        bIsService = TRUE;
    }
  }
  return bIsService;
}

BOOL I2PService::Run(
    I2PService &service) {
  m_Service = &service;
  SERVICE_TABLE_ENTRY serviceTable[] = {
    { service.m_Name, ServiceMain },
    { NULL, NULL }
  };
  return StartServiceCtrlDispatcher(serviceTable);
}

void WINAPI I2PService::ServiceMain(
    DWORD dwArgc,
    PSTR *pszArgv) {
  assert(m_Service != NULL);
  m_Service->m_StatusHandle = RegisterServiceCtrlHandler(
    m_Service->m_Name, ServiceCtrlHandler);
  if (m_Service->m_StatusHandle == NULL) {
    throw GetLastError();
  }
  m_Service->Start(dwArgc, pszArgv);
}

void WINAPI I2PService::ServiceCtrlHandler(
    DWORD dwCtrl) {
  switch (dwCtrl) {
    case SERVICE_CONTROL_STOP: m_Service->Stop(); break;
    case SERVICE_CONTROL_PAUSE: m_Service->Pause(); break;
    case SERVICE_CONTROL_CONTINUE: m_Service->Continue(); break;
    case SERVICE_CONTROL_SHUTDOWN: m_Service->Shutdown(); break;
    case SERVICE_CONTROL_INTERROGATE: break;
    default: break;
  }
}

I2PService::I2PService(
    PSTR pszServiceName,
    BOOL fCanStop,
    BOOL fCanShutdown,
    BOOL fCanPauseContinue) {
  if (pszServiceName == NULL) {
    m_Name = "";  // TODO(unassigned): why?
  } else {
    m_Name = pszServiceName;
  }
  m_StatusHandle = NULL;
  m_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  m_Status.dwCurrentState = SERVICE_START_PENDING;
  DWORD dwControlsAccepted = 0;
  if (fCanStop)
    dwControlsAccepted |= SERVICE_ACCEPT_STOP;
  if (fCanShutdown)
    dwControlsAccepted |= SERVICE_ACCEPT_SHUTDOWN;
  if (fCanPauseContinue)
    dwControlsAccepted |= SERVICE_ACCEPT_PAUSE_CONTINUE;
  m_Status.dwControlsAccepted = dwControlsAccepted;
  m_Status.dwWin32ExitCode = NO_ERROR;
  m_Status.dwServiceSpecificExitCode = 0;
  m_Status.dwCheckPoint = 0;
  m_Status.dwWaitHint = 0;
  m_Stopping = FALSE;
  // Create a manual-reset event that is not signaled at first to indicate
  // the stopped signal of the service.
  m_StoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (m_StoppedEvent == NULL) {
    throw GetLastError();
  }
}

I2PService::~I2PService(void) {
  if (m_StoppedEvent) {
    CloseHandle(m_StoppedEvent);
    m_StoppedEvent = NULL;
  }
}

void I2PService::Start(
    DWORD dwArgc,
    PSTR *pszArgv) {
  try {
    SetServiceStatus(SERVICE_START_PENDING);
    OnStart(dwArgc, pszArgv);
    SetServiceStatus(SERVICE_RUNNING);
  } catch (DWORD dwError) {
    LogPrint(eLogError, "I2PService::Start() execption: ", dwError);
    SetServiceStatus(SERVICE_STOPPED, dwError);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to start.", EVENTLOG_ERROR_TYPE);
    SetServiceStatus(SERVICE_STOPPED);
  }
}

void I2PService::OnStart(
    DWORD dwArgc,
    PSTR *pszArgv) {
  // TODO(unassigned): unused args
  LogPrint(eLogInfo, "I2PServiceWin32: Service in OnStart()",
    EVENTLOG_INFORMATION_TYPE);
  Daemon.Start();
  m_Worker = std::make_unique<std::thread>(
      std::bind(
          &I2PService::WorkerThread,
          this));
}

void I2PService::WorkerThread() {
  while (!m_Stopping) {
    ::Sleep(1000);  // Simulate some lengthy operations.
  }
  // Signal the stopped event.
  SetEvent(m_StoppedEvent);
}

void I2PService::Stop() {
  DWORD dwOriginalState = m_Status.dwCurrentState;
  try {
    SetServiceStatus(SERVICE_STOP_PENDING);
    OnStop();
    SetServiceStatus(SERVICE_STOPPED);
  } catch (DWORD dwError) {
    LogPrint(eLogError, "I2PService::Stop() exception: ", dwError);

    SetServiceStatus(dwOriginalState);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to stop.", EVENTLOG_ERROR_TYPE);
    SetServiceStatus(dwOriginalState);
  }
}

void I2PService::OnStop() {
  // Log a service stop message to the Application log.
  LogPrint(eLogInfo,
      "I2PService: Win32Service in OnStop()", EVENTLOG_INFORMATION_TYPE);
  Daemon.Stop();
  m_Stopping = TRUE;
  if (WaitForSingleObject(m_StoppedEvent, INFINITE) != WAIT_OBJECT_0) {
    throw GetLastError();
  }
  m_Worker->join();
  m_Worker.reset(nullptr);
}

void I2PService::Pause() {
  try {
    SetServiceStatus(SERVICE_PAUSE_PENDING);
    OnPause();
    SetServiceStatus(SERVICE_PAUSED);
  } catch (DWORD dwError) {
    LogPrint(eLogError, "I2PService::Pause() exception: ", dwError);
    SetServiceStatus(SERVICE_RUNNING);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to pause.", EVENTLOG_ERROR_TYPE);
    SetServiceStatus(SERVICE_RUNNING);
  }
}

void I2PService::OnPause() {}

void I2PService::Continue() {
  try {
    SetServiceStatus(SERVICE_CONTINUE_PENDING);
    OnContinue();
    SetServiceStatus(SERVICE_RUNNING);
  } catch (DWORD dwError) {
    LogPrint(eLogError, "I2PService::Continue() exception: ", dwError);
    SetServiceStatus(SERVICE_PAUSED);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to resume.", EVENTLOG_ERROR_TYPE);
    SetServiceStatus(SERVICE_PAUSED);
  }
}

void I2PService::OnContinue() {}

void I2PService::Shutdown() {
  try {
    OnShutdown();
    SetServiceStatus(SERVICE_STOPPED);
  } catch (DWORD dwError) {
    LogPrint(eLogError, "I2PService::Shutdown() exception: ", dwError);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to shut down.", EVENTLOG_ERROR_TYPE);
  }
}

void I2PService::OnShutdown() {}

void I2PService::SetServiceStatus(
    DWORD dwCurrentState,
    DWORD dwWin32ExitCode,
    DWORD dwWaitHint) {
  static DWORD dwCheckPoint = 1;
  m_Status.dwCurrentState = dwCurrentState;
  m_Status.dwWin32ExitCode = dwWin32ExitCode;
  m_Status.dwWaitHint = dwWaitHint;
  m_Status.dwCheckPoint =
    ((dwCurrentState == SERVICE_RUNNING) ||
    (dwCurrentState == SERVICE_STOPPED)) ? 0 : dwCheckPoint++;
  ::SetServiceStatus(m_StatusHandle, &m_Status);
}

//*****************************************************************************

void FreeHandles(SC_HANDLE schSCManager, SC_HANDLE schService) {
  if (schSCManager) {
    CloseServiceHandle(schSCManager);
    schSCManager = NULL;
  }
  if (schService) {
    CloseServiceHandle(schService);
    schService = NULL;
  }
}

void InstallService(
    PSTR pszServiceName,
    PSTR pszDisplayName,
    DWORD dwStartType,
    PSTR pszDependencies,
    PSTR pszAccount,
    PSTR pszPassword) {
  printf("Try to install Win32Service (%s).\n", pszServiceName);
  char szPath[MAX_PATH];
  SC_HANDLE schSCManager = NULL;
  SC_HANDLE schService = NULL;
  if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)) == 0) {
    printf("GetModuleFileName failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(schSCManager, schService);
    return;
  }
  // Open the local default service control manager database
  schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT |
    SC_MANAGER_CREATE_SERVICE);
  if (schSCManager == NULL) {
    printf("OpenSCManager failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(schSCManager, schService);
    return;
  }
  // Install the service into SCM by calling CreateService
  schService = CreateService(
    schSCManager,                   // SCManager database
    pszServiceName,                 // Name of service
    pszDisplayName,                 // Name to display
    SERVICE_QUERY_STATUS,           // Desired access
    SERVICE_WIN32_OWN_PROCESS,      // Service type
    dwStartType,                    // Service start type
    SERVICE_ERROR_NORMAL,           // Error control type
    szPath,                         // Service's binary
    NULL,                           // No load ordering group
    NULL,                           // No tag identifier
    pszDependencies,                // Dependencies
    pszAccount,                     // Service running account
    pszPassword);                   // Password of the account

  if (schService == NULL) {
    printf("CreateService failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(schSCManager, schService);
    return;
  }
  printf("Win32Service is installed as %s.\n", pszServiceName);
  // Centralized cleanup for all allocated resources.
  FreeHandles(schSCManager, schService);
}

void UninstallService(PSTR pszServiceName) {
  printf("Try to uninstall Win32Service (%s).\n", pszServiceName);
  SC_HANDLE schSCManager = NULL;
  SC_HANDLE schService = NULL;
  SERVICE_STATUS ssSvcStatus = {};
  // Open the local default service control manager database
  schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (schSCManager == NULL) {
    printf("OpenSCManager failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(schSCManager, schService);
    return;
  }
  // Open the service with delete, stop, and query status permissions
  schService = OpenService(schSCManager, pszServiceName, SERVICE_STOP |
    SERVICE_QUERY_STATUS | DELETE);
  if (schService == NULL) {
    printf("OpenService failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(schSCManager, schService);
    return;
  }
  // Try to stop the service
  if (ControlService(schService, SERVICE_CONTROL_STOP, &ssSvcStatus)) {
    printf("Stopping %s.\n", pszServiceName);
    Sleep(1000);
    while (QueryServiceStatus(schService, &ssSvcStatus)) {
      if (ssSvcStatus.dwCurrentState == SERVICE_STOP_PENDING) {
        printf(".");
        Sleep(1000);
      } else {
        break;
      }
    }
    if (ssSvcStatus.dwCurrentState == SERVICE_STOPPED) {
      printf("\n%s is stopped.\n", pszServiceName);
    } else {
      printf("\n%s failed to stop.\n", pszServiceName);
    }
  }
  // Now remove the service by calling DeleteService.
  if (!DeleteService(schService)) {
    printf("DeleteService failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(schSCManager, schService);
    return;
  }
  printf("%s is removed.\n", pszServiceName);
  // Centralized cleanup for all allocated resources.
  FreeHandles(schSCManager, schService);
}
