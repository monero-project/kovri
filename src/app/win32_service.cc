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

BOOL I2PService::IsService() {
  BOOL is_service = FALSE;
  HWINSTA h_win_station = GetProcessWindowStation();
  if (h_win_station != NULL) {
    USEROBJECTFLAGS uof = { 0 };
    if (GetUserObjectInformation(hWinStation, UOI_FLAGS, &uof,
      sizeof(USEROBJECTFLAGS), NULL) && ((uof.dwFlags & WSF_VISIBLE) == 0)) {
        is_service = TRUE;
    }
  }
  return is_service;
}

BOOL I2PService::Run(
    I2PService &service) {
  m_Service = &service;
  SERVICE_TABLE_ENTRY service_table[] = {
    { service.m_Name, ServiceMain },
    { NULL, NULL }
  };
  return StartServiceCtrlDispatcher(service_table);
}

void WINAPI I2PService::ServiceMain(
    DWORD dw_argc,
    PSTR *psz_argv) {
  assert(m_Service != NULL);
  m_Service->m_StatusHandle = RegisterServiceCtrlHandler(
    m_Service->m_Name, ServiceCtrlHandler);
  if (m_Service->m_StatusHandle == NULL) {
    throw GetLastError();
  }
  m_Service->Start(dw_argc, psz_argv);
}

void WINAPI I2PService::ServiceCtrlHandler(
    DWORD dw_ctrl) {
  switch (dw_ctrl) {
    case SERVICE_CONTROL_STOP: m_Service->Stop(); break;
    case SERVICE_CONTROL_PAUSE: m_Service->Pause(); break;
    case SERVICE_CONTROL_CONTINUE: m_Service->Continue(); break;
    case SERVICE_CONTROL_SHUTDOWN: m_Service->Shutdown(); break;
    case SERVICE_CONTROL_INTERROGATE: break;
    default: break;
  }
}

I2PService::I2PService(
    PSTR psz_service_name,
    BOOL can_stop,
    BOOL can_shutdown,
    BOOL can_pause_continue) {
  if (psz_service_name == NULL) {
    m_Name = "";  // TODO(unassigned): why?
  } else {
    m_Name = psz_service_name;
  }
  m_StatusHandle = NULL;
  m_Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  m_Status.dwCurrentState = SERVICE_START_PENDING;
  DWORD dw_controls_accepted = 0;
  if (can_stop)
    dw_controls_accepted |= SERVICE_ACCEPT_STOP;
  if (can_shutdown)
    dw_controls_accepted |= SERVICE_ACCEPT_SHUTDOWN;
  if (can_pause_continue)
    dw_controls_accepted |= SERVICE_ACCEPT_PAUSE_CONTINUE;
  m_Status.dw_controls_accepted = dw_controls_accepted;
  m_Status.dw_win32_exit_code = NO_ERROR;
  m_Status.dw_service_specific_exit_code = 0;
  m_Status.dw_check_point = 0;
  m_Status.dw_wait_hint = 0;
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
    DWORD dw_argc,
    PSTR *psz_argv) {
  try {
    SetServiceStatus(SERVICE_START_PENDING);
    OnStart(dw_argc, psz_argv);
    SetServiceStatus(SERVICE_RUNNING);
  } catch (DWORD dw_error) {
    LogPrint(eLogError, "I2PService::Start() execption: ", dw_error);
    SetServiceStatus(SERVICE_STOPPED, dw_error);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to start.", EVENTLOG_ERROR_TYPE);
    SetServiceStatus(SERVICE_STOPPED);
  }
}

void I2PService::OnStart(
    DWORD dw_argc,
    PSTR *psz_argv) {
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
  DWORD dw_original_state = m_Status.dwCurrentState;
  try {
    SetServiceStatus(SERVICE_STOP_PENDING);
    OnStop();
    SetServiceStatus(SERVICE_STOPPED);
  } catch (DWORD dw_error) {
    LogPrint(eLogError, "I2PService::Stop() exception: ", dw_error);

    SetServiceStatus(dw_original_state);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to stop.", EVENTLOG_ERROR_TYPE);
    SetServiceStatus(dw_original_state);
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
  } catch (DWORD dw_error) {
    LogPrint(eLogError, "I2PService::Pause() exception: ", dw_error);
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
  } catch (DWORD dw_error) {
    LogPrint(eLogError, "I2PService::Continue() exception: ", dw_error);
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
  } catch (DWORD dw_error) {
    LogPrint(eLogError, "I2PService::Shutdown() exception: ", dw_error);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to shut down.", EVENTLOG_ERROR_TYPE);
  }
}

void I2PService::OnShutdown() {}

void I2PService::SetServiceStatus(
    DWORD dw_current_state,
    DWORD dw_win32_exit_code,
    DWORD dw_wait_hint) {
  static DWORD dw_check_point = 1;
  m_Status.dw_current_state = dw_current_state;
  m_Status.dw_win32_exit_code = dw_win32_exit_code;
  m_Status.dw_wait_hint = dw_wait_hint;
  m_Status.dw_check_point =
    ((dw_current_state == SERVICE_RUNNING) ||
    (dw_current_state == SERVICE_STOPPED)) ? 0 : dw_check_point++;
  ::SetServiceStatus(m_StatusHandle, &m_Status);
}

//*****************************************************************************

void FreeHandles(SC_HANDLE sch_sc_manager, SC_HANDLE sch_service) {
  if (sch_sc_manager) {
    CloseServiceHandle(sch_sc_manager);
    sch_sc_manager = NULL;
  }
  if (sch_service) {
    CloseServiceHandle(sch_service);
    sch_service = NULL;
  }
}

void InstallService(
    PSTR psz_service_name,
    PSTR psz_display_name,
    DWORD dw_start_type,
    PSTR psz_dependencies,
    PSTR psz_account,
    PSTR psz_password) {
  printf("Try to install Win32Service (%s).\n", psz_service_name);
  char sz_path[MAX_PATH];
  SC_HANDLE sch_sc_manager = NULL;
  SC_HANDLE sch_service = NULL;
  if (GetModuleFileName(NULL, sz_path, ARRAYSIZE(sz_path)) == 0) {
    printf("GetModuleFileName failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(sch_sc_manager, sch_service);
    return;
  }
  // Open the local default service control manager database
  sch_sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT |
    SC_MANAGER_CREATE_SERVICE);
  if (sch_sc_manager == NULL) {
    printf("OpenSCManager failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(sch_sc_manager, sch_service);
    return;
  }
  // Install the service into SCM by calling CreateService
  sch_service = CreateService(
    sch_sc_manager,                   // SCManager database
    psz_service_name,                 // Name of service
    psz_display_name,                 // Name to display
    SERVICE_QUERY_STATUS,           // Desired access
    SERVICE_WIN32_OWN_PROCESS,      // Service type
    dw_start_type,                    // Service start type
    SERVICE_ERROR_NORMAL,           // Error control type
    sz_path,                         // Service's binary
    NULL,                           // No load ordering group
    NULL,                           // No tag identifier
    psz_dependencies,                // Dependencies
    psz_account,                     // Service running account
    psz_password);                   // Password of the account

  if (sch_service == NULL) {
    printf("CreateService failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(sch_sc_manager, sch_service);
    return;
  }
  printf("Win32Service is installed as %s.\n", psz_service_name);
  // Centralized cleanup for all allocated resources.
  FreeHandles(sch_sc_manager, sch_service);
}

void UninstallService(PSTR psz_service_name) {
  printf("Try to uninstall Win32Service (%s).\n", psz_service_name);
  SC_HANDLE sch_sc_manager = NULL;
  SC_HANDLE sch_service = NULL;
  SERVICE_STATUS ss_svc_status = {};
  // Open the local default service control manager database
  sch_sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (sch_sc_manager == NULL) {
    printf("OpenSCManager failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(sch_sc_manager, sch_service);
    return;
  }
  // Open the service with delete, stop, and query status permissions
  sch_service = OpenService(sch_sc_manager, psz_service_name, SERVICE_STOP |
    SERVICE_QUERY_STATUS | DELETE);
  if (sch_service == NULL) {
    printf("OpenService failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(sch_sc_manager, sch_service);
    return;
  }
  // Try to stop the service
  if (ControlService(sch_service, SERVICE_CONTROL_STOP, &ss_svc_status)) {
    printf("Stopping %s.\n", psz_service_name);
    Sleep(1000);
    while (QueryServiceStatus(schService, &ss_svc_status)) {
      if (ss_svc_status.dw_current_state == SERVICE_STOP_PENDING) {
        printf(".");
        Sleep(1000);
      } else {
        break;
      }
    }
    if (ss_svc_status.dw_current_state == SERVICE_STOPPED) {
      printf("\n%s is stopped.\n", psz_service_name);
    } else {
      printf("\n%s failed to stop.\n", psz_service_name);
    }
  }
  // Now remove the service by calling DeleteService.
  if (!DeleteService(sch_service)) {
    printf("DeleteService failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(schSCManager, sch_service);
    return;
  }
  printf("%s is removed.\n", psz_service_name);
  // Centralized cleanup for all allocated resources.
  FreeHandles(sch_sc_manager, sch_service);
}
