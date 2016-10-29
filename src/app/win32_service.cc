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

#include "app/win32_service.h"

#include <assert.h>

#include <memory>

#include "app/daemon.h"

#include "core/util/log.h"

I2PService *I2PService::m_Service = NULL;

BOOL I2PService::IsService() {
  BOOL is_service = FALSE;
  HWINSTA win_station = GetProcessWindowStation();
  if (win_station != NULL) {
    USEROBJECTFLAGS uof = { 0 };
    if (GetUserObjectInformation(win_station, UOI_FLAGS, &uof,
      sizeof(USEROBJECTFLAGS), NULL) && ((uof.flags & WSF_VISIBLE) == 0)) {
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
    DWORD argc,
    PSTR *argv) {
  assert(m_Service != NULL);
  m_Service->m_StatusHandle = RegisterServiceCtrlHandler(
    m_Service->m_Name, ServiceCtrlHandler);
  if (m_Service->m_StatusHandle == NULL) {
    throw GetLastError();
  }
  m_Service->Start(argc, argv);
}

void WINAPI I2PService::ServiceCtrlHandler(
    DWORD ctrl) {
  switch (ctrl) {
    case SERVICE_CONTROL_STOP: m_Service->Stop(); break;
    case SERVICE_CONTROL_PAUSE: m_Service->Pause(); break;
    case SERVICE_CONTROL_CONTINUE: m_Service->Continue(); break;
    case SERVICE_CONTROL_SHUTDOWN: m_Service->Shutdown(); break;
    case SERVICE_CONTROL_INTERROGATE: break;
    default: break;
  }
}

I2PService::I2PService(
    PSTR service_name,
    BOOL can_stop,
    BOOL can_shutdown,
    BOOL can_pause_continue) {
  if (service_name == NULL) {
    m_Name = "";  // TODO(unassigned): why?
  } else {
    m_Name = service_name;
  }
  m_StatusHandle = NULL;
  m_Status.service_type = SERVICE_WIN32_OWN_PROCESS;
  m_Status.current_state = SERVICE_START_PENDING;
  DWORD controls_accepted = 0;
  if (can_stop)
    controls_accepted |= SERVICE_ACCEPT_STOP;
  if (can_shutdown)
    controls_accepted |= SERVICE_ACCEPT_SHUTDOWN;
  if (can_pause_continue)
    controls_accepted |= SERVICE_ACCEPT_PAUSE_CONTINUE;
  m_Status.controls_accepted = controls_accepted;
  m_Status.win32_exit_code = NO_ERROR;
  m_Status.service_specific_exit_code = 0;
  m_Status.check_point = 0;
  m_Status.wait_hint = 0;
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
    DWORD argc,
    PSTR *argv) {
  try {
    SetServiceStatus(SERVICE_START_PENDING);
    OnStart(argc, argv);
    SetServiceStatus(SERVICE_RUNNING);
  } catch (DWORD error) {
    LogPrint(eLogError, "I2PService::Start() execption: ", error);
    SetServiceStatus(SERVICE_STOPPED, error);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to start.", EVENTLOG_ERROR_TYPE);
    SetServiceStatus(SERVICE_STOPPED);
  }
}

void I2PService::OnStart(
    DWORD argc,
    PSTR *argv) {
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
  DWORD original_state = m_Status.current_state;
  try {
    SetServiceStatus(SERVICE_STOP_PENDING);
    OnStop();
    SetServiceStatus(SERVICE_STOPPED);
  } catch (DWORD error) {
    LogPrint(eLogError, "I2PService::Stop() exception: ", error);

    SetServiceStatus(original_state);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to stop.", EVENTLOG_ERROR_TYPE);
    SetServiceStatus(original_state);
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
  } catch (DWORD error) {
    LogPrint(eLogError, "I2PService::Pause() exception: ", error);
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
  } catch (DWORD error) {
    LogPrint(eLogError, "I2PService::Continue() exception: ", error);
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
  } catch (DWORD error) {
    LogPrint(eLogError, "I2PService::Shutdown() exception: ", error);
  } catch (...) {
    LogPrint(eLogError,
        "I2PService: Win32Service failed to shut down.", EVENTLOG_ERROR_TYPE);
  }
}

void I2PService::OnShutdown() {}

void I2PService::SetServiceStatus(
    DWORD current_state,
    DWORD win32_exit_code,
    DWORD wait_hint) {
  static DWORD check_point = 1;
  m_Status.current_state = current_state;
  m_Status.win32_exit_code = win32_exit_code;
  m_Status.wait_hint = wait_hint;
  m_Status.check_point =
    ((current_state == SERVICE_RUNNING) ||
    (current_state == SERVICE_STOPPED)) ? 0 : check_point++;
  ::SetServiceStatus(m_StatusHandle, &m_Status);
}

//*****************************************************************************

void FreeHandles(SC_HANDLE manager, SC_HANDLE service) {
  if (manager) {
    CloseServiceHandle(manager);
    manager = NULL;
  }
  if (service) {
    CloseServiceHandle(sch_service);
    service = NULL;
  }
}

void InstallService(
    PSTR service_name,
    PSTR display_name,
    DWORD start_type,
    PSTR dependencies,
    PSTR account,
    PSTR password) {
  printf("Try to install Win32Service (%s).\n", service_name);
  char path[MAX_PATH];
  SC_HANDLE manager = NULL;
  SC_HANDLE service = NULL;
  if (GetModuleFileName(NULL, path, ARRAYSIZE(path)) == 0) {
    printf("GetModuleFileName failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(manager, service);
    return;
  }
  // Open the local default service control manager database
  manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT |
    SC_MANAGER_CREATE_SERVICE);
  if (manager == NULL) {
    printf("OpenSCManager failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(manager, service);
    return;
  }
  // Install the service into SCM by calling CreateService
  service = CreateService(
    manager,                   // SCManager database
    service_name,                 // Name of service
    display_name,                 // Name to display
    SERVICE_QUERY_STATUS,           // Desired access
    SERVICE_WIN32_OWN_PROCESS,      // Service type
    start_type,                    // Service start type
    SERVICE_ERROR_NORMAL,           // Error control type
    path,                         // Service's binary
    NULL,                           // No load ordering group
    NULL,                           // No tag identifier
    dependencies,                // Dependencies
    account,                     // Service running account
    password);                   // Password of the account

  if (service == NULL) {
    printf("CreateService failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(manager, service);
    return;
  }
  printf("Win32Service is installed as %s.\n", service_name);
  // Centralized cleanup for all allocated resources.
  FreeHandles(manager, service);
}

void UninstallService(PSTR service_name) {
  printf("Try to uninstall Win32Service (%s).\n", service_name);
  SC_HANDLE manager = NULL;
  SC_HANDLE service = NULL;
  SERVICE_STATUS status = {};
  // Open the local default service control manager database
  manager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (manager == NULL) {
    printf("OpenSCManager failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(manager, service);
    return;
  }
  // Open the service with delete, stop, and query status permissions
  service = OpenService(manager, service_name, SERVICE_STOP |
    SERVICE_QUERY_STATUS | DELETE);
  if (service == NULL) {
    printf("OpenService failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(manager, service);
    return;
  }
  // Try to stop the service
  if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
    printf("Stopping %s.\n", service_name);
    Sleep(1000);
    while (QueryServiceStatus(service, &status)) {
      if (status.current_state == SERVICE_STOP_PENDING) {
        printf(".");
        Sleep(1000);
      } else {
        break;
      }
    }
    if (status.current_state == SERVICE_STOPPED) {
      printf("\n%s is stopped.\n", service_name);
    } else {
      printf("\n%s failed to stop.\n", service_name);
    }
  }
  // Now remove the service by calling DeleteService.
  if (!DeleteService(service)) {
    printf("DeleteService failed w/err 0x%08lx\n", GetLastError());
    FreeHandles(manager, service);
    return;
  }
  printf("%s is removed.\n", service_name);
  // Centralized cleanup for all allocated resources.
  FreeHandles(manager, service);
}
