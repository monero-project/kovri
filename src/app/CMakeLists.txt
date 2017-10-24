include_directories("../")

set(APP_SRC
  "main.cc"
  "daemon.cc")

# Linux/OSX/BSD/DragonFly
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND APP_SRC "daemon_linux.cc")
else()
  list(APPEND APP_SRC "daemon_win32.cc")
  list(APPEND APP_SRC "win32_service.cc")
endif()

if(WITH_BINARY)
  ConfigureBinary(${APP_NAME} "${APP_SRC}" ${PROJECT_NAME})
endif()

# vim: noai:ts=2:sw=2
