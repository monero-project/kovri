cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(kovri-app CXX)

add_executable(kovri-app
  main.cc
  daemon.cc
  daemon.h)
target_include_directories(kovri-app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Linux/OSX/BSD/DragonFly
if (WIN32)
  target_sources(kovri-app PRIVATE daemon_win32.cc win32_service.cc win32_service.h)
else()
  target_sources(kovri-app PRIVATE daemon_linux.cc)
endif()
ConfigureBinary(kovri-app "kovri") 

if (COMMAND cotire)
  set_target_properties(kovri-app PROPERTIES COTIRE_PREFIX_HEADER_INCLUDE_PATH "${CMAKE_SOURCE_DIR}/deps")
  cotire(kovri-app)
endif()
# vim: noai:ts=2:sw=2
