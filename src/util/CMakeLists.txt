cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(kovri-util CXX)

add_executable(kovri-util
  base.cc
  benchmark.cc
  i2pcontrol_client.cc
  i2pcontrol.cc
  main.cc
  routerinfo.cc
  su3file.cc
  base.h
  benchmark.h
  command.h
  cpuid.h
  fuzz.h
  i2pcontrol.h
  i2pcontrol_client.h
  kovri.h
  routerinfo.h
  su3file.h)
target_include_directories(kovri-util PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)

if(NOT WIN32)
  target_sources(kovri-util PRIVATE kovri.cc)
endif()

if(WITH_CRYPTOPP)
  target_sources(kovri-util PRIVATE cpuid.cc)
endif()

if(WITH_FUZZ_TESTS)
  target_sources(kovri-util PRIVATE 
    ../../tests/fuzz_tests/i2pcontrol.cc
    ../../tests/fuzz_tests/lease_set.cc
    ../../tests/fuzz_tests/routerinfo.cc
    ../../tests/fuzz_tests/su3.cc
    fuzz.cc)
endif()

ConfigureBinary(kovri-util "kovri-util")

if (COMMAND cotire)
  set_target_properties(kovri-client PROPERTIES COTIRE_PREFIX_HEADER_INCLUDE_PATH "${CMAKE_SOURCE_DIR}/deps")
  cotire(kovri-util)
endif()

# vim: noai:ts=2:sw=2
