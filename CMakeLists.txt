cmake_minimum_required(VERSION 2.8.12)
project("kovri")

# Configurable options
option(KOVRI_DATA_PATH "The path to the kovri data folder")
option(WITH_AESNI      "Use AES-NI instructions set" OFF)
option(WITH_BENCHMARKS "Build with benchmarks" OFF)
option(WITH_BINARY     "Build binary" ON)
option(WITH_CRYPTOPP   "Build with Crypto++" ON)  # Default ON unless we switch libraries
option(WITH_DOXYGEN    "Enable support for Doxygen" OFF)
option(WITH_HARDENING  "Use hardening compiler flags" OFF)
option(WITH_LIBRARY    "Build library" ON)
option(WITH_OPTIMIZE   "Optimization flags" OFF)
option(WITH_STATIC     "Static build" OFF)
option(WITH_TESTS      "Build unit tests" OFF)
option(WITH_UPNP       "Include support for UPnP client" OFF)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/build/cmake/")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Default build is Debug
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Compiler flags customization (by vendor)
if(NOT MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Winvalid-pch")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pedantic")
  # TODO: The following is incompatible with static build and enabled hardening
  #  for OpenWRT.
  # Multiple definitions of __stack_chk_fail (libssp & libc)
  set(CMAKE_CXX_FLAGS_MINSIZEREL
    "${CMAKE_CXX_FLAGS_MINSIZEREL} -flto -s -ffunction-sections -fdata-sections")
  # -flto is added from above
  set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "-Wl,--gc-sections")
endif()

# Check for c++11 support
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" CXX11_SUPPORTED)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" CXX0X_SUPPORTED)
if(CXX11_SUPPORTED)
  add_definitions("-std=c++11")
elseif(CXX0X_SUPPORTED) # gcc 4.6
  add_definitions("-std=c++0x")
elseif(NOT MSVC)
  message(SEND_ERROR "C++11 standard not supported by compiler. Version too old?")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(WITH_HARDENING)
    add_definitions("-D_FORTIFY_SOURCE=2")
    set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security -Werror=format-security")
    set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -fstack-protector-strong -fPIE --param ssp-buffer-size=4 -z relro -z now")
    endif()
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # Uncomment for verbose output
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -v")
endif()

# Compiler flags customization (by system)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  # "'sleep_for' is not a member of 'std::this_thread'" in gcc 4.7/4.8
  add_definitions("-D_GLIBCXX_USE_NANOSLEEP=1")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif()

if(WITH_UPNP)
  add_definitions(-DUSE_UPNP)
  if(NOT MSVC)
    set(DL_LIB ${CMAKE_DL_LIBS})
  endif()
endif()

if(WITH_AESNI)
  add_definitions("-maes -DAESNI")
endif()

if(WITH_OPTIMIZE AND (NOT MSVC))
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
endif()

# Libraries
# TODO: once CMake 3.1+ becomes mainstream, see e.g.
#  http://stackoverflow.com/a/29871891/673826 use imported Threads::Threads
#  instead
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
if(THREADS_HAVE_PTHREAD_ARG) # compile time flag
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()

if(WITH_STATIC)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME OFF)
  set(BUILD_SHARED_LIBS OFF)
  if(NOT WIN32)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
  endif()
  if(${CMAKE_CXX_COMPILER} MATCHES ".*-openwrt-.*")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
    set(CMAKE_THREAD_LIBS_INIT
      "gcc_eh -Wl,-u,pthread_create,-u,pthread_once,-u,pthread_mutex_lock,-u,pthread_mutex_unlock,-u,pthread_join,-u,pthread_equal,-u,pthread_detach,-u,pthread_cond_wait,-u,pthread_cond_signal,-u,pthread_cond_destroy,-u,pthread_cond_broadcast,-u,pthread_cancel")
  endif()
endif()

if(NOT WIN32)
  # TODO: Consider separate compilation for COMMON_SRC for library.
  # No need in -fPIC overhead for binary if not interested in library
  # HINT: revert c266cff CMakeLists.txt: compilation speed up
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
endif()

find_package(
  Boost
  COMPONENTS
    chrono log
    program_options date_time
    thread system
    filesystem regex
  REQUIRED)

if(NOT Boost_FOUND)
  message(SEND_ERROR "Boost not found, or version below 1.46. Please download Boost!")
else()
  add_definitions(-DBOOST_ALL_DYN_LINK)
endif()

if(WITH_CRYPTOPP)
  find_package(CryptoPP REQUIRED)
  if(NOT DEFINED CRYPTO++_INCLUDE_DIR)
    message(SEND_ERROR "Could not find Crypto++. Please download and install it first!")
  endif()
endif()

if(APPLE)
  # If we're on OS X check for Homebrew's copy of OpenSSL instead of Apple's
  if (NOT OpenSSL_DIR)
    execute_process (COMMAND brew --prefix openssl
      OUTPUT_VARIABLE OPENSSL_ROOT_DIR
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
endif()

find_package(OpenSSL REQUIRED)
if(NOT DEFINED OPENSSL_INCLUDE_DIR)
  message(SEND_ERROR "Could not find OpenSSL. Please download and install it first!")
endif()

find_package(MiniUPnPc)
if(NOT ${MINIUPNPC_FOUND})
  set(WITH_UPNP OFF)
endif()

# Doxygen support
if(WITH_DOXYGEN)
  include(UseDoxygen)
endif()

# Load includes
include_directories(${CMAKE_SOURCE_DIR} ${Boost_INCLUDE_DIRS} ${CRYPTO++_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})

# Set default path
if(KOVRI_DATA_PATH)
  set(KOVRI_DATA_DIR ${KOVRI_DATA_PATH})
  # Using custom path, make sure the code knows about this
  add_definitions(-DKOVRI_CUSTOM_DATA_PATH="${KOVRI_DATA_PATH}")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(KOVRI_DATA_DIR "$ENV{APPDATA}\\kovri")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(KOVRI_DATA_DIR "$ENV{HOME}/Library/Application Support/kovri")
else()
  set(KOVRI_DATA_DIR "$ENV{HOME}/.kovri")
endif()

# Show summary
message(STATUS "---------------------------------------")
message(STATUS "Build type         : ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler vendor    : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler version   : ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Compiler path      : ${CMAKE_CXX_COMPILER}")
message(STATUS "Install prefix:    : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Kovri data directory: ${KOVRI_DATA_DIR}")
message(STATUS "Options:")
message(STATUS "  AESNI            : ${WITH_AESNI}")
message(STATUS "  BENCHMARKS       : ${WITH_BENCHMARKS}")
message(STATUS "  BINARY           : ${WITH_BINARY}")
message(STATUS "  CRYPTOPP         : ${WITH_CRYPTOPP}")
message(STATUS "  DOXYGEN          : ${WITH_DOXYGEN}")
message(STATUS "  HARDENING        : ${WITH_HARDENING}")
message(STATUS "  LIBRARY          : ${WITH_LIBRARY}")
message(STATUS "  OPTIMIZATION     : ${WITH_OPTIMIZE}")
message(STATUS "  STATIC BUILD     : ${WITH_STATIC}")
message(STATUS "  TESTS            : ${WITH_TESTS}")
message(STATUS "  UPnP             : ${WITH_UPNP}")
message(STATUS "---------------------------------------")

# Handle paths nicely
include(GNUInstallDirs)

set(APP_NAME "${PROJECT_NAME}-app")
set(CLIENT_NAME "${PROJECT_NAME}-client")
set(CORE_NAME "${PROJECT_NAME}-core")
set(TESTS_NAME "${PROJECT_NAME}-tests")
set(BENCHMARKS_NAME "${PROJECT_NAME}-benchmarks")
add_subdirectory(src)

# Copy needed resources
if(WITH_BINARY)
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/pkg/certificates" DESTINATION "${KOVRI_DATA_DIR}/")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/pkg/kovri.conf" DESTINATION "${KOVRI_DATA_DIR}/")
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/pkg/tunnels.conf" DESTINATION "${KOVRI_DATA_DIR}/")
endif()

# vim: noai:ts=2:sw=2
