cmake_minimum_required(VERSION 2.8.12)
project("kovri" C CXX)

# Configurable options
option(KOVRI_DATA_PATH "The path to the kovri data folder")
option(WITH_BENCHMARKS "Build with benchmarks" OFF)
option(WITH_BINARY     "Build binary" ON)
option(WITH_COVERAGE   "Build with coverage" OFF)
option(WITH_CRYPTOPP   "Build with Crypto++" ON)  # Default ON unless we switch libraries
option(WITH_CPPNETLIB  "Build with cpp-netlib" ON)
option(WITH_DOXYGEN    "Enable support for Doxygen" OFF)
option(WITH_HARDENING  "Use hardening compiler flags" OFF)
option(WITH_LIBRARY    "Build library" ON)
option(WITH_OPTIMIZE   "Optimization flags" OFF)
option(WITH_STATIC     "Static build" OFF)
option(WITH_SUPERCOP   "Build Ed25519 using the ref10 implementation from SUPERCOP" ON)  # Default ON unless we switch implementations
option(WITH_TESTS      "Build unit tests" OFF)
option(WITH_UPNP       "Include support for UPnP client" OFF)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Default build is Debug
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Check whether we're on a 32-bit or 64-bit system
if(CMAKE_SIZEOF_VOID_P EQUAL "8")
  set(ARCH_WIDTH "64")
else()
  set(ARCH_WIDTH "32")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(LINUX TRUE)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  set(FREEBSD TRUE)
endif()

# TODO(anonimal): continue with systems as needed

### TODO(unassigned): improve detection and use-case
# Minimal processor detection (needed for ARM build)
set(CPU "${CMAKE_SYSTEM_PROCESSOR}")
string(SUBSTRING "${CPU}" 0 3 PARSE_ARM)
if (CPU STREQUAL "aarch64" OR PARSE_ARM STREQUAL "arm")
  set(ARM TRUE)
endif()

# Detect minimum compiler version
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9.3)
    message(FATAL_ERROR "GCC 4.9.3 or higher is required")
  endif()
  set(GNU TRUE)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 3.5)
    message(FATAL_ERROR "Clang 3.5 or higher is required")
  endif()
  set(CLANG TRUE)
endif()

# Check for C++14 support (minimum version compilers guarantee this)
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++1y" CXX14_SUPPORTED)
if(CXX14_SUPPORTED)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y")
elseif(NOT MSVC)
  message(FATAL_ERROR "C++14 standard not supported by compiler. See building instructions.")
endif()

### TODO(unassigned): review, cleanup, improve
# Compiler flags (by vendor)
if(NOT MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Winvalid-pch")
  if(NOT ARM)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
  endif()
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pedantic")
  # TODO: The following is incompatible with static build and enabled hardening
  #  for OpenWRT.
  # Multiple definitions of __stack_chk_fail (libssp & libc)
  set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -flto -s -ffunction-sections -fdata-sections")
  # -flto is added from above
  set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "-Wl,--gc-sections")
  if(WITH_HARDENING)
    add_definitions("-D_FORTIFY_SOURCE=2")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security -Werror=format-security")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -fPIE --param ssp-buffer-size=4")
    if(GNU AND NOT MINGW)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -z relro -z now")
    endif()
  endif()
  if(WITH_OPTIMIZE AND NOT WITH_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
  endif()
  if(WITH_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 --coverage")
  endif()
endif()

if(WITH_UPNP)
  add_definitions(-DUSE_UPNP)
  if(NOT MSVC)
    set(DL_LIB ${CMAKE_DL_LIBS})
  endif()
endif()

if(NOT WIN32 AND NOT WITH_STATIC)
  # TODO: Consider separate compilation for COMMON_SRC for library.
  # No need in -fPIC overhead for binary if not interested in library
  # HINT: revert c266cff CMakeLists.txt: compilation speed up
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
endif()

if(WITH_STATIC)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
  set(BUILD_SHARED_LIBS OFF)
  if(MINGW)
    # Needed for windows static build to ensure full paths are used/libraries linked
    string(REGEX MATCH "^[^/]:/[^/]*" msys2_install_path "${CMAKE_C_COMPILER}")
    message(STATUS "MSYS location: ${msys2_install_path}")
    set(CMAKE_INCLUDE_PATH "${msys2_install_path}/mingw${ARCH_WIDTH}/include")
    set(DEFLIB ${msys2_install_path}/mingw${ARCH_WIDTH}/lib)
    list(REMOVE_ITEM CMAKE_C_IMPLICIT_LINK_DIRECTORIES ${DEFLIB})
    list(REMOVE_ITEM CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES ${DEFLIB})
    # NOTE: leave uncommented for openssl static
    if(MINGW)
      set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
    endif()
  endif()
  if(${CMAKE_CXX_COMPILER} MATCHES ".*-openwrt-.*")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
    set(CMAKE_THREAD_LIBS_INIT
      "gcc_eh -Wl,-u,pthread_create,-u,pthread_once,-u,pthread_mutex_lock,-u,pthread_mutex_unlock,-u,pthread_join,-u,pthread_equal,-u,pthread_detach,-u,pthread_cond_wait,-u,pthread_cond_signal,-u,pthread_cond_destroy,-u,pthread_cond_broadcast,-u,pthread_cancel")
  endif()
endif()

find_package(
  Boost 1.58
  COMPONENTS
    chrono log
    program_options date_time
    thread system
    filesystem regex
  REQUIRED)

if(NOT Boost_FOUND)
  message(FATAL_ERROR "Boost not found or requirement not satisfied. See building instructions.")
else()
  message(STATUS "Found Boost: ${Boost_INCLUDE_DIR}, ${Boost_LIBRARIES}")
  if(NOT WITH_STATIC)
    add_definitions(-DBOOST_ALL_DYN_LINK)
  endif()
  include_directories(${Boost_INCLUDE_DIRS})
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

if(WITH_CRYPTOPP)
  find_package(CryptoPP REQUIRED)
  if(NOT CryptoPP_FOUND)
    message(FATAL_ERROR "Could not find Crypto++. See building instructions.")
  else()
    message(STATUS "Found Crypto++: ${CryptoPP_INCLUDE_DIR}, ${CryptoPP_LIBRARIES}")
    include_directories(${CryptoPP_INCLUDE_DIR}/../)  # We back-track for <cryptopp/*>
  endif()
endif()

# Despite only cpp-netlib requiring openssl, OSX apparently needs this as well
if (APPLE)
  # If we're on OS X check for Homebrew's copy of OpenSSL instead of Apple's
  if (NOT OpenSSL_DIR)
    execute_process (COMMAND brew --prefix openssl
      OUTPUT_VARIABLE OPENSSL_ROOT_DIR
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
  if (WITH_STATIC)
    #set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
  endif()
  find_package(OpenSSL REQUIRED)
  if(NOT DEFINED OPENSSL_INCLUDE_DIR)
    message(FATAL_ERROR "Could not find OpenSSL. Please download and install it first!")
  else()
    include_directories(${OPENSSL_INCLUDE_DIR})
  endif()
endif()

# Note: we're actually building off branch 0.13-release - not 0.12.0.
# cpp-netlib's MINOR is kept at 0.12 until 0.13 is official.
# CMake will find cppnetlibConfig*.cmake in cpp-netlib's build directory
# (we *could* instruct to make install for cpp-netlib but that's not needed ATM).
if(WITH_CPPNETLIB)
  set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} deps/cpp-netlib)
  find_package(cppnetlib 0.12.0 REQUIRED)
  if(NOT DEFINED CPPNETLIB_INCLUDE_DIRS)
    message(FATAL_ERROR "Could not find cpp-netlib 0.12.0. See building instructions.")
  else()
    message(STATUS "Found cpp-netlib: ${CPPNETLIB_INCLUDE_DIRS}, ${CPPNETLIB_LIBRARIES}")
    include_directories(${CPPNETLIB_INCLUDE_DIRS})
  endif()
endif()

# TODO(anonimal): when UPnP is working, consider static as well
if(WITH_UPNP)
  find_package(MiniUPnPc REQUIRED)
  if(NOT ${MINIUPNPC_FOUND})
    message(FATAL_ERROR "Could not find MiniUPnPc. See building instructions.")
  endif()
endif()

# Doxygen support
if(WITH_DOXYGEN)
  include(UseDoxygen)
endif()

# Load remaining includes
include_directories(${CMAKE_SOURCE_DIR})

# Use data-path set in Makefile. Code must call upon this definition.
if(KOVRI_DATA_PATH)
  add_definitions(-DKOVRI_CUSTOM_DATA_PATH="${KOVRI_DATA_PATH}")
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
message(STATUS "  BENCHMARKS       : ${WITH_BENCHMARKS}")
message(STATUS "  BINARY           : ${WITH_BINARY}")
message(STATUS "  COVERAGE         : ${WITH_COVERAGE}")
message(STATUS "  CRYPTOPP         : ${WITH_CRYPTOPP}")
message(STATUS "  DOXYGEN          : ${WITH_DOXYGEN}")
message(STATUS "  HARDENING        : ${WITH_HARDENING}")
message(STATUS "  LIBRARY          : ${WITH_LIBRARY}")
message(STATUS "  OPTIMIZATION     : ${WITH_OPTIMIZE}")
message(STATUS "  STATIC BUILD     : ${WITH_STATIC}")
message(STATUS "  SUPERCOP         : ${WITH_SUPERCOP}")
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
add_subdirectory(tests)
