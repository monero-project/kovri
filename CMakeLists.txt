cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(kovri CXX)

set(KOVRI_PROJECT "The Kovri I2P Router Project")

# Versioning
set(KOVRI_VERSION "0.1.0-pre-alpha")
set(KOVRI_CODENAME "In the beginning")

# Get git revision
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/.git)
  find_package(Git)
  if(GIT_FOUND)
    execute_process(
      COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD  # use short hash for now
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
      OUTPUT_VARIABLE "KOVRI_GIT_REVISION"
      ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
  else()
    set(KOVRI_GIT_REVISION " ")
  endif()
endif()

message(STATUS "")
message(STATUS "${KOVRI_PROJECT}")
message(STATUS "${KOVRI_VERSION}-${KOVRI_GIT_REVISION} \"${KOVRI_CODENAME}\"")
message(STATUS "")

# I2NP/NetDb RI properties (used internally)
set(I2P_VERSION "0.9.28")
set(I2P_NETWORK_ID "2")  # "1" is reserved for I2P version less than 0.6.1.10

# Produce version definitions, output to build directory
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in" "${CMAKE_BINARY_DIR}/version.h" @ONLY)

# The interface target for internal usage requirements 
add_library(kovri-private INTERFACE) 

# Include build directory so we need to git-ignore version file output
target_include_directories(kovri-private INTERFACE ${CMAKE_BINARY_DIR})

# Configurable options
option(KOVRI_DATA_PATH "The path to the kovri data folder")
option(WITH_BINARY     "Build kovri binary" ON)
option(WITH_KOVRI_UTIL "Build kovri utility binary" OFF)
option(WITH_COVERAGE   "Build with coverage" OFF)
option(WITH_CRYPTOPP   "Build with Crypto++" ON)  # Default ON unless we switch libraries
option(WITH_CPPNETLIB  "Build with cpp-netlib" ON)
option(WITH_DOXYGEN    "Enable support for Doxygen" OFF)
option(WITH_HARDENING  "Use hardening compiler flags" OFF)
option(WITH_LIBRARY    "Build library" ON)
option(WITH_OPTIMIZE   "Optimization flags" OFF)
option(WITH_PYTHON     "Build wrappers which require Boost.Python" OFF)
option(WITH_STATIC     "Static build" OFF)
option(WITH_STATIC_DEPS "Static build with static dependencies" OFF)
option(WITH_SUPERCOP   "Build Ed25519 using the ref10 implementation from SUPERCOP" ON)  # Default ON unless we switch implementations
option(WITH_TESTS      "Build unit tests" OFF)
option(WITH_FUZZ_TESTS "Build fuzz tests" OFF)
option(WITH_UPNP       "Include support for UPnP client" OFF)


set(CMAKE_VERBOSE_MAKEFILE true)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cotire/CMake)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7420 
set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Release>:NDEBUG>)

# Exceptions *should* substitute assertions in tests
if (WITH_TESTS)
  set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS NDEBUG)
endif()

# Default build is Debug
# TODO(anonimal): currently, there are no other release-specific flags (fix this when we release)
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
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9.2)
    message(FATAL_ERROR "GCC 4.9.2 or higher is required")
  endif()
  set(GNU TRUE)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 3.5)
    message(FATAL_ERROR "Clang 3.5 or higher is required")
  endif()
  set(CLANG TRUE)
endif()

# Require C++14 support (minimum version compilers guarantee this)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

### TODO(unassigned): review, cleanup, improve
# Compiler flags (by vendor)
if(NOT MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Winvalid-pch")
  if( (NOT ARM) AND (NOT ANDROID) )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
  endif()
  # TOOD(unassigned): we actually don't need this and it's quite annoying
  #set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -pedantic")

  # TODO(unassigned): we currently are not developing for OpenWRT
  # TODO(unassgiend): review if the following is incompatible with static build and enabled hardening for OpenWRT
  # Multiple definitions of __stack_chk_fail (libssp & libc)
  #set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -flto -s -ffunction-sections -fdata-sections")
  # -flto is added from above
  #set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL "-Wl,--gc-sections")

  # https://developers.redhat.com/blog/2018/03/21/compiler-and-linker-flags-gcc/ 
  if(WITH_HARDENING)
    # Run-time buffer overflow detection
    set_property(DIRECTORY APPEND PROPERTY COMPILE_DEFINITIONS _FORTIFY_SOURCE=2)
    # Reject potentially unsafe format string arguents
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wformat -Wformat-security -Werror=format-security")
    # Stack smashing protector
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong --param ssp-buffer-size=4")
    # Full ASLR for executables
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    if(GNU AND NOT MINGW)
      # Read-only segments after relocation and Disable lazy binding
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -z relro -z now")
    endif()
  endif()
  if(ANDROID)
    #From Android 5: "only position independent executables (PIE) are supported"
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  endif()
  if(WITH_OPTIMIZE AND NOT WITH_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
  endif()
  if(WITH_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 --coverage")
  endif()
endif()

if(NOT WIN32 AND NOT WITH_STATIC)
  # TODO: Consider separate compilation for COMMON_SRC for library.
  # No need in -fPIC overhead for binary if not interested in library
  # HINT: revert c266cff CMakeLists.txt: compilation speed up
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

set(Boost_USE_MULTITHREADED ON)

if(WITH_STATIC_DEPS AND MSVC)
  foreach(flag_var IN ITEMS
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    if(${flag_var} MATCHES "/MD")
      string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endif()
  endforeach()
  set(Boost_USE_STATIC_RUNTIME ON)
endif()

if(WITH_STATIC)
  set(Boost_USE_STATIC_LIBS ON)
  if (NOT MSVC)
    set(Boost_USE_STATIC_RUNTIME ON)
  endif()
  set(BUILD_SHARED_LIBS OFF)
  if(${CMAKE_CXX_COMPILER} MATCHES ".*-openwrt-.*")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
    set(CMAKE_THREAD_LIBS_INIT
      "gcc_eh -Wl,-u,pthread_create,-u,pthread_once,-u,pthread_mutex_lock,-u,pthread_mutex_unlock,-u,pthread_join,-u,pthread_equal,-u,pthread_detach,-u,pthread_cond_wait,-u,pthread_cond_signal,-u,pthread_cond_destroy,-u,pthread_cond_broadcast,-u,pthread_cancel")
  endif()
endif()

# Get uname output
function(Uname output pattern)
  execute_process(
      COMMAND sh -c "uname -a 2>&1"
      COMMAND grep "${pattern}"
      OUTPUT_VARIABLE ${output}
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(${output} "${${output}}" PARENT_SCOPE)
endfunction(Uname)

# TODO(unassigned): extend Boost.Python cross-platform build support 
set(additional_components)
if (WITH_PYTHON)
  Uname(ARCH_LINUX "ARCH")
  Uname(UBUNTU "Ubuntu")
  if (APPLE OR ARCH_LINUX)
    set(additional_components python3)
  elseif (UBUNTU)
    set(additional_components python-py35)
  else()
    message(FATAL_ERROR
      "Boost.Python package not yet supported for your system. See TODO in root CMake recipe or open a feature request")
  endif()
endif()

find_package(Boost 1.58 REQUIRED COMPONENTS filesystem log program_options ${additional_components})
if (NOT Boost_FOUND)
  message(FATAL_ERROR "Boost not found or requirement not satisfied. See building instructions.")
endif()

if(NOT WITH_STATIC)
  target_compile_definitions(kovri-private INTERFACE BOOST_ALL_DYN_LINK)
endif()

# Libraries
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if(WITH_CRYPTOPP)
  find_package(CryptoPP REQUIRED)
  if(NOT CryptoPP_FOUND)
    message(FATAL_ERROR "Could not find Crypto++. See building instructions.")
  else()
    target_link_libraries(kovri-private INTERFACE CryptoPP::CryptoPP)
    target_compile_definitions(kovri-private INTERFACE WITH_CRYPTOPP)
  endif()
endif()

# Despite only cpp-netlib requiring openssl, OSX and ANDROID apparently needs this as well
if (APPLE OR ANDROID)
  # If we're on OS X check for Homebrew's copy of OpenSSL instead of Apple's
  if (APPLE AND NOT OpenSSL_DIR)
    execute_process (COMMAND brew --prefix openssl
      OUTPUT_VARIABLE OPENSSL_ROOT_DIR
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
  if (WITH_STATIC)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
  endif()
  find_package(OpenSSL REQUIRED)
  if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "Could not find OpenSSL. Please download and install it first!")
  else()
    target_link_libraries(kovri-private INTERFACE OpenSSL::SSL)
  endif()
endif()

add_subdirectory(deps)

# Note: we're actually building off branch 0.13-release - not 0.12.0.
if(WITH_CPPNETLIB)
  set(CPP-NETLIB_BUILD_SHARED_LIBS OFF CACHE BOOL "Build cpp-netlib as shared libraries.") 
  set(CPP-NETLIB_BUILD_TESTS OFF CACHE BOOL "Build the cpp-netlib project tests.") 
  set(CPP-NETLIB_BUILD_EXAMPLES OFF CACHE BOOL  "Build the cpp-netlib project examples.") 
  set(CPP-NETLIB_ENABLE_HTTPS ON CACHE BOOL  "Build cpp-netlib with support for https if OpenSSL is found.") 
  set(CPP-NETLIB_STATIC_OPENSSL ${WITH_STATIC_DEPS} CACHE BOOL  "Build cpp-netlib using static OpenSSL") 
  set(CPP-NETLIB_STATIC_BOOST ${WITH_STATIC} CACHE BOOL "Build cpp-netlib using static Boost") 
  add_subdirectory(deps/cpp-netlib)
endif()

if(WITH_FUZZ_TESTS)
  if(NOT CLANG)
    message(FATAL_ERROR "clang is required for fuzz tests. See building instructions.")
  endif()
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5)
    message(FATAL_ERROR "Clang version 5 or higher is required")
  endif()
  find_package(Fuzzer REQUIRED)
  if(NOT Fuzzer_FOUND)
    message(FATAL_ERROR "Could not find Fuzzer. See building instructions.")
  else()
    message(STATUS "Found Fuzzer: ${Fuzzer_INCLUDE_DIR}, ${Fuzzer_LIBRARIES}")
    target_include_directories(kovri-private INTERFACE ${Fuzzer_INCLUDE_DIR})
    target_compile_definitions(kovri-private INTERFACE WITH_FUZZ_TESTS)
  endif()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-coverage=trace-pc-guard -fsanitize=address")
endif()

# Doxygen support
if(WITH_DOXYGEN)
  include(UseDoxygen)
endif()

# For Boost.Python wrapping
if (WITH_PYTHON)
  find_package(PythonLibs REQUIRED)
  if (NOT PythonLibs_FOUND)
    message(FATAL_ERROR "Python not found or requirement not satisfied. See building instructions.")
  else()
    message(STATUS "Found Python: ${PYTHON_INCLUDE_DIR}, ${PYTHON_LIBRARIES}")
    target_include_directories(kovri-private INTERFACE ${PYTHON_INCLUDE_DIRS})
  endif()
endif()

# Speed up MSVC build
# https://blogs.msdn.microsoft.com/vcblog/2016/10/26/recommendations-to-speed-c-builds-in-visual-studio/
if (MSVC) 
  set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} /DEBUG:fastlink") 
  # The /MP flag is applied by cotire
  # set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
  
  set(COTIRE_PCH_MEMORY_SCALING_FACTOR "300")
  include(cotire)
endif() 

# Load remaining includes
target_include_directories(kovri-private INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# Use data-path set in Makefile. Code must call upon this definition.
if(KOVRI_DATA_PATH)
  target_include_directories(kovri-private INTERFACE KOVRI_CUSTOM_DATA_PATH="${KOVRI_DATA_PATH}")
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
message(STATUS "  BINARY           : ${WITH_BINARY}")
message(STATUS "  KOVRI UTIL       : ${WITH_KOVRI_UTIL}")
message(STATUS "  COVERAGE         : ${WITH_COVERAGE}")
message(STATUS "  CRYPTOPP         : ${WITH_CRYPTOPP}")
message(STATUS "  DOXYGEN          : ${WITH_DOXYGEN}")
message(STATUS "  HARDENING        : ${WITH_HARDENING}")
message(STATUS "  LIBRARY          : ${WITH_LIBRARY}")
message(STATUS "  OPTIMIZATION     : ${WITH_OPTIMIZE}")
message(STATUS "  PYTHON           : ${WITH_PYTHON}")
message(STATUS "  STATIC BUILD     : ${WITH_STATIC}")
message(STATUS "  STATIC DEPS BUILD: ${WITH_STATIC_DEPS}")
message(STATUS "  SUPERCOP         : ${WITH_SUPERCOP}")
message(STATUS "  TESTS            : ${WITH_TESTS}")
message(STATUS "  FUZZ TESTS       : ${WITH_FUZZ_TESTS}")
message(STATUS "  UPnP             : ${WITH_UPNP}")
message(STATUS "---------------------------------------")

# Handle paths nicely
include(GNUInstallDirs)

add_subdirectory(src)

if (WITH_TESTS)
  enable_testing()
  add_subdirectory(tests/unit_tests)
endif()

if (WITH_PYTHON)
  add_subdirectory(contrib/python)
endif()