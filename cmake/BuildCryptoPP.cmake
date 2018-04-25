set(CRYPTOPP_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/deps/cryptopp)

set(library_type SHARED)
if (MSVC)
  set(library_type STATIC)
elseif(MINGW)
  set(library_type STATIC)
else()
  if (WITH_STATIC_DEPS OR CMAKE_BUILD_TYPE STREQUAL Release)
    set(library_type STATIC)
  endif()
endif()

add_library(CryptoPP::CryptoPP ${library_type} IMPORTED)

find_path(CryptoPP_INCLUDE_DIR
  NAME cryptlib.h
  PATHS ${CRYPTOPP_ROOT} NO_DEFAULT_PATH)

set_target_properties(CryptoPP::CryptoPP PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CryptoPP_INCLUDE_DIR};${CryptoPP_INCLUDE_DIR}/..")

include(ExternalProject)
if (NOT MSVC)
  string(TOLOWER ${library_type} library_type)

  if (CMAKE_GENERATOR STREQUAL Ninja)
    find_program(BUILD_CMD NAMES gmake make smake)
  else()
    set(BUILD_CMD ${CMAKE_MAKE_PROGRAM})
  endif()
  
  if(CMAKE_CXX_COMPILER_LAUNCHER)
    set(CCACHE_COMMAND "${CMAKE_CXX_COMPILER_LAUNCHER} ${CMAKE_CXX_COMPILER}")
    set(BUILD_CMD ${CMAKE_COMMAND} -E env CXX=${CCACHE_COMMAND} ${BUILD_CMD})
    unset(CCACHE_COMMAND)
  endif()

  include(ProcessorCount)
  ProcessorCount(ThreadNum)
  set(MAKE_ARGS)
  if(NOT N EQUAL 0)
    set(MAKE_ARGS -j${ThreadNum})
  endif()

  if (library_type STREQUAL shared)
    set(BYPRODUCT ${CMAKE_SHARED_LIBRARY_PREFIX}cryptopp${CMAKE_SHARED_LIBRARY_SUFFIX})
  else()
    set(BYPRODUCT ${CMAKE_STATIC_LIBRARY_PREFIX}cryptopp${CMAKE_STATIC_LIBRARY_SUFFIX})
  endif()

  # https://www.cryptopp.com/wiki/GNUmakefile
  ExternalProject_Add(cryptopp
    SOURCE_DIR ${CRYPTOPP_ROOT}
    BUILD_IN_SOURCE TRUE
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${BUILD_CMD} clean
    COMMAND ${BUILD_CMD} ${library_type} ${MAKE_ARGS}
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${CRYPTOPP_ROOT}/${BYPRODUCT})
  
  add_dependencies(CryptoPP::CryptoPP cryptopp)
  
  set_target_properties(CryptoPP::CryptoPP PROPERTIES
      IMPORTED_LOCATION "${CRYPTOPP_ROOT}/${BYPRODUCT}"
      IMPORTED_LINK_INTERFACE_LANGUAGES "CXX")
  
  unset(BYPRODUCT)
  unset(ThreadNum)
  unset(MAKE_ARGS)
  unset(BUILD_CMD)
else()
  # Looking for MSBuild
  if (MSVC_IDE)
    set(MSBUILD_COMMAND ${CMAKE_MAKE_PROGRAM})
  else()
    # https://github.com/Microsoft/vswhere/wiki/Find-MSBuild
    set(VSWHERE_COMMAND ${CMAKE_CURRENT_BINARY_DIR}/vswhere.exe)
    file(DOWNLOAD https://github.com/Microsoft/vswhere/releases/download/2.4.1/vswhere.exe ${VSWHERE_COMMAND}
      EXPECTED_HASH MD5=088c7c215082e2510e388afab98e3e25
      SHOW_PROGRESS)
    execute_process(COMMAND ${VSWHERE_COMMAND} -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
      OUTPUT_VARIABLE VS_TOOLS_PATH
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(MSBUILD_COMMAND "${VS_TOOLS_PATH}/MSBuild/15.0/Bin/MSBuild.exe")

    unset(VSWHERE_COMMAND)
    unset(VS_TOOLS_PATH)
  endif()

  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PLATFORM x64)
  else()
    set(PLATFORM Win32)
  endif()

  # https://www.cryptopp.com/wiki/Visual_Studio#Dynamic_Runtime_Linking
  set(SED_COMMAND ${CMAKE_CURRENT_BINARY_DIR}/sed.exe)
  file(DOWNLOAD https://github.com/mbuilov/sed-windows/raw/master/sed-4.4-x64.exe ${SED_COMMAND}
      EXPECTED_HASH MD5=cedee72cc0b6a819833af9051b61c469
      SHOW_PROGRESS)
  
  file(GLOB VCXPROJ RELATIVE ${CRYPTOPP_ROOT} "deps/cryptopp/*.vcxproj")

  if(WITH_STATIC_DEPS)
    set(SED_ARGS_RELEASE "s|<RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary>|<RuntimeLibrary>MultiThreaded</RuntimeLibrary>|g")
    set(SED_ARGS_DEBUG "s|<RuntimeLibrary>MultiThreadedDebugDLL</RuntimeLibrary>|<RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>|g")
  else()
    set(SED_ARGS_RELEASE "s|<RuntimeLibrary>MultiThreaded</RuntimeLibrary>|<RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary>|g")
    set(SED_ARGS_DEBUG "s|<RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>|<RuntimeLibrary>MultiThreadedDebugDLL</RuntimeLibrary>|g")
  endif()

  # https://www.cryptopp.com/wiki/Visual_Studio
  ExternalProject_Add(cryptopp
    SOURCE_DIR ${CRYPTOPP_ROOT} 
    BUILD_IN_SOURCE TRUE
    PATCH_COMMAND ${SED_COMMAND} -i "${SED_ARGS_RELEASE}" ${VCXPROJ}
    COMMAND ${SED_COMMAND} -i "${SED_ARGS_DEBUG}" ${VCXPROJ}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${MSBUILD_COMMAND} /t:Build /p:Configuration=$<CONFIG> /p:Platform=${PLATFORM} ${CRYPTOPP_ROOT}/cryptlib.vcxproj
    BUILD_BYPRODUCTS 
      ${CRYPTOPP_ROOT}/${PLATFORM}/Output/Debug/cryptlib.lib
      ${CRYPTOPP_ROOT}/${PLATFORM}/Output/Release/cryptlib.lib
    INSTALL_COMMAND "")
  
  add_dependencies(CryptoPP::CryptoPP cryptopp)

  set_target_properties(CryptoPP::CryptoPP PROPERTIES
    IMPORTED_LOCATION_DEBUG "${CRYPTOPP_ROOT}/${PLATFORM}/Output/Debug/cryptlib.lib"
    IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
    IMPORTED_LOCATION_RELEASE "${CRYPTOPP_ROOT}/${PLATFORM}/Output/Release/cryptlib.lib"
    IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
    IMPORTED_CONFIGURATIONS "Debug;Release")
  
  unset(SED_COMMAND)
  unset(MSBUILD_COMMAND)
endif()

unset(library_type)
unset(CRYPTOPP_ROOT)