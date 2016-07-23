#
# Copyright (c) 2013-2016, The Kovri I2P Router Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# - Find Crypto++

if(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)
   set(CRYPTO++_FOUND TRUE)

else(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)
  find_path(CRYPTO++_INCLUDE_DIR cryptopp/cryptlib.h
  /usr/include
  /usr/local/include
  $ENV{SystemDrive}/Crypto++/include
  $ENV{CRYPTOPP}
  $ENV{CRYPTOPP}/..
  $ENV{CRYPTOPP}/include
  ${PROJECT_SOURCE_DIR}/../..)

  find_library(CRYPTO++_LIBRARIES NAMES cryptopp
  PATHS
  /usr/lib
  /usr/local/lib
  /opt/local/lib
  $ENV{SystemDrive}/Crypto++/lib
  $ENV{CRYPTOPP}/lib)

  if(MSVC AND NOT CRYPTO++_LIBRARIES) # Give a chance for MSVC multiconfig
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PLATFORM x64)
  else()
    set(PLATFORM Win32)
  endif()
  find_library(CRYPTO++_LIBRARIES_RELEASE NAMES cryptlib cryptopp
    HINTS
    ${PROJECT_SOURCE_DIR}/../../cryptopp/${PLATFORM}/Output/Release
    PATHS
    $ENV{CRYPTOPP}/Win32/Output/Release)
  find_library(CRYPTO++_LIBRARIES_DEBUG NAMES cryptlib cryptopp
    HINTS
    ${PROJECT_SOURCE_DIR}/../../cryptopp/${PLATFORM}/Output/Debug
    PATHS
    $ENV{CRYPTOPP}/Win32/Output/Debug)
  set(CRYPTO++_LIBRARIES
    debug ${CRYPTO++_LIBRARIES_DEBUG}
    optimized ${CRYPTO++_LIBRARIES_RELEASE}
    CACHE PATH "Path to Crypto++ library" FORCE)
  endif()

  if(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)
  set(CRYPTO++_FOUND TRUE)
  message(STATUS "Found Crypto++: ${CRYPTO++_INCLUDE_DIR}, ${CRYPTO++_LIBRARIES}")
  else(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)
  set(CRYPTO++_FOUND FALSE)
  message(STATUS "Crypto++ not found.")
  endif(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)

  mark_as_advanced(CRYPTO++_INCLUDE_DIR CRYPTO++_LIBRARIES)

endif(CRYPTO++_INCLUDE_DIR AND CRYPTO++_LIBRARIES)
