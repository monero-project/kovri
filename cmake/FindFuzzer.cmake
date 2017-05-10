#
# Copyright (c) 2015-2017, The Kovri I2P Router Project
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

function(FindFuzzerLibrary)
  find_library(Fuzzer_LIBRARIES
    NAMES LLVMFuzzerNoMain
    PATHS ${PROJECT_SOURCE_DIR}/contrib/Fuzzer/build /usr/lib /usr/local/lib
    NO_DEFAULT_PATH)
endfunction(FindFuzzerLibrary)

function(BuildFuzzerLibrary)
  message("Building libFuzzer.a ...")
  AUX_SOURCE_DIRECTORY(${Fuzzer_INCLUDE_DIR} FUZZER_SRC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O2 -fno-omit-frame-pointer -std=c++11")
  add_library("Fuzzer" ${FUZZER_SRC})
  install(
    TARGETS "Fuzzer"
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR})

endfunction(BuildFuzzerLibrary)

if(Fuzzer_INCLUDE_DIR AND Fuzzer_LIBRARIES)
   set(Fuzzer_FOUND TRUE)

else(Fuzzer_INCLUDE_DIR AND Fuzzer_LIBRARIES)
  find_path(Fuzzer_INCLUDE_DIR
    name FuzzerDefs.h
    PATHS ${PROJECT_SOURCE_DIR}/contrib/Fuzzer /usr/include /usr/local/include
    NO_DEFAULT_PATH)

  FindFuzzerLibrary()

  if(Fuzzer_INCLUDE_DIR AND Fuzzer_LIBRARIES)
    set(Fuzzer_FOUND TRUE)
  else(Fuzzer_INCLUDE_DIR AND Fuzzer_LIBRARIES)
    set(Fuzzer_FOUND FALSE)
  endif(Fuzzer_INCLUDE_DIR AND Fuzzer_LIBRARIES)

  mark_as_advanced(Fuzzer_INCLUDE_DIR Fuzzer_LIBRARIES)

endif(Fuzzer_INCLUDE_DIR AND Fuzzer_LIBRARIES)
