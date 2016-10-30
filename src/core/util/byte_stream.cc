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

#include "core/util/byte_stream.h"

#include <stdexcept>

#include "core/util/i2p_endian.h"

namespace kovri {
namespace core {

InputByteStream::InputByteStream(
    std::uint8_t* data,
    std::size_t len)
    : m_Data(data),
      m_Length(len) {}

void InputByteStream::ConsumeData(
    std::size_t amount) {
  if (amount > m_Length)
    throw std::length_error("SSUPacketParser: too many bytes to consume.");
  m_Data += amount;
  m_Length -= amount;
}

std::uint8_t* InputByteStream::ReadBytes(
    std::size_t amount) {
  std::uint8_t* ptr = m_Data;
  ConsumeData(amount);
  return ptr;
}

std::uint32_t InputByteStream::ReadUInt32() {
  return bufbe32toh(ReadBytes(4));
}

std::uint16_t InputByteStream::ReadUInt16() {
  return bufbe16toh(ReadBytes(2));
}

std::uint8_t InputByteStream::ReadUInt8() {
  return *ReadBytes(1);
}

OutputByteStream::OutputByteStream(
  std::uint8_t* data,
  std::size_t len)
  : m_Data(data), m_Length(len) { }

void OutputByteStream::ProduceData(std::size_t amount) {
  if (amount > m_Length)
    throw std::length_error("SSUPacketParser: too many bytes to produce.");
  m_Data += amount;
  m_Length -= amount;
}

void OutputByteStream::WriteData(const std::uint8_t* data, std::size_t len) {
  std::uint8_t* ptr = m_Data; 
  ProduceData(len);
  memcpy(ptr, data, len);
}

void OutputByteStream::WriteUInt8(std::uint8_t data) {
  WriteData(&data, 1);
}

void OutputByteStream::WriteUInt16(std::uint16_t data) {
  std::uint8_t buf[2] = {};
  htobe16buf(buf, data);
  WriteData(buf, sizeof(buf));
}

void OutputByteStream::WriteUInt32(std::uint32_t data) {
  std::uint8_t buf[4] = {};
  htobe32buf(buf, data);
  WriteData(buf, sizeof(buf));
}

std::uint8_t* OutputByteStream::GetPosition() const {
  return m_Data;
}

} // namespace core
} // namespace kovri
