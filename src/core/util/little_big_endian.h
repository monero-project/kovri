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

// LittleBigEndian.h fixed for 64-bits added union
//

#ifndef SRC_CORE_UTIL_LITTLE_BIG_ENDIAN_H_
#define SRC_CORE_UTIL_LITTLE_BIG_ENDIAN_H_

// Determine Little-Endian or Big-Endian

#define CURRENT_BYTE_ORDER       (*(int *)"\x01\x02\x03\x04")
#define LITTLE_ENDIAN_BYTE_ORDER 0x04030201
#define BIG_ENDIAN_BYTE_ORDER    0x01020304
#define PDP_ENDIAN_BYTE_ORDER    0x02010403

#define IS_LITTLE_ENDIAN (CURRENT_BYTE_ORDER == LITTLE_ENDIAN_BYTE_ORDER)
#define IS_BIG_ENDIAN    (CURRENT_BYTE_ORDER == BIG_ENDIAN_BYTE_ORDER)
#define IS_PDP_ENDIAN    (CURRENT_BYTE_ORDER == PDP_ENDIAN_BYTE_ORDER)

// Forward declaration

template<typename T>
struct LittleEndian;

template<typename T>
struct BigEndian;

// Little-Endian template

#pragma pack(push, 1)
template<typename T>
struct LittleEndian {
  union {
    unsigned char bytes[sizeof(T)];
    T raw_value;
  };

  explicit LittleEndian(T t = T()) {
    operator =(t);
  }

  LittleEndian(const LittleEndian<T> & t) {
    raw_value = t.raw_value;
  }

  explicit LittleEndian(const BigEndian<T> & t) {
    for (unsigned i = 0; i < sizeof(T); i++)
      bytes[i] = t.bytes[sizeof(T)-1-i];
  }

  operator const T() const {
    T t = T();
    for (unsigned i = 0; i < sizeof(T); i++)
      t |= T(bytes[i]) << (i << 3);
    return t;
  }

  const T operator = (const T t) {
    for (unsigned i = 0; i < sizeof(T); i++)
      bytes[sizeof(T)-1 - i] = static_cast<unsigned char>(t >> (i << 3));
    return t;
  }

  // operators
  const T operator += (const T t) {
    return (*this = *this + t);
  }

  const T operator -= (const T t) {
    return (*this = *this - t);
  }

  const T operator *= (const T t) {
    return (*this = *this * t);
  }

  const T operator /= (const T t) {
    return (*this = *this / t);
  }

  const T operator %= (const T t) {
    return (*this = *this % t);
  }

  LittleEndian<T> operator ++(int) {
    LittleEndian<T> tmp(*this);
    operator ++();
    return tmp;
  }

  LittleEndian<T> & operator ++() {
    for (unsigned i = 0; i < sizeof(T); i++) {
      ++bytes[i];
      if (bytes[i] != 0)
        break;
    }
    return (*this);
  }

  LittleEndian<T> operator --(int) {
    LittleEndian<T> tmp(*this);
    operator --();
    return tmp;
  }

  LittleEndian<T> & operator --() {
    for (unsigned i = 0; i < sizeof(T); i++) {
      --bytes[i];
      if (bytes[i] != (T)(-1))
        break;
    }
    return (*this);
  }
};
#pragma pack(pop)

// Big-Endian template

#pragma pack(push, 1)
template<typename T>
struct BigEndian {
  union {
    unsigned char bytes[sizeof(T)];
    T raw_value;
  };

  explicit BigEndian(T t = T()) {
    operator =(t);
  }

  BigEndian(const BigEndian<T> & t) {
    raw_value = t.raw_value;
  }

  explicit BigEndian(const LittleEndian<T> & t) {
    for (unsigned i = 0; i < sizeof(T); i++)
      bytes[i] = t.bytes[sizeof(T)-1-i];
  }

  operator const T() const {
    T t = T();
    for (unsigned i = 0; i < sizeof(T); i++)
      t |= T(bytes[sizeof(T) - 1 - i]) << (i << 3);
    return t;
  }

  const T operator = (const T t) {
    for (unsigned i = 0; i < sizeof(T); i++)
      bytes[sizeof(T) - 1 - i] = t >> (i << 3);
    return t;
  }

  // operators
  const T operator += (const T t) {
    return (*this = *this + t);
  }

  const T operator -= (const T t) {
    return (*this = *this - t);
  }

  const T operator *= (const T t) {
    return (*this = *this * t);
  }

  const T operator /= (const T t) {
    return (*this = *this / t);
  }

  const T operator %= (const T t) {
    return (*this = *this % t);
  }

  BigEndian<T> operator ++(int) {
    BigEndian<T> tmp(*this);
    operator ++();
    return tmp;
  }

  BigEndian<T> & operator ++() {
    for (unsigned i = 0; i < sizeof(T); i++) {
      ++bytes[sizeof(T) - 1 - i];
      if (bytes[sizeof(T) - 1 - i] != 0)
        break;
    }
    return (*this);
  }

  BigEndian<T> operator --(int) {
    BigEndian<T> tmp(*this);
    operator --();
    return tmp;
  }

  BigEndian<T> & operator --() {
    for (unsigned i = 0; i < sizeof(T); i++) {
      --bytes[sizeof(T) - 1 - i];
      if (bytes[sizeof(T) - 1 - i] != (T)(-1))
        break;
    }
    return (*this);
  }
};
#pragma pack(pop)

#endif  // SRC_CORE_UTIL_LITTLE_BIG_ENDIAN_H_
