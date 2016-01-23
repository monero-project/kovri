#include <cstdlib>

namespace i2p 
{

const uint8_t BUFFER_DEFAULT_CHAR = 'a';

/**
   Buffer prefilled with a default value
 */
template <uint8_t ch=BUFFER_DEFAULT_CHAR>
struct FilledBuffer {
  FilledBuffer(size_t len) {
    _data = new uint8_t[len];
    std::memset(_data, ch, len);
  }

  ~FilledBuffer() {
    delete [] _data;
  }
  
  operator const uint8_t* () {
    return _data;
  }
  operator uint8_t*() {
    return _data;
  }

  uint8_t* _data;
};
  
typedef FilledBuffer<> Buffer;

}
