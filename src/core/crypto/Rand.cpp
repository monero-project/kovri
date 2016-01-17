
#include "Rand.h"
#include "cryptopp_rand.h"
#include <cryptopp/osrng.h>

//
// implementation of i2p::crypto::Rand* functions
//

namespace i2p {
namespace crypto {


  static CryptoPP::AutoSeededRandomPool rnd;
  
  PRNG & GetPRNG() {
    return rnd;
  }
                 
  
  void RandBytes(void * dataptr, size_t datalen) {
    rnd.GenerateBlock((uint8_t*)dataptr, datalen);
  }
  
}
}
