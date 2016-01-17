#ifndef SRC_CORE_CRYPTO_CRYPTOPP_RAND_H_
#define SRC_CORE_CRYPTO_CRYPTOPP_RAND_H_

// cryptopp specific prng header

#include <cryptopp/osrng.h>

namespace i2p {
  namespace crypto {

    typedef CryptoPP::RandomNumberGenerator PRNG;
    PRNG & GetPRNG();

  }
}

#endif
