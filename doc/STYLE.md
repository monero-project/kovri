## Style
We ardently adhere to (or are in the process of adhering to) [Google's C++ Style Guide](https://google.github.io/styleguide/cppguide.html).
Please run [cpplint](https://github.com/google/styleguide/tree/gh-pages/cpplint) on any applicable work before contributing to Kovri and take no offense if your contribution ends up being style refactored.

In addition to the aforementioned, please consider the following:

- Please keep in line with codebase's present style for consistency.
- Why a vertical style? It's easy to code things fast but doing things slower tends to reduce human error (slows the eye down + easier to count and compare datatypes + easier to maintain).
- But why this specific style? Anonymity. Doing things here that wouldn't be done elsewhere helps reduce the chance of programmer correlation. This allows any contributor to *blend-in* as long as they adhere to specifics.
- Lines should be <=80 spaces unless impossible to do so (see [cpplint](https://github.com/google/styleguide/tree/gh-pages/cpplint)).
- ```XXX``` and any unassigned ```TODO```'s should be marked instead as ```TODO(unassigned):``` so Doxygen can catch them.
- Always use three-slash ```/// C++ comments``` for Doxygen unless the comments span more than 10 lines (give or take). When that happens, a traditional
```c
  /**
   * should suffice
   */
```
- ``if/else`` statements should never one-liner. Nothing bracketed should one-liner unless it is empty (see vertical theory above).
- Please remove EOL whitespace: ```'s/ *$//g'``` (see [cpplint](https://github.com/google/styleguide/tree/gh-pages/cpplint)).
- New files should maintain consistency with other filename case, e.g., CryptoPP_rand.h instead of cryptopp_rand.h
- Pointers: reference/dereference operators on the left (attached to datatype) when possible.
- Class member variables are prepended with m_
- Enumerators are prepended with e_
- Abstain from datatype declaration redundancy (e.g., use commas instead of repeating the datatype).
```cpp
uint32_t tunnelID,
         nextTunnelID;

uint8_t layerKey[32],
        ivKey[32],
        replyKey[32],
        replyIV[16],
        randPad[29];

bool isGateway,
     isEndpoint;
```
- If function args newline break, ensure that *every* indent is 4 spaces (and not 2).
```cpp
if (clearText[BUILD_REQUEST_RECORD_FLAG_OFFSET] & 0x40) {
  // So, we send it to reply tunnel
  i2p::transport::transports.SendMessage(
      clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
      ToSharedI2NPMessage(
          CreateTunnelGatewayMsg(
              bufbe32toh(
                  clearText + BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
              e_I2NPVariableTunnelBuildReply,
              buf,
              len,
              bufbe32toh(
                  clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET))));
} else {
  i2p::transport::transports.SendMessage(
      clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
      ToSharedI2NPMessage(
          CreateI2NPMessage(
              e_I2NPVariableTunnelBuild,
              buf,
              len,
              bufbe32toh(
                  clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET))));
}
```
