## Style
We ardently adhere to (or are in the process of adhering to) [Google's C++ Style Guide](https://google.github.io/styleguide/cppguide.html).
Please run [cpplint](https://github.com/google/styleguide/tree/gh-pages/cpplint) on any applicable work before contributing to Kovri and take no offense if your contribution ends up being style refactored.

In addition to the aforementioned, please consider the following:

- Please keep in line with codebase's present (vertical) style for consistency
- If anonymity is a concern, try to blend in with a present contributor's style
- Lines should be <=80 spaces unless impossible to do so (see [cpplint](https://github.com/google/styleguide/tree/gh-pages/cpplint))
- Pointers: reference/dereference operators on the left (attached to datatype) when possible
- Class member variables should be prepended with m_
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
- TODO's should me marked as ```TODO(unassigned):``` (replace unassigned with your name) so Doxygen can catch them
- Use three-slash ```/// C++ comments``` for Doxygen unless the comments span more than 10 lines (give or take). When that happens, a traditional
```c
  /**
   * should suffice
   */
```
- New files should maintain consistency with other filename case
