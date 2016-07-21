# Style
We ardently adhere to (or are in the process of adhering to) [Google's C++ Style Guide](https://google.github.io/styleguide/cppguide.html).
Please run [cpplint](https://pypi.python.org/pypi/cpplint/) on any applicable work before contributing to Kovri and take no offense if your contribution ends up being style refactored.

## A few differences from Google's proposed C++ style

- Implementation file extension is ``cpp`` instead of ``cc``.
- No more than one statement per line.
  - For example, one-liner ``if`` statement with its body is forbidden.
- In the same manner, one-liner function definitions are forbidden.
- Avoid inline functions.
- Newline break all function parameters for consisentcy across codebase:

```cpp
  /// @brief Constructs SSU header with pre-determined payload type
  explicit SSUHeader(
      SSUPayloadType type);

  /// @brief Constructs SSU header with pre-determined payload type and content
  /// @note Assumes content is valid
  /// @param SSUPayloadType SSU payload type
  /// @param mac Pointer to header's MAC material
  /// @param iv Pointer to header's IV material
  /// @param time Header's timestamp
  SSUHeader(
      SSUPayloadType type,
      std::uint8_t* mac,
      std::uint8_t* iv,
      std::uint32_t time);

  /// @brief Sets MAC from appointed position within header
  /// @note Assumes content is valid (based on position)
  void SetMAC(
      std::uint8_t* mac);

  /// @brief Gets acquired MAC after it has been set when parsed
  /// @return Pointer to MAC material
  std::uint8_t* GetMAC() const;
```

- Expressions can be broken before operators if:
  - The line is greater that 80 columns
  - Doing so aids in better documentation

```cpp
if (this is a very long expr1
    && this is a very long expr2
    && this is also a very long expr3)
  DoSomeThing();
```

```cpp
return SSUPacket::GetSize()
       + static_cast<std::size_t>(SSUSize::DHPublic)  // Y to complete the DH agreement
       + 1 + m_AddressSize  // 1 byte address size, address size,
       + 2 + 4 + 4          // Port size (2 bytes), relay tag size, time size
       + m_SignatureSize;   // Signature size
```

In addition to the aforementioned, please consider the following:

- Please keep in line with codebase's present (vertical) style for consistency
- If anonymity is a concern, try to blend in with a present contributor's style
- Lines should be <=80 spaces unless impossible to do so (see [cpplint](https://pypi.python.org/pypi/cpplint/))
- Pointers: reference/dereference operators on the left (attached to datatype) when possible
- Class member variables should be prepended with ```m_``` to keep consistency with codebase
- Use Doxygen style documentation for functions when possible
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
