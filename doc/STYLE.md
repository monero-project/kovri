# Style
1. Read [Google's C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
2. Run [cpplint](https://pypi.python.org/pypi/cpplint/)
```bash
$ cpplint src/path/to/my/file
```
3. Run [clang-format](http://llvm.org/releases/3.8.0/tools/clang/docs/ClangFormat.html) with ```-style=file``` using provided [.clang-format](https://github.com/monero-project/kovri/blob/master/.clang-format)
```bash
$ cd kovri/ && clang-format -i -style=file src/path/to/my/file
```

## Here's what's currently not caught by clang-format and differs from Google's proposed C++ style

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

- Avoid prepended mixed-case ```k``` and MACRO_TYPE for all constants
- Use Doxygen three-slash ```/// C++ comments``` when documenting for Doxygen
- Try to document all your work for Doxygen as you progress
- If anonymity is a concern, try to blend in with a present contributor's style
