# TrCrypt

## Compile-time String Encryption for C++

TrCrypt is a lightweight, compile-time string encryption library for C++. It securely stores strings in your binary, making reverse engineering more challenging.

### Why TrCrypt?

- Compile-time Encryption: No plain text in the binary
- Runtime Decryption: Encrypted strings, decrypted only when needed
- Easy to Use: Simple macro-based usage
- Lightweight: Minimal overhead compared to plain text bins
- Uses a 8  rounds Feistel network for encryption
- C++11+ compatible
- Works with ASCII and wide strings

### Features

- Compile-time string encryption
- Runtime decryption
- changeable encryption key (i use a dynamic algorith, you can change that easy)
- Works with ASCII and wide strings



### Example

```cpp

    auto encrypted1 = CRYPT("Hello, World!");
    std::cout << "Decrypted: " << encrypted1 << std::endl;

    std::cout << CRYPT("Encrypted String!") << std::endl;

    printf(CRYPT("Encrypted Print!"));
```

### How It Works

TrCrypt uses a Feistel network with 8 rounds for encryption:
1. Strings encrypted at compile-time using constexpr functions
2. Stored in encrypted form in the `EncryptedString` class
3. Decryption occurs only when accessed
4. Encryption key generated at compile-time, easily customizable

### Change encryption Key

Modify this line in the `EncryptedString` constructor:

```cpp
: key(INT_MAX / 0x100 - 0x1000)
```

### Limitations

- Works best with strings that are multiples of 8 bytes
- Very long strings might impact compile-time performance

Licensed under the MIT License.
Copyright by TrickSTRR
