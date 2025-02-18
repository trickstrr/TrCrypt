# **TrCrypt – AES-128 Compile-time String Encryption for `printf`**  

TrCrypt is a lightweight **compile-time string encryption** library for **C++**, designed to protect string literals from static analysis tools like **IDA Pro**. It ensures that **strings are never stored in plaintext** in the compiled binary.  

## **Features**
- **AES-128 Encryption at Compile-Time** – Strings are encrypted before compilation finishes.  
- **Runtime Decryption** – Strings are decrypted **only when accessed** at runtime.  
- **Optimized for `printf`** – Ensures compatibility with `printf`-based output formatting.  
- **Heap Security** – Uses `SecureAllocator` to prevent heap dumps from revealing decrypted strings.  
- **C++11+ Compatible** – Works with modern C++ standards.
- **SBOX Generator** - You can use the genSbox.h to generate new SBoxes and inverted SBoxes. by: David Canright

## **Usage**
```cpp
#include "TrCrypt.h"
#include <cstdio>

int main() {
    printf("%s\n", TRCRYPT("Hello, Secure World!"));
    return 0;
}
```
**Output:** `"Hello, Secure World!"`  

## **Limitations**
- **Performance Overhead** – Encryption & decryption introduce a slight runtime cost.  
- **Limited String Size** – Large encrypted strings may impact **binary size**.  

## **License**
**MIT License** – Free to use and modify.  
**Author:** TrickSTRR
