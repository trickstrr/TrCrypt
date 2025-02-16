#include <iostream>
#include <iomanip>
#include "TrCrypt.h"


int main() {
    auto encrypted1 = CRYPT("Hello, World!");
    std::cout << "Decrypted: " << encrypted1 << std::endl;
    std::cout << CRYPT("Encrypted String!") << std::endl;

    printf(CRYPT("Encrypted Print!"));

    return 0;
}