/*
 * TrCrypt - Compile-time String Encryption for C++
 *
 * Copyright (c) 2025 TrickSTRR
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef TRCRYPT_H
#define TRCRYPT_H

#include <iostream>
#include <string>
#include <array>
#include <cstring>
#include <climits>

constexpr int f(int subblock, char key) {
    return subblock ^ key;
}


constexpr void encrypt_block(int& left, int& right, long long key) {
    constexpr int rounds = 16;
    for (int i = 0; i < rounds; i++) {
        int temp = right ^ f(left, static_cast<char>(key + i));
        if (i != 7) {
            right = left;
            left = temp;
        }
        else right = temp;
        
    }
}

template <std::size_t N>
class EncryptedString {
public:
    constexpr EncryptedString(const char(&str)[N])
        : key((N* UINT64_C(0x1337BEEF)) ^ UINT64_C(0xC0FFEE)), size(N), encrypted(encrypt_string(str)) {
    }
    friend std::ostream& operator<<(std::ostream& os, const EncryptedString& es) {
        os << es.decrypt();
        return os;
    }
    const char* c_str() const {
        return decrypt();
    }

    operator const char* () const {
        return decrypt();
    }

private:
    constexpr std::array<char, N> encrypt_string(const char(&str)[N]) const {
        std::array<char, N> result{};
        for (std::size_t i = 0; i < N; ++i) {
            result[i] = str[i];
        }
        for (std::size_t i = 0; i + 8 <= N; i += 8) {
            int left = *reinterpret_cast<int*>(&result[i]);
            int right = *reinterpret_cast<int*>(&result[i + 4]);
            encrypt_block(left, right, key);
            *reinterpret_cast<int*>(&result[i]) = left;
            *reinterpret_cast<int*>(&result[i + 4]) = right;
        }
        return result;
    }
    const char* decrypt() const {
        static std::string decrypted_message;
        decrypted_message.clear();
        decrypted_message.resize(N);
        for (std::size_t i = 0; i + 8 <= N; i += 8) {
            int left = *reinterpret_cast<const int*>(&encrypted[i]);
            int right = *reinterpret_cast<const int*>(&encrypted[i + 4]);
            decrypt_block(left, right, key);
            *reinterpret_cast<int*>(&decrypted_message[i]) = left;
            *reinterpret_cast<int*>(&decrypted_message[i + 4]) = right;
        }
        for (std::size_t i = (N / 8) * 8; i < N; ++i) {
            decrypted_message[i] = encrypted[i];
        }
        decrypted_message.erase(decrypted_message.find_last_not_of('\0') + 1);
        return decrypted_message.c_str();
    }
    static void decrypt_block(int& left, int& right, long long key) {
        constexpr int rounds = 16;
        for (int i = rounds - 1; i >= 0; i--) {
            int temp = left ^ f(right, static_cast<char>(key + i));
            if (i != 7) {
                left = right;
                right = temp;
            }
            else {
                right = temp;
            }
        }
    }

    const long long key;
    const std::size_t size;
    const std::array<char, N> encrypted;
};
#define CRYPT(str) (EncryptedString<sizeof(str)>(str))
#endif