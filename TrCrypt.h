#ifndef TRCRYPT_AES_H
#define TRCRYPT_AES_H
#include <iostream>
#include <string>
#include <array>
#include <cstring>
#include <cstdint>
#include <memory>
#include <random>
#include <mutex>
#include <thread>
#include <vector>
#include <codecvt>
#include <locale>
#include <Windows.h>


constexpr uint8_t sbox[256] = {
99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
};

constexpr uint8_t inv_sbox[256] = {
82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
};

constexpr uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

template <typename T>
class SecureAllocator {
private:
	static void* secure_malloc(size_t size) {
		void* ptr = std::malloc(size);
		if (ptr) {
			std::random_device rd;
			std::mt19937 gen(rd());
			std::uniform_int_distribution<> dis(0, 255);
			for (size_t i = 0; i < size; ++i) {
				static_cast<uint8_t*>(ptr)[i] = dis(gen);
			}
		}
		return ptr;
	}
	static void secure_free(void* ptr, size_t size) {
		if (ptr) {
			std::random_device rd;
			std::mt19937 gen(rd());
			std::uniform_int_distribution<> dis(0, 255);
			for (size_t i = 0; i < size; ++i) {
				static_cast<uint8_t*>(ptr)[i] = dis(gen);
			}
			std::free(ptr);
		}
	}
public:
	using value_type = T;
	SecureAllocator() = default;
	template <class U> constexpr SecureAllocator(const SecureAllocator<U>&) noexcept {}
	T* allocate(std::size_t n) { return static_cast<T*>(secure_malloc(n * sizeof(T))); }
	void deallocate(T* p, std::size_t n) { secure_free(p, n * sizeof(T)); }
};

template <class T, class U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) { return true; }
template <class T, class U>
bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) { return false; }

using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

class AESKey {
public:
	static std::array<uint8_t, 16> generate() {
		static std::mutex mtx;
		std::lock_guard<std::mutex> lock(mtx);
		std::array<uint8_t, 16> key;
		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<> dis(0, 255);
		for (int i = 0; i < 16; ++i) {
			key[i] = static_cast<uint8_t>(dis(gen));
		}
		return key;
	}
};
thread_local std::array<uint8_t, 16> aes_key = AESKey::generate();

__inline constexpr void aesSubBytes(uint8_t block[16]) {
	for (int i = 0; i < 16; i++) block[i] = sbox[block[i]];
}

__inline constexpr void aesInvSubBytes(uint8_t block[16]) {
	for (int i = 0; i < 16; i++) block[i] = inv_sbox[block[i]];
}

__inline constexpr void aesShiftRows(uint8_t block[16]) {
	uint8_t temp[16] = {
	block[0], block[5], block[10], block[15],
	block[4], block[9], block[14], block[3],
	block[8], block[13], block[2], block[7],
	block[12], block[1], block[6], block[11]
	};
	for (int i = 0; i < 16; i++) block[i] = temp[i];
}

__inline constexpr void aesInvShiftRows(uint8_t block[16]) {
	uint8_t temp[16] = {
	block[0], block[13], block[10], block[7],
	block[4], block[1], block[14], block[11],
	block[8], block[5], block[2], block[15],
	block[12], block[9], block[6], block[3]
	};
	for (int i = 0; i < 16; i++) block[i] = temp[i];
}

__inline constexpr void aesAddRoundKey(uint8_t block[16], const uint8_t roundKey[16]) {
	for (int i = 0; i < 16; i++) block[i] ^= roundKey[i];
}

__inline constexpr void aesKeyExpansion(const uint8_t key[16], uint8_t expandedKeys[176]) {
	for (int i = 0; i < 16; i++) expandedKeys[i] = key[i];
	uint8_t temp[4] = { 0, 0, 0, 0 };
	for (int i = 16, r = 0; i < 176; i += 4) {
		for (int j = 0; j < 4; j++) temp[j] = expandedKeys[i - 4 + j];
		if (i % 16 == 0) {
			uint8_t t = temp[0];
			temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
			for (int j = 0; j < 4; j++) temp[j] = sbox[temp[j]];
			temp[0] ^= rcon[r++];
		}
		for (int j = 0; j < 4; j++) expandedKeys[i + j] = expandedKeys[i - 16 + j] ^ temp[j];
	}
}

__inline constexpr void aesEncryptBlock(uint8_t block[16], const uint8_t key[16]) {
	uint8_t expandedKeys[176];
	aesKeyExpansion(key, expandedKeys);
	aesAddRoundKey(block, key);
	for (int round = 1; round < 10; round++) {
		aesSubBytes(block);
		aesShiftRows(block);
		aesAddRoundKey(block, expandedKeys + round * 16);
	}
	aesSubBytes(block);
	aesShiftRows(block);
	aesAddRoundKey(block, expandedKeys + 160);
}

__inline constexpr void aesDecryptBlock(uint8_t block[16], const uint8_t key[16]) {
	uint8_t expandedKeys[176];
	aesKeyExpansion(key, expandedKeys);
	aesAddRoundKey(block, expandedKeys + 160);
	for (int round = 9; round > 0; round--) {
		aesInvShiftRows(block);
		aesInvSubBytes(block);
		aesAddRoundKey(block, expandedKeys + round * 16);
	}
	aesInvShiftRows(block);
	aesInvSubBytes(block);
	aesAddRoundKey(block, key);
}
std::vector<uint8_t> stringToBytes(const std::string& str) {
	return std::vector<uint8_t>(str.begin(), str.end());
}

std::string bytesToString(const std::vector<uint8_t>& bytes) {
	return std::string(bytes.begin(), bytes.end());
}

std::string bytesToUTF8String(const std::vector<uint8_t>& bytes) {
	int utf16Length = MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), nullptr, 0);
	std::wstring utf16String(utf16Length, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), &utf16String[0], utf16Length);
	int utf8Length = WideCharToMultiByte(CP_UTF8, 0, utf16String.c_str(), -1, nullptr, 0, nullptr, nullptr);
	std::string utf8String(utf8Length, '\0');
	WideCharToMultiByte(CP_UTF8, 0, utf16String.c_str(), -1, &utf8String[0], utf8Length, nullptr, nullptr);
	utf8String.pop_back();
	return utf8String;
}

std::vector<uint8_t> pkcs7Pad(const std::vector<uint8_t>& data) {
	const size_t block_size = 16;
	size_t padding_length = block_size - (data.size() % block_size);
	std::vector<uint8_t> padded = data;
	padded.insert(padded.end(), padding_length, static_cast<uint8_t>(padding_length));
	return padded;
}

std::vector<uint8_t> pkcs7Unpad(const std::vector<uint8_t>& data) {
	if (data.empty()) return {};
	uint8_t padding_length = data.back();
	if (padding_length > data.size() || padding_length == 0) return {};
	for (size_t i = data.size() - padding_length; i < data.size(); ++i) {
		if (data[i] != padding_length) return {};
	}
	std::vector<uint8_t> unpadded(data.begin(), data.end() - padding_length);
	return unpadded;
}

template <std::size_t N>
class EncryptedString {
public:
	constexpr EncryptedString(const char(&str)[N]) : encrypted(encrypt(str)) {}
	friend std::ostream& operator<<(std::ostream& os, const EncryptedString& es) {
		os << es.c_str();
		return os;
	}
	const char* c_str() const {
		static thread_local std::string decrypted;
		decrypted = decrypt();
		return decrypted.c_str();
	}
	operator const char* () const {
		return c_str();
	}

private:
	constexpr std::vector<uint8_t> encrypt(const char(&str)[N]) const {
		std::vector<uint8_t> padded = pkcs7Pad(stringToBytes(std::string(str, N - 1)));
		std::vector<uint8_t> encrypted = padded;
		for (size_t i = 0; i < encrypted.size(); i += 16) {
			aesEncryptBlock(&encrypted[i], aes_key.data());
		}
		return encrypted;
	}

	std::string decrypt() const {
		std::vector<uint8_t> decrypted = encrypted;
		for (size_t i = 0; i < decrypted.size(); i += 16) {
			aesDecryptBlock(&decrypted[i], aes_key.data());
		}
		auto unpadded = pkcs7Unpad(decrypted);
		std::string result = bytesToUTF8String(unpadded);
		return result;
	}

	const std::vector<uint8_t> encrypted;
};

#define TRCRYPT(str) (EncryptedString<sizeof(str)>(str))
#endif