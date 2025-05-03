#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>
#include <stdexcept>

namespace CryptoUtils {

std::string bytesToHex(const unsigned char* bytes, size_t length);
std::vector<unsigned char> hexToBytes(const std::string& hex);
void handleError(const std::string& message);

}

#endif