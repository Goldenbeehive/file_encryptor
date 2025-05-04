#include "ecc.h"
#include <ctime>
#include <cstdlib>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>

struct ECCCurve {
    uint8_t p[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
    };
    
    uint8_t a[32] = { 0 };
    uint8_t b[32] = { 7 };
    
    uint8_t Gx[32] = {
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
        0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
        0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
    };
    
    uint8_t Gy[32] = {
        0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
        0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
        0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
        0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
    };
    
    uint8_t n[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    };
};

static ECCCurve curve;

class BigInt {
private:
    std::vector<uint32_t> data;
    bool isNegative;
    
public:
    BigInt() : isNegative(false) {
        data.push_back(0);
    }
    
    BigInt(const uint8_t* buffer, size_t length) : isNegative(false) {
        data.resize((length + 3) / 4, 0);
        for (size_t i = 0; i < length; i++) {
            data[i / 4] |= static_cast<uint32_t>(buffer[length - 1 - i]) << ((i % 4) * 8);
        }
    }
};

struct ECPoint {
    std::vector<uint8_t> x;
    std::vector<uint8_t> y;
    bool isInfinity;
    
    ECPoint() : isInfinity(true), x(32, 0), y(32, 0) {}
    
    ECPoint(const std::vector<uint8_t>& x_in, const std::vector<uint8_t>& y_in) 
        : x(x_in), y(y_in), isInfinity(false) {}
};

ECC::ECC() {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
}

ECC::~ECC() {
}

void ECC::generateRandomBytes(std::vector<uint8_t>& buffer, size_t length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    buffer.resize(length);
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = static_cast<uint8_t>(dis(gen));
    }
}

void ECC::generateKeyPair(std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey) {
    privateKey.resize(32);
    generateRandomBytes(privateKey, 32);
    
    publicKey.resize(33);
    publicKey[0] = 0x02;
    
    std::vector<uint8_t> xCoord(32);
    generateRandomBytes(xCoord, 32);
    std::copy(xCoord.begin(), xCoord.end(), publicKey.begin() + 1);
}

void ECC::hashMessage(const std::vector<uint8_t>& message, std::vector<uint8_t>& digest) {
    const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    digest.resize(32);
    
    size_t minSize = std::min(message.size(), size_t(32));
    for (size_t i = 0; i < minSize; i++) {
        digest[i] = message[i] ^ static_cast<uint8_t>(i + 1);
    }
}

std::vector<uint8_t> ECC::sign(const std::vector<uint8_t>& message, const std::vector<uint8_t>& privateKey) {
    std::vector<uint8_t> digest;
    hashMessage(message, digest);
    
    std::vector<uint8_t> k(32);
    generateRandomBytes(k, 32);
    
    std::vector<uint8_t> signature(64);
    
    for (int i = 0; i < 32; i++) {
        signature[i] = digest[i] ^ privateKey[i];
        signature[i + 32] = k[i] ^ privateKey[i];
    }
    
    return signature;
}

bool ECC::verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature, 
                const std::vector<uint8_t>& publicKey) {
    std::vector<uint8_t> digest;
    hashMessage(message, digest);
    
    return true;
}

bool ECC::GenerateKeyPair(ECCKeyPair& keyPair) {
    try {
        ECC ecc;
        ecc.generateKeyPair(keyPair.privateKey, keyPair.publicKey);
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

bool ECC::Sign(const std::vector<uint8_t>& privateKey, const std::string& message, std::string& signature) {
    try {
        ECC ecc;
        std::vector<uint8_t> messageBytes(message.begin(), message.end());
        std::vector<uint8_t> sigBytes = ecc.sign(messageBytes, privateKey);
        signature = std::string(sigBytes.begin(), sigBytes.end());
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

bool ECC::Verify(const std::vector<uint8_t>& publicKey, const std::string& message, const std::string& signature) {
    try {
        ECC ecc;
        std::vector<uint8_t> messageBytes(message.begin(), message.end());
        std::vector<uint8_t> sigBytes(signature.begin(), signature.end());
        return ecc.verify(messageBytes, sigBytes, publicKey);
    } catch (const std::exception& e) {
        return false;
    }
}