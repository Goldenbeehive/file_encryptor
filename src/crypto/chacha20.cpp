#include "chacha20.h"
#include <cstring>
#include <stdexcept>
#include <random>
#include <algorithm>

const uint32_t CHACHA20_CONSTANTS[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

ChaCha20::ChaCha20() : counter_(0) {
    key_.resize(KEY_SIZE, 0);
    nonce_.resize(NONCE_SIZE, 0);
}

ChaCha20::ChaCha20(const std::vector<uint8_t>& key) : counter_(0) {
    setKey(key);
    generateRandomNonce();
}

void ChaCha20::setKey(const std::vector<uint8_t>& key) {
    if (key.size() != KEY_SIZE) {
        throw std::runtime_error("ChaCha20 key must be 32 bytes");
    }
    key_ = key;
}

void ChaCha20::setNonce(const std::vector<uint8_t>& nonce) {
    if (nonce.size() != NONCE_SIZE) {
        throw std::runtime_error("ChaCha20 nonce must be 12 bytes");
    }
    nonce_ = nonce;
}

void ChaCha20::generateRandomNonce() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    
    nonce_.resize(NONCE_SIZE);
    for (size_t i = 0; i < NONCE_SIZE; i++) {
        nonce_[i] = static_cast<uint8_t>(distrib(gen));
    }
}

void ChaCha20::quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8) | (d >> 24);
    c += d; b ^= c; b = (b << 7) | (b >> 25);
}

void ChaCha20::chacha20Block(uint32_t output[16]) {
    std::memcpy(state_, CHACHA20_CONSTANTS, 16);
    
    for (int i = 0; i < 8; i++) {
        state_[4+i] = ((uint32_t)key_[4*i]) |
                      ((uint32_t)key_[4*i+1] << 8) |
                      ((uint32_t)key_[4*i+2] << 16) |
                      ((uint32_t)key_[4*i+3] << 24);
    }
    
    state_[12] = counter_;
    
    for (int i = 0; i < 3; i++) {
        state_[13+i] = ((uint32_t)nonce_[4*i]) |
                       ((uint32_t)nonce_[4*i+1] << 8) |
                       ((uint32_t)nonce_[4*i+2] << 16) |
                       ((uint32_t)nonce_[4*i+3] << 24);
    }
    
    uint32_t x[16];
    std::memcpy(x, state_, 64);
    
    for (int i = 0; i < 10; i++) {
        quarterRound(x[0], x[4], x[8], x[12]);
        quarterRound(x[1], x[5], x[9], x[13]);
        quarterRound(x[2], x[6], x[10], x[14]);
        quarterRound(x[3], x[7], x[11], x[15]);
        
        quarterRound(x[0], x[5], x[10], x[15]);
        quarterRound(x[1], x[6], x[11], x[12]);
        quarterRound(x[2], x[7], x[8], x[13]);
        quarterRound(x[3], x[4], x[9], x[14]);
    }
    
    for (int i = 0; i < 16; i++) {
        output[i] = x[i] + state_[i];
    }
}

void ChaCha20::generateKeystream(uint8_t* keystream, size_t counter) {
    uint32_t block[16];
    if (counter > UINT32_MAX) {
        throw std::runtime_error("Counter too large");
    }
    counter_ = static_cast<uint32_t>(counter);
    chacha20Block(block);
    
    for (int i = 0; i < 16; i++) {
        keystream[i*4] = block[i] & 0xff;
        keystream[i*4+1] = (block[i] >> 8) & 0xff;
        keystream[i*4+2] = (block[i] >> 16) & 0xff;
        keystream[i*4+3] = (block[i] >> 24) & 0xff;
    }
}

std::vector<uint8_t> ChaCha20::encrypt(const std::vector<uint8_t>& plaintext) {
    std::vector<uint8_t> result(plaintext.size());
    
    for (size_t i = 0; i < plaintext.size(); i += 64) {
        uint8_t keystream[64];
        generateKeystream(keystream, i / 64);
        
        size_t blockSize = std::min(size_t(64), plaintext.size() - i);
        for (size_t j = 0; j < blockSize; j++) {
            result[i + j] = plaintext[i + j] ^ keystream[j];
        }
    }
    
    return result;
}

std::vector<uint8_t> ChaCha20::decrypt(const std::vector<uint8_t>& ciphertext) {
    return encrypt(ciphertext);
}

std::string ChaCha20::encrypt(const std::string& plaintext) {
    std::vector<uint8_t> plaintextBytes(plaintext.begin(), plaintext.end());
    auto encryptedBytes = encrypt(plaintextBytes);
    return std::string(encryptedBytes.begin(), encryptedBytes.end());
}

std::string ChaCha20::decrypt(const std::string& ciphertext) {
    std::vector<uint8_t> ciphertextBytes(ciphertext.begin(), ciphertext.end());
    auto decryptedBytes = decrypt(ciphertextBytes);
    return std::string(decryptedBytes.begin(), decryptedBytes.end());
}

bool ChaCha20::Encrypt(const std::string& key, const std::string& plaintext, std::string& ciphertext) {
    try {
        std::vector<uint8_t> keyBytes(key.begin(), key.end());
        
        keyBytes.resize(KEY_SIZE);
        
        ChaCha20 chacha;
        chacha.setKey(keyBytes);
        chacha.generateRandomNonce();
        
        ciphertext = chacha.encrypt(plaintext);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool ChaCha20::Decrypt(const std::string& key, const std::string& ciphertext, std::string& plaintext) {
    try {
        std::vector<uint8_t> keyBytes(key.begin(), key.end());
        
        keyBytes.resize(KEY_SIZE);
        
        ChaCha20 chacha;
        chacha.setKey(keyBytes);
        
        plaintext = chacha.decrypt(ciphertext);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}