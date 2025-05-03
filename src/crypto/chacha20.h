#ifndef CHACHA20_H
#define CHACHA20_H

#include <cstdint>
#include <array>
#include <vector>
#include <string>

class ChaCha20 {
public:
    static const size_t KEY_SIZE = 32;
    static const size_t NONCE_SIZE = 12;
    
    ChaCha20();
    ChaCha20(const std::vector<uint8_t>& key);
    
    static bool Encrypt(const std::string& key, const std::string& plaintext, std::string& ciphertext);
    static bool Decrypt(const std::string& key, const std::string& ciphertext, std::string& plaintext);
    
    void setKey(const std::vector<uint8_t>& key);
    void setNonce(const std::vector<uint8_t>& nonce);
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);
    
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

private:
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    void chacha20Block(uint32_t output[16]);
    void generateKeystream(uint8_t* keystream, size_t counter);
    void generateRandomNonce();

    std::vector<uint8_t> key_;
    std::vector<uint8_t> nonce_;
    uint32_t counter_;
    uint32_t state_[16];
};

#endif