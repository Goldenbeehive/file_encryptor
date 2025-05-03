#ifndef ECC_H
#define ECC_H

#include <cstdint>
#include <vector>
#include <string>

struct ECCKeyPair {
    std::vector<uint8_t> privateKey;
    std::vector<uint8_t> publicKey;
};

class ECC {
public:
    ECC();
    ~ECC();

    void generateKeyPair(std::vector<uint8_t>& privateKey, std::vector<uint8_t>& publicKey);
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message, const std::vector<uint8_t>& privateKey);
    bool verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature, 
                const std::vector<uint8_t>& publicKey);

    static bool GenerateKeyPair(ECCKeyPair& keyPair);
    static bool Sign(const std::vector<uint8_t>& privateKey, const std::string& message, std::string& signature);
    static bool Verify(const std::vector<uint8_t>& publicKey, const std::string& message, const std::string& signature);

private:
    void hashMessage(const std::vector<uint8_t>& message, std::vector<uint8_t>& hashedMessage);
    void generateRandomBytes(std::vector<uint8_t>& buffer, size_t length);
};

#endif