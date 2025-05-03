#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include <string>
#include <vector>
#include <memory>

class KeyManager {
public:
    KeyManager();
    ~KeyManager();

    void generateKeyPair();
    bool loadKeyPair(const std::string& privateKeyFile, const std::string& publicKeyFile);
    bool saveKeyPair(const std::string& privateKeyFile, const std::string& publicKeyFile) const;
    std::vector<unsigned char> getPublicKey() const;
    std::vector<unsigned char> getPrivateKey() const;

    std::shared_ptr<std::vector<unsigned char>> generateKey();
    std::shared_ptr<std::vector<unsigned char>> loadKey(const std::string& keyPath);
    void saveKey(const std::string& keyPath);
    std::shared_ptr<std::vector<unsigned char>> getCurrentKey();

private:
    std::vector<unsigned char> privateKey;
    std::vector<unsigned char> publicKey;
};

#endif