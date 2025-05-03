#ifndef FILE_ENCRYPTOR_H
#define FILE_ENCRYPTOR_H

#include <string>
#include <vector>

struct EncryptionResult {
    bool success;
    std::string message;
};

EncryptionResult encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, 
                           const std::string& keyPath = "");

EncryptionResult decryptFile(const std::string& inputFilePath, const std::string& outputFilePath, 
                           const std::string& keyPath = "");

bool generateEncryptionKeys(const std::string& privateKeyPath, const std::string& publicKeyPath);
std::vector<unsigned char> loadKey(const std::string& keyPath);

#endif