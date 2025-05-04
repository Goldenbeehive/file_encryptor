#ifndef FILE_ENCRYPTOR_H
#define FILE_ENCRYPTOR_H

#include <string>
#include <vector>

struct EncryptionResult {
    bool success;
    std::string message;
};

// Original functions that load keys internally
EncryptionResult encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, 
                           const std::string& keyPath = "");

EncryptionResult decryptFile(const std::string& inputFilePath, const std::string& outputFilePath, 
                           const std::string& keyPath = "");

// New functions that accept pre-loaded keys
EncryptionResult encryptFileWithKey(const std::string& inputFilePath, const std::string& outputFilePath, 
                                 const std::vector<unsigned char>& publicKey);

EncryptionResult decryptFileWithKey(const std::string& inputFilePath, const std::string& outputFilePath, 
                                 const std::vector<unsigned char>& privateKey);

bool generateEncryptionKeys(const std::string& privateKeyPath, const std::string& publicKeyPath);
std::vector<unsigned char> loadKey(const std::string& keyPath);

void decryptFilesInDirectory(const std::string& privateKeyFile);
void secureFilesInDirectory(const std::string& publicKeyFile);

#endif