#include "file_encryptor.h"
#include "crypto/chacha20.h"
#include "crypto/ecc.h"
#include "io/file_handler.h"
#include "keys/key_manager.h"
#include <iostream>
#include <fstream>
#include <random>

std::vector<unsigned char> generateSymmetricKey() {
    std::vector<unsigned char> key(ChaCha20::KEY_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    
    for (size_t i = 0; i < key.size(); i++) {
        key[i] = static_cast<unsigned char>(distrib(gen));
    }
    
    return key;
}

bool generateEncryptionKeys(const std::string& privateKeyPath, const std::string& publicKeyPath) {
    try {
        KeyManager keyManager;
        keyManager.generateKeyPair();
        return keyManager.saveKeyPair(privateKeyPath, publicKeyPath);
    } catch (const std::exception& e) {
        std::cerr << "Error generating keys: " << e.what() << std::endl;
        return false;
    }
}

std::vector<unsigned char> loadKey(const std::string& keyPath) {
    try {
        std::ifstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            std::cerr << "Failed to open key file" << std::endl;
            return {};
        }
        
        keyFile.seekg(0, std::ios::end);
        size_t fileSize = keyFile.tellg();
        keyFile.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> key(fileSize);
        keyFile.read(reinterpret_cast<char*>(key.data()), fileSize);
        
        return key;
    } catch (const std::exception& e) {
        std::cerr << "Error loading key: " << e.what() << std::endl;
        return {};
    }
}

EncryptionResult encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, 
                           const std::string& keyPath) {
    EncryptionResult result;
    
    try {
        std::vector<uint8_t> fileData = readBinaryFile(inputFilePath);
        
        KeyManager keyManager;
        std::vector<uint8_t> publicKey;
        
        if (!keyPath.empty()) {
            publicKey = loadKey(keyPath);
            if (publicKey.empty()) {
                result.success = false;
                result.message = "Failed to load public key";
                return result;
            }
        } else {
            keyManager.generateKeyPair();
            publicKey = keyManager.getPublicKey();
            keyManager.saveKeyPair("private.key", "public.key");
            std::cout << "New key pair generated and saved to 'private.key' and 'public.key'" << std::endl;
        }

        auto symmetricKey = generateSymmetricKey();
        auto nonce = std::vector<uint8_t>(ChaCha20::NONCE_SIZE);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);
        for (size_t i = 0; i < nonce.size(); i++) {
            nonce[i] = static_cast<uint8_t>(distrib(gen));
        }
        
        std::vector<uint8_t> outputData;
        outputData.reserve(symmetricKey.size() + nonce.size() + fileData.size() + 8);
        
        uint32_t keySize = static_cast<uint32_t>(symmetricKey.size());
        outputData.push_back((keySize >> 24) & 0xFF);
        outputData.push_back((keySize >> 16) & 0xFF);
        outputData.push_back((keySize >> 8) & 0xFF);
        outputData.push_back(keySize & 0xFF);
        
        outputData.insert(outputData.end(), symmetricKey.begin(), symmetricKey.end());
        
        uint32_t nonceSize = static_cast<uint32_t>(nonce.size());
        outputData.push_back((nonceSize >> 24) & 0xFF);
        outputData.push_back((nonceSize >> 16) & 0xFF);
        outputData.push_back((nonceSize >> 8) & 0xFF);
        outputData.push_back(nonceSize & 0xFF);
        
        outputData.insert(outputData.end(), nonce.begin(), nonce.end());
        
        ChaCha20 chacha;
        chacha.setKey(symmetricKey);
        chacha.setNonce(nonce);
        auto encryptedData = chacha.encrypt(fileData);
        
        outputData.insert(outputData.end(), encryptedData.begin(), encryptedData.end());
        
        writeBinaryFile(outputFilePath, outputData);
        
        result.success = true;
        result.message = "File encrypted successfully";
        return result;
        
    } catch (const std::exception& e) {
        result.success = false;
        result.message = std::string("Encryption error: ") + e.what();
        return result;
    }
}

EncryptionResult decryptFile(const std::string& inputFilePath, const std::string& outputFilePath, 
                           const std::string& keyPath) {
    EncryptionResult result;
    
    try {
        std::vector<uint8_t> encryptedData = readBinaryFile(inputFilePath);
        
        if (encryptedData.size() < 8) {
            result.success = false;
            result.message = "Invalid encrypted file format";
            return result;
        }
        
        uint32_t keySize = (encryptedData[0] << 24) | (encryptedData[1] << 16) | 
                          (encryptedData[2] << 8) | encryptedData[3];
        
        if (encryptedData.size() < 4 + keySize + 4) {
            result.success = false;
            result.message = "Invalid encrypted file format";
            return result;
        }
        
        std::vector<uint8_t> symmetricKey(encryptedData.begin() + 4, 
                                        encryptedData.begin() + 4 + keySize);
        
        size_t nonceOffset = 4 + keySize;
        uint32_t nonceSize = (encryptedData[nonceOffset] << 24) | (encryptedData[nonceOffset+1] << 16) | 
                           (encryptedData[nonceOffset+2] << 8) | encryptedData[nonceOffset+3];
        
        if (encryptedData.size() < nonceOffset + 4 + nonceSize) {
            result.success = false;
            result.message = "Invalid encrypted file format";
            return result;
        }
        
        std::vector<uint8_t> nonce(encryptedData.begin() + nonceOffset + 4, 
                                 encryptedData.begin() + nonceOffset + 4 + nonceSize);
        
        std::vector<uint8_t> dataToDecrypt(encryptedData.begin() + nonceOffset + 4 + nonceSize, 
                                         encryptedData.end());
        
        ChaCha20 chacha;
        chacha.setKey(symmetricKey);
        chacha.setNonce(nonce);
        auto decryptedData = chacha.decrypt(dataToDecrypt);
        
        writeBinaryFile(outputFilePath, decryptedData);
        
        result.success = true;
        result.message = "File decrypted successfully";
        return result;
        
    } catch (const std::exception& e) {
        result.success = false;
        result.message = std::string("Decryption error: ") + e.what();
        return result;
    }
}
