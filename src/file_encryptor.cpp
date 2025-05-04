#include "file_encryptor.h"
#include "crypto/chacha20.h"
#include "crypto/ecc.h"
#include "crypto/steganography.h"
#include "io/file_handler.h"
#include "keys/key_manager.h"
#include "constants.h"
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
        
        // Save keys only to images, not to regular files
        bool privateImgResult = Steganography::hideDataInImage(
            PRIVATE_KEY_IMAGE, 
            keyManager.getPrivateKey(), 
            PRIVATE_KEY_IMAGE
        );
        
        bool publicImgResult = Steganography::hideDataInImage(
            PUBLIC_KEY_IMAGE,
            keyManager.getPublicKey(),
            PUBLIC_KEY_IMAGE
        );
        
        if (!privateImgResult || !publicImgResult) {
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

std::vector<unsigned char> loadKey(const std::string& keyPath) {
    try {
        // Always try to load from image first
        if (keyPath == "private.key" || keyPath == "security_key.prv" || keyPath.empty()) {
            auto keyData = Steganography::extractDataFromImage(PRIVATE_KEY_IMAGE);
            if (!keyData.empty()) {
                return keyData;
            }
        }
        else if (keyPath == "public.key" || keyPath == "security_key.pub" || keyPath.empty()) {
            auto keyData = Steganography::extractDataFromImage(PUBLIC_KEY_IMAGE);
            if (!keyData.empty()) {
                return keyData;
            }
        }
        
        // For any other key path, just try to load the file directly
        std::ifstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            return {};
        }
        
        keyFile.seekg(0, std::ios::end);
        size_t fileSize = keyFile.tellg();
        keyFile.seekg(0, std::ios::beg);
        
        std::vector<unsigned char> key(fileSize);
        keyFile.read(reinterpret_cast<char*>(key.data()), fileSize);
        
        return key;
    } catch (const std::exception& e) {
        return {};
    }
}

// New implementation that accepts a pre-loaded key
EncryptionResult encryptFileWithKey(const std::string& inputFilePath, const std::string& outputFilePath, 
                                 const std::vector<unsigned char>& publicKey) {
    EncryptionResult result;
    
    try {
        std::vector<uint8_t> fileData = readBinaryFile(inputFilePath);
        
        // No need to load the key, it's provided as a parameter
        if (publicKey.empty()) {
            result.success = false;
            result.message = "Invalid public key provided";
            return result;
        }

        auto symmetricKey = generateSymmetricKey();
        auto nonce = std::vector<uint8_t>(ChaCha20::NONCE_SIZE);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);
        for (size_t i = 0; i < nonce.size(); i++) {
            nonce[i] = static_cast<uint8_t>(distrib(gen));
        }
        
        // Rest of encryption process is the same
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

// Modify existing encryptFile to use the new implementation
EncryptionResult encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, 
                           const std::string& keyPath) {
    std::vector<uint8_t> publicKey;
    
    if (!keyPath.empty()) {
        publicKey = loadKey(keyPath);
        if (publicKey.empty()) {
            // Try loading from default image
            publicKey = Steganography::extractDataFromImage(PUBLIC_KEY_IMAGE);
            if (publicKey.empty()) {
                EncryptionResult result;
                result.success = false;
                result.message = "Failed to load public key from image";
                return result;
            }
        }
    } else {
        // Try loading from default image
        publicKey = Steganography::extractDataFromImage(PUBLIC_KEY_IMAGE);
        if (publicKey.empty()) {
            KeyManager keyManager;
            keyManager.generateKeyPair();
            publicKey = keyManager.getPublicKey();
            
            // Save to images only
            Steganography::hideDataInImage(PRIVATE_KEY_IMAGE, keyManager.getPrivateKey(), PRIVATE_KEY_IMAGE);
            Steganography::hideDataInImage(PUBLIC_KEY_IMAGE, publicKey, PUBLIC_KEY_IMAGE);
        }
    }
    
    return encryptFileWithKey(inputFilePath, outputFilePath, publicKey);
}

// New implementation for decryption with pre-loaded key
EncryptionResult decryptFileWithKey(const std::string& inputFilePath, const std::string& outputFilePath, 
                                 const std::vector<unsigned char>& privateKey) {
    EncryptionResult result;
    
    try {
        // No need to load the key, it's provided as a parameter
        if (privateKey.empty()) {
            result.success = false;
            result.message = "Invalid private key provided";
            return result;
        }
        
        std::vector<uint8_t> encryptedData = readBinaryFile(inputFilePath);
        
        if (encryptedData.size() < 8) {
            result.success = false;
            result.message = "Invalid encrypted file format";
            return result;
        }
        
        // Rest of decryption process is the same
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

// Modify existing decryptFile function to use the new implementation
EncryptionResult decryptFile(const std::string& inputFilePath, const std::string& outputFilePath, 
                           const std::string& keyPath) {
    std::vector<uint8_t> privateKey;
    
    if (!keyPath.empty()) {
        // Try to load private key from specified path or image
        privateKey = loadKey(keyPath);
    } else {
        // Try to load from default image
        privateKey = Steganography::extractDataFromImage(PRIVATE_KEY_IMAGE);
    }
    
    if (privateKey.empty()) {
        EncryptionResult result;
        result.success = false;
        result.message = "Failed to load private key for decryption";
        return result;
    }
    
    return decryptFileWithKey(inputFilePath, outputFilePath, privateKey);
}
