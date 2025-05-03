#include "key_manager.h"
#include "../crypto/ecc.h"
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <cstdlib>

// Constants
const size_t KEY_SIZE = 32; // 256 bits

KeyManager::KeyManager() {
    // Initialize with empty keys
    privateKey.clear();
    publicKey.clear();
}

KeyManager::~KeyManager() {
    // Securely clear private key when done
    if (!privateKey.empty()) {
        std::fill(privateKey.begin(), privateKey.end(), 0);
    }
}

void KeyManager::generateKeyPair() {
    ECC ecc;
    ecc.generateKeyPair(privateKey, publicKey);
}

bool KeyManager::loadKeyPair(const std::string& privateKeyFile, const std::string& publicKeyFile) {
    try {
        std::ifstream privFile(privateKeyFile, std::ios::binary);
        std::ifstream pubFile(publicKeyFile, std::ios::binary);
        
        if (!privFile || !pubFile) {
            return false;
        }
        
        // Read private key
        privFile.seekg(0, std::ios::end);
        privateKey.resize(privFile.tellg());
        privFile.seekg(0, std::ios::beg);
        privFile.read(reinterpret_cast<char*>(privateKey.data()), privateKey.size());
        
        // Read public key
        pubFile.seekg(0, std::ios::end);
        publicKey.resize(pubFile.tellg());
        pubFile.seekg(0, std::ios::beg);
        pubFile.read(reinterpret_cast<char*>(publicKey.data()), publicKey.size());
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error loading key pair: " << e.what() << std::endl;
        privateKey.clear();
        publicKey.clear();
        return false;
    }
}

bool KeyManager::saveKeyPair(const std::string& privateKeyFile, const std::string& publicKeyFile) const {
    try {
        std::ofstream privFile(privateKeyFile, std::ios::binary);
        std::ofstream pubFile(publicKeyFile, std::ios::binary);
        
        if (!privFile || !pubFile) {
            return false;
        }
        
        // Write private key
        privFile.write(reinterpret_cast<const char*>(privateKey.data()), privateKey.size());
        
        // Write public key
        pubFile.write(reinterpret_cast<const char*>(publicKey.data()), publicKey.size());
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving key pair: " << e.what() << std::endl;
        return false;
    }
}

std::vector<unsigned char> KeyManager::getPublicKey() const {
    return publicKey;
}

std::vector<unsigned char> KeyManager::getPrivateKey() const {
    return privateKey;
}

// For compatibility with tests
std::shared_ptr<std::vector<unsigned char>> KeyManager::generateKey() {
    auto key = std::make_shared<std::vector<unsigned char>>(KEY_SIZE);
    // Generate random bytes for key
    for (size_t i = 0; i < KEY_SIZE; i++) {
        (*key)[i] = static_cast<unsigned char>(std::rand() % 256);
    }
    return key;
}

std::shared_ptr<std::vector<unsigned char>> KeyManager::loadKey(const std::string& keyPath) {
    try {
        std::ifstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            return nullptr;
        }
        
        auto key = std::make_shared<std::vector<unsigned char>>(KEY_SIZE);
        keyFile.read(reinterpret_cast<char*>(key->data()), KEY_SIZE);
        
        if (keyFile.gcount() != KEY_SIZE) {
            return nullptr;
        }
        
        return key;
    } catch (...) {
        return nullptr;
    }
}

void KeyManager::saveKey(const std::string& keyPath) {
    try {
        std::ofstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Could not open file for writing");
        }
        
        auto key = getCurrentKey();
        keyFile.write(reinterpret_cast<const char*>(key->data()), key->size());
    } catch (const std::exception& e) {
        std::cerr << "Error saving key: " << e.what() << std::endl;
    }
}

std::shared_ptr<std::vector<unsigned char>> KeyManager::getCurrentKey() {
    if (privateKey.empty()) {
        return generateKey();
    }
    return std::make_shared<std::vector<unsigned char>>(privateKey);
}