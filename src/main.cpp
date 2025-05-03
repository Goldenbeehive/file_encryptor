#include <iostream>
#include <string>
#include "file_encryptor.h"

void printUsage() {
    std::cout << "File Encryptor/Decryptor using ChaCha20 and ECC\n";
    std::cout << "Usage:\n";
    std::cout << "  file-encryptor encrypt <input_file> <output_file> [key_file]\n";
    std::cout << "  file-encryptor decrypt <input_file> <output_file> [key_file]\n";
    std::cout << "  file-encryptor generate <private_key_file> <public_key_file>\n";
    std::cout << "  file-encryptor help\n";
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
}

int main(int argc, char* argv[]) {
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