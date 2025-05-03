#include "cli.h"
#include <iostream>
#include <string>

void displayHelp() {
    std::cout << "File Encryptor/Decryptor CLI\n";
    std::cout << "Usage:\n";
    std::cout << "  encrypt <filename> <key>   Encrypt a file\n";
    std::cout << "  decrypt <filename> <key>   Decrypt a file\n";
    std::cout << "  help                        Show this help message\n";
}

void handleUserInput(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Error: No command provided. Use 'help' for usage information.\n";
        return;
    }

    std::string command = argv[1];

    if (command == "help") {
        displayHelp();
    } else if (command == "encrypt" && argc == 4) {
        std::string filename = argv[2];
        std::string key = argv[3];
        std::cout << "Encrypting file: " << filename << " with key: " << key << "\n";
    } else if (command == "decrypt" && argc == 4) {
        std::string filename = argv[2];
        std::string key = argv[3];
        std::cout << "Decrypting file: " << filename << " with key: " << key << "\n";
    } else {
        std::cerr << "Error: Invalid command or arguments. Use 'help' for usage information.\n";
    }
}