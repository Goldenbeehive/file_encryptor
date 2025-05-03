#ifndef CLI_H
#define CLI_H

#include <string>

class CLI {
public:
    void displayWelcomeMessage();
    void displayHelp();
    std::string getUserInput();
    void displayEncryptionResult(const std::string& result);
    void displayDecryptionResult(const std::string& result);
    void displayError(const std::string& errorMessage);
};

#endif