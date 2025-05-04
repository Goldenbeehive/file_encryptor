#ifndef GUI_H
#define GUI_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <functional>

class GUI {
public:
    GUI();
    ~GUI();
    
    bool initialize(HINSTANCE hInstance);
    void showStartMessage();
    void showCompletionMessage();
    void showDecryptingMessage();  // New method to show decryption in progress
    void showDecryptionComplete(); // New method to show decryption is complete
    void notifyDecryptionComplete(); // Method to be called when decryption is done
    void close();
    
    // Set the decrypt callback function
    void setDecryptCallback(std::function<void()> callback);
    
    // Event handling
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    
private:
    HWND hwnd;        // Main window handle
    HWND btnDecrypt;  // Button handle
    std::function<void()> decryptCallback;
    
    static GUI* instance;
};

// Global function to be called from WinMain
int RunGUIApplication(HINSTANCE hInstance);

#endif // GUI_H
