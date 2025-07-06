#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>

// Helper function for robust logging
void LogToFileAndDebug(const std::string& msg) {
    // Output to debugger
    OutputDebugStringA(msg.c_str());
    
    // Get the DLL's directory path
    char dllPath[MAX_PATH];
    HMODULE hModule = GetModuleHandleA("cat.dll");
    if (hModule != NULL) {
        GetModuleFileNameA(hModule, dllPath, MAX_PATH);
        std::string dllPathStr(dllPath);
        size_t lastSlash = dllPathStr.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            std::string dllDir = dllPathStr.substr(0, lastSlash + 1);
            std::string logPath = dllDir + "cat_dll_log.txt";
            
            // Output to file in DLL directory
            std::ofstream log(logPath, std::ios::app);
            if (log.is_open()) {
                // Add timestamp
                std::time_t t = std::time(nullptr);
                char timebuf[64];
                std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
                log << "[" << timebuf << "] " << msg << std::endl;
                log.close();
            }
        }
    }
    
    // Fallback to C: drive if DLL path not found
    if (hModule == NULL) {
        std::ofstream log("C:/cat_dll_log.txt", std::ios::app);
        if (log.is_open()) {
            // Add timestamp
            std::time_t t = std::time(nullptr);
            char timebuf[64];
            std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
            log << "[" << timebuf << "] " << msg << std::endl;
            log.close();
        }
    }
}

// Export function to ensure the DLL is properly recognized
__declspec(dllexport) void CatFunction()
{
    LogToFileAndDebug("cat.dll: CatFunction called");
    // This function can be called from the injected process
    try {
        LogToFileAndDebug("cat.dll: CatFunction attempting MessageBoxA");
        MessageBoxA(NULL, "Cat DLL Function Called!", "cat.dll", MB_OK | MB_ICONINFORMATION);
        LogToFileAndDebug("cat.dll: CatFunction MessageBoxA succeeded");
    } catch (...) {
        LogToFileAndDebug("cat.dll: CatFunction MessageBoxA failed");
    }
}

// Global variable to track if DLL was loaded
bool g_DllLoaded = false;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        LogToFileAndDebug("cat.dll: DLL_PROCESS_ATTACH");
        // Disable thread library calls
        DisableThreadLibraryCalls(hModule);
        try {
            LogToFileAndDebug("cat.dll: Attempting MessageBoxA for injection");
            MessageBoxA(NULL, "DLL Injected Successfully!", "cat.dll", MB_OK | MB_ICONINFORMATION);
            LogToFileAndDebug("cat.dll: MessageBoxA for injection succeeded");
            g_DllLoaded = true;
        } catch (...) {
            LogToFileAndDebug("cat.dll: Injection successful but MessageBox failed");
        }
        break;
        
    case DLL_THREAD_ATTACH:
        LogToFileAndDebug("cat.dll: DLL_THREAD_ATTACH");
        break;
        
    case DLL_THREAD_DETACH:
        LogToFileAndDebug("cat.dll: DLL_THREAD_DETACH");
        break;
        
    case DLL_PROCESS_DETACH:
        LogToFileAndDebug("cat.dll: DLL_PROCESS_DETACH");
        if (g_DllLoaded) {
            try {
                LogToFileAndDebug("cat.dll: Attempting MessageBoxA for unload");
                MessageBoxA(NULL, "DLL Unloaded!", "cat.dll", MB_OK | MB_ICONINFORMATION);
                LogToFileAndDebug("cat.dll: MessageBoxA for unload succeeded");
            } catch (...) {
                LogToFileAndDebug("cat.dll: MessageBoxA for unload failed");
            }
        }
        break;
    }
    return TRUE;
}
