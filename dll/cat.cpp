#include <windows.h>
#include <iostream>
#include <fstream>

// Export function to ensure the DLL is properly recognized
__declspec(dllexport) void CatFunction()
{
    OutputDebugStringA("cat.dll: CatFunction called");
    // This function can be called from the injected process
    MessageBoxA(NULL, "Cat DLL Function Called!", "cat.dll", MB_OK | MB_ICONINFORMATION);
}

// Global variable to track if DLL was loaded
bool g_DllLoaded = false;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Disable thread library calls
        DisableThreadLibraryCalls(hModule);
        OutputDebugStringA("cat.dll: DLL_PROCESS_ATTACH");
        
        // Show message box when DLL is injected
        try {
            MessageBoxA(NULL, "DLL Injected Successfully!", "cat.dll", MB_OK | MB_ICONINFORMATION);
            g_DllLoaded = true;
        } catch (...) {
            // If MessageBox fails, try alternative method
            OutputDebugStringA("cat.dll: Injection successful but MessageBox failed");
            std::ofstream log("C:/cat_dll_log.txt", std::ios::app);
            if (log.is_open()) {
                log << "cat.dll: Injection successful but MessageBox failed\n";
                log.close();
            }
        }
        break;
        
    case DLL_THREAD_ATTACH:
        break;
        
    case DLL_THREAD_DETACH:
        break;
        
    case DLL_PROCESS_DETACH:
        if (g_DllLoaded) {
            OutputDebugStringA("cat.dll: DLL_PROCESS_DETACH");
            MessageBoxA(NULL, "DLL Unloaded!", "cat.dll", MB_OK | MB_ICONINFORMATION);
        }
        break;
    }
    return TRUE;
}
