


#include <windows.h>
#include <stdio.h>


#include <TlHelp32.h>

uintptr_t GetModuleBase(const wchar_t* moduleName, DWORD pid) {
    uintptr_t base = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        me.dwSize = sizeof(me);
        if (Module32FirstW(snapshot, &me)) {
            do {
                if (_wcsicmp(me.szModule, moduleName) == 0) {
                    base = (uintptr_t)me.modBaseAddr;
                    break;
                }
            } while (Module32NextW(snapshot, &me));
        }
        CloseHandle(snapshot);
    }
    return base;
}

DWORD WINAPI PayloadThread(LPVOID lpParam) {
    // Wait for MSOSVG.dll to load (retry every 100ms)
    HMODULE hMod = NULL;
    while ((hMod = GetModuleHandleW(L"MSOSVG.dll")) == NULL) {
        Sleep(100);
    }

    // Get base address
    uintptr_t base = (uintptr_t)hMod;

    // Example offset: address of the function or instruction to patch
    // NOTE: You must reverse engineer or disassemble MSOSVG.dll to find this offset
    uintptr_t patchAddress = base + 0x2a30; // 0x12345; // Replace with actual offset
    // 2a30

    // Overwrite instructions — e.g., 5 NOPs
    BYTE patch[] = { 0x90, 0x90, 0x90, 0x90, 0x90 }; // NOPs
    DWORD oldProtect;
    if (VirtualProtect((LPVOID)patchAddress, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy((void*)patchAddress, patch, sizeof(patch));
        VirtualProtect((LPVOID)patchAddress, sizeof(patch), oldProtect, &oldProtect);
    }

    MessageBoxW(NULL, L"Patch applied!", L"MSOSVG", MB_OK);
    return 0;
}


/*
DWORD WINAPI PayloadThread(LPVOID lpParam) {
    MessageBoxW(NULL, L"MSOSVG.DLL Injected!", L"Injected", MB_OK);
    
    FILE* f = fopen("C:\\Users\\elsku\\paskaa.txt", "w");
    if (f) {
        fprintf(f, "DLL loaded!\n");
        fclose(f);
    }

    return 0;
}
*/


BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        //MessageBoxW(NULL, L"MSOSVG.DLL Injected!", L"Injected", MB_OK); // Proof of life

        /*
        FILE* f = fopen("C:\\Users\\elsku\\paskaa.txt", "w");
        if (f) {
            fprintf(f, "DLL loaded!\n");
            fclose(f);
        }
        */
        // You can also log to a file here or start a thread
        break;
    }
    //MessageBoxW(NULL, L"MSOSVG.DLL Injected!", L"Injected", MB_OK); // Proof of life

    DisableThreadLibraryCalls(hModule); // Optimization

        // Safe: spin off a new thread
    CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    return TRUE;
}