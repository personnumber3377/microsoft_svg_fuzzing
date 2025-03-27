#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>

#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")


// Type definition for FMain function from wwlib.dll
// typedef void (__stdcall *FMain_t)(void*, void*, unsigned int, unsigned int);

typedef void (*FMain_t)(void* a1, void* a2, unsigned int a3, void* global_ptr);


// Dummy versions of original params (adjust as needed for your fuzz loop)
void* dummy_param1 = nullptr;
void* dummy_param2 = nullptr;
unsigned int dummy_param3 = 0;
unsigned int dummy_param4 = 0;

// Your fuzzing function
void RunFuzzLoop() {
    std::cout << "[+] Running fuzz loop..." << std::endl;

    // Insert your fuzzing code here, e.g.
    // - Load test input
    // - Call target COM/svg render/etc APIs
    // - Monitor for crashes
    
    std::ifstream file("input.svg", std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[-] Failed to open input.svg" << std::endl;
        return;
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), {});
    file.close();

    std::cout << "[+] Loaded input.svg with size: " << buffer.size() << " bytes" << std::endl;

    // You could call your fuzz target function here, similar to your fuzz_function()
}

//int main() {

/*






void WinMain(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4)

{
  char cVar1;
  LSTATUS LVar2;
  undefined4 uVar3;
  DWORD DVar4;
  HMODULE hModule;
  FARPROC pFVar5;
  wchar_t *pwVar6;
  ulonglong uVar7;
  bool bVar8;
  undefined auStackY_2a8 [32];
  DWORD local_278 [2];
  int local_270 [2];
  DWORD local_268 [2];
  HKEY local_260;
  WCHAR local_258 [264];
  ulonglong local_48;
  
  local_48 = __security_cookie ^ (ulonglong)auStackY_2a8;
  local_278[0] = 0;
  local_260 = (HKEY)0x0;
  _snwprintf_s<260>(local_258,0xffffffffffffffff,L"Software\\Microsoft\\Office\\%d.%d\\Word\\Boot ",
                    0x10);
  LVar2 = RegOpenKeyExW((HKEY)0xffffffff80000001,local_258,0,3,&local_260);
  if ((LVar2 == 0) && (local_260 != (HKEY)0x0)) {
    local_268[0] = 0;
    LVar2 = RegQueryValueExW(local_260,L"BootProfilerResiliency",(LPDWORD)0x0,local_268,(LPBYTE) 0x0,
                             local_278);
    RegCloseKey(local_260);
    if (LVar2 != 0) goto LAB_1400010fb;
  }
  else {
LAB_1400010fb:
    local_270[0] = 0;
    local_268[0] = 4;
    local_260 = (HKEY)0x0;
    _snwprintf_s<260>(local_258,0xffffffffffffffff,L"Software\\Microsoft\\Office\\%d.%d\\Word\\Bo ot"
                      ,0x10);
    LVar2 = RegOpenKeyExW((HKEY)0xffffffff80000001,local_258,0,3,&local_260);
    if ((LVar2 == 0) && (local_260 != (HKEY)0x0)) {
      local_278[0] = 0;
      LVar2 = RegQueryValueExW(local_260,L"BootProfilerMsec",(LPDWORD)0x0,local_278,
                               (LPBYTE)local_270,local_268);
      RegCloseKey(local_260);
      if ((LVar2 == 0) &&
         (((local_278[0] == 4 && (local_270[0] != 0)) &&
          (uVar3 = FUN_1400038f0((undefined8 *)&vBootProfilerDescriptor), (char)uVar3 != '\0'))) ) {
        _DAT_140008958 = local_270[0];
        uVar7 = 1;
        DAT_140008928 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,1,0,(LPCWSTR)0x0);
        if (((DAT_140008928 == (HANDLE)0x0) ||
            (cVar1 = FUN_140003960(0x140008920,uVar7), cVar1 == '\0')) &&
           (_vBootProfilerDescriptor != (HANDLE)0x0)) {
          ReleaseMutex(_vBootProfilerDescriptor);
        }
      }
    }
  }
  local_260 = (HKEY)0x0;
  local_278[0] = 0;
  local_270[0] = 0;
  local_268[0] = 4;
  _snwprintf_s<260>(local_258,0xffffffffffffffff,L"Software\\Microsoft\\Office\\%d.%d\\Word",0x 10);
  pwVar6 = local_258;
  LVar2 = RegOpenKeyExW((HKEY)0xffffffff80000001,pwVar6,0,1,&local_260);
  if ((LVar2 == 0) && (local_260 != (HKEY)0x0)) {
    pwVar6 = L"WwlibtDll";
    LVar2 = RegQueryValueExW(local_260,L"WwlibtDll",(LPDWORD)0x0,local_278,(LPBYTE)local_270,
                             local_268);
    RegCloseKey(local_260);
    if ((LVar2 != 0) || (local_278[0] != 4)) goto LAB_14000125c;
    bVar8 = local_270[0] != 0;
  }
  else {
LAB_14000125c:
    bVar8 = false;
  }
  if (bVar8) {
    hModule = Mso::SafeLoadLibrary(L"wwlibt.dll",pwVar6,0);
LAB_140001e47:
    if (hModule == (HMODULE)0x0) goto LAB_140001e58;
  }
  else {
    pwVar6 = L"wwlib.dll";
    hModule = LoadLibraryExW(L"wwlib.dll",(HANDLE)0x0,0x1000);
    if ((hModule == (HMODULE)0x0) && (DVar4 = GetLastError(), DVar4 == 0x57)) {
      pwVar6 = (wchar_t *)GetModuleHandleW(L"kernel32.dll");
      pFVar5 = GetProcAddress((HMODULE)pwVar6,"AddDllDirectory");
      if (pFVar5 == (FARPROC)0x0) {
        pwVar6 = L"wwlib.dll";
        hModule = LoadLibraryExW(L"wwlib.dll",(HANDLE)0x0,0);
      }
    }
    if (hModule == (HMODULE)0x0) {
      hModule = HinstLoadWWLibDarwin(pwVar6);
      goto LAB_140001e47;
    }
  }
  pFVar5 = GetProcAddress(hModule,"FMain");
  if (pFVar5 != (FARPROC)0x0) {
    (*pFVar5)(param_1,param_2,param_4,DAT_140008110);
  }
LAB_140001e58:
  __security_check_cookie(local_48 ^ (ulonglong)auStackY_2a8);
  return;
}










    FARPROC pFMain = GetProcAddress(hWwlib, "FMain");
    if (!pFMain) {
        std::wcerr << L"[-] Failed to find FMain in wwlib.dll (" << GetLastError() << L")" << std::endl;
        return 1;
    }

    std::wcout << L"[+] Calling FMain..." << std::endl;
    reinterpret_cast<FMain_t>(pFMain)(hInstance, hPrevInstance, lpCmdLine, nCmdShow);
*/






/*

void SetOfficeWordRegistry() {
    DWORD zero = 0;

    // Set BootProfilerResiliency = 0
    RegSetKeyValueW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Office\\16.0\\Word\\Boot",
        L"BootProfilerResiliency",
        REG_DWORD,
        &zero,
        sizeof(zero)
    );

    // Set BootProfilerMsec = 0
    RegSetKeyValueW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Office\\16.0\\Word\\Boot",
        L"BootProfilerMsec",
        REG_DWORD,
        &zero,
        sizeof(zero)
    );

    // Set WwlibtDll = "" (empty string disables test DLL override)
    const wchar_t empty[] = L"";
    RegSetKeyValueW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Office\\16.0\\Word",
        L"WwlibtDll",
        REG_SZ,
        empty,
        (DWORD)((wcslen(empty) + 1) * sizeof(wchar_t))
    );
}

*/



void SetOfficeWordRegistry() {
    HKEY hKey;
    DWORD disposition;

    // Define the registry paths
    LPCWSTR wordBootKey = L"Software\\Microsoft\\Office\\16.0\\Word\\Boot";
    LPCWSTR wordKey     = L"Software\\Microsoft\\Office\\16.0\\Word";

    // Create/Open the Boot subkey
    if (RegCreateKeyExW(HKEY_CURRENT_USER, wordBootKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, &disposition) == ERROR_SUCCESS) {
        DWORD resiliencyVal = 1;
        if (RegSetValueExW(hKey, L"BootProfilerResiliency", 0, REG_DWORD, reinterpret_cast<BYTE*>(&resiliencyVal), sizeof(DWORD)) != ERROR_SUCCESS) {
            std::wcerr << L"[-] Failed to set BootProfilerResiliency" << std::endl;
        } else {
            std::wcout << L"[+] BootProfilerResiliency set" << std::endl;
        }

        DWORD msecVal = 100; // or any non-zero value
        if (RegSetValueExW(hKey, L"BootProfilerMsec", 0, REG_DWORD, reinterpret_cast<BYTE*>(&msecVal), sizeof(DWORD)) != ERROR_SUCCESS) {
            std::wcerr << L"[-] Failed to set BootProfilerMsec" << std::endl;
        } else {
            std::wcout << L"[+] BootProfilerMsec set" << std::endl;
        }

        RegCloseKey(hKey);
    } else {
        std::wcerr << L"[-] Failed to open/create Boot key" << std::endl;
    }

    // Create/Open the main Word key to mock "WwlibtDll" value
    if (RegCreateKeyExW(HKEY_CURRENT_USER, wordKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, &disposition) == ERROR_SUCCESS) {
        DWORD dummyVal = 1; // some non-zero value as per check in decomp
        if (RegSetValueExW(hKey, L"WwlibtDll", 0, REG_DWORD, reinterpret_cast<BYTE*>(&dummyVal), sizeof(DWORD)) != ERROR_SUCCESS) {
            std::wcerr << L"[-] Failed to set WwlibtDll" << std::endl;
        } else {
            std::wcout << L"[+] WwlibtDll set" << std::endl;
        }

        RegCloseKey(hKey);
    } else {
        std::wcerr << L"[-] Failed to open/create Word key" << std::endl;
    }
}


// void* someglobal = 0;

uint8_t profiler_data[0x100] = {}; // zero-initialized


int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR     lpCmdLine,
    int       nCmdShow
) {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    freopen("CONIN$", "r", stdin);


    std::wcout << L"[+] Called WinMain!!!" << std::endl;
    // Include the office directory
    
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    AddDllDirectory(L"C:\\Program Files\\Microsoft Office\\root\\Office16");
    AddDllDirectory(L"C:\\Program Files\\Microsoft Office\\root\\vfs\\ProgramFilesCommonX64\\Microsoft Shared\\OFFICE16");

    SetOfficeWordRegistry();

    std::wcout << L"[+] Loading wwlib.dll..." << std::endl;
    printf("%s", "poopooooooo\n");
    HMODULE hWwlib = LoadLibraryW(L"wwlib.dll");
    if (!hWwlib) {
        std::wcerr << L"[-] Failed to load wwlib.dll (" << GetLastError() << L")" << std::endl;
        return 1;
    }

    std::wcout << L"[+] Getting FMain function..." << std::endl;
    

    FMain_t FMain = (FMain_t)GetProcAddress(hWwlib, "FMain");
    if (!FMain) {
        MessageBoxA(NULL, "Failed to get FMain", "Error", MB_OK);
        return 1;
    }

    // Example usage - you'll need to set actual values
    void* param1 = nullptr;
    void* param2 = nullptr;
    unsigned int param4 = 0;
    // void* global_data_ptr = (void*)0xDEADBEEF; // placeholder for actual global pointer
    // someglobal = (void*)0x1; // Maybe set to one???
    // printf("Here is the pointer thing %p\n", someglobal);
    FMain(param1, param2, param4, &profiler_data);
    /*
    std::wcout << L"[+] Running fuzz loop after FMain..." << std::endl;
    RunFuzzLoop();
    */

    return 0;
}