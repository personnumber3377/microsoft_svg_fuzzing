#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <fstream>

#include <vector>
#include <string>
#include <iostream>

#define GLOBAL_BUFFER_SIZE 100000

unsigned char global_buffer[GLOBAL_BUFFER_SIZE]; // Just assume that the data fits here...
size_t global_buf_len = 0;

#include <sstream>
#include <iomanip>
#include <random>
// #include <windows.h>

__declspec(noinline) void save_crashing_input(const std::vector<uint8_t>& buffer, DWORD exception_code) {
    // Generate a random 5-character alphanumeric suffix
    std::string suffix;
    static const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::default_random_engine rng((unsigned int)GetTickCount());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    for (int i = 0; i < 5; ++i) {
        suffix += charset[dist(rng)];
    }

    std::ostringstream filename;
    filename << "crash_"
             << std::hex << std::setw(8) << std::setfill('0') << exception_code
             << "_" << suffix << ".svg";

    std::ofstream out(filename.str(), std::ios::binary);
    if (out.is_open()) {
        out.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        out.close();
        fprintf(stderr, "[+] Saved crash to %s\n", filename.str().c_str());
    } else {
        fprintf(stderr, "[-] Failed to save crash file: %s\n", filename.str().c_str());
    }
}



__declspec(noinline) void save_crashing_input_new(DWORD exception_code) {
    const unsigned char* data = global_buffer;
    size_t size = global_buf_len;
    // Generate a random 5-character alphanumeric suffix
    std::string suffix;
    static const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::default_random_engine rng((unsigned int)GetTickCount());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    for (int i = 0; i < 5; ++i) {
        suffix += charset[dist(rng)];
    }

    std::ostringstream filename;
    filename << "crash_"
             << std::hex << std::setw(8) << std::setfill('0') << exception_code
             << "_" << suffix << ".svg";

    std::ofstream out(filename.str(), std::ios::binary);
    if (out.is_open()) {
        out.write(reinterpret_cast<const char*>(data), size);
        out.close();
        fprintf(stderr, "[+] Saved crash to %s\n", filename.str().c_str());
    } else {
        fprintf(stderr, "[-] Failed to save crash file: %s\n", filename.str().c_str());
    }
}

/*



#include <windows.h>
#include <stdio.h>

void save_crashing_input(const unsigned char* buf, unsigned int size, DWORD exception_code) {
    char filename[256];
    snprintf(filename, sizeof(filename), "crash_%08x.svg", exception_code);  // e.g., crash_e06d7363.svg

    FILE* f = fopen(filename, "wb");
    if (f) {
        fwrite(buf, 1, size, f);
        fclose(f);
        fprintf(stderr, "[+] Saved crashing input to %s\n", filename);
    } else {
        fprintf(stderr, "[-] Failed to save crash file\n");
    }
}

unsigned char run_fuzz_one(char** argv, unsigned char* buf, unsigned int buf_size,
                           unsigned char (*common_fuzz_stuff)(char**, unsigned char*, unsigned int)) {
    unsigned char result = 0;

    __try {
        // Call your actual fuzz logic here (e.g. render, parse, etc.)
        result = common_fuzz_stuff(argv, buf, buf_size);  // or call FMain, etc.
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        fprintf(stderr, "[!] Exception caught: 0x%08x\n", code);

        save_crashing_input(buf, buf_size, code);

        // Return 0 or 1 depending on whether you want to continue fuzzing
        result = 1;  // Tell fuzzer to skip remaining mutations of this input
    }

    return result;
}

*/

#include <thread>
#include <atomic>

std::atomic<bool> processing_done = false;

void fuzz_timeout_watchdog(unsigned int timeout_ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
    if (!processing_done) {
        // Timeout hit. Log and abort this iteration.
        FILE* f = fopen("C:\\Users\\elsku\\hook_hit.txt", "a+");
        if (f) {
            fprintf(f, "[!] TIMEOUT after %u ms\n", timeout_ms);
            fclose(f);
        }

        // You can either longjmp, return, or exit the thread.
        TerminateThread(GetCurrentThread(), 1);  // Not ideal but it works for debugging.
    }
}







void debug_print(const char* string) {
    FILE* f = fopen("C:\\Users\\elsku\\hook_hit.txt", "a+");
    if (f) {
        fprintf(f, string);
        fclose(f);
    }
}

void debug_print_ptr(const char* label, void* ptr) {
    FILE* f = fopen("C:\\Users\\elsku\\hook_hit.txt", "a+");
    if (f) {
        fprintf(f, "%s: %p\n", label, ptr);
        fclose(f);
    }
}

BYTE originalBytes[5]; // Original instructions from the function...
uintptr_t target; // Address of the target function...

typedef void (*MyHookedFuncType)(void); // Your replacement function

typedef HRESULT (__stdcall *ISVGImageFactoryCreate1Proxy_t)(void**, char);

typedef void* (__thiscall *CreateSVGImage_t)(void*, void*);
typedef void (__thiscall *DestroyFunc)(void*);
typedef void* (__thiscall *AcquireEffectTree_t)(void* this_ptr, void** out_effect, void* transform_matrix, void* maybe_null);

void* factory = nullptr; // The image factory variable. Inited in fuzz_init...


LONG WINAPI GlobalExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    debug_print("Called the shit handler!!!\n");
    DWORD code = ExceptionInfo->ExceptionRecord->ExceptionCode;

    // Save the crashing input
    // save_crashing_input(global_buffer, code);
    save_crashing_input_new(code);
    // Optional: log register values, etc.
    // printf("RIP = 0x%p\n", ExceptionInfo->ContextRecord->Rip);

    // Let the exception propagate to WinAFL after logging
    return EXCEPTION_EXECUTE_HANDLER;  // or EXCEPTION_CONTINUE_SEARCH;
}


HMODULE hDll;
ISVGImageFactoryCreate1Proxy_t ISVGImageFactoryCreate1Proxy;

int fuzz_init() {
    SetUnhandledExceptionFilter(GlobalExceptionHandler); // Set the bullshit here...
    HMODULE hDll = LoadLibraryW(L"MSOSVG.dll");
    if (!hDll) {
        // std::cerr << "Failed to load MSOSVG.DLL" << std::endl;
        debug_print("Failed to load MSOSVG.DD!!!!\n");


        return 1;
    }

    ISVGImageFactoryCreate1Proxy = 
        (ISVGImageFactoryCreate1Proxy_t) GetProcAddress(hDll, "ISVGImageFactoryCreate1Proxy");

    if (!ISVGImageFactoryCreate1Proxy) {
        debug_print("Failed to get function address for ISVGImageFactoryCreate1Proxy\n");
        FreeLibrary(hDll);
        return 1;
    }

    ISVGImageFactoryCreate1Proxy(&factory, 0); // Need to pass in flags maybe???
    if (!factory) {
        debug_print("Error: Failed to get SVGImageFactory!\n");
        return 1;
    }

    return 0;
}

// Function to read a file into a buffer
bool ReadFileToBuffer(const std::string& filename, std::vector<uint8_t>& buffer) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        return false;
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (fileSize < 1) { // Ensure there is data
        return false;
    }

    buffer.resize(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    return true;
}


#include <objidl.h>  // IStream
#include <ole2.h>    // CreateStreamOnHGlobal

IStream* CreateMemoryStream(const std::vector<uint8_t>& data) {
    IStream* stream = nullptr;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, data.size());

    if (hMem) {
        void* pMem = GlobalLock(hMem);
        if (pMem) {
            memcpy(pMem, data.data(), data.size());
            GlobalUnlock(hMem);
            HRESULT hr = CreateStreamOnHGlobal(hMem, TRUE, &stream);
            if (FAILED(hr)) {
                // std::cerr << "Failed to create memory stream!" << std::endl;
                return nullptr;
            }
        }
    }
    return stream;
}

// Function to call CreateSVGImage
int fuzz_function(const std::vector<uint8_t>& svgData) {

    void* svgImage = nullptr;
    HRESULT res;

    // Get the function pointer for CreateSVGImage from the vtable
    void** vtable_ptr = *(void***)factory;
    CreateSVGImage_t create_svg_func = (CreateSVGImage_t)vtable_ptr[3]; // Usually function at index 5

    if (!create_svg_func) {
        return 1;
    }
    void* stream_ptr = *(void**)((uintptr_t)factory + 0x10);
    void** stream_location = (void**)((uintptr_t)factory + 0x10);
    //debug_print("Calling CreateMemoryStream\n");
    IStream* svgStream = CreateMemoryStream(svgData);  // svgData is your SVG file contents
    *stream_location = svgStream;  // Assign our new memory stream to the factory
    *(IStream**)((char*)factory + 0x10) = svgStream;

    create_svg_func(factory, &svgImage);

    if (!svgImage) {
        return 1;
    }

    void** svg_vtable = *(void***)svgImage;
    AcquireEffectTree_t acquire_func = (AcquireEffectTree_t)svg_vtable[3]; // adjust index if necessary // The get the stuff is at index 3 in the vtable...

    if (!acquire_func) {
        //debug_print("Error: Could not get AcquireEffectTree from vtable!\n\n");
        return 1;
    }

    // Setup dummy args
    void* out_effect_ptr = nullptr;

    double identity_matrix[6] = {
        1.0, 0.0,  // first row
        0.0, 1.0,  // second row
        0.0, 0.0   // translation
    };

    void* result = acquire_func(svgImage, &out_effect_ptr, identity_matrix, nullptr);
    //debug_print_ptr("AcquireEffectTree returned", result);
    //debug_print_ptr("Effect result", out_effect_ptr);
    DestroyFunc destroy_func = (DestroyFunc)vtable_ptr[0]; // Assuming first function in vtable is destroy
    if (destroy_func) {
        destroy_func(svgImage);
    }

    return 0;
}

void poopoothing(char* filename) {
    std::vector<uint8_t> buffer;
    if (!ReadFileToBuffer(filename, buffer)) {
        return;
    }
    memcpy(global_buffer, buffer.data(), buffer.size());
    global_buf_len = buffer.size();
    processing_done = false;
    std::thread watchdog(fuzz_timeout_watchdog, 1000*5);  // 5 second timeout

    // Your fuzzing logic
    fuzz_function(buffer);

    processing_done = true;
    watchdog.join();  // Clean up
    // fuzz_function(buffer);
    return;
}






void report_shit(DWORD code, char* filename) {

        
    // fprintf(stderr, "[!] Exception caught: 0x%08x\n", code);

    FILE* f = fopen("C:\\Users\\elsku\\hook_hit.txt", "a+");
    if (f) {
        fprintf(f, "[!] Exception caught: 0x%08x\n", code);
        fclose(f);
    }
    std::vector<uint8_t> buffer;
    if (!ReadFileToBuffer(filename, buffer)) {
        return;
    }
    // save_crashing_input(buffer, code);

    return;

}

// Main fuzzing function
__declspec(noinline) volatile void __fastcall actual_stuff(char* filename) {
    


    poopoothing(filename);

    /*
    volatile bool force_use = true;

    // __try {

    __try {
        // Call your actual fuzz logic here (e.g. render, parse, etc.)
        //result = common_fuzz_stuff(argv, buf, buf_size);  // or call FMain, etc.

        poopoothing(filename);
    } __except(EXCEPTION_EXECUTE_HANDLER) {

        DWORD code = GetExceptionCode();
        
        report_shit(code, filename);
        // fprintf(stderr, "poopoo\n");


        // Return 0 or 1 depending on whether you want to continue fuzzing
        // result = 1;  // Tell fuzzer to skip remaining mutations of this input
    }
    // fuzz_function(buffer);
    */
}

__declspec(noinline) void __fastcall loop(char* filename) {
    actual_stuff(filename);
}

// This is your custom function that will be jumped to
void MyHookedFunction() {
    
    FILE* f = fopen("C:\\Users\\elsku\\hook_hit.txt", "a+");
    if (f) {
        fprintf(f, "Hook triggered!\n");
        fclose(f);
    }

    DWORD oldProtect;
    debug_print("Patching the old shit back...\n");
    // Copy the original instructions back....
    VirtualProtect((LPVOID)target, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)target, originalBytes, sizeof(originalBytes));
    VirtualProtect((LPVOID)target, 5, oldProtect, &oldProtect);

    if (fuzz_init()) {
        debug_print("Initialization failed!!!!\n");
        return;
    }

    // Now jump to our actual fuzzing function maybe....

    while (1) {
        // debug_print("Calling loop...\n");
        loop("C:\\Users\\elsku\\final\\input.svg");
    }
}

uintptr_t GetModuleBase(const wchar_t* moduleName) {
    uintptr_t base = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
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

void LogBytes(void* address, size_t length) {
    BYTE* bytes = reinterpret_cast<BYTE*>(address);
    char buffer[256] = {0};

    FILE* f = fopen("C:\\Users\\elsku\\hook_hit.txt", "a+");
    if (!f) return;

    fprintf(f, "Bytes at %p: ", address);
    for (size_t i = 0; i < length; ++i) {
        fprintf(f, "%02X ", bytes[i]);
    }
    fprintf(f, "\n");

    fclose(f);
}

void PatchFunction() {
    // Wait for MSOSVG.dll to load
    HMODULE hMod;
    debug_print("Waiting for MSOSVG...\n\n");
    while ((hMod = GetModuleHandleW(L"MSOSVG.dll")) == NULL) {
        debug_print("Waiting for MSOSVG...\n\n");
        Sleep(100);
    }
    debug_print("Success!!!\n\n");
    uintptr_t base = (uintptr_t)hMod;
    // uintptr_t target = base + 0x2a30; // RVA of ISVGImageFactoryCreate1Proxy


    target = base + 0x50f0; // 0x2a30; // RVA of msosvg!Mso::SVG::SVGImage::AcquireEffectTree

    // Oof
    



    memcpy(originalBytes, (void*)target, 5);

    // Wait until dll is initialized...
    BYTE expected[3] = { 0x48, 0x8B, 0xC4 }; // The real starting bytes of AcquireEffectTree
    BYTE buffer[3] = { 0 };

    debug_print("Waiting for MSOSVG a bit more...\n\n");

    bool valid = false;
    while (!valid) {
        memcpy(buffer, (void*)target, 3);
        debug_print("Comparing...\n");
        if (memcmp(buffer, expected, 3) == 0) {
            valid = true;
        } else {
            LogBytes((void*)target, 3); // Log those three bytes...
            Sleep(100); // Wait a bit more...
        }
    }

    
    debug_print("Done!\n\n");

    Sleep(1000);
    // Write a 5-byte JMP to our function
    DWORD oldProtect;
    if (VirtualProtect((LPVOID)target, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        uintptr_t relAddr = (uintptr_t)MyHookedFunction - (target + 5); // Relative offset

        BYTE patch[5] = {
            0xE9,                        // JMP rel32
            (BYTE)(relAddr & 0xFF),
            (BYTE)((relAddr >> 8) & 0xFF),
            (BYTE)((relAddr >> 16) & 0xFF),
            (BYTE)((relAddr >> 24) & 0xFF)
        };
        debug_print("Here are the patch bytes:\n");
        LogBytes((void*)patch, 5); // Log those three bytes...
        memcpy((void*)target, patch, sizeof(patch));
        VirtualProtect((LPVOID)target, 5, oldProtect, &oldProtect);
        debug_print("Now patch was applied...\n");
        // MessageBoxW(NULL, L"Patch applied!", L"MSOSVG", MB_OK);
    } else {
        debug_print("Patch failed to apply...\n");
        // MessageBoxW(NULL, L"Failed to change protection!", L"MSOSVG", MB_OK);
    }
    debug_print("End of the patch function......\n");
    // Debug output to file
    std::ofstream log("C:\\Users\\elsku\\msosvg_patch.log", std::ios::app);
    log << "MSOSVG Base: 0x" << std::hex << base << std::endl;
    log << "Target address (to patch): 0x" << std::hex << target << std::endl;
    // log << "Hook function address: 0x" << std::hex << hookFunc << std::endl;
    // log << "Calculated relative JMP offset: 0x" << std::hex << relAddr << std::endl;
    log.close();

}

DWORD WINAPI PayloadThread(LPVOID) {
    debug_print("Payload thread...\n");
    PatchFunction();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    debug_print("Called DllMain...\n");
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    }
    return TRUE;
}
