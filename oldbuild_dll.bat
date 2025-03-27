
REM cl /EHsc /std:c++17 /MD fuzzer.cpp /link gdiplus.lib gdi32.lib user32.lib /MACHINE:X64 /out:fuzzer.exe

REM cl /EHsc /std:c++17 /Zi /FS /MT fuzzer.cpp /link gdiplus.lib gdi32.lib user32.lib ole32.lib /DEBUG /MACHINE:X64 /out:fuzzer.exe


REM cl /EHsc /std:c++17 /Zi /FS /MT dllinjection.cpp /link /SUBSYSTEM:WINDOWS user32.lib advapi32.lib /DEBUG /MACHINE:X64 /out:fuzzer.exe

cl /LD sample.cpp /MACHINE:X64 /Fe:sample.dll /link ole32.lib user32.lib

REM cl /EHsc /std:c++17 /Zi /FS /MT sample.cpp /link user32.lib advapi32.lib /DEBUG /MACHINE:X64 /out:fuzzer.exe
