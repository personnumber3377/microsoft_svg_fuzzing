

set AFL_AUTORESUME=1
set AFL_CUSTOM_MUTATOR_ONLY=1
set AFL_IGNORE_SEED_PROBLEMS=1
set AFL_DISABLE_TRIM=1

REM set PYTHONPATH="C:\Users\elsku\final\"

set PYTHONPATH="C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.12_3.12.2544.0_x64__qbz5n2kfra8p0\"

REM set PYTHONHOME="C:\Users\elsku\AppData\Local\Programs\Python\Python313\"



REM set PYTHONHOME="C:\Users\elsku\final\"



REM copy ..\svgmutatorstuff\build_thing\mutator.dll .\python_mutator.dll


set PYTHONHOME="C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.12_3.12.2544.0_x64__qbz5n2kfra8p0\"

REM copy C:\Users\elsku\winafl\winafl\build\bin\Release\afl-fuzz.exe C:\Users\elsku\winafl\testing\afl-fuzz.exe

REM copy C:\Users\elsku\python_mutator.dll .

REM /mnt/c/Users/elsku/newtools/aflfuzz/winafl/build64/bin/Release/
REM -generate_unwind
REM
REM copy C:\Users\elsku\python_mutator.dll C:\Users\elsku\winafl\testing\
REM copy C:\Users\elsku\python_mutator.dll C:\Users\elsku\winafl\winafl\python_mutator.dll
REM C:\Users\elsku\newtools\aflfuzz\winafl\build64\bin\Release\afl-fuzz.exe -T 100000 -d -i corpus -o findings -y -t 60000 -f input.svg -- -instrument_module MSOSVG.DLL -generate_unwind -stack_offset 1024 -trace_basic_blocks -iterations 100000 -target_module fuzzer.exe -target_offset 0x2100 -nargs 1 -persist -- ".\fuzzer.exe" "@@" 

REM C:\Users\elsku\newtools\aflfuzz\winafl\build64\bin\Release\afl-fuzz.exe -T 100000 -d -i corpus -o findings -y -t 60000 -f input.svg -- -instrument_module MSOSVG.DLL -instrument_module gfx.dll -generate_unwind -stack_offset 1024 -trace_basic_blocks -iterations 100000 -target_module sample.dll -target_offset 0x16a0 -nargs 1 -persist -- "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" 
REM copy C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release\*.dll .

copy ..\python_mutator.dll . 

copy python312.dll C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release\
copy python_mutator.dll C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release\


copy ..\svgmutatorstuff\svg_custom_mutator\*.py .
REM C:\\Users\\elsku\\winafl\\winafl\\python_mutator.dll

C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release\afl-fuzz.exe -T 100000 -l C:\Users\elsku\winafl\winafl\python_mutator.dll  -i corpus -o findings -y -t 60000 -f input.svg -- -instrument_module MSOSVG.DLL -instrument_module gfx.dll -instrument_module msxml6.dll -generate_unwind -stack_offset 1024 -iterations 100000 -target_module sample.dll -target_offset 0x1690 -nargs 1 -persist -- "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"


REM 0x18d0 was the offset
REM 0x1900 was the old shit



