

set AFL_AUTORESUME=1
set AFL_CUSTOM_MUTATOR_ONLY=1
set AFL_IGNORE_SEED_PROBLEMS=1
set AFL_DISABLE_TRIM=1

copy C:\Users\elsku\winafl\winafl\build\bin\Release\afl-fuzz.exe C:\Users\elsku\winafl\testing\afl-fuzz.exe

copy C:\Users\elsku\python_mutator.dll .

REM /mnt/c/Users/elsku/newtools/aflfuzz/winafl/build64/bin/Release/
REM -generate_unwind
REM
copy C:\Users\elsku\python_mutator.dll C:\Users\elsku\winafl\testing\
copy C:\Users\elsku\python_mutator.dll C:\Users\elsku\winafl\winafl\python_mutator.dll
REM C:\Users\elsku\newtools\aflfuzz\winafl\build64\bin\Release\afl-fuzz.exe -T 100000 -d -i corpus -o findings -y -t 60000 -f input.svg -- -instrument_module MSOSVG.DLL -generate_unwind -stack_offset 1024 -trace_basic_blocks -iterations 100000 -target_module fuzzer.exe -target_offset 0x2100 -nargs 1 -persist -- ".\fuzzer.exe" "@@" 

REM C:\Users\elsku\newtools\aflfuzz\winafl\build64\bin\Release\afl-fuzz.exe -T 100000 -d -i corpus -o findings -y -t 60000 -f input.svg -- -instrument_module MSOSVG.DLL -instrument_module gfx.dll -generate_unwind -stack_offset 1024 -trace_basic_blocks -iterations 100000 -target_module sample.dll -target_offset 0x16a0 -nargs 1 -persist -- "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" 
copy C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release\*.dll .

C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release\afl-fuzz.exe -T 100000  -i corpus -o findings -y -t 60000 -f input.svg -- -instrument_module sample.dll -generate_unwind -stack_offset 1024 -trace_basic_blocks -iterations 100000 -target_module sample.dll -target_offset 0x16a0 -nargs 1 -persist -- "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"

REM 0x18d0 was the offset
REM 0x1900 was the old shit
