

set AFL_AUTORESUME=1
set AFL_CUSTOM_MUTATOR_ONLY=1
set AFL_IGNORE_SEED_PROBLEMS=1
set AFL_DISABLE_TRIM=1

set AFL_ONLY_CUSTOM=1
REM set AFL_DISABLE_TRIM=1

REM C:\Users\elsku\AppData\Local\Programs\Python\Python313\

REM set PYTHONPATH=C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.12_3.12.2544.0_x64__qbz5n2kfra8p0\
REM set PYTHONHOME=C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.12_3.12.2544.0_x64__qbz5n2kfra8p0\

REM C:\Users\elsku\AppData\Local\Programs\Python\Python313\

set PYTHONPATH=C:\Users\elsku\AppData\Local\Programs\Python\Python313\
set PYTHONHOME=C:\Users\elsku\AppData\Local\Programs\Python\Python313\

copy ..\svgmutatorstuff\svg_custom_mutator\*.py .
REM C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release

copy ..\svgmutatorstuff\svg_custom_mutator\*.py C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release\
copy C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release\main.py C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release\mutator.py
REM copy ..\svgmutatorstuff\svg_custom_mutator\mutator.dll .\python_mutator.dll
copy ..\svgmutatorstuff\build_thing\mutator.dll .\python_mutator.dll
REM C:\\Users\\elsku\\winafl\\winafl\\python_mutator.dll
REM Use dumb mode with -d to skip deterministic steps and only fuzz with the svg fuzzer...



C:\Users\elsku\newtools\newwinafl\winafl\build64\bin\Release\afl-fuzz.exe -d -T 100000 -l C:\Users\elsku\final\python_mutator.dll  -i corpus -o findings -y -t 60000 -f input.svg -- -instrument_module MSOSVG.DLL -instrument_module gfx.dll -instrument_module msxml6.dll -generate_unwind -stack_offset 1024 -iterations 100000 -target_module sample.dll -target_offset 0x1690 -nargs 1 -persist -- "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"




