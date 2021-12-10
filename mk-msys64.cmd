@echo off
cd /d "%~dp0"
call "C:\msys64\msys2_shell.cmd" -mingw64 -no-start -defterm -where "%CD%" -c "make -B"
pause
