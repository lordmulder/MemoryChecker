@echo off

if "%PANDODC_PATH%"=="" (
	set "PANDODC_PATH=c:\Program Files (x86)\Pandoc"
)

echo on
"%PANDODC_PATH%\pandoc.exe" -o "%~dp0\README.html" --self-contained --css etc\style\gh-pandoc.min.css "%~dp0\README.md"
@echo off

echo.
pause
