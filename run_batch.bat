@echo off
cd C:\Users\narvi\OneDrive\Documents\jewelry-business-webapp

REM Check if the Flask app is already running
tasklist | findstr /I "python.exe"
IF %ERRORLEVEL% EQU 0 (
    echo Flask app is already running. Terminating it now...
    taskkill /F /IM python.exe
)

REM Start the Flask app using Poetry
start /B poetry run python run.py
timeout /t 2

REM Open the web browser
start http://127.0.0.1:8000/login
