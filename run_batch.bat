@echo off
cd C:\Users\narvi\OneDrive\Documents\jewelry-business-webapp

REM Check if the Flask app is already running
tasklist | findstr /I "python.exe"
IF %ERRORLEVEL% EQU 0 (
    echo Flask app is already running. Terminating it now...
    taskkill /F /IM python.exe
)

REM Start the Flask app using Poetry (tied to the cmd session)
poetry run python run.py

REM Open the web browser (this will only run after the Python app exits)
start http://127.0.0.1:8000/login
