@echo off
echo ===============================================
echo   Starting LeakCheck System with Semantic Detection
echo ===============================================
echo.

echo Starting Llama Server...
start "Llama Server" cmd /k "cd llama && start_llama_server.bat"

timeout /t 3 /nobreak >nul

echo.
echo Starting Python Semantic Detector...
start "Semantic Detector" cmd /k "cd semantic && python semantic_detector.py"

timeout /t 5 /nobreak >nul

echo.
echo Starting Node.js Server...
start "Node Server" cmd /k "cd prototype && node server.js"

echo.
echo ===============================================
echo   All services started!
echo ===============================================
echo.
echo Services running:
echo  - Llama Server: http://localhost:8080
echo  - Semantic Detector: http://localhost:5001
echo  - Node Server: http://localhost:3000
echo.
echo Press any key to close this window...
pause >nul
