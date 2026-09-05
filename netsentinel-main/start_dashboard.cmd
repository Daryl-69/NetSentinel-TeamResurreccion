@echo off
echo ============================================
echo Starting NetSentinel Dashboard (Correct Port)
echo ============================================
echo.

cd "Share Figma conversation"

echo [1/2] Setting environment...
set PORT=5173
set VITE_WS_URL=ws://localhost:8000/ws

echo [2/2] Starting Vite dev server on port 5173...
echo.
echo Once started, open: http://localhost:5173
echo.

npm run dev -- --port 5173 --host 0.0.0.0

pause
