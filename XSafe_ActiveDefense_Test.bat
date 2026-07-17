@echo off
chcp 65001 >nul 2>&1
REM ============================================================
REM  X-Safe Active-Defense SELF-TEST sample (100 PERCENT HARMLESS)
REM  Purpose: verify "realtime guard -> bottom-right popup" works.
REM  This file contains a marker string that X-Safe flags suspicious.
REM
REM  HOW TO TEST THE POPUP:
REM    1) MOVE or COPY this file into your Downloads folder.
REM       X-Safe realtime guard scans it and pops a toast.
REM    2) OR in X-Safe main window click the "Self-Test Defense" button.
REM    3) OR right-click the tray icon -> "Active Defense Self-Test".
REM
REM  Double-clicking this file only prints text and waits. Fully safe.
REM ============================================================
echo X-SAFE-SELF-TEST-SUSPICIOUS-PROGRAM
echo [X-Safe self-test] This is a harmless test sample.
echo [X-Safe self-test] If a bottom-right X-Safe alert appears, active defense works.
echo.
echo Tip: copy this file into the Downloads folder to trigger the realtime popup.
echo.
echo Press any key to exit...
pause >nul
