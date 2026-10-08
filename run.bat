@echo off
title RPG Web Server

cd /d "%~dp0"

echo ========================================
echo        RPG WEB SERVER
echo ========================================
echo.
echo Iniciando servidor Python...
echo.

python server.py

echo.
echo El servidor se ha detenido.
pause