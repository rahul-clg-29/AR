@echo off
title AIRA - Autonomous Incident Reasoning Agent
echo ====================================================================
echo   AIRA: Autonomous Incident Reasoning Agent - SOC Analyst Workbench
echo ====================================================================
echo Starting server on http://127.0.0.1:8000 ...
cd /d "%~dp0"
python run_ui.py
pause
