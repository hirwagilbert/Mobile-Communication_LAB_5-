@echo off
REM ==========================================================
REM  Mobile Communications - Unit 5 Lab (Mini Projects 5.1-5.3)
REM  Runs every script and saves the console output to outputs\
REM  Requirements: Python 3.8+ (standard library only)
REM ==========================================================
cd /d "%~dp0"
set PYTHONUTF8=1
set PY=python
where python >nul 2>nul || set PY=py
if not exist outputs mkdir outputs

echo.
echo [1/4] Mini Project 5.1 Part A - challenge-response authentication
%PY% mp5_1_auth_and_ids\part_a_mutual_auth.py > outputs\mp5_1_part_a_output.txt
type outputs\mp5_1_part_a_output.txt

echo.
echo [2/4] Mini Project 5.1 Part B - signaling-plane anomaly detection
%PY% mp5_1_auth_and_ids\part_b_signaling_ids.py > outputs\mp5_1_part_b_output.txt
type outputs\mp5_1_part_b_output.txt

echo.
echo [3/4] Mini Project 5.2 - malware mitigation control matrix
%PY% mp5_2_malware_matrix\mitigation_matrix.py > outputs\mp5_2_output.txt
type outputs\mp5_2_output.txt

echo.
echo [4/4] Mini Project 5.3 - privacy-compliance checklist
%PY% mp5_3_privacy_checklist\privacy_checklist.py > outputs\mp5_3_output.txt
type outputs\mp5_3_output.txt

echo.
echo All done. Console outputs, CSV and JSON files are in the outputs folder.
pause
