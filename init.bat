@ECHO OFF
SET currentpath=%~dp0
title CIS
CLS
Powershell -executionpolicy remotesigned -File %~dp0\CIS.ps1
:MENU
CLS
SET INPUT=
ECHO 
SET /P INPUT= Choose An Option :  
IF /I '%INPUT%'=='1' GOTO actmeth
IF /I '%INPUT%'=='q' GOTO Quit
:actmeth
IF EXIST %temp%\Microsoft-Activation-Scripts (
    RMDIR %temp%\Microsoft-Activation-Scripts
)
git clone https://github.com/massgravel/Microsoft-Activation-Scripts.git %temp%\Microsoft-Activation-Scripts
cd Microsoft-Activation-Scripts\MAS\Separate-Files-VersionOnline_KMS_Activation
cmd.exe /c Activate.cmd
:Quit
cls
