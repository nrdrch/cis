@ECHO OFF
title CIS
CLS
:: Powershell -executionpolicy remotesigned -File %temp%\cis\CIS.ps1
:MENU
CLS
SET INPUT=
ECHO To Activate Windows : 1
ECHO To Quit             : Q
SET /P INPUT= Choose An Option :  
IF /I '%INPUT%'=='1' GOTO actmeth
IF /I '%INPUT%'=='q' GOTO Quit
:actmeth
IF EXIST  C:\Users\%username%\Documents\Microsoft-Activation-Scripts (
    RMDIR  C:\Users\%username%\Documents\Microsoft-Activation-Scripts
)
git clone https://github.com/massgravel/Microsoft-Activation-Scripts.git  C:\Users\%username%\Documents\Microsoft-Activation-Scripts
cd C:\Users\%username%\Documents\Microsoft-Activation-Scripts\MAS\Separate-Files-Version\Online_KMS_Activation
cmd.exe /c Activate.cmd
:Quit
cls
