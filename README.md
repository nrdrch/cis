# CIS
#### Clean Up A Fresh Windows10 Install 
-----------------------------------------------------------------
#### You May Be Required To 
- Change Your Execution Policy with: 
```
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```
- Install [Git for Windows](https://gitforwindows.org/)
#### To Run & Install This Use:
```
git clone https://github.com/nrdrch/cis.git $Env:TEMP\cis | cmd.exe /c $Env:TEMP\cis\init.bat
