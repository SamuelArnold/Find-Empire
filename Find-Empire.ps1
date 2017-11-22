######################
# Find Empire
# Created By Sam Arnold
#
#
# Based on the python Nork Nork project
# https://github.com/n00py/NorkNork
# and 
# Get-Injected Threads by Jaredc Atkinson
# https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2
#
######################


######################
# Check powershellversion
#[x] This section is done and works
#######################
echo "`n`n######################
# Check powershellversion
#######################"
if ($PSVersionTable.PSVersion.Major -ile 4) {
    echo "Powershell version is not 5. Upgrade because it is vulnerable"
    $PSVersionTable.PSVersion
    }
else {
     echo "Powershell is 5. Everything is good. \n\n"
}


######################
# Check Security Protocol
#[x] This section is done and works
######################
echo "`n`n================================================="
echo "Check Security Protocol"
echo "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
echo "Data: Security Packages"
echo "================================================="
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$Name = "Security Packages"
$value = "1"
$sp =  (Get-ItemProperty -Path $registryPath -Name $Name).$Name
echo $sp
$ssp="kerberos","msv1_0","schannel","wdigest","tspkg","pku2u", 0,$null,[DBNull]::Value,'',"",'""'
echo $ssp
if( $ssp -contains $sp){
    echo "Everything is chill"
}
else{ 
    echo "THINGS ARE MESSED UP! SECURITY PROTOCOL NEEDS TO BE CHANGED"
    }


######################
# Disable Machine acct_change
#[x] This section is done and works
######################
echo "`n`n================================================="
echo "Check Security Protocol"
echo "SYSTEM\CurrentControlSet\services\Netlogon\Parameters"
echo "Data: DisablePasswordChange"
echo "================================================="
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters"
$Name = "DisablePasswordChange"
$value = "1"
$sp =  (Get-ItemProperty -Path $registryPath -Name $Name).$Name
echo $sp
$ssp= 1 
echo $ssp
if( $ssp -contains $sp){
    echo "fuck shit is messed up"
}
else{ 
    echo "Everything is chill"
    }

######################
# Binary Exploitation
#[] This section is not done
######################





######################
# Look for scrips in Run
# {} Not done!
######################

##### DOESNT WORK YET
   <# 
echo "`n`n================================================="
echo "Check to see if powershell is in Run keys"
echo "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
echo "================================================="
 $registryPath1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
 Set-Variable -Name result1 -Value  (Get-ItemProperty -Path $registryPath1  )
echo $result1
 $registryPath2 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
Set-Variable -Name result2 -Value  (Get-ItemProperty -Path $registryPath2  )
echo $result2 
cmd.exe | REG QUERY "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" 
REG QUERY "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" 
REG QUERY HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 

$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$result = Get-Item -Path $path | select-object -ExpandProperty property | % {
   New-Object psobject -Property @{"Name"=$_; "Value" = (Get-ItemProperty -Path $path -Name $_).$_}     
} 

$result
foreach($line in $result) {
     # echo $line  
        if ($line -match  'powershell.exe') { 
        echo  "               "
        echo "==========================" 
        echo  $line  
        echo  "               "
        echo "==========================" 
         echo "Powershell found!!!!"
        }
 }



 $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RUN';

$result = Get-Item -Path $path | select-object -ExpandProperty property | % {
   New-Object psobject -Property @{"Name"=$_; "Value" = (Get-ItemProperty -Path $path -Name $_).$_}     
} 

$result
#>

#######################
# Check to see if Powershell is launched in scheduled tasks 
#[x] This section is done and works
#######################
echo "`n`n================================================="
echo "Check to see if powershell is in schtasks"
echo "================================================="
Set-Variable -Name result -Value (schtasks /query /fo csv /V)
#echo $result
foreach($line in $result) {
     # echo $line  
  
        if ($line -match  'powershell.exe') { 
        echo  "               "
        echo "==========================" 
        echo  $line  
        echo  "               "
        echo "==========================" 
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!" 
        echo "Powershell found in Schedule tasks!"
        echo "==========================" 
        }
}



########################
# Get WMI Object
########################

$wmiObjecttt=     ("Get-WMIObject -Namespace root\Subscription -Class __EventConsumer")
echo $wmiObjecttt

# Conversion
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($wmiObjecttt))
[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($wmiObjecttt))
[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("YmxhaGJsYWg="))


########################
# Check Threads
#[] not done
########################
#echo "Get Path To Injected threads module"
#$mipath = "C:\Users\Sied Shoj\source\repos\R3belCommand\R3belCommand\"
#import-Module $mipath +"Get-InjectedThread.ps1"


#import-Module "./Get-InjectedThread.ps1"
#echo "Below are process with injected threads"
#Get-InjectedThread

#echo "Stop thread? Thread ID?"
#$ThreadID = Read-Host
#Stop-Thread -ThreadId $ThreadID


######################
# Check for powershells running (that may not be powershell)
#[] not done
######################

echo "`nPossible Non Powershells Shells part 1"
echo "-------------------------------------"
 Get-Process | where {$_.modules.ModuleName -eq 'System.Management.ni.dll'}
 Get-Process | where {$_.modules.ModuleName -eq 'System.Management.dll'}
 Get-Process | where {$_.modules.ModuleName -eq 'System.Data.dll'}
 Get-Process | where {$_.modules.ModuleName -eq 'System.Management.Automation.ni.dll'}
 Get-Process | where {$_.modules.ModuleName -eq 'System.Management.Automation.dll'}
 Get-Process | where {$_.modules.ModuleName -eq 'System.Reflection.dll'}
 Get-Process | where {$_.modules.ModuleName -eq 'Microsoft.PowerShell.Commands.Diagnostics.ni.dll'}

echo "`n`nPossible Non Powershells Shells part 2 (may give false readings)"
echo "-------------------------------------"
Get-Process | where {$_.modules.ModuleName -eq 'shlwapi.dll'}



# Possible Non Powershells Shells
echo "`n`nPossible Non Powershells Shells part 3"
echo "-------------------------------------"
Get-Process | where {$_.modules.ModuleName -eq 'Wow64.dll'}
Get-Process | where {$_.modules.ModuleName -eq 'Wow64win.dll'}

echo "`n`n######################"
echo "Try to find .Net Compilers"
echo "-------------------------------------"
Get-Process | where {$_.modules.ModuleName -eq 'mscorjit.dll'}



######################
# Check for processes that inject things
#[x] done
######################
echo "`n`n######################"
echo "Try to find process that inject threads into others. Should be blank"
echo "######################"
Get-Process | where {$_.modules.ModuleName -eq 'ReflectivePick_x86.dll'}
Get-Process | where {$_.modules.ModuleName -eq 'ReflectivePick_x86.dll.enc'}
Get-Process | where {$_.modules.ModuleName -eq 'ReflectivePick_x64.dll'}
Get-Process | where {$_.modules.ModuleName -eq 'ReflectivePick_x64.dll.enc'}
Get-Process | where {$_.modules.ModuleName -eq 'ReflectiveDll.dll'}
Get-Process | where {$_.modules.ModuleName -eq 'reflective.dll'}
Get-Process | where {$_.modules.ModuleName -eq 'reflective_dll.x64.dll'}
Get-Process | where {$_.modules.ModuleName -eq 'reflective_dll.dll'}
Get-Process | where {$_.modules.ModuleName -eq 'reflective_dll.arm.dll'}
Get-Process | where {$_.modules.ModuleName -eq 'System.Reflection.dll'}