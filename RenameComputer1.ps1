

Param()


# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64")
{
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe")
    {
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy bypass -File "$PSCommandPath"
        Exit $lastexitcode
    }
}

# Create a tag file just so Intune knows this was installed
if (-not (Test-Path "$($env:ProgramData)\Microsoft\RenameComputer"))
{
    Mkdir "$($env:ProgramData)\Microsoft\RenameComputer"
}
Set-Content -Path "$($env:ProgramData)\Microsoft\RenameComputer\RenameComputer.ps1.tag" -Value "Installed"

# Initialization
$dest = "$($env:ProgramData)\Microsoft\RenameComputer"
if (-not (Test-Path $dest))
{
    mkdir $dest
}
Start-Transcript "$dest\RenameComputer.log" -Append

DISM.exe /Online /add-capability /CapabilityName:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

$CurrentUser = $env:UserName
$currentuser
$details = Get-ADUser -identity $currentuser -properties *
$City= $details.City
$UserDN = $details.DistinguishedName
$UserDNEs = $UserDN.Split(",")
$UserDNTarget="OU=ClientsCOE10,"+$UserDNEs[2]+","+$UserDNEs[3]+","+$UserDNEs[4]+","+$UserDNEs[5]+,","+$UserDNEs[6]+","+$UserDNEs[7]
$UserDNTarget
$UserDN

$hostname = $env:computername
$hostname
$Detailsm = Get-ADComputer -Identity $hostname -Properties *
$OUId = $detailsm.DistinguishedName
$Ouid

$DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('PasswordHash'))
# UserName = <Account with admin access>
$UserName = 'Contoso\ACC'
$Password = $DecodedText | ConvertTo-SecureString -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($UserName,$Password)
$creds

If($UserDNTarget.Contains($city))
{
#Write-Host "Condition is True"
Move-ADObject -Identity $Ouid -TargetPath $UserDNTarget -Credential $creds
}

# Make sure we are already domain-joined

# Make sure we have connectivity
$dcInfo = [ADSI]"LDAP://Contoso.net"
if ($dcInfo.dnsHostName -eq $null)
{
    Write-Host "No connectivity to the domain."
    $goodToGo = $false
}

else
{
 $DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('PasswordHAsh'))

# UserName = <Account with admin access>
$UserName = 'Contoso\ACC'
$Password = $DecodedText | ConvertTo-SecureString -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential($UserName,$Password)

  $Serial = Get-WmiObject Win32_bios | Select-Object -ExpandProperty SerialNumber
    $NewName = "US$Serial"

if ($NewNaame.Length -ge 15) 

{
   $NewName = $NewName.substring(0, 15)
   Write-Host "Renaming computer to $($NewName)"
   Rename-Computer -NewName "$NewName" -DomainCredential $creds
 
}
Else
{
    Write-Host "Renaming computer to $($NewName)"
    Rename-Computer -NewName "$NewName" -DomainCredential $creds
}


    # Remove the scheduled task
    Disable-ScheduledTask -TaskName "RenameComputer" -ErrorAction Ignore
    Unregister-ScheduledTask -TaskName "RenameComputer" -Confirm:$false -ErrorAction Ignore
    Write-Host "Scheduled task unregistered."

    # Make sure we reboot if still in ESP/OOBE by reporting a 3010 return code
    if ($details.CsUserName -match "defaultUser")
    {
        Write-Host "Exiting during ESP/OOBE with return code 3010"
        Stop-Transcript
        Exit 3010
    }
    else {
        Write-Host "Initiating a restart in 10 minutes"
        & shutdown.exe /g /t 600 /f /c "Restarting the computer due to a computer name change.  Save your work."
        Stop-Transcript
        Exit 0
    }
}
else
{
    # Check to see if already scheduled
    $existingTask = Get-ScheduledTask -TaskName "RenameComputer" -ErrorAction SilentlyContinue
    if ($existingTask -ne $null)
    {
        Write-Host "Scheduled task already exists."
        Stop-Transcript
        Exit 0
    }

    # Copy myself to a safe place if not already there
    if (-not (Test-Path "$dest\RenameComputer.ps1"))
    {
        Copy-Item $PSCommandPath "$dest\RenameComputer.PS1"
    }

    # Create the scheduled task action
    $action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -ExecutionPolicy bypass -WindowStyle Hidden -File $dest\RenameComputer.ps1"

    # Create the scheduled task trigger
    $timespan = New-Timespan -minutes 5
    $triggers = @()
    $triggers += New-ScheduledTaskTrigger -Daily -At 9am
    $triggers += New-ScheduledTaskTrigger -AtLogOn -RandomDelay $timespan
    $triggers += New-ScheduledTaskTrigger -AtStartup -RandomDelay $timespan
    
    # Register the scheduled task
    Register-ScheduledTask -User SYSTEM -Action $action -Trigger $triggers -TaskName "RenameComputer" -Description "RenameComputer" -Force
    Write-Host "Scheduled task created."
}

Stop-Transcript
