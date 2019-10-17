<#
.NAME
    Active Directory Tools
.SYNOPSIS
    Provide PoSH command line interface for everyday AD tasks
.NOTES
    Author: Kevin Wells

    Once elevated, script must be run as AD user with admin rights.
    The polling engine must have the features below installed.
        Remote Server Administration Tools
        Role Administration Tools
        AD DS and AD LDS Tools
        Active Directory module for Windows PowerShell

    1.0 | 09/13/2019 | Kevin Wells
        Initial Version
    1.1 | 09/16/2019 | Kevin Wells
        Added logging to text file
    1.2 | 09/18/2019 | Kevin Wells
        Reworked menus
        Renamed vars/functions for PoSH best practices
        Added computer menu
        Added Bitlocker key lookup
        Added LAPS lookup
        Changed header format
    1.3 | 09/19/2019 | Kevin Wells
        Reworked menus
        Changed naming convention of functions to match verb usage
        Branched existing functions into separate reusable functions
    1.4 | 09/24/2019 | Kevin Wells
        Changed displayed errors to warnings for better visual experience
        Added more error handling and ways to break if accidentally in user
            or computer search menu
        Added self-elevation to prevent users from trying to run as non-admin account
        Added domain controller menu and selection
    1.5 | 09/25/2019 | Kevin Wells
        Added window resize and window color change
    1.6 | 09/26/2019 | Kevin Wells
        Added even more input error handling
        Renamed some functions to use approved PS verbs
        Changed layout of headers
    1.7 | 10/02/2019 | Kevin Wells
        Added a dynamic menu function to generate menus based upon parameters passed to it
        Added RDP option under computer menu
        Added option to view/change description field of user
        Added script exit logging
    2.0 | 10/15/2020 | Kevin Wells
        Rewrote functions to provide parameters and remove global variables
        Rewrote the logic for the way some of the confirmations were written
        Rewrote logging to remove user activity and to include errors thrown

.LINK
    github.com/kawells
#>
cls
# Function to get the timestamp for logging
function Get-TimeStamp { return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date) }
# Specify log location
try {
    $rootDir = "C:\Users\" + $env:UserName + "\Documents\"
    $logFile = $rootDir + "adtlog.txt"
}
catch {
    Write-Host "Loading log.............[Fail]"
    Write-Output $error[0] | Out-file $logFile -append
    pause
    Start-Exit
}
Write-Host "Loading log.............[Good]"
# Self elevate the script
try {
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
        }
    }
}
catch {
    Write-Host "Elevating script........[Fail]"
    Write-Output "$(Get-TimeStamp) Unable to elevate the script" | Out-file $logFile -append
    Write-Output $error[0] | Out-file $logFile -append
    pause
    Start-Exit
}
Write-Host "Elevating script........[Good]"
# Resize and color the display
try {
    $pshost = get-host
    $pswindow = $pshost.ui.rawui
    $pswindow.windowtitle = "AD Tools"
    $pswindow.foregroundcolor = "White"
    $pswindow.backgroundcolor = "Black"
}
catch {
    Write-Host "Setting window color....[Fail]"
    Write-Output "$(Get-TimeStamp) Unable to elevate the script" | Out-file $logFile -append
    Write-Output $error[0] | Out-file $logFile -append
}
Write-Host "Setting window color....[Good]"
# Load AD module
try { Import-Module activedirectory }
catch {
    Write-Host "Loading AD module.......[Fail]"
    Write-Output "$(Get-TimeStamp) Unable to load AD module" | Out-file $logFile -append
    Write-Output $error[0] | Out-file $logFile -append
    pause
    Start-Exit
}
Write-Host "Loading AD module.......[Good]"
try { $adDc = Get-ADDomainController } #contains working DC
catch {
    Write-Host "Getting current DC......[Fail]"
    Write-Output "$(Get-TimeStamp) Unable to get current AD controller" | Out-file $logFile -append
    Write-Output $error[0] | Out-file $logFile -append
    pause
    Start-Exit
}
Write-Host "Getting current DC......[Good]"
#Pause at completion of load screen
pause
# Define what to do upon exit of menu
function Start-Exit { exit }
# Outputs text menu based upon -headerType parameter
function Show-Header {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        [ValidateSet('main','user','group','comp','domain')]
        [string[]]
        $headerType,
        [Parameter ()]
        [string[]]
        $domainName,
        [Parameter ()]
        [string[]]
        $userName,
        [Parameter ()]
        [string[]]
        $compName
    )
    $adtVersion = "v2.0" # Set version number of script
    $hRule = "======================================================" #horizontal rule used in menus
    # Comment the next line and uncomment the one below that to restore normal menu behavior, hiding errors
    # $header = 'Write-Host "$hRule`n            Active Directory Tools $adtVersion`n$hRule`n'
    $header = 'clear;Write-Host "$hRule`n            Active Directory Tools $adtVersion`n$hRule`n'
    switch($headerType){
        'main'{$header += 'Main Menu: $domainName`n$hRule"'}
        'user'{
            if ($userName -ne $null) { $header += 'User Menu: $userName on $domainName`n$hRule"' }
            else { $header += 'User Menu: $domainName`n$hRule"' }
        }
        'group'{$header += 'Group Menu: $userName on $domainName`n$hRule"'}
        'comp'{
            if ($compName -ne $null) { $header += 'Computer Menu: $compName on $domainName`n$hRule"' }
            else { $header += 'Computer Menu: $domainName`n$hRule"' }
        }
        'domain'{$header += 'DC Menu: $domainName`n$hRule"'}
        default{$header += '"'}
    }
    invoke-expression $header
}
# Get the computer name from user and verify in AD
function Get-Comp {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter ()]
        $adComp
    )
    while ($true) {
        Show-Header -headerType comp -compName $adComp.Name -domainName $adDc.Name
        $compInput = Read-Host -Prompt "Enter a new computer name"
        $compExist = [bool] (Get-ADComputer -Server $adDc -Filter { Name -eq $compInput })
        # Display results
        if ($compExist){
            $adComp = Get-ADComputer -Identity $compInput -Server $adDc -Properties *
            Show-Header -headerType comp -compName $adComp.Name -domainName $adDc.Name
            Write-Host " Active computer set to $compInput."
            pause 
            return $adComp
        }
        else {
            Write-Warning "Computer name $compInput was not found. Please try again."
            pause
        }
    }
}
# Show the bitlocker key of computer
function Show-Bl {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter (Mandatory)]
        $adComp
    )
    try {
        $bitlocker = Get-ADObject -SearchBase $adComp.DistinguishedName -Server $adDc -Filter 'objectclass -eq "msFVE-RecoveryInformation"' -Properties msFVE-RecoveryPassword |`
            Select msFVE-RecoveryPassword
        do {
            Show-Header -headerType comp -compName $adComp.Name -domainName $adDc.Name
            Write-Host " Bitlocker recovery key(s):`n "
            $bitlocker.'msFVE-RecoveryPassword'
            $selection = Read-Host "`nCopy Bitlocker key to clipboard (y or n)"
            switch ($selection){
                'y'{
                    Set-Clipboard -Value $bitlocker.'msFVE-RecoveryPassword'
                    Show-Header -headerType comp -compName $adComp.Name -domainName $adDc.Name
                    Write-Host " Bitlocker key(s) copied to clipboard."
                    break
                }
                'n'{
                    Show-Header -headerType comp -compName $adComp.Name -domainName $adDc.Name
                    Write-Host " Bitlocker key(s) not copied to clipboard."
                    break
                }
                default{ Write-Warning 'Invalid selection.';pause }
            }    
        } while ($selection -notin ('y','n'))
    } 
    catch { Write-Warning "Bitlocker recovery key(s) not found." }
    pause
    Show-CompMenu -adDc $adDc -adComp $adComp
}
# Show the LAPS of computer
function Show-Laps {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter (Mandatory)]
        $adComp
    )
    $laps = $adComp.'ms-Mcs-AdmPwd'
    try {
        Show-Header -headerType comp -compName $adComp.Name -domainName $adDc.Name
        Write-Host " LAPS: $laps"
        do {
            $selection = Read-Host "`nCopy LAPS to clipboard? (y or n)"
            switch ($selection) {
                'y'{
                    Show-Header -headerType comp -compName $adComp.Name -domainName $adDc.Name
                    Set-Clipboard -value $laps
                    Write-Host " Password copied to clipboard."
                    break
                }
                'n'{
                    Show-Header -headerType comp -compName $adComp.Name -domainName $adDc.Name
                    Write-Host " Password not copied to clipboard."
                    break
                }
                default{ Write-Warning 'Invalid selection.';pause }
            }
        } while ($selection -notin ('y','n'))
    }
    catch { Write-Warning "LAPS not found." }
    $laps = $null
    pause
    Show-CompMenu -adDc $adDc -adComp $adComp
}
# Start RDP session if computer is online
function Start-Rdp {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter (Mandatory)]
        $adComp
    )
    Show-Header -headerType comp -compName $adComp.Name -domainName $adDc.Name
    Write-Host "Starting RDP session to"$adComp.Name
    $compOnline = [bool](Test-Connection -Computername $adComp.Name -Count 1 -Quiet)
    if ($compOnline) { $currentComp = $adComp.Name; mstsc /v:$currentComp }
    else { Write-Warning "Unable to establish connection. Computer is offline or unavailable." }
    pause
}
# Get the username
function Get-User {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter ()]
        $adUser
    )
    While ($true) {
        Show-Header -headerType user -userName $adUser.Name -domainName $adDc.Name
        $userInput = Read-Host -Prompt "Enter a new username"
        $accountExist = [bool] (Get-ADUser -Server $adDc -Filter "SamAccountName -eq '$userInput'")
        if ($accountExist) {
            $adUser = Get-ADUser -Filter "SamAccountName -eq '$userInput'" -server $adDc -properties *
            Show-Header -headerType user -userName $adUser.Name -domainName $adDc.Name
            Write-Host "Active user set to $userInput."
            Write-Host " Username:" $adUser.SamAccountName
            Write-Host " Locked out:" $adUser.LockedOut
            Write-Host " Password set:" $adUser.PasswordLastSet
            pause 
            Return $adUser
            break
        }
        else { Write-Warning " Username $userInput was not found. Please try again.";pause }
    }
}
# Resets the user account password
function Set-UserPass {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter (Mandatory)]
        $adUser
    )
    while ($true) {
        while ($selection -ne 'y') {
            Show-Header -headerType user -userName $adUser.Name -domainName $adDc.Name
            Write-Host " Password set:" $adUser.PasswordLastSet
            $selection = Read-Host "Are you sure you want to set a new password? (y or n)"
            switch ($selection) {
                'y' { break }
                'n' { return; break }
                default { Write-Warning 'Invalid selection.';pause }
            }
        }
        $newpass = Read-Host -Prompt "Enter the new password" -AsSecureString
        Set-ADAccountPassword -Identity $adUser -Server $adDc -NewPassword $newpass -Reset
        $tempUserName = $adUser.SamAccountName
        $adUser = Get-ADUser -Filter "SamAccountName -eq '$tempUserName'" -server $adDc -properties *
        $pwdDate = $adUser.PasswordLastSet.ToShortDateString()
        $dateNow = Get-Date
        $dateNow = $dateNow.ToShortDateString() 
        # Validate password reset by comparing date password was set to today's date
        if ($pwdDate -eq $dateNow) {
            Show-Header -headerType user -userName $adUser.Name -domainName $adDc.Name
            Write-Host "The password has been set."
            Write-Host " Password set:" $adUser.PasswordLastSet
            pause
            return
        }
        else { Write-Warning "The password has not been set. Please try again."; pause }
        # Same thing but require change password at next logon
        #Set-ADAccountPassword $adUser -NewPassword $newpass -Reset -PassThru | Set-ADuser -ChangePasswordAtLogon $True
    }
}
# Unlocks the user account
function Set-UserUnlock {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter (Mandatory)]
        $adUser
    )
    $lockStatus = $adUser.LockedOut
    if ($lockStatus -match "True")
    {
        Show-Header -headerType user -userName $adUser.Name -domainName $adDc.Name
        Write-Host "Unlocking account ..."
        Unlock-ADAccount -Identity $adUser -Server $adDc
        $tempUserName = $adUser.SamAccountName
        $adUser = Get-ADUser -Filter "SamAccountName -eq '$tempUserName'" -server $adDc -properties *
        $lockStatus = $adUser.LockedOut
        if ($lockStatus -match "False")
        {
            Write-Host " Locked out:" $adUser.LockedOut
            pause
            return $adUser
        }
        else { Write-Warning "Unable to unlock account. Please try again."; pause; return $adUser }
    }
    else { Write-Warning "Account is already unlocked. No action taken.";pause;return $adUser }
}
# Resets the user account password
function Set-UserDesc {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter (Mandatory)]
        $adUser
    )
    while ($selection -ne 'y') {
        Show-Header -headerType user -userName $adUser.Name -domainName $adDc.Name
        Write-Host "Current user description:" $adUser.Description
        $selection = Read-Host "Are you sure you want to set a new description? (y or n)"
        switch ($selection) {
            'y' { break }
            'n' { return $adUser; break }
            default { Write-Warning 'Invalid selection.';pause }
        }
    }
    $newDesc = Read-Host -Prompt "Enter the new user description"
    try {
        Set-ADUser $adUser -Server $adDc -Description $newDesc
        $tempUserName = $adUser.SamAccountName
        $adUser = Get-ADUser -Filter "SamAccountName -eq '$tempUserName'" -server $adDc -properties *
        $newDesc = $adUser.Description
        Show-Header -headerType user -userName $adUser.Name -domainName $adDc.Name
        Write-Host "New user description:" $adUser.Description
        pause
        return $adUser
    }
    catch {
        Write-Output "$(Get-TimeStamp) Error setting user description to $newDesc" | Out-file $logFile -append
        Write-Output $error[0] | Out-file $logFile -append
        return $adUser
    }
}
# Get user group input and validates group name, then returns group name
function Get-UserGroup {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter (Mandatory)]
        $adUser
    )
    While ($true) {
        Show-Header -headerType user -userName $adUser.Name -domainName $adDc.Name
        $userInput = Read-Host -Prompt "Enter the group name"
        $groupExist = [bool] (Get-ADGroup -Identity $userInput -Server $adDc)
        if ($groupExist) {
            try {
                $adGroup = Get-ADGroup -Identity $userInput -Server $adDc
                return $adGroup.Name
                break
            }
            catch {
                Write-Output "$(Get-TimeStamp) Error adding user to $userInput" | Out-file $logFile -append
                Write-Output $error[0] | Out-file $logFile -append
                return $adGroup.Name
            }
        }
        else { Write-Warning "Group $userInput was not found. Please try again.";pause }
    }
}
# Adds user to group passed by parameter $adGroup
function Add-UserToGroup {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter (Mandatory)]
        $adUser,
        [Parameter (Mandatory)]
        $adGroup
    )
    # Get group object
    $adGroupObj = Get-ADGroup -Identity $adGroup -Server $adDc
    $adGroup = $adGroupObj
    Show-Header -headerType group -userName $adUser.Name -domainName $adDc.Name
    # If user is already in the group, take no action
    $groupFiltered = ADPrincipalGroupMembership $adUser -Server $adDc | select Name | Where-Object {$_.Name -eq $adGroup.Name} | Sort Name
    if ($adGroup.Name -eq $groupFiltered.Name){
        $warnString = $adUser.Name+" is already a member of "+$adGroup.Name+". No action taken."
        $warnString | Write-Warning
    }
    # If user is not in the group, add user to the group
    else { 
        Add-ADGroupMember -Identity $adGroup.Name -Members $adUser -Server $adDc
        $groupFiltered = ADPrincipalGroupMembership $adUser -Server $adDc | select Name | Where-Object {$_.Name -eq $adGroup.Name} | Sort Name
        if ($adGroup.Name -eq $groupFiltered.Name) {
            Write-Host $adUser.Name "has successfully been added to" $adGroup.Name"."
        }
        else {
            $warnString = $adUser.Name+" has not been added to "+$groupFiltered+". Please try again."
            $warnString | Write-Warning
        }
    }
    pause
}
# Get DC from user
function Get-Dc {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc
    )
    while ($true) {
        Show-Header -headerType domain -domainName $adDc.Name
        Write-Host "`n Your active DC is: $adDc`n"
        $newDc = Read-Host "Enter new DC ('C' to cancel)"
        # Provides a way for user to break prompt loop and returns existing DC object
        if ($newDc -eq 'c') {
            Write-Warning "Action cancelled. No changes made."
            pause
            return $adDc
        }
        else {
            try {
                $adDc = (Get-ADDomainController -Identity $newDC)
                Write-Host "`n Active DC set to: $adDc`n"
            }
            catch {
                Write-Host ""
                Write-Warning """$newDC"" was not found. No changes made."
                Write-Output "$(Get-TimeStamp) Error setting DC" | Out-file $logFile -append
                Write-Output $error[0] | Out-file $logFile -append
            }
            pause
            return $adDc
        }
    }
}
# Displays the group menu
function Show-GroupMenu {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter (Mandatory)]
        $adUser
    )
    try {
        while ($true) {
            Show-Header -headerType group -userName $adUser.Name -domainName $adDc.Name
            Write-Host " 1. Display current group memberships"
            Write-Host " 2. Add to short term debarment"
            Write-Host " 3. Add to long term debarment"
            Write-Host " 4. Add to permanent debarment"
            Write-Host " 5. Add to a different group"
            Write-Host " U. Return to the user menu"
            Write-Host " M. Return to the main menu"
            Write-Host " Q. Quit"
            $selection = Read-Host "Please make a selection"
            switch ($selection) {
                '1'{
                    Show-Header -headerType group -userName $adUser.Name -domainName $adDc.Name
                    Write-Host "Current group memberships:`n"
                    Get-ADPrincipalGroupMembership $adUser -Server $adDc |`
                        sort name |`
                        select -ExpandProperty name
                    pause
                }
                '2'{ Add-UserToGroup -adUser $adUser -adDc $adDc -adGroup "SG_PIV_Withdrawal_Short"; break }
                '3'{ Add-UserToGroup -adUser $adUser -adDc $adDc -adGroup "SG_PIV_Withdrawal_Long"; break }
                '4'{ Add-UserToGroup -adUser $adUser -adDc $adDc -adGroup "SG_PIV_Withdrawal_Permanent"; break }
                '5'{
                    $otherGroup = Get-UserGroup -adUser $adUser -adDc $adDc
                    Add-UserToGroup -adUser $adUser -adDc $adDc -adGroup $otherGroup
                    break
                }
                'u'{ Show-UserMenu -adUser $adUser -adDc $adDc; break}
                'm'{ Show-MainMenu -adUser $adUser -adDc $adDc; break }
                'q'{ Start-Exit }
                default { Write-Warning 'Invalid selection.';pause }
            }
        }
    }
    catch {
        Write-Output "$(Get-TimeStamp) Error from the group menu" | Out-file $logFile -append
        Write-Output $error[0] | Out-file $logFile -append
    }
}
# Displays Main Menu
function Show-MainMenu {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter ()]
        $adComp,
        [Parameter ()]
        $adUser
    )
    try {
        while ($true) {
            Show-Header -headerType main -domainName $adDc.Name
            Write-Host " 1. User management menu"
            Write-Host " 2. Computer management menu"
            Write-Host " 3. Change active DC"
            Write-Host " Q. Quit"
            $selection = Read-Host "Please make a selection"
            switch ($selection) {
                '1'{ Show-UserMenu -adUser $adUser -adDc $adDc; break }
                '2'{ Show-CompMenu -adComp $adComp -adDc $adDc; break }
                '3'{ $newDc = (Get-Dc -adDc $adDc); $adDc = $newDc; break}
                'q'{ Start-Exit }
                default { Write-Warning 'Invalid selection.';pause }
            }
        }
    }
    catch {
        Write-Output "$(Get-TimeStamp) Error from the main menu" | Out-file $logFile -append
        Write-Output $error[0] | Out-file $logFile -append
    }
}
# Displays User menu
function Show-UserMenu {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter ()]
        $adUser
    )
    try {
        while ($true) {
            if ($adUser -eq $null) { $adUser = Get-User -adDc $adDc }
            Show-Header -headerType user -userName $adUser.Name -domainName $adDc.Name
            Write-Host " 1. Enter a new username"
            Write-Host " 2. Reset the password"
            Write-Host " 3. Unlock the account"
            Write-Host " 4. Manage group membership"
            Write-Host " 5. Manage user description"
            Write-Host " M. Return to the main menu"
            Write-Host " Q. Quit"
            $selection = Read-Host "Please make a selection"
            switch ($selection) {
                '1'{ $adUser = Get-User -adUser $adUser -adDc $adDc; break }
                '2'{ Set-UserPass -adUser $adUser -adDc $adDc; break }
                '3'{ $adUser = Set-UserUnlock -adUser $adUser -adDc $adDc; break }
                '4'{ Show-GroupMenu -adUser $adUser -adDc $adDc; break }
                '5'{ $adUser = Set-UserDesc -adUser $adUser -adDc $adDc; break }
                'm'{ Show-MainMenu -adUser $adUser -adDc $adDc; break }
                'q'{ Start-Exit }
                default { Write-Warning 'Invalid selection.';pause }
            }
        }
    }
    catch {
        Write-Output "$(Get-TimeStamp) Error from the user menu" | Out-file $logFile -append
        Write-Output $error[0] | Out-file $logFile -append
    }
}
# Displays Computer menu
function Show-CompMenu {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $adDc,
        [Parameter ()]
        $adComp
    )
    try {
        while ($true) {
            if ($adComp -eq $null) { $adComp = (Get-Comp -adDc $adDc) }
            Show-Header -headerType comp -compName $adComp.Name -domainName $adDc.Name
            Write-Host " 1. Enter a new computer name"
            Write-Host " 2. Display the Bitlocker recovery key"
            Write-Host " 3. Display the local administrator password (LAPS)"
            Write-Host " 4. Open RDP session"
            Write-Host " M. Return to the main menu"
            Write-Host " Q. Quit"
            $selection = Read-Host "Please make a selection"
            switch ($selection) {
                '1'{ $adComp = (Get-Comp -adComp $adComp -adDc $adDc); break }
                '2'{ Show-Bl -adComp $adComp -adDc $adDc; break }
                '3'{ Show-Laps -adComp $adComp -adDc $adDc; break }
                '4'{ Start-Rdp -adComp $adComp -adDc $adDc; break }
                'm'{ Show-MainMenu -adComp $adComp -adDc $adDc; break }
                'q'{ Start-Exit }
                default { Write-Warning 'Invalid selection.';pause }
            }
        }
    }
    catch {
        Write-Output "$(Get-TimeStamp) Error from the computer menu" | Out-file $logFile -append
        Write-Output $error[0] | Out-file $logFile -append
    }
}
## Begin Menu Display
Show-MainMenu -adDc $adDc
