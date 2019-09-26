<#
.NAME
    Active Directory Tools
.SYNOPSIS
    Provide PoSH command line interface for everyday AD tasks
.NOTES
    Author: Kevin Wells

    PowerShell ISE must be run as administrator
    The polling engine must have the features below installed.
     +- Remote Server Administration Tools
    |-+ Role Administration Tools
    |-+ AD DS and AD LDS Tools
    |-+ Active Directory module for Windows PowerShell

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

.LINK
    github.com/kawells
#>
# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
# Load AD module or exit if failure
try { Import-Module activedirectory }
catch {
    Write-Warning "Unable to import active directory module."
    pause
    exit
}
#resize and color the display
$pshost = get-host
$pswindow = $pshost.ui.rawui
$newsize = $pswindow.buffersize
$newsize.height = 3000
$newsize.width = 150
$pswindow.buffersize = $newsize
$newsize = $pswindow.windowsize
$newsize.height = 40
$newsize.width = 100
$pswindow.windowsize = $newsize
$pswindow.windowtitle = "AD Tools"
$pswindow.foregroundcolor = "White"
$pswindow.backgroundcolor = "Black"
cls
# Set location and file name of log file
$logDir = "C:\Users\" + $env:UserName + "\Documents\"
$logFile = $logDir + "adtlog.txt" 
# Declare global vars
$global:adDc = Get-ADDomainController #contains working DC
$global:adUser = $null #contains working username
$global:adComp = $null #contains working computer name
$global:adGroup = $null #contains group name that user will be added to in UserGroup function
## Define all functions
# Display the timestamp for logging
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}
# Show header for user menu
function Show-UmHeader {
    cls
    if ($global:adUser -ne $null ) { Write-Host "================ User Menu:" $global:adUser.Name "on"$global:adDc.Name "================" }
    else { Write-Host "================ User Menu ================" }
}
# Show header for computer menu
function Show-CmHeader {
    cls
    if ($global:adComp -ne $null ) { Write-Host "================ Computer Menu:" $global:adComp.Name "on"$global:adDc.Name  "================" }
    else { Write-Host "================ Computer Menu ================" }
}
# Show header for group membership menu
function Show-GmHeader {
    cls
    Write-Host "================ User Group Menu:" $global:adUser.Name "on"$global:adDc.Name "================"   
}
# Show header for main menu
function Show-MmHeader {
    cls
    Write-Host "================ Main Menu:"$global:adDc.Name "================"
}
# Show header for DC menu
function Show-DmHeader {
    cls
    Write-Host "================ Domain Controller Menu:"$global:adDc.Name "================"
}
# Get DC from user
function Get-Dc {
    do {
        Show-DmHeader
        Write-Host " You are currently using" $global:adDc.Name
        $userInput = Read-Host -Prompt " Enter the domain controller to use"
        $global:adDc = $userInput
        $dcFound = Find-Dc
        if ($dcFound -match "True") {
            $global:adDc = Get-ADDomainController -Identity $userInput
            Write-Output "$(Get-TimeStamp) DC found in AD" | Out-file $logFile -append
            Show-DmHeader
            Write-Host " Active Directory Results`n"
            Write-Host " Domain controller: "$global:adDc.Name
            $conf = Read-Host "`nIs this correct? (y or n)"
            if ($conf -ne 'y') { $global:adDc = Get-ADDomainController }
        }
        else {
            $global:adDc = Get-ADDomainController
            Write-Output "$(Get-TimeStamp) DC not found" | Out-file $logFile -append
            Show-DmHeader
            Write-Host " Active Directory Results`n"
            Write-Host " Domain controller:" $userInput "was not found.`n"
            Write-Host " R: Try again"
            Write-Host " M: Return to the main menu"
            Write-Host " Q: Quit"
            $conf = Read-Host -Prompt "Please make a selection"
            switch ($conf){
                'm' {
                return $global:adDc
                }
                'q' { exit }
            }
        }
    } While ($conf -ne 'y')
    cls
    return $global:adDc       
}
# Verify DC in AD
function Find-Dc {
    $accountExist = [bool] (Get-ADDomainController -Identity $global:adDc)
    return $accountExist
}
# Get the username
function Get-User {
    do { 
        Show-UmHeader
        $userInput = Read-Host -Prompt " Enter the username"
        Write-Output "$(Get-TimeStamp) User entered username: $userInput" | Out-file $logFile -append
        $global:adUser = $userInput
        $userFound = Find-User
        if ($userFound -match "True") {
            $global:adUser = Get-ADUser $userInput -server $global:adDc -properties PasswordLastSet
            Write-Output "$(Get-TimeStamp) Account found in AD" | Out-file $logFile -append
            Show-UmHeader
            Write-Host " Active Directory Results`n"
            Write-Host " Username:    "$global:adUser.Name
            $userLocked = Show-UserLock
            $userPassSet = Show-UserPassSet
            $conf = Read-Host "`nIs this correct? (y or n)"

        }
        else {
            $global:adUser = $null
            Write-Output "$(Get-TimeStamp) Account not found" | Out-file $logFile -append
            Show-UmHeader
            Write-Host " Active Directory Results`n"
            Write-Host " Username:" $userInput "was not found.`n"
            Write-Host " R: Try again"
            Write-Host " M: Return to the main menu"
            Write-Host " Q: Quit"
            $conf = Read-Host -Prompt "Please make a selection"
            switch ($conf){
                'm' {
                return $global:adUser
                }
                'q' { exit }
            }
        }
    } While ($conf -ne 'y')
    cls
    return $global:adUser
}
# Verify user in AD
function Find-User {
    $accountExist = [bool] (Get-ADUser -Server $global:adDc -Filter "SamAccountName -eq '$global:adUser'")
    return $accountExist
}
# Verify comp in AD
function Find-Comp {
    $compExist = [bool] (Get-ADComputer -Server $global:adDc -Filter { Name -eq $userInput })
    return $compExist
}
# Display and return user account lock status
function Show-UserLock {
    $userLocked = [bool] (Get-ADUser -Server $global:adDc -Filter "SamAccountName -eq '$global:adUser'" -Properties * | Select-Object LockedOut)
    if ( $userLocked -match "True" ){
        Write-Host " Status:       Locked"
        Write-Output "$(Get-TimeStamp) Account status: locked" | Out-file $logFile -append 
    }
    elseif ( $userLocked -match "False" ){
        Write-Host " Status:       Unlocked"
        Write-Output "$(Get-TimeStamp) Account status: unlocked" | Out-file $logFile -append
    }
    else {
        Write-Host " Status:       Unable to determine lock status"
        Write-Output "$(Get-TimeStamp) Unable to determine account lock status" | Out-file $logFile -append 
    }
    return $userLocked
}
# Display and return date of user account password last reset
function Show-UserPassSet {
    $passSet = $global:adUser.PasswordLastSet.ToShortDateString()
    Write-Host " Password Set:" $passSet
    return $passSet
}
# Get the computer name from user
function Get-Comp {
    do { 
            cls
            Write-Host "================ Computer Menu ================"
            $userInput = Read-Host -Prompt "Enter the computer name"
            Write-Output "$(Get-TimeStamp) User entered computer name: $userInput" | Out-file $logFile -append
            $global:adComp = $userInput
            $compExist = Find-Comp
            # Display results
            cls
            if ($compExist -match "True"){
                $global:adComp = Get-ADComputer $userInput
                Show-CmHeader
                Write-Host " Active Directory Results`n"
                " Computer name: " + $global:adComp.Name 
                $conf = Read-Host "`nIs this correct? (y or n)"
                Write-Output "$(Get-TimeStamp) Computer found in AD" | Out-file $logFile -append
            }
            else {
            $global:adComp = $null
                Show-CmHeader
                Write-Output "$(Get-TimeStamp) Computer not found" | Out-file $logFile -append
                Write-Host " Active Directory Results`n"
                Write-Host " Computer:" $userInput "was not found.`n"
                Write-Host " R: Try again"
                Write-Host " M: Return to the main menu"
                Write-Host " Q: Quit"
                $conf = Read-Host -Prompt "Please make a selection"
                switch ($conf){
                    'm' {
                    return $global:adUser
                    }
                    'q' { exit }
                }
            }
            cls
    } While ($conf -ne 'y')

}
# Show the bitlocker key of computer
function Show-Bl {
    $bitlocker = (Get-ADObject -Server $global:adDc -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $global:adComp.DistinguishedName -Properties 'msFVE-RecoveryPassword').'msFVE-RecoveryPassword'
    Write-Output "$(Get-TimeStamp) Bitlocker keys: $bitlocker" | Out-file $logFile -append
    Show-CmHeader
    " Bitlocker recovery key(s):`n "
    $bitlocker
    $conf = Read-Host "`nCopy Bitlocker key to clipboard? (y or n)"
    if ($conf -eq 'y') {
        Set-Clipboard -Value $bitlocker
        "`n Bitlocker key copied to clipboard.`n"
        Write-Output "$(Get-TimeStamp) Bitlocker key copied to clipboard" | Out-file $logFile -append  
    } else { "`n Bitlocker key not copied to clipboard.`n" }
    $bitlocker = $null
    pause
}
# Show the LAPS of computer
function Show-Laps {
    $laPass = Get-ADComputer $global:adComp -Server $global:adDc -Properties * | select -ExpandProperty ms-Mcs-AdmPwd
    Write-Output "$(Get-TimeStamp) LAPS: $laPass" | Out-file $logFile -append
    Show-CmHeader
    "`n LAPS: $laPass"
    $conf = Read-Host "`n Copy LAPS to clipboard? (y or n)"
    if ($conf -eq 'y') {
        Get-ADComputer $global:adComp -Server $global:adDc -Properties * | select -ExpandProperty ms-Mcs-AdmPwd | Set-Clipboard
        "`n Password copied to clipboard.`n"
        Write-Output "$(Get-TimeStamp) Password copied to clipboard" | Out-file $logFile -append    
    } else { "`n Password not copied to clipboard.`n" }
    $laPass = $null
    pause
}
# Displays the computer menu
function Show-CompMenu {
    do {
        Show-CmHeader
        Write-Host " 1: Enter a new computer name"
        Write-Host " 2: Display the Bitlocker recovery key"
        Write-Host " 3: Display the local administrator password (LAPS)"
        Write-Host " M: Return to the main menu"
        Write-Host " Q: Quit"
        $selection = Read-Host "Please make a selection"
        cls
        switch ($selection){
            '1' {
                Get-Comp
            }
            '2' {
                Show-Bl
            }
            '3' {
                Show-Laps
            }
            'q' {
                Write-Output "$(Get-TimeStamp) Session ended" | Out-file $logFile -append
                exit
            }
        }
        if ($selection -notin (1,2,3,'m','q')) {
            Write-Warning "Invalid selection. Please try again."
            pause
        }
    } until ($selection -eq 'm')
}
# Displays the user menu
function Show-UserMenu {  
    do {
        Show-UmHeader
        Write-Host " 1: Enter a new username"
        Write-Host " 2: Reset the password"
        Write-Host " 3: Unlock the account"
        Write-Host " 4: Manage group membership"
        Write-Host " M: Return to the main menu"
        Write-Host " Q: Quit"
        $selection = Read-Host "Please make a selection"
        cls
        switch ($selection){
            '1' { Get-User }
            '2' { UserReset }
            '3' { UserUnlock }
            '4' { Show-GroupMenu }
            'q' {
                Write-Output "$(Get-TimeStamp) Session ended" | Out-file $logFile -append
                exit
            }
        }
        if ($selection -notin (1,2,3,4,'m','q')) {
            Write-Warning "Invalid selection."
            pause
        }
    } until ($selection -eq 'm')
}
# Resets the user account
function UserReset {
    Show-UmHeader
    $pwdDate = $global:adUser.passwordlastset.ToShortDateString()
    Write-Host " Username:" $global:adUser.Name
    Write-Host " Password last set on" $pwdDate
    $newpass = Read-Host -Prompt " Enter the new password" -AsSecureString
    Set-ADAccountPassword -Identity $global:adUser -Server $global:adDc -NewPassword $newpass -Reset
    $global:adUser = Get-ADUser -filter { SamAccountName -eq $global:adUser } -properties passwordlastset
    $pwdDate = $global:adUser.passwordlastset.ToShortDateString()
    $dateNow = Get-Date
    $dateNow = $dateNow.ToShortDateString()
    # Validate password reset by comparing date password was set to today's date
    if ($pwdDate -eq $dateNow) {
        " " + $global:adUser.Name + "'s password has been reset.`n"
        Write-Output "$(Get-TimeStamp) Password was reset" | Out-file $logFile -append
    }
    else {
        Write-Warning $global:adUser.Name + "'s password has not been reset. Please try again.`n" -Category InvalidOperation
        Write-Output "$(Get-TimeStamp) ERROR: Password was not reset" | Out-file $logFile -append
    }
    # Same thing but require change password at next logon
    #Set-ADAccountPassword $global:adUser -NewPassword $newpass -Reset -PassThru | Set-ADuser -ChangePasswordAtLogon $True
    pause
}
# Unlocks the user account
function UserUnlock {
    Show-UmHeader 
    $lockStatus = Show-UserLock
    if ($lockStatus -match "True")
    {
        "`n Unlocking account for " + $global:adUser + "...`n"
        Unlock-ADAccount -Identity $global:adUser
        $lockStatus = Show-UserLock
        if ($lockStatus -match "False")
        {
            " Account successfully unlocked.`n"
            Write-Output "$(Get-TimeStamp) Account unlocked" | Out-file $logFile -append 
        }
    }
    else { "No action taken.`n" }
    pause
}
# Get user group input
function Get-UserGroup {
    do { 
        Show-GmHeader
        $userInput = Read-Host -Prompt " Enter the group name to add the user"
        Write-Output "$(Get-TimeStamp) User entered group: $userInput" | Out-file $logFile -append
        $global:adGroup = $userInput
        $groupFound = Find-UserGroup
        if ($groupFound) {
            $global:adGroup = Get-ADGroup -Server $global:adDc -Identity $userInput
            Write-Output "$(Get-TimeStamp) Group found in AD" | Out-file $logFile -append
            Show-GmHeader
            Write-Host " Active Directory Results`n"
            Write-Host " Group name: "$global:adGroup.Name
            $conf = Read-Host "`nIs this correct? (y or n)"
        }
        else {
            Show-GmHeader
            Read-Host -Prompt "`n Group not found.`n`nPress Enter to try again"
            Write-Output "$(Get-TimeStamp) Group not found" | Out-file $logFile -append
        }
    } While ($conf -ne 'y')
    cls
}
# Add user to $global:adGroup
function Add-UserToGroup {
    Show-GMHeader
    # If user is already in the group, take no action
    $groupFiltered = ADPrincipalGroupMembership $global:adUser -Server $global:adDc | select Name | Where-Object {$_.Name -eq $global:adGroup.Name} | Sort Name
    if ($global:adGroup.Name -eq $groupFiltered.Name){
        " " + $global:adUser.Name + " is already a member of " + $global:adGroup.Name + ". No action taken.`n"
        Write-Output "$(Get-TimeStamp) User is already in group" | Out-file $logFile -append
    }
    # If user is not in the group, add user to the group
    else { 
        Show-GMHeader
        " Adding " + $global:adUser.Name + " to " + $global:adGroup.Name + "..."
        Add-ADGroupMember -Identity $global:adGroup.Name -Members $global:adUser -Server $global:adDc
        $groupFiltered = ADPrincipalGroupMembership $global:adUser -Server $global:adDc | select Name | Where-Object {$_.Name -eq $global:adGroup.Name} | Sort Name
        if ($global:adGroup.Name -eq $groupFiltered.Name)
        {
            " " + $global:adUser.Name + " has successfully been added to " + $global:adGroup.Name + ".`n"
            Write-Output "$(Get-TimeStamp) Added to $groupFiltered" | Out-file $logFile -append
        }
        else
        {
            Write-Warning $global:adUser.Name" has not been added to $groupFiltered. Please try again.`n" -Category InvalidOperation
            Write-Output "$(Get-TimeStamp) ERROR: Unable to add to $groupFiltered" | Out-file $logFile -append
        }
    }
    pause
}
# Show user current group memberships
function Show-UserGroups {
    Show-GMHeader
    Write-Host " Current group memberships"
    Get-ADPrincipalGroupMembership $global:adUser -Server $global:adDc | select name | sort name
}
# Verify user group exists
function Find-UserGroup {
    $groupExist = Get-ADGroup -Identity $global:adGroup -Server $global:adDc
    return $groupExist
}
# Show group menu
function Show-GroupMenu {
    do {
        Show-GMHeader
        Write-Host " 1: Display user's current group memberships"
        Write-Host " 2: Add to short term debarment group"
        Write-Host " 3: Add to long term debarment group"
        Write-Host " 4: Add to permanent debarment group"
        Write-Host " 5: Add to a different group"
        Write-Host " M: Return to the user menu"
        Write-Host " Q: Quit"
        $selection = Read-Host "Please make a selection"
        cls
        switch ($selection){
            '1' {
                Show-UserGroups
                pause
            }
            '2' {
                $global:adGroup = Get-ADGroup -Identity "SG_PIV_Withdrawal_Short"
                Add-UserToGroup
            }
            '3' {
                $global:adGroup = Get-ADGroup -Identity "SG_PIV_Withdrawal_Long"
                Add-UserToGroup
            }
            '4' {
                $global:adGroup = Get-ADGroup -Identity "SG_PIV_Withdrawal_Permanent"
                Add-UserToGroup
            }
            '5' {
                Get-UserGroup
                Add-UserToGroup
            }
            'q' {
                Write-Output "$(Get-TimeStamp) Session ended" | Out-file $logFile -append
                exit
            }
        }
        if ($selection -notin (1,2,3,4,5,'m','q')) {
            Write-Warning "Invalid selection."
            pause
        }
    } until ($selection -eq 'm')
}
# Show Main Menu
Write-Output "`n`n$(Get-TimeStamp) Session started" | Out-file $logFile -append  
do {
    Show-MmHeader
    Write-Host " 1: User management menu"
    Write-Host " 2: Computer management menu"
    Write-Host " 3. Change active DC"
    Write-Host " Q: Quit"
    $selection = Read-Host "Please make a selection"
    cls
    switch ($selection){
        '1' {
            if ($global:adUser -eq $null) { Get-User }
            if ($global:adUser -ne $null) { Show-UserMenu }
        }
        '2' {
            if ($global:adComp -eq $null) { Get-Comp }
            if ($global:adComp -ne $null) { Show-CompMenu }
        }
        '3' { Get-Dc }

    }
    if ($selection -notin (1,2,3,'q')) {
        Write-Warning "Invalid selection."
        pause
    }
} until ($selection -eq 'q')
Write-Output "$(Get-TimeStamp) Session ended" | Out-file $logFile -append
