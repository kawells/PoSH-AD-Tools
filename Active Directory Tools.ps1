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
.LINK
    github.com/kawells
#>
Import-Module activedirectory
$logDir = "C:\Users\" + $env:UserName + "\Documents\"
$logFile = $logDir + "adtlog.txt" #location and file name of log file
## Declare global vars
$global:adUser = $null #contains working username
$global:adComp = $null #contains working computer name
$global:adGroup = $null #contains group name that user will be added to in UserGroup function
## Define all functions
# Displays the timestamp for logging
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}
# Gets the username
function Show-UmHeader {
    cls
    Write-Host "================ User Menu:" $global:adUser.Name "================"
}
function Show-CmHeader {
    cls
    Write-Host "================ Computer Menu:" $global:adComp.Name "================"   
}
function Get-User {
    do { 
        cls
        Write-Host "================ User Menu ================"
        $userInput = Read-Host -Prompt " Enter the username"
        Write-Output "$(Get-TimeStamp) User entered username: $userInput" | Out-file $logFile -append
        $global:adUser = $userInput
        $userFound = Find-User
        if ($userFound -match "True") {
            $global:adUser = Get-ADUser $userInput -properties PasswordLastSet
            Write-Output "$(Get-TimeStamp) Account found in AD" | Out-file $logFile -append
            Show-UmHeader
            Write-Host " Active Directory Results`n"
            Write-Host " Username:     "$global:adUser.Name
            $userLocked = Show-UserLock
            $userPassSet = Show-UserPassSet
            $conf = Read-Host "`nIs this correct? (y or n)"
        }
        else {
                cls
                Write-Host "================ User Menu ================"
                Read-Host -Prompt "`n Account not found.`n`nPress Enter to try again"
                Write-Output "$(Get-TimeStamp) Account not found" | Out-file $logFile -append
        }
    } While ($conf -ne 'y')
    cls
    return $global:adUser
}
# Verify user in AD
function Find-User {
    $accountExist = [bool] (Get-ADUser -Filter "SamAccountName -eq '$global:adUser'")
    return $accountExist
}
# Verify comp in AD
function Find-Comp {
    $compExist = [bool] (Get-ADComputer -Filter { Name -eq $userInput })
    return $compExist
}
# Display and return user account lock status
function Show-UserLock {
    $userLocked = [bool] (Get-ADUser -Filter "SamAccountName -eq '$global:adUser'" -Properties * | Select-Object LockedOut)
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
# Gets and validates the computer name
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
                cls
                Write-Host "================ Computer Menu:" $global:adComp.Name "================"
                Write-Host " Active Directory Results`n"
                "`n Computer name: " + $userInput
                Write-Output "$(Get-TimeStamp) Computer found in AD" | Out-file $logFile -append 
                $conf = Read-Host "`nIs this correct? (y or n)"
            }
            else {
                Read-Host -Prompt "`n Computer not found.`n`nPress Enter to try again"
                Write-Output "$(Get-TimeStamp) Computer not found" | Out-file $logFile -append 
            }
            cls
    } While ($conf -ne 'y')

}
# Shows the bitlocker key of computer
function Show-Bl {
    $bitlocker = (Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $global:adComp.DistinguishedName -Properties 'msFVE-RecoveryPassword').'msFVE-RecoveryPassword'
    Write-Output "$(Get-TimeStamp) Bitlocker keys: $bitlocker" | Out-file $logFile -append
    Write-Host "================ Computer Menu:" $global:adComp.Name "================"
    " Bitlocker recovery key(s):`n "
    $bitlocker
    $conf = Read-Host "`nCopy Bitlocker key to clipboard? (y or n)"
    if ($conf -eq 'y') {
        Set-Clipboard -Value $bitlocker
        "`n Bitlocker key copied to clipboard.`n"
        Write-Output "$(Get-TimeStamp) Bitlocker key copied to clipboard" | Out-file $logFile -append  
    } else { "`n Bitlocker key not copied to clipboard.`n" }
    pause
}
# Shows the LAPS of computer
function Show-Laps {
    $laPass = Get-ADComputer $global:adComp -Properties * | select -ExpandProperty ms-Mcs-AdmPwd
    Write-Output "$(Get-TimeStamp) LAPS: $laPass" | Out-file $logFile -append
    Write-Host "================ Computer Menu:" $global:adComp.Name "================"
    "`n LAPS: $laPass"
    $conf = Read-Host "`n Copy LAPS to clipboard? (y or n)"
    if ($conf -eq 'y') {
        Get-ADComputer $global:adComp -Properties * | select -ExpandProperty ms-Mcs-AdmPwd | Set-Clipboard
        "`n Password copied to clipboard.`n"
        Write-Output "$(Get-TimeStamp) Password copied to clipboard" | Out-file $logFile -append    
    } else { "`n Password not copied to clipboard.`n" }
    pause
}
# Displays the computer menu
function Show-CompMenu {
    do {
        cls
        Write-Output "$(Get-TimeStamp) Entered computer menu" | Out-file $logFile -append
        Write-Host "================ Computer Menu:" $global:adComp.Name "================"
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
            Write-Error "Invalid selection." -Category InvalidData
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
        Write-Host " 4: Move to short term debarment"
        Write-Host " 5: Move to long term debarment"
        Write-Host " 6: Move to permanent debarment"
        Write-Host " M: Return to the main menu"
        Write-Host " Q: Quit"
        $selection = Read-Host "Please make a selection"
        cls
        switch ($selection){
            '1' { Get-User }
            '2' { UserReset }
            '3' { UserUnlock }
            '4' {
                $global:adGroup = "SG_PIV_Withdrawal_Short"
                UserGroup
            }
            '5' {
                $global:adGroup = "SG_PIV_Withdrawal_Long"
                UserGroup
            }
            '6' {
                $global:adGroup = "SG_PIV_Withdrawal_Permanent"
                UserGroup
            }
            'q' {
                Write-Output "$(Get-TimeStamp) Session ended" | Out-file $logFile -append
                exit
            }
        }
        if ($selection -notin (1,2,3,4,5,6,'m','q')) {
            Write-Error "Invalid selection." -Category InvalidData
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
    Set-ADAccountPassword -Identity $global:adUser -NewPassword $newpass -Reset
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
        Write-Error $global:adUser.Name + "'s password has not been reset. Please try again.`n" -Category InvalidOperation
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
# Prompts for group to add user to
function Get-UserGroup {
    
}
# Displays group memberships
function Show-UserGroup {
    
}
# Displays group memberships
function UserGroup {
    Write-Output "$(Get-TimeStamp) Entered add to group menu for $global:adGroup" | Out-file $logFile -append
    "Username: " + $global:adUser.Name

    # Display current groups
    "`n Current group membership:"   
    Get-ADPrincipalGroupMembership $global:adUser | select name
    
    # If user is already in the group, take no action
    if ( (Get-ADPrincipalGroupMembership $global:adUser | select name) -like "*$global:adGroup*" )
    {
        "`n " + $global:adUser + " is already a member of $global:adGroup.`n"
        Write-Output "$(Get-TimeStamp) Already in $global:adGroup" | Out-file $logFile -append
    }
    # If user is not in the group, add user to the group
    else { 
        "`n Adding " + $global:adUser.Name + " to $global:adGroup..."
        Add-ADGroupMember -Identity $global:adGroup -Members $global:adUser
        if ( (Get-ADPrincipalGroupMembership $global:adUser | select name) -like "*$global:adGroup*" )
        {
            "`n " + $global:adUser.Name + " has successfully been added to $global:adGroup.`n"
            Write-Output "$(Get-TimeStamp) Added to $global:adGroup" | Out-file $logFile -append
        }
        else
        {
            Write-Error $global:adUser.Name + " has not been added to $global:adGroup. Please try again.`n" -Category InvalidOperation
            Write-Output "$(Get-TimeStamp) ERROR: Unable to add to $global:adGroup" | Out-file $logFile -append
        }
    }    
    pause
}


# Display Main Menu
Write-Output "`n`n$(Get-TimeStamp) Session started" | Out-file $logFile -append  
do {
    cls
    Write-Host "================ Main Menu ================"
    Write-Host " 1: User management menu"
    Write-Host " 2: Computer management menu"
    Write-Host " Q: Quit"
    $selection = Read-Host "Please make a selection"
    cls
    switch ($selection){
        '1' {
            if ($global:adUser -eq $null) { Get-User }
            Show-UserMenu
        }
        '2' {
            if ($global:adComp -eq $null) { Get-Comp }
            Show-CompMenu
        }
    }
    if ($selection -notin (1,2,'q')) {
        Write-Error "Invalid selection." -Category InvalidData
        pause
    }
} until ($selection -eq 'q')
Write-Output "$(Get-TimeStamp) Session ended" | Out-file $logFile -append
