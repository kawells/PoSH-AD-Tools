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
.LINK
    github.com/kawells
#>
Import-Module activedirectory
## Declare global vars
$global:adUser = $null #contains username
$global:adComp = $null #contains working computer name
$global:adLocked = $null #status of account lock
$global:adGroup = $null #contains group name that user will be added to in user-group function
$logFile = "C:\adtlog.txt" #location and file name of log file
## Define all functions
# Displays the timestamp for logging
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}
# Displays the main menu
function MainMenu {
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
                UserMenu
            }
            '2' {
                if ($global:adComp -eq $null) { Get-Comp }
                CompMenu
            }
        }
        if ($selection -notin (1,2,'q')) {
            Write-Error "Invalid selection." -Category InvalidData
            pause
        }
    } until ($selection -eq 'q')
    Write-Output "$(Get-TimeStamp) Session ended" | Out-file $logFile -append
}
# Gets and validates the username
function Get-User {
    do { 
            cls
            $userInput = Read-Host -Prompt "Enter the username"
            Write-Output "$(Get-TimeStamp) User entered username: $userInput" | Out-file $logFile -append
            # Verify account exists
            $accountExist = [bool] (Get-ADUser -Filter { SamAccountName -eq $userInput })
            # Check to see if account is locked
            $accountLocked = [bool] (Get-ADUser $userInput -Properties * | Select-Object LockedOut)
            $global:adLocked = $accountLocked
            # Display results
            cls
            "Active Directory search results for " + $userInput + ":"
            if ($accountExist -eq "true"){
                $global:adUser = Get-ADUser $userInput -properties PasswordLastSet
                Write-Host "`n Account found.`n`n Username:" $global:adUser.Name
                Write-Host " Password last set on" $global:adUser.PasswordLastSet
                Write-Output "$(Get-TimeStamp) Account found in AD" | Out-file $logFile -append 
                if ( (Get-ADUser $global:adUser -Properties * | Select-Object LockedOut) -match "True" ){
                    Write-Host " Status: Locked"
                    Write-Output "$(Get-TimeStamp) Account status: locked" | Out-file $logFile -append 
                }
                elseif ( (Get-ADUser $global:adUser -Properties * | Select-Object LockedOut) -match "False"){
                    Write-Host " Status: Unlocked"
                    Write-Output "$(Get-TimeStamp) Account status: unlocked" | Out-file $logFile -append
                }
                else {
                    Write-Host " Status: Unable to determine lock status"
                    Write-Output "$(Get-TimeStamp) Unable to determine account lock status" | Out-file $logFile -append 
                }
                $conf = Read-Host "`nIs this correct? (y or n)"
            }
            else {
                Read-Host -Prompt "`n Account not found.`n`nPress Enter to try again"
                Write-Output "$(Get-TimeStamp) Account not found" | Out-file $logFile -append 
            }
            cls
    } While ($conf -ne 'y')
}
# Gets and validates the computer name
function Get-Comp {
    do { 
            cls
            # Computer name prompt
            $userInput = Read-Host -Prompt "Enter the computer name"
            Write-Output "$(Get-TimeStamp) User entered computer name: $userInput" | Out-file $logFile -append

            # Verify computer exists
            $accountExist = [bool] (Get-ADComputer -Filter { Name -eq $userInput })
            
            # Display results
            cls
            "Active Directory search results for " + $userInput + ":"
            if ($accountExist -eq "true"){
                $global:adComp = Get-ADComputer $userInput
                "`n Computer found.`n Computer name: " + $global:adComp.Name
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
# Gets the bitlocker key of computer
function Get-Bl {
    $bitlocker = (Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $global:adComp.DistinguishedName -Properties 'msFVE-RecoveryPassword').'msFVE-RecoveryPassword'
    Write-Output "$(Get-TimeStamp) Entered Bitlocker menu" | Out-file $logFile -append    
    Write-Output "$(Get-TimeStamp) Bitlocker keys: $bitlocker" | Out-file $logFile -append
    "Computer name: " + $global:adComp.Name
    "`n Bitlocker recovery key(s):"
    $bitlocker
    $conf = Read-Host "`n Copy Bitlocker key to clipboard? (y or n)"
    if ($conf -eq 'y') {
        Set-Clipboard -Value $bitlocker
        "`n Bitlocker key copied to clipboard.`n"
        Write-Output "$(Get-TimeStamp) Bitlocker key copied to clipboard" | Out-file $logFile -append  
    } else { "`n Bitlocker key not copied to clipboard.`n" }
    pause
}
# Gets the LAPS of computer
function Get-Laps {
    $laPass = Get-ADComputer $global:adComp -Properties * | select -ExpandProperty ms-Mcs-AdmPwd
    Write-Output "$(Get-TimeStamp) Entered LAPS menu" | Out-file $logFile -append
    Write-Output "$(Get-TimeStamp) LAPS: $laPass" | Out-file $logFile -append
    "Computer name: " + $global:adComp.Name
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
function CompMenu {
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
                Get-Bl
            }
            '3' {
                Get-Laps
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
function UserMenu {  
    do {
        cls
        Write-Output "$(Get-TimeStamp) Entered user menu" | Out-file $logFile -append
        Write-Host "================ User Menu:" $global:adUser.Name "================"
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
    $pwdDate = $global:adUser.passwordlastset.ToShortDateString()
    Write-Host "Username:" $global:adUser.Name
    Write-Host "Password last set on" $pwdDate
    $newpass = Read-Host -Prompt " Enter the new password" -AsSecureString
    "`n Resetting password for " + $global:adUser.Name + "..."
    Set-ADAccountPassword -Identity $global:adUser -NewPassword $newpass -Reset
    $global:adUser = Get-ADUser -filter { SamAccountName -eq $global:adUser } -properties passwordlastset
    $pwdDate = $global:adUser.passwordlastset.ToShortDateString()
    $dateNow = Get-Date
    $dateNow = $dateNow.ToShortDateString()
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
    Write-Output "$(Get-TimeStamp) Entered unlock menu" | Out-file $logFile -append
    
    "Username: " + $global:adUser.Name

    if ( (Get-ADUser $global:adUser -Properties * | Select-Object LockedOut) -match "True" )
    {
        "`n Status: Locked`n Unlocking account for " + $global:adUser + "...`n"
        Unlock-ADAccount -Identity $global:adUser
        if ( (Get-ADUser $global:adUser -Properties * | Select-Object LockedOut) -match "False")
        {
            " Status: Account successfully unlocked.`n"
            Write-Output "$(Get-TimeStamp) Account unlocked" | Out-file $logFile -append 
        }
    }
    elseif ( (Get-ADUser $global:adUser -Properties * | Select-Object LockedOut) -match "False")
    {
        "`n Status: Account is already unlocked. No action taken.`n"
        Write-Output "$(Get-TimeStamp) Account already unlocked" | Out-file $logFile -append
    }
    else
    {
        Write-Error "Unable to determine lock status. Please try again.`n" -Category InvalidOperation
        Write-Output "$(Get-TimeStamp) ERROR: Unable to determine lock status" | Out-file $logFile -append
    }  
    pause
}
# Displays group memberships, adds user to group defined in $global:adGroup
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
# Call function to display main menu
MainMenu
