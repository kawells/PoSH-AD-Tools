# Comments #####################################################################
# Application Name: Active Directory Tools
# Author: Kevin Wells
# Version: 1.2
# Created: September 13, 2019
#
# Notes:
# Must be run as administrator
# 
# Prerequisites:
# The polling engine must have the features below installed.
#  +- Remote Server Administration Tools
# |-+ Role Administration Tools
# |-+ AD DS and AD LDS Tools
# |-+ Active Directory module for Windows PowerShell.

Import-Module activedirectory

# Declare global vars
$global:adUser = $null #contains username
$global:adComp = $null #comtains working computer name
$global:adLocked = $null #status of account lock
$global:adGroup = $null #contains group name that user will be added to in user-group function
$logFile = "C:\adtlog.txt" #location and file name of log file

# Define all functions
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}

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

function Get-User {
    do { 
            cls
            # Username prompt
            $userInput = Read-Host -Prompt "Enter the username"
            $global:adUser = $userInput
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
                $global:adUser = Get-ADUser $userInput
                "`n Account found.`n Username: " + $userInput
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
                $conf = Read-Host "`nIs this the correct username? (y or n)"
            }
            else {
                Read-Host -Prompt "`n Account not found.`n`nPress Enter to try again"
                Write-Output "$(Get-TimeStamp) Account not found" | Out-file $logFile -append 
            }
            cls
    } While ($conf -ne 'y')
}

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
                $conf = Read-Host "`nIs this the correct computer name? (y or n)"
            }
            else {
                Read-Host -Prompt "`n Computer not found.`n`nPress Enter to try again"
                Write-Output "$(Get-TimeStamp) Computer not found" | Out-file $logFile -append 
            }
            cls
    } While ($conf -ne 'y')
}

function Get-Bl {
    "Computer name: " + $global:adComp.Name
    Write-Output "$(Get-TimeStamp) Entered Bitlocker menu" | Out-file $logFile -append

    # Get and display Bitlocker key(s)
    $bitlocker = (Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $global:adComp.DistinguishedName -Properties 'msFVE-RecoveryPassword').'msFVE-RecoveryPassword'
    "`n Bitlocker recovery key(s):"
    $bitlocker
    Write-Output "$(Get-TimeStamp) Bitlocker keys: $bitlocker" | Out-file $logFile -append
    
    # Copy to clipboard prompt
    $conf = Read-Host "`n Copy Bitlocker key to clipboard? (y or n)"
    if ($conf -eq 'y') {
        Set-Clipboard -Value $bitlocker
        "`n Bitlocker key copied to clipboard.`n"
        Write-Output "$(Get-TimeStamp) Bitlocker key copied to clipboard" | Out-file $logFile -append  
    } else { "`n Bitlocker key not copied to clipboard.`n" }
    pause
}

function Get-Laps {
    "Computer name: " + $global:adComp.Name
    Write-Output "$(Get-TimeStamp) Entered LAPS menu" | Out-file $logFile -append

    # Display LAPS
    $laPass = Get-ADComputer $global:adComp -Properties * | select -ExpandProperty ms-Mcs-AdmPwd
    "`n LAPS: $laPass"
    Write-Output "$(Get-TimeStamp) LAPS: $laPass" | Out-file $logFile -append

    # Copy to clipboard prompt
    $conf = Read-Host "`n Copy password to clipboard? (y or n)"
    if ($conf -eq 'y') {
        Get-ADComputer $global:adComp -Properties * | select -ExpandProperty ms-Mcs-AdmPwd | Set-Clipboard
        "`n Password copied to clipboard.`n"
        Write-Output "$(Get-TimeStamp) Password copied to clipboard" | Out-file $logFile -append    
    } else { "`n Password not copied to clipboard.`n" }
    pause
}

function CompMenu {
    do {
        cls
        Write-Output "$(Get-TimeStamp) Entered computer menu" | Out-file $logFile -append
        Write-Host "================ Computer Menu:" $global:adComp.Name "================"
        Write-Host " 1: Enter a new computer name"
        Write-Host " 2: Display the Bitlocker recovery key"
        Write-Host " 3: Display local administrator password (LAPS)"
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

function UserReset {
    "Username: " + $global:adUser.Name
    # Prompt for new password
    $newpass = Read-Host -Prompt " Enter the new password" -AsSecureString

    # Set new password
    Set-ADAccountPassword -Identity $global:adUser -NewPassword $newpass -Reset
    "`n Resetting password for " + $global:adUser + "..."
    # Same thing but require change password at next logon
    #Set-ADAccountPassword $global:adUser -NewPassword $newpass -Reset -PassThru | Set-ADuser -ChangePasswordAtLogon $True
    " " + $global:adUser + "'s password has been reset.`n"
    pause
}

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
