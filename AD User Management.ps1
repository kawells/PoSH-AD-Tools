# Comments #####################################################################
# Application Name: NARA AD User MGMT Script
# Author: Kevin Wells
# Version: 1.0
# Created: September 13, 2019
#
# Notes:
# Must be run as a_account
# 
# Prerequisites:
# The polling engine must have the features below installed.
#  +- Remote Server Administration Tools
# |-+ Role Administration Tools
# |-+ AD DS and AD LDS Tools
# |-+ Active Directory module for Windows PowerShell.

Import-Module activedirectory

# Declare global vars
$global:aduser = $null
$global:adlocked = $null

#Define all functions
function get-timestamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}

function get-user {
    do { 
            cls
            # Username prompt
            $userinput = Read-Host -Prompt "Enter the username"
            $global:aduser = $userinput
            Write-Output "`n`n" | Out-file C:\scripts\adumlog.txt -append
            Write-Output "$(Get-TimeStamp) User entered username: $userinput" | Out-file C:\scripts\adumlog.txt -append

            # Verify account exists
            $accountExist = [bool] (Get-ADUser -Filter { SamAccountName -eq $userinput })
            
            # Check to see if account is locked
            $accountLocked = [bool] (Get-ADUser $userinput -Properties * | Select-Object LockedOut)
            $global:adlocked = $accountLocked
            
            # Display results
            cls
            "Active Directory search results for " + $userinput + ":"
            if ($accountExist -eq "true"){
                "`n Account found.`n Username: " + $userinput
                Write-Output "$(Get-TimeStamp) Account found in AD" | Out-file C:\scripts\adumlog.txt -append 
                if ( (Get-ADUser $global:aduser -Properties * | Select-Object LockedOut) -match "True" ){
                    Write-Host " Status: Locked"
                    Write-Output "$(Get-TimeStamp) Account status: locked" | Out-file C:\scripts\adumlog.txt -append 
                }
                elseif ( (Get-ADUser $global:aduser -Properties * | Select-Object LockedOut) -match "False"){
                    Write-Host " Status: Unlocked"
                    Write-Output "$(Get-TimeStamp) Account status: unlocked" | Out-file C:\scripts\adumlog.txt -append
                }
                else {
                    Write-Host " Status: Unable to determine lock status"
                    Write-Output "$(Get-TimeStamp) Unable to determine account lock status" | Out-file C:\scripts\adumlog.txt -append 
                }
                $confirmation = Read-Host "`nIs this the correct username? (y or n)"
            }
            else {
                Read-Host -Prompt "`n Account not found.`n`nPress Enter to try again"
                Write-Output "$(Get-TimeStamp) Account not found" | Out-file C:\scripts\adumlog.txt -append 
            }
            cls
    } While ($confirmation -ne 'y')
}

function user-menu {  
    do {
        cls
        Write-Output "$(Get-TimeStamp) Entered menu" | Out-file C:\scripts\adumlog.txt -append
        "Username: " + $global:aduser
        $menu = Read-Host "`n 1: Reset the password`n 2: Unlock the account`n 3: Move to short term debarment`n 4: Move to long term debarment`n 5: Move to permanent debarment`n 6: Enter new username`n 7: Exit `n`nPlease make a selection"
        cls
        if ($menu -eq '1') { user-reset }
        if ($menu -eq '2') { user-unlock }
        if ($menu -eq '3') { user-shortdebar }
        if ($menu -eq '4') { user-longdebar }
        if ($menu -eq '5') { user-permdebar }
        if ($menu -eq '6') { get-user }
        if (($menu -ne '1') -and ($menu -ne '2') -and ($menu -ne '3') -and ($menu -ne '4') -and ($menu -ne '5') -and ($menu -ne '6') -and ($menu -ne '7')) { "`nInvalid selection." }
    } While ($menu -ne '7')
}

function user-reset {
    "Username: " + $global:aduser
    # Prompt for new password
    $newpass = Read-Host -Prompt " Enter the new password" -AsSecureString

    # Set new password
    Set-ADAccountPassword -Identity $global:aduser -NewPassword $newpass -Reset
    "`n Resetting password for " + $global:aduser + "..."
    # Same thing but require change password at next logon
    #Set-ADAccountPassword $global:aduser -NewPassword $newpass -Reset -PassThru | Set-ADuser -ChangePasswordAtLogon $True

    " " + $global:aduser + "'s password has been reset."
    Read-Host -Prompt "`nPress Enter to continue"
}

function user-unlock {
    Write-Output "$(Get-TimeStamp) Entered unlock menu" | Out-file C:\scripts\adumlog.txt -append
    
    "Username: " + $global:aduser

    if ( (Get-ADUser $global:aduser -Properties * | Select-Object LockedOut) -match "True" )
    {
        "`n Status: Locked`n Unlocking account for " + $global:aduser + "...`n"
        Unlock-ADAccount -Identity $global:aduser
        if ( (Get-ADUser $global:aduser -Properties * | Select-Object LockedOut) -match "False")
        {
            " Status: Account successfully unlocked."
            Write-Output "$(Get-TimeStamp) Account unlocked" | Out-file C:\scripts\adumlog.txt -append 
        }
    }
    elseif ( (Get-ADUser $global:aduser -Properties * | Select-Object LockedOut) -match "False")
    {
        "`n Status: Account is already unlocked. No action taken."
        Write-Output "$(Get-TimeStamp) Account already unlocked" | Out-file C:\scripts\adumlog.txt -append
    }
    else
    {
        "`n Status: ERROR: Unable to determine lock status. Please try again."
        Write-Output "$(Get-TimeStamp) ERROR: Unable to determine lock status" | Out-file C:\scripts\adumlog.txt -append
    }  

    Read-Host -Prompt "`nPress Enter to continue"
}

function user-shortdebar {
    Write-Output "$(Get-TimeStamp) Entered short term debar menu" | Out-file C:\scripts\adumlog.txt -append
    "Username: " + $global:aduser

    # Display current groups
    "`n Current group membership:"   
    Get-ADPrincipalGroupMembership $global:aduser | select name
    
    # If user is already in the group, take no action
    if ( (Get-ADPrincipalGroupMembership $global:aduser | select name) -like '*SG_PIV_Withdrawal_Short*' )
    {
        "`n " + $global:aduser + " is already a member of short term debarment."
        Write-Output "$(Get-TimeStamp) Already in short term debar" | Out-file C:\scripts\adumlog.txt -append
    }
    
    # If user is not in the group, add user to the group
    else { 
        "`n Adding " + $global:aduser + " to SG_PIV_Withdrawal_Short group..."
        Add-ADGroupMember -Identity 'SG_PIV_Withdrawal_Short' -Members $global:aduser
        if ( (Get-ADPrincipalGroupMembership $global:aduser | select name) -like '*SG_PIV_Withdrawal_Short*' )
        {
            "`n " + $global:aduser + " has successfully been added to short term debarment."
            Write-Output "$(Get-TimeStamp) Added to short term debar" | Out-file C:\scripts\adumlog.txt -append
        }
        else
        {
            "`n ERROR: " + $global:aduser + " has not been added to short term debarment. Please try again."
            Write-Output "$(Get-TimeStamp) ERROR: Unable to add to short term debar" | Out-file C:\scripts\adumlog.txt -append
        }
    }    
    Read-Host -Prompt "`nPress Enter to continue"
}

function user-longdebar {
    Write-Output "$(Get-TimeStamp) Entered long term debar menu" | Out-file C:\scripts\adumlog.txt -append
    "Username: " + $global:aduser

    # Display current groups
    "`n Current group membership:"   
    Get-ADPrincipalGroupMembership $global:aduser | select name
    
    # If user is already in the group, take no action
    if ( (Get-ADPrincipalGroupMembership $global:aduser | select name) -like '*SG_PIV_Withdrawal_Long*' ) { "`n " + $global:aduser + " is already a member of long term debarment." }

    # If user is not in the group, add user to the group
    else { 
        "`n Adding " + $global:aduser + " to SG_PIV_Withdrawal_Long group..."
        Add-ADGroupMember -Identity 'SG_PIV_Withdrawal_Long' -Members $global:aduser
        if ( (Get-ADPrincipalGroupMembership $global:aduser | select name) -like '*SG_PIV_Withdrawal_Long*' ) { "`n " + $global:aduser + " has successfully been added to long term debarment." }
        else { "`n ERROR: " + $global:aduser + " has not been added to long term debarment. Please try again." }
    }   
    Read-Host -Prompt "`nPress Enter to continue"
}

function user-permdebar {
    Write-Output "$(Get-TimeStamp) Entered perm debar menu" | Out-file C:\scripts\adumlog.txt -append
    "Username: " + $global:aduser

    # Display current groups
    "`n Current group membership:"   
    Get-ADPrincipalGroupMembership $global:aduser | select name
    
    # If user is already in the group, take no action
    if ( (Get-ADPrincipalGroupMembership $global:aduser | select name) -like '*SG_PIV_Withdrawal_Permanent*' ) { "`n " + $global:aduser + " is already a member of permanent debarment." }

    # If user is not in the group, add user to the group
    else { 
        "`n Adding " + $global:aduser + " to SG_PIV_Withdrawal_Permanent group..."
        Add-ADGroupMember -Identity 'SG_PIV_Withdrawal_Permanent' -Members $global:aduser
        if ( (Get-ADPrincipalGroupMembership $global:aduser | select name) -like '*SG_PIV_Withdrawal_Permanent*' ) { "`n " + $global:aduser + " has successfully been added to permanent debarment." }
        else { "`n ERROR: " + $global:aduser + " has not been added to permanent term debarment. Please try again." }
    }
    Read-Host -Prompt "`nPress Enter to continue"
}


# Run get user function
get-user

# Run menu prompt function
user-menu

write-Output "$(Get-TimeStamp) Session ended" | Out-file C:\scripts\adumlog.txt -append