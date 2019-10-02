# Get the username
function Get-User {
    do { 
        Show-UmHeader
        $userInput = Read-Host -Prompt "Enter the username"
        Write-Output "$(Get-TimeStamp) User entered username: $userInput" | Out-file $logFile -append
        $global:adUser = $userInput
        $userFound = Find-User
        if ($userFound -match "True") {
            $global:adUser = Get-ADUser $userInput -server $global:adDc -properties PasswordLastSet
            Write-Output "$(Get-TimeStamp) Account found in AD" | Out-file $logFile -append
            do {
                Show-UmHeader
                Write-Host " Active Directory Results`n"
                Write-Host " Username:"$global:adUser.SamAccountName
                $userLocked = Show-UserLock
                $userPassSet = Show-UserPassSet
                $conf = Read-Host "`nIs this correct? (y or n)"
                switch ($conf){
                    'y' { Show-UserMenu; break }
                    'n' { $global:adUser = $null; break }
                    default { Show-MenuDef }
                }
            } while ($conf -ne 'n')
        }
        else {
            $global:adUser = $null
            Write-Output "$(Get-TimeStamp) Account not found" | Out-file $logFile -append
            do {
                Show-UmHeader
                Write-Host " Active Directory Results`n"
                Write-Host " Username:" $userInput "was not found.`n"
                Write-Host " R: Try again"
                Write-Host " M: Return to the main menu"
                Write-Host " Q: Quit"
                $conf = Read-Host -Prompt "Please make a selection"
                switch ($conf){
                    'r' { break }
                    'm' { Show-MainMenu;break }
                    'q' { exit }
                    default { Show-MenuDef }
                }
            } while ($conf -ne 'r')
        }
    } While ($conf -ne 'y')
    return $global:adUser
}
# Verify user in AD
function Find-User {
    $accountExist = [bool] (Get-ADUser -Server $global:adDc -Filter "SamAccountName -eq '$global:adUser'")
    return $accountExist
}
# Display and return user account lock status
function Show-UserLock {
    $userLocked = [bool] (Get-ADUser -Server $global:adDc -Filter "SamAccountName -eq '$global:adUser'" -Properties * | Select-Object LockedOut)
    switch ($userLocked){
        'True'{
            Write-Host " Status: Locked"
            Write-Output "$(Get-TimeStamp) Account status: locked" | Out-file $logFile -append 
        }
        'False'{
            Write-Host " Status: Unlocked"
            Write-Output "$(Get-TimeStamp) Account status: unlocked" | Out-file $logFile -append
        }
        default {
            Write-Host " Status: Unable to determine lock status"
            Write-Output "$(Get-TimeStamp) Unable to determine account lock status" | Out-file $logFile -append 
        }
    }
    return $userLocked
}
# Display and return date of user account password last reset
function Show-UserPassSet {
    $passSet = $global:adUser.PasswordLastSet.ToShortDateString()
    Write-Host " Password Set:" $passSet
    return $passSet
}
# Resets the user account password
function Set-UserPass {
    if ($global:adUser -eq $null) { Get-User }
    Show-UmHeader
    $pwdDate = $global:adUser.passwordlastset.ToShortDateString()
    Write-Host " Username:" $global:adUser.SamAccountName
    Write-Host " Password last set on" $pwdDate
    do {
        $conf = Read-Host "`nAre you sure you want to set a new password? (y or n)"
        if ($conf -notin ('y','n')) { Write-Warning "Invalid selection." }
        switch ($conf) { 'n' { return } }   
    } while ($conf -notin ('y','n'))
    $newpass = Read-Host -Prompt "Enter the new password" -AsSecureString
    Set-ADAccountPassword -Identity $global:adUser -Server $global:adDc -NewPassword $newpass -Reset
    $global:adUser = Get-ADUser -filter { SamAccountName -eq $global:adUser } -properties passwordlastset
    $pwdDate = $global:adUser.passwordlastset.ToShortDateString()
    $dateNow = Get-Date
    $dateNow = $dateNow.ToShortDateString()
    # Validate password reset by comparing date password was set to today's date
    if ($pwdDate -eq $dateNow) {
        " " + $global:adUser.SamAccountName + "'s password has been reset.`n"
        Write-Output "$(Get-TimeStamp) Password was reset" | Out-file $logFile -append
    }
    else {
        Write-Warning $global:adUser.SamAccountName + "'s password has not been reset. Please try again.`n"
        Write-Output "$(Get-TimeStamp) ERROR: Password was not reset" | Out-file $logFile -append
    }
    # Same thing but require change password at next logon
    #Set-ADAccountPassword $global:adUser -NewPassword $newpass -Reset -PassThru | Set-ADuser -ChangePasswordAtLogon $True
    pause
}
# Unlocks the user account
function Set-UserUnlock {
    if ($global:adUser -eq $null) { Get-User }
    Show-UmHeader 
    $lockStatus = Show-UserLock
    if ($lockStatus -match "True")
    {
        "`n Unlocking account for " + $global:adUser.SamAccountName + "...`n"
        Unlock-ADAccount -Identity $global:adUser
        $lockStatus = Show-UserLock
        if ($lockStatus -match "False")
        {
            " Account successfully unlocked.`n"
            Write-Output "$(Get-TimeStamp) Account unlocked" | Out-file $logFile -append 
        }
    }
    else { " No action taken.`n" }
    pause
}
# Get user group input
function Get-UserGroup {
    if ($global:adUser -eq $null) { Get-User }
    do { 
        Show-GmHeader
        $userInput = Read-Host -Prompt "Enter the group name to add the user"
        Write-Output "$(Get-TimeStamp) User entered group: $userInput" | Out-file $logFile -append
        $global:adGroup = $userInput
        $groupFound = Find-UserGroup
        if ($groupFound) {
            $global:adGroup = Get-ADGroup -Server $global:adDc -Identity $userInput
            Write-Output "$(Get-TimeStamp) Group $userInput found in AD" | Out-file $logFile -append
            Show-GmHeader
            Write-Host " Active Directory Results`n"
            Write-Host " Group name: "$global:adGroup.Name
            $conf = Read-Host "`nIs this correct? (y or n)"
            switch ($conf) {
                'y' { return $global:adGroup }
                'n' { }
                default { Show-MenuDef }
            }
        }
        else {
            $global:adGroup = $null
            Write-Output "$(Get-TimeStamp) Group $userInput not found" | Out-file $logFile -append
            do {
                Show-GmHeader
                Write-Host " Group $userInput not found."
                Write-Host " R: Try again"
                Write-Host " M: Return to the group menu"
                Write-Host " Q: Quit"
                $conf = Read-Host -Prompt "Please make a selection"
                switch ($conf){
                    'r' { }
                    'm' { Show-GroupMenu }
                    'q' { exit }
                    default { Show-MenuDef }
                }
            } while ($conf -ne 'r')
        }
    } While ($conf -ne 'y')
    return $global:adGroup
}
# Add user to $global:adGroup
function Add-UserToGroup {
    if ($global:adUser -eq $null) { Get-User }
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
        if ($global:adGroup.Name -eq $groupFiltered.Name) {
            " " + $global:adUser.Name + " has successfully been added to " + $global:adGroup.Name + ".`n"
            Write-Output "$(Get-TimeStamp) Added to $groupFiltered" | Out-file $logFile -append
        }
        else {
            Write-Warning $global:adUser.Name" has not been added to $groupFiltered. Please try again.`n"
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
    pause
}
# Verify user group exists
function Find-UserGroup {
    $groupExist = Get-ADGroup -Identity $global:adGroup -Server $global:adDc
    return $groupExist
}