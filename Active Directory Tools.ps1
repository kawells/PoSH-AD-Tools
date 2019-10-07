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

.LINK
    github.com/kawells
#>
Import-Module activedirectory
# Define what to do upon exit of menu
function Start-Exit { exit }
## Create dynamic menus based upon passed arrays
function Show-DynamicMenu{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$menuTitle,
        [Parameter(Mandatory=$true)]
        [array]$menuKeys,
        [Parameter(Mandatory=$true)]
        [array]$menuOptions,
        [Parameter(Mandatory=$true)]
        [array]$menuActions
    )
    # validates that the number of objects in keys, options, and actions match
    if (-Not (($menuKeys.Length -eq $menuOptions.Length) -and ($menuOptions.Length -eq $menuActions.Length))) {
        Write-Error "menuKeys, menuOptions, and menuActions must have the same number of objects in each array."
        return
    }
    else { $menuLength = $menuKeys.Length }
    while ($true){
        Invoke-Expression $menuTitle
        for ($i=1;$i -le $menuLength; $i++){
            " " + $menuKeys[$i-1] + ": " + $menuOptions[$i-1]
        }
        $selection = Read-Host "Please make a selection"
        $switch = 'switch($selection){'
        for($i=1;$i -le $menuLength; $i++){
            $switch += "`n`t $($menuKeys[$i-1]) { $($menuActions[$i-1]); break }"
        }
        $switch += "`n`t default { Write-Warning 'Invalid selection.';pause }"
        $switch += "`n}"
        Invoke-Expression $switch
    }
}

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
    $header = 'Write-Host "$hRule`n            Active Directory Tools $adtVersion`n$hRule`n'
#    $header = 'clear;Write-Host "$hRule`n            Active Directory Tools $adtVersion`n$hRule`n'
    switch($headerType){
        'main'{$header += 'Main Menu: $domainName`n$hRule"'}
        'user'{$header += 'User Menu: $userName on $domainName`n$hRule"'}
        'group'{$header += 'Group Menu: $userName on $domainName`n$hRule"'}
        'comp'{$header += 'Computer Menu: $compName on $domainName`n$hRule"'}
        'domain'{$header += 'DC Menu: $domainName`n$hRule"'}
        default{$header += '"'}
    }
    invoke-expression $header
}
# Displays Main Menu
function Show-MainMenu {
    $adDc = Get-ADDomainController # Get active DC as object
    while ($true) {
        Show-Header -headerType main -domainName $adDc.Name
        Write-Host " 1. User management menu"
        Write-Host " 2. Computer management menu"
        Write-Host " 3. Change active DC"
        Write-Host " Q. Quit"
        $selection = Read-Host "Please make a selection"
        switch ($selection) {
            '1'{ Show-UserMenu -domain $adDc; break }
            '2'{ Show-CompMenu -domain $adDc; break }
            '3'{
                $newDc = (Get-Dc -domain $adDc)
                $adDc = $newDc
                break
            }
            'q'{ Start-Exit }
            default { Write-Warning 'Invalid selection.';pause }
        }
    }
}
# Displays User menu
function Show-UserMenu {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $domain
    )
    while ($true) {
        if ($adUser -eq $null) { $adUser = Get-User }
        Show-Header -headerType user -userName $adUser.Name -domainName $domain.Name
        Write-Host " 1. Enter a new username"
        Write-Host " 2. Reset the password"
        Write-Host " 3. Unlock the account"
        Write-Host " 4. Manage group membership"
        Write-Host " 5. Manage user description"
        Write-Host " M. Return to the main menu"
        Write-Host " Q. Quit"
        $selection = Read-Host "Please make a selection"
        switch ($selection) {
            '1'{ Get-User -user $adUser -domainName $domain.Name; break }
            '2'{ Set-UserPass -user $adUser -domainName $domain.Name; break }
            '3'{ Set-UserUnlock -user $adUser -domainName $domain.Name; break }
            '4'{ Show-GroupMenu -user $adUser -domainName $domain.Name; break }
            '5'{ Show-DescrMenu -user $adUser -domainName $domain.Name; break }
            'm'{ Show-MainMenu; break }
            'q'{ Start-Exit }
            default { Write-Warning 'Invalid selection.';pause }
        }
    }
}
# Displays Computer menu
function Show-CompMenu {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $domain
    )
    if ($global:adComp -eq $null) { Get-Comp }
    $menuTitle = 'Show-Header -headerType comp'
    $menuKeys = @(
        '1',
        '2',
        '3',
        '4',
        'M',
        'Q'
    )
    $menuOptions = @(
        'Enter a new computer name',
        'Display the Bitlocker recovery key',
        'Display the local administrator password (LAPS)',
        'Open RDP session',
        'Return to the main menu',
        'Quit'
    )
    $menuActions = @(
        'Get-Comp',
        'Show-Bl',
        'Show-Laps',
        'Start-Rdp',
        'Show-MainMenu',
        'Start-Exit'
    )
    Show-DynamicMenu -menuTitle $menuTitle -menuKeys $menuKeys -menuOptions $menuOptions -menuActions $menuActions
}
# Get DC from user
function Get-Dc {
    [CmdletBinding()]
    Param (
        [Parameter (Mandatory)]
        $domain
    )
    while ($true) {
        Show-Header -headerType domain -domainName $domain.Name
        Write-Host "`n Your active DC is: $domain`n"
        $newDc = Read-Host "Enter new DC ('C' to cancel)"
        # Provides a way for user to break prompt loop and returns existing DC object
        if ($newDc -eq 'c') {
            Write-Warning "Action cancelled. No changes made."
            pause
            return $domain
        }
        else {
            try {
                $domain = (Get-ADDomainController -Identity $newDC)
                Write-Host "`n Active DC has been set to: $domain`n"
            }
            catch {
                Write-Host ""
                Write-Warning """$newDC"" was not found. No changes made."
            }
            pause
            return $domain
        }
    }
}
## Begin Menu Display
Show-MainMenu
