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
        Broke out some functions into dot sourced scripts

.LINK
    github.com/kawells
#>
cls
# Self-elevate the script if required
try {
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
     if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
      $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
      Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
      Exit
     }
    }
    "Elevating script to administrator... Ok"
}
catch { "Elevating script to administrator... Fail"; pause; exit }
# Define root and other paths
try {
    "Loading functions... Ok"
    $rootDir = "C:\Users\" + $env:UserName + "\Documents\"
    $logFile = $rootDir + "adtlog.txt"
    $userFile = $rootDir + "AD User Management.ps1"
    $compFile = $rootDir + "AD Comp Management.ps1"
    $dcFile = $rootDir + "AD DC Management.ps1"
    $menuFile = $rootDir + "Dynamic Menu.ps1"
    # Dot source functions
    . $userFile
    . $compFile
    . $dcFile
    . $menuFile
}
catch { "Loading functions... Fail"; pause; exit }
$WarningPreference = 'Continue' # Set warnings to display
$version = "v1.7" # Set version number of script
# Resize and color the display
try {
    $pshost = get-host
    $pswindow = $pshost.ui.rawui
    $pswindow.windowtitle = "AD Tools"
    $pswindow.foregroundcolor = "White"
    $pswindow.backgroundcolor = "Black"
    "Setting window color... Ok"
}
catch { "Setting window color... Fail" }
# Load AD module or exit if failure
try { Import-Module activedirectory; "Loading AD module... Ok" }
catch { "Loading AD module... Fail"; pause; exit }
# Declare global vars
try { $global:adDc = Get-ADDomainController; "Getting current AD controller... Ok" } #contains working DC
catch { "Getting current AD controller... Fail"; pause; exit }
$global:adUser = $null #contains working username
$global:adComp = $null #contains working computer name
$global:adGroup = $null #contains group name that user will be added to in UserGroup function
$global:hRule = "======================================================" #horizontal rule used in menus
pause
## Define functions
# Display the timestamp for logging
function Get-TimeStamp {
    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
}
# Show default error message when invalid menu option is entered
function Show-MenuDef{
    Write-Warning "Invalid selection."
    pause
}
# Show header for user menu
function Show-UmHeader {
    Show-Header
    if ($global:adUser -ne $null ) { Write-Host "User Menu:" $global:adUser.SamAccountName "on"$global:adDc.Name }
    else { Write-Host "User Menu:"$global:adDc.Name }
    Write-Host $global:hRule
}
# Show header for computer menu
function Show-CmHeader {
    Show-Header
    if ($global:adComp -ne $null ) { Write-Host "Computer Menu:" $global:adComp.Name "on"$global:adDc.Name}
    else { Write-Host "Computer Menu:"$global:adDc.Name }
    Write-Host $global:hRule
}
# Show header for group membership menu
function Show-GmHeader {
    Show-Header
    Write-Host "User Group Menu:" $global:adUser.SamAccountName "on"$global:adDc.Name
    Write-Host $global:hRule 
}
# Show header for main menu
function Show-MmHeader {
    Show-Header
    Write-Host "Main Menu:"$global:adDc.Name
    Write-Host $global:hRule
}
# Show header for DC menu
function Show-DmHeader {
    Show-Header
    Write-Host "Domain Controller Menu:"$global:adDc.Name
    Write-Host $global:hRule
}
# Show script header
function Show-Header {
    cls
    Write-Host $global:hRule
    Write-Host "            Active Directory Tools"$version
    Write-Host $global:hRule
}
# Displays Group menu
function Show-GroupMenu {
    if ($global:adUser -eq $null) { Get-User }
    $menuTitle = 'Show-UmHeader'
    $menuKeys = @(
        '1',
        '2',
        '3',
        '4',
        '5',
        'U',
        'M',
        'Q'
    )
    $menuOptions = @(
        'Display user''s current group memberships',
        'Add to short term debarment group',
        'Add to long term debarment group',
        'Add to permanent debarment group',
        'Add to a different group',
        'Return to the user menu',
        'Return to the main menu',
        'Quit'
    )
    $menuActions = @(
        'Show-UserGroups',
        '$global:adGroup = Get-ADGroup -Identity "SG_PIV_Withdrawal_Short";Add-UserToGroup',
        '$global:adGroup = Get-ADGroup -Identity "SG_PIV_Withdrawal_Long";Add-UserToGroup',
        '$global:adGroup = Get-ADGroup -Identity "SG_PIV_Withdrawal_Permanent";Add-UserToGroup',
        'Get-UserGroup; if ($global:adGroup -ne $null) { Add-UserToGroup }',
        'Show-UserMenu',
        'Show-MainMenu',
        'exit'
    )
    Show-DynamicMenu -menuTitle $menuTitle -menuKeys $menuKeys -menuOptions $menuOptions -menuActions $menuActions
}
# Displays User menu
function Show-UserMenu {
    if ($global:adUser -eq $null) { Get-User }
    $menuTitle = 'Show-UmHeader'
    $menuKeys = @(
        '1',
        '2',
        '3',
        '4',
        'M',
        'Q'
    )
    $menuOptions = @(
        'Enter a new username',
        'Reset the password',
        'Unlock the account',
        'Manage group membership',
        'Return to the main menu',
        'Quit'
    )
    $menuActions = @(
        'Get-User',
        'Set-UserPass',
        'Set-UserUnlock',
        'Show-GroupMenu',
        'Show-MainMenu',
        'exit'
    )
    Show-DynamicMenu -menuTitle $menuTitle -menuKeys $menuKeys -menuOptions $menuOptions -menuActions $menuActions
}
# Displays Computer menu
function Show-CompMenu {
    if ($global:adComp -eq $null) { Get-Comp }
    $menuTitle = 'Show-CmHeader'
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
        'exit'
    )
    Show-DynamicMenu -menuTitle $menuTitle -menuKeys $menuKeys -menuOptions $menuOptions -menuActions $menuActions
} 
# Displays Main Menu
function Show-MainMenu {
    Write-Output "`n`n$(Get-TimeStamp) Session started" | Out-file $logFile -append
    $menuTitle = 'Show-MmHeader'
    $menuKeys = @(
        '1',
        '2',
        '3',
        'Q'
    )
    $menuOptions = @(
        'User management menu',
        'Computer management menu',
        'Change active DC',
        'Quit'
    )
    $menuActions = @(
        'Show-UserMenu',
        'Show-CompMenu',
        'Get-Dc',
        'exit'
    )
    Show-DynamicMenu -menuTitle $menuTitle -menuKeys $menuKeys -menuOptions $menuOptions -menuActions $menuActions
}
# Begins the entire menu navigation
Show-MainMenu