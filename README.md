# PoSH-AD-Tools
Active Directory Tools for Powershell

# Notes:
This is a self-elevating script that must be run as administrator. It provides a basic text-based command-line GUI with menus for active directory user management and computer management. Tasks include unlock account, reset password, display bitlocker recovery key, display LAPS, and more. A log file of the session is generated per user, located in the current user's "Documents" folder. 
 
# Prerequisites:
Scripts must be located in C:\Users\"Current User"\Documents\, including:

Active Directory Tools.ps1

AD Comp Management.ps1

AD DC Management.ps1

AD User Management.ps1

Dynamic Menu.ps1


The polling engine must have the features below installed.

Remote Server Administration Tools

Role Administration Tools

AD DS and AD LDS Tools

Active Directory module for Windows PowerShell.
