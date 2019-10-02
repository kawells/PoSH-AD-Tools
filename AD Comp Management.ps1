# Get the computer name from user
function Get-Comp {
    do { 
        Show-CmHeader
        $userInput = Read-Host -Prompt "Enter the computer name"
        Write-Output "$(Get-TimeStamp) User entered computer name: $userInput" | Out-file $logFile -append
        $global:adComp = $userInput
        $compExist = Find-Comp
        # Display results
        if ($compExist -match "True"){
            $global:adComp = Get-ADComputer $userInput
            Write-Output "$(Get-TimeStamp) Computer found in AD" | Out-file $logFile -append
            do {
                Show-CmHeader
                Write-Host " Active Directory Results`n"
                " Computer name: " + $global:adComp.Name 
                $conf = Read-Host "`nIs this correct? (y or n)"
                switch ($conf){
                    'y' { Show-CompMenu; break }
                    'n' { break }
                    default { Show-MenuDef }
                }
            } while ($conf -ne 'n')
        }
        else {
            $global:adComp = $null
            Write-Output "$(Get-TimeStamp) Computer not found" | Out-file $logFile -append
            do {
                Show-CmHeader
                Write-Host " Active Directory Results`n"
                Write-Host " Computer:" $userInput "was not found.`n"
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
            } while ($conf -ne 'm')
        }
    } While ($conf -ne 'y')
}
# Verify comp in AD
function Find-Comp {
    $compExist = [bool] (Get-ADComputer -Server $global:adDc -Filter { Name -eq $userInput })
    return $compExist
}
# Show the bitlocker key of computer
function Show-Bl {
    $bitlocker = (Get-ADObject -Server $global:adDc -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $global:adComp.DistinguishedName -Properties 'msFVE-RecoveryPassword').'msFVE-RecoveryPassword'
    if ($bitlocker -ne $null) {
        Write-Output "$(Get-TimeStamp) Bitlocker key(s): $bitlocker" | Out-file $logFile -append
        do {
            Show-CmHeader
            " Bitlocker recovery key(s):`n "
            $bitlocker
            $conf = Read-Host "`nCopy Bitlocker key to clipboard (y or n)"
            switch ($conf){
                'y'{
                    Set-Clipboard -Value $bitlocker
                    "`n Bitlocker key copied to clipboard.`n"
                    Write-Output "$(Get-TimeStamp) Bitlocker key copied to clipboard" | Out-file $logFile -append
                }
                'n'{
                    "`n Bitlocker key not copied to clipboard.`n"
                    Write-Output "$(Get-TimeStamp) Bitlocker key copied to clipboard" | Out-file $logFile -append
                }
                default{ Show-MenuDef }
            }    
        } while ($conf -notin ('y','n'))
    } 
    else {
        Write-Warning " Bitlocker recovery key was not found."
        Write-Output "$(Get-TimeStamp) Bitlocker key not found in AD" | Out-file $logFile -append
    }
    $bitlocker = $null
    pause
}
# Show the LAPS of computer
function Show-Laps {
    $laPass = Get-ADComputer $global:adComp -Server $global:adDc -Properties * | select -ExpandProperty ms-Mcs-AdmPwd
    Write-Output "$(Get-TimeStamp) LAPS: $laPass" | Out-file $logFile -append
    Show-CmHeader
    "`n LAPS: $laPass"
    do {
        $conf = Read-Host "`nCopy LAPS to clipboard? (y or n)"
        switch ($conf) {
            'y' {
                Get-ADComputer $global:adComp -Server $global:adDc -Properties * | select -ExpandProperty ms-Mcs-AdmPwd | Set-Clipboard
                "`n Password copied to clipboard.`n"
                Write-Output "$(Get-TimeStamp) Password copied to clipboard" | Out-file $logFile -append
            }
            'n' { "`n Password not copied to clipboard.`n" }
            default { Show-MenuDef }
        }
    } while ($conf -notin ('y','n'))
    $laPass = $null
    pause
}
# Start RDP session if computer is online
function Start-Rdp {
    $compOnline = [bool](Test-Connection -Computername $global:adComp.Name -Count 1 -Quiet)
    if ($compOnline) { $currentComp = $global:adComp.Name; mstsc /v:$currentComp }
    else { Write-Warning "Unable to establish connection. Computer is offline or unavailable."; pause }
}