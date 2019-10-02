# Get DC from user
function Get-Dc {
    do {
        Show-DmHeader
        Write-Host " You are currently using" $global:adDc.Name
        $conf = Read-Host "Are you sure you want to set a domain controller? (y or n)"
        switch ($conf) {
            'n' { return }
            'y' { }
            default { Show-MenuDef }
        }   
    } while ($conf -ne 'y')
    do {
        Show-DmHeader
        $userInput = Read-Host -Prompt "Enter the domain controller to use"
        $dcFound = Find-Dc
        if ($dcFound -match "True") {
            Write-Output "$(Get-TimeStamp) DC found in AD" | Out-file $logFile -append
            Show-DmHeader
            Write-Host " Active Directory Results`n"
            Write-Host " Domain controller:"$userInput
            $conf = Read-Host "`nIs this correct? (y or n)"
            switch ($conf) {
                'y' {
                    $global:adDc = Get-ADDomainController -Identity $userInput
                    Show-DmHeader
                    " The working domain controller has been changed to " + $global:adDc.Name
                    pause
                    return
                }
                'n' { $global:adDc = Get-ADDomainController }
                default { Show-MenuDef }
            }
        }
        else {
            $global:adDc = Get-ADDomainController
            Write-Output "$(Get-TimeStamp) DC not found" | Out-file $logFile -append
            do {
                Show-DmHeader
                Write-Host " Active Directory Results`n"
                Write-Host " Domain controller:" $userInput "was not found.`n"
                Write-Host " R: Try again"
                Write-Host " M: Return to the main menu"
                Write-Host " Q: Quit"
                $conf = Read-Host -Prompt "Please make a selection"
                switch ($conf){
                    'r' { break }
                    'm' { Show-MainMenu; break }
                    'q' { exit }
                    default { Show-MenuDef }
                }
            } while ($conf -eq 'r')
        }
    } while ($conf -eq 'n')
    return $global:adDc       
}
# Verify DC in AD
function Find-Dc {
    $accountExist = [bool] (Get-ADDomainController -Identity $global:adDc)
    return $accountExist
}