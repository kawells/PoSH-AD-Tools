<#
.NAME
    Dynamic Menu
.SYNOPSIS
    Provide PoSH dynamic menu based upon mandatory parameters
.NOTES
    Author: Kevin Wells

    1.0 | 09/26/2019 | Kevin Wells
        Initial creation

.LINK
    github.com/kawells
#>
Function Show-DynamicMenu{
    Param(
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
    do {
        if ($menuTitle -ne $null) { Write-Host $menuTitle } # displays menutitle
        for ($i=1;$i -le $menuLength; $i++){
            $menuKeys[$i-1] + ": " + $menuOptions[$i-1]
        }
        $selection = Read-Host "Please make a selection"
        $switch = 'switch($selection){'
        for($i=1;$i -le $menuLength; $i++){
            $switch += "`n`t $($menuKeys[$i-1]) { $($menuActions[$i-1]); break }"
        }
        $switch += "`n`t default { Write-Warning 'Invalid selection.' }"
        $switch += "`n}"
        Invoke-Expression $switch
    } while ($selection -notin $menuKeys)
}
