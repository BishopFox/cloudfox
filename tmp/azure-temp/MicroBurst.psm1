# Test to see if each module is installed, load scripts as applicable

$prefBackup = $WarningPreference
$global:WarningPreference = 'SilentlyContinue'

# Az
try{
    Get-InstalledModule -ErrorAction Stop -Name Az | Out-Null
    Import-Module Az -ErrorAction Stop
    Import-Module $PSScriptRoot\Az\MicroBurst-Az.psm1
    $azStatus = "1"
}
catch{Write-Host -ForegroundColor DarkRed "Az module not installed, checking other modules"}



# AzureAD
try{
    Get-InstalledModule -ErrorAction Stop -Name AzureAD | Out-Null
    Import-Module AzureAD -ErrorAction Stop
    Import-Module $PSScriptRoot\AzureAD\MicroBurst-AzureAD.psm1
}
catch{Write-Host -ForegroundColor DarkRed "AzureAD module not installed, checking other modules"}

<# AzureRm - Uncomment this section if you want to import the functions
try{
    Get-InstalledModule -ErrorAction Stop -Name AzureRM | Out-Null
    Import-Module AzureRM -ErrorAction Stop
    Import-Module $PSScriptRoot\AzureRM\MicroBurst-AzureRM.psm1
}
catch{
    # If Az is already installed, no need to warn on no AzureRM
    if($azStatus -ne "1"){Write-Host -ForegroundColor DarkRed "AzureRM module not installed, checking other modules"}
}
#>

# MSOL
try{
    Get-InstalledModule -ErrorAction Stop -Name msonline | Out-Null
    Import-Module msonline -ErrorAction Stop
    Import-Module $PSScriptRoot\MSOL\MicroBurst-MSOL.psm1
}
catch{Write-Host -ForegroundColor DarkRed "MSOnline module not installed, checking other modules"}


# Import Additional Functions

Import-Module $PSScriptRoot\Misc\MicroBurst-Misc.psm1
Import-Module $PSScriptRoot\REST\MicroBurst-AzureREST.psm1

$global:WarningPreference = $prefBackup