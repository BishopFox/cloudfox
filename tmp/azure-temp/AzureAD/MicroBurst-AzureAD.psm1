
Get-ChildItem (Join-Path -Path $PSScriptRoot -ChildPath *.ps1) | ForEach-Object -Process {
    Import-Module $_.FullName
}
Write-Host "Imported AzureAD MicroBurst functions"