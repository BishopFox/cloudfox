<#
    File: Get-AzAppRegistrationManifest.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2021
    Description: PowerShell functions for enumerating App Registration credentials from AAD manifests.
#>


# Check if the Az Module is installed and imported
if(!(Get-Module Az)){
    try{Import-Module Az -ErrorAction Stop}
    catch{Install-Module -Name Az -Confirm}
    }


Function Get-AzAppRegistrationManifest
{

    [CmdletBinding()]
    Param()

    $resource = "https://graph.microsoft.com"
    $AccessToken = Get-AzAccessToken -ResourceUrl $resource
    if ($AccessToken.Token -is [System.Security.SecureString]) {
        $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
        try {
            $Token = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
        }
    } else {
        $Token = $AccessToken.Token
    }
    $url = "https://graph.microsoft.com/v1.0/myorganization/applications/?`$select=displayName,id,appId,createdDateTime,keyCredentials"

    $authHeader = @{
      "Authorization" = "Bearer " + $Token
    }

    while ($null -ne $url) {
        $results = Invoke-RestMethod -Uri $url -Headers $authHeader -Method "GET" -Verbose:$false
        foreach ($appReg in $results.value) {

            if($appReg.displayName){$displayName = $appReg.displayName}
            else{$displayName = $appReg.Id}
                
            $appID = $appReg.Id

            #Write-Verbose "Trying - $displayName"
            foreach ($cred in $appReg.keyCredentials) {
                if ($cred.Key.Length -gt 2000) {

                    $outputBase = "$PWD\$appID"
                    $outputFile = "$PWD\$appID.pfx"
                    $iter = 1

                    while(Test-Path $outputFile){                    
                        $outputFile = (-join($outputBase,'-',([string]$iter),'.pfx'))
                        $iter +=1
                        Write-Verbose "`tMultiple Creds - Trying $outputFile"
                    }
        
                    [IO.File]::WriteAllBytes($outputFile, [Convert]::FromBase64String($cred.Key))
                    $certResults = Get-PfxData $outputFile
        
                    $ErrorActionPreference = 'SilentlyContinue'
                    if($certResults -ne $null){
                        Write-Verbose "`t$displayName - $appID - has a stored pfx credential"    
                         "$displayName `t $appID" | Out-File -Append "$PWD\AffectedAppRegistrations.txt"
                    }
                    else{Remove-Item $outputFile| Out-Null}
                }
            }
        }
      $url = $results.'@odata.nextLink'
    }
}