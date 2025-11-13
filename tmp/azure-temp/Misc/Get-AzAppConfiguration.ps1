<#
    File: Get-AzAppConfiguration.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2022
    Description: PowerShell function for dumping Azure App Configuration key values using the access keys.

    Signing Code reused from - https://learn.microsoft.com/en-us/azure/azure-app-configuration/rest-api-authentication-hmac#powershell
#>



function Sign-Request(
    [string] $hostname,
    [string] $method,      # GET, PUT, POST, DELETE
    [string] $url,         # path+query
    [string] $body,        # request body
    [string] $credential,  # access key id
    [string] $secret       # access key value (base64 encoded)
)
{  
    $verb = $method.ToUpperInvariant()
    $utcNow = (Get-Date).ToUniversalTime().ToString("R", [Globalization.DateTimeFormatInfo]::InvariantInfo)
    $contentHash = Compute-SHA256Hash $body

    $signedHeaders = "x-ms-date;host;x-ms-content-sha256";  # Semicolon separated header names

    $stringToSign = $verb + "`n" +
                    $url + "`n" +
                    $utcNow + ";" + $hostname + ";" + $contentHash  # Semicolon separated signedHeaders values

    $signature = Compute-HMACSHA256Hash $secret $stringToSign

    # Return request headers
    return @{
        "x-ms-date" = $utcNow;
        "x-ms-content-sha256" = $contentHash;
        "Authorization" = "HMAC-SHA256 Credential=" + $credential + "&SignedHeaders=" + $signedHeaders + "&Signature=" + $signature
    }
}

function Compute-SHA256Hash(
    [string] $content
)
{
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToBase64String($sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($content)))
    }
    finally {
        $sha256.Dispose()
    }
}

function Compute-HMACSHA256Hash(
    [string] $secret,      # base64 encoded
    [string] $content
)
{
    $hmac = [System.Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($secret))
    try {
        return [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes($content)))
    }
    finally {
        $hmac.Dispose()
    }
}



function Get-AzAppConfiguration{
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="App Configuration Endpoint.")]
        [string]$AppConfiguration = "",
        
        [parameter(Mandatory=$true,
        HelpMessage="Access Key ID.")]
        [String]$Id = "",

        [parameter(Mandatory=$true,
        HelpMessage="Access Key Secret.")]
        [String]$Secret = "",

        [parameter(Mandatory=$false,
        HelpMessage="Next Link for Pagination.")]
        [String]$nextLink = $null

        )

    # nextLink is used for the pagination
    if($nextLink){$uri = [System.Uri]::new(-join("https://$AppConfiguration.azconfig.io",$nextLink))}
    else{$uri = [System.Uri]::new("https://$AppConfiguration.azconfig.io/kv?api-version=1.0")}

    $headers = Sign-Request $uri.Authority GET $uri.PathAndQuery $null $Id $Secret

    $itemsList = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers
    
    $configResults = [System.Text.Encoding]::ASCII.GetString($itemsList.Content) | ConvertFrom-Json

    # Recurse if there are additional links to follow
    if($configResults.'@nextLink'){Get-AzAppConfiguration -AppConfiguration $AppConfiguration -Id $Id -Secret $Secret -nextLink $configResults.'@nextLink'}

    $configResults.items | select key,value,label,content_type,tags,locked,last_modified,etag

}