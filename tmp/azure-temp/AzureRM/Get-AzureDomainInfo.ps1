<#
    File: Get-AzureDomainInfo.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2018
    Description: PowerShell functions for enumerating information from Azure domains.
#>

# To Do:
#       Add Ctrl-C handling for skipping sections/storage accounts
#       Higher level metrics reporting (X% of your domain users have contributor rights, etc.)
#       Apply NSGs to Public IPs and VMs to pre-map existing internet facing services
#       Add better error handling - More try/catch blocks for built-in functions that you may not have rights for
#       Fix the ResourceGroup filtering
#       Add a "Findings" file that lists out the specific bad config items
#       Add additional options for data output (XML/CSV/Datatable)
#       Add additional AzureRM Functions - https://docs.microsoft.com/en-us/azure/azure-resource-manager/powershell-azure-resource-manager


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


Function Get-AzureDomainInfo
{
<#
    .SYNOPSIS
        PowerShell function for dumping information from Azure subscriptions via authenticated ASM and ARM connections.
	.DESCRIPTION
        The function will dump available information for an Azure domain out to CSV and txt files in the -folder parameter directory.		
	.PARAMETER folder
        The folder to output to.   
    .PARAMETER Users
        These are specific parameters to limit the output. You may not care about exporting the users and groups. Use -Users N and -Groups N to disable.
    .EXAMPLE
        PS C:\> Get-AzureDomainInfo -folder MicroBurst -Verbose
		VERBOSE: Currently logged in via AzureRM as ktest@fosaaen.com
		VERBOSE: Dumping information for Selected Subscriptions...
		VERBOSE: Dumping information for the 'MicroBurst Demo' Subscription...
		VERBOSE: Getting Domain Users...
		VERBOSE: 	70 Domain Users were found.
		VERBOSE: Getting Domain Groups...
		VERBOSE: 	15 Domain Groups were found.
		VERBOSE: Getting Domain Users for each group...
		VERBOSE: 	Domain Group Users were enumerated for 15 groups.
		VERBOSE: Getting Storage Accounts...
		VERBOSE: 	Listing out blob files for the icrourstesourcesdiag storage account...
		VERBOSE: 		Listing files for the bootdiagnostics-mbdemoser container
		VERBOSE: 	No available File Service files for the icrourstesourcesdiag storage account...
		VERBOSE: 	No available Data Tables for the icrourstesourcesdiag storage account...
		VERBOSE: 	Listing out blob files for the microburst storage account...
		VERBOSE: 		Listing files for the test container
		VERBOSE: 	No available File Service files for the microburst storage account...
		VERBOSE: 	No available Data Tables for the microburst storage account...
		VERBOSE: 	2 storage accounts were found.
		VERBOSE: 	2 Domain Authentication endpoints were enumerated.
		VERBOSE: Getting Domain Service Principals...
		VERBOSE: 	58 service principals were enumerated.
		VERBOSE: Getting Azure Resource Groups...
		VERBOSE: 	3 Resource Groups were enumerated.
		VERBOSE: Getting Azure Resources...
		VERBOSE: 	36 Resources were enumerated.
		VERBOSE: Getting AzureSQL Resources...
		VERBOSE: 	1 AzureSQL servers were enumerated.
		VERBOSE: 	2 AzureSQL databases were enumerated.
		VERBOSE: Getting Azure App Services...
		VERBOSE: 	2 App Services enumerated.
		VERBOSE: Getting Network Interfaces...
		VERBOSE: 	4 Network Interfaces Enumerated...
		VERBOSE: Getting Public IPs for each Network Interface...
		VERBOSE: Getting Network Security Groups...
		VERBOSE: 	3 Network Security Groups were enumerated.
		VERBOSE: 	6 Network Security Group Firewall Rules were enumerated.
		VERBOSE: 		3 Inbound 'Any Any' Network Security Group Firewall Rules were enumerated.
		VERBOSE: Getting RBAC Users and Roles...
		VERBOSE: 	2 Users with 'Owner' permissions were enumerated.
		VERBOSE: 	92 roles were enumerated.

		VERBOSE: Done with all tasks for the 'MicroBurst Demo' Subscription.

#>


    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Folder to output to.")]
        [string]$folder = "",
        
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription name to use.")]
        [string]$Subscription = "",

        [Parameter(Mandatory=$false,
        HelpMessage="Limit to a specific Resource.")]
        [string]$ResourceGroup = "",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump list of Users.")]
        [ValidateSet("Y","N")]
        [String]$Users = "Y",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump list of Groups.")]
        [ValidateSet("Y","N")]
        [String]$Groups = "Y",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump list of Storage Accounts.")]
        [ValidateSet("Y","N")]
        [String]$StorageAccounts = "Y",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump list of Resources.")]
        [ValidateSet("Y","N")]
        [String]$Resources = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump list of Virtual Machines.")]
        [ValidateSet("Y","N")]
        [String]$VMs = "Y",
        
        [parameter(Mandatory=$false,
        HelpMessage="Dump list of Network Information.")]
        [ValidateSet("Y","N")]
        [String]$NetworkInfo = "Y",

        [parameter(Mandatory=$false,
        HelpMessage="Dump list of RBAC Users/Roles/etc.")]
        [ValidateSet("Y","N")]
        [String]$RBAC = "Y",
                
        [parameter(Mandatory=$false,
        HelpMessage="Bypass the login process. Use this if you are already authenticated.")]
        [ValidateSet("Y","N")]
        [String]$LoginBypass = "N"
    )

    if ($LoginBypass -eq "N"){
        # Check to see if we're logged in with AzureRM
        $LoginStatus = Get-AzureRmContext
        if ($LoginStatus.Account -eq $null){Write-Warning "No active AzureRM login. Prompting for login." 
            try {Login-AzureRmAccount -ErrorAction Stop | Out-Null}
            catch{Write-Warning "Login process failed.";break}
            }
        else{$AZRMContext = Get-AzureRmContext; $AZRMAccount = $AZRMContext.Account;Write-Verbose "Currently logged in via AzureRM as $AZRMAccount"; Write-Verbose 'Use Login-AzureRmAccount to change your user'}
    }

    # Subscription name is required, list sub names in gridview if one is not provided
    if ($Subscription){}
    else{

        # List subscriptions, pipe out to gridview selection
        $Subscriptions = Get-AzureRmSubscription -WarningAction SilentlyContinue
        $subChoice = $Subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru

        if($subChoice.count -eq 0){Write-Verbose 'No subscriptions selected, exiting'; break}

        Write-Verbose "Dumping information for Selected Subscriptions..."

        # Recursively iterate through the selected subscriptions and pass along the parameters
        Foreach ($sub in $subChoice){$subName = $sub.Name;Write-Verbose "Dumping information for the '$subName' Subscription..."; Select-AzureRMSubscription -Subscription $subName | Out-Null; Get-AzureDomainInfo -Subscription $sub.Name -ResourceGroup $ResourceGroup -LoginBypass Y -folder $folder -Users $Users -Groups $Groups -StorageAccounts $StorageAccounts -Resources $Resources -VMs $VMs -NetworkInfo $NetworkInfo -RBAC $RBAC}
        break

    }

    # Folder Parameter Checking - Creates AzureRM folder to separate from MSOL folder
    if ($folder){
        if(Test-Path $folder){
            if(Test-Path $folder"\AzureRM"){}
            else{New-Item -ItemType Directory $folder"\AzureRM"|Out-Null}}
        else{New-Item -ItemType Directory $folder|Out-Null ; New-Item -ItemType Directory $folder"\AzureRM"|Out-Null}; $folder = -join ($folder, "\AzureRM")}
    else{if(Test-Path AzureRM){}else{New-Item -ItemType Directory AzureRM|Out-Null};$folder= -join ($pwd, "\AzureRM")}


    if(Test-Path $folder"\"$Subscription){}
    else{New-Item -ItemType Directory $folder"\"$Subscription | Out-Null}
    
    $folder = -join ($folder, "\", $Subscription)
    
    # Get TenantId
    $tenantID = Get-AzureRmTenant | select TenantId

    # Get/Write Users for each domain
    if ($Users -eq "Y"){
        Write-Verbose "Getting Domain Users..."
        $userLists= Get-AzureRmADUser 
        $userLists | Export-Csv -NoTypeInformation -LiteralPath $folder"\Users.CSV"
        $userCount = $userLists.Count
        Write-Verbose "`t$userCount Domain Users were found."
    }

    # Get/Write Groups for each domain
    If ($Groups -eq "Y"){
        Write-Verbose "Getting Domain Groups..."
        
        # Check Output Path
        if(Test-Path $folder"\Groups"){}
        else{New-Item -ItemType Directory $folder"\Groups" | Out-Null}

        # Gather info to variable
        $groupLists=Get-AzureRmADGroup
        $groupCount = $groupLists.Count
        Write-Verbose "`t$groupCount Domain Groups were found."
        Write-Verbose "Getting Domain Users for each group..."

        # Export Data
        $groupLists | Export-Csv -NoTypeInformation -LiteralPath $folder"\Groups.CSV"

        # Iterate through each group, and export users
        $groupLists | ForEach-Object {$groupName=$_.DisplayName; Get-AzureRmADGroupMember -GroupObjectId $_.Id | Select-Object @{ Label = "Group Name"; Expression={$groupName}}, DisplayName | Export-Csv -NoTypeInformation -LiteralPath $folder"\Groups\"$groupName"_Users.CSV"}
        Write-Verbose "`tDomain Group Users were enumerated for $groupCount groups."
    }


    # Get Storage Account name(s)
    if($StorageAccounts -eq "Y"){
        
        Write-Verbose "Getting Storage Accounts..."

        if($ResourceGroup){
            foreach($rg in $ResourceGroup){
                # Gather info to variable
                $storageAccountLists += Get-AzureRmStorageAccount -ResourceGroupName $rg | select StorageAccountName,ResourceGroupName 
            }
        }
        else{
            # Gather info to variable
            $storageAccountLists = Get-AzureRmStorageAccount | select StorageAccountName,ResourceGroupName 
        }

        if ($storageAccountLists){

            # Check Output Path
            if(Test-Path $folder"\Files"){}
            else{New-Item -ItemType Directory $folder"\Files" | Out-Null}

            # Iterate Storage Accounts and export data
            Foreach ($storageAccount in $storageAccountLists){
                $StorageAccountName = $storageAccount.StorageAccountName
        
                Write-Verbose "`tListing out blob files for the $StorageAccountName storage account..."
                
                # Try to Set Context, Write-Verbose if you don't have the rights
                Try{
                    
                    Set-AzureRmCurrentStorageAccount –ResourceGroupName $storageAccount.ResourceGroupName -Name $storageAccount.StorageAccountName -ErrorAction Stop | Out-Null
                    
                                        
                    $strgName = $storageAccount.StorageAccountName

                    # Create folder for each Storage Account for cleaner output
                    if(Test-Path $folder"\Files\"$strgName){}
                    else{New-Item -ItemType Directory $folder"\Files\"$strgName | Out-Null}

                    # List Containers and Files and Export to CSV
                    $containers = Get-AzureStorageContainer | select Name
        
                    foreach ($container in $containers){
                        $containerName = $container.Name
                        Write-Verbose "`t`tListing files for the $containerName container"
                        $pathName = "\Files\"+$strgName+"\Blob_Files_"+$container.Name
                        $blobs = Get-AzureStorageBlob -Container $container.Name 
                        $blobs | ForEach-Object {$_.ICloudBlob | select @{name="Uri"; expression={$_.Uri}},@{name="StorageUri"; expression={$_.StorageUri}},@{name="SnapshotTime"; expression={$_.SnapshotTime}},@{name="IsSnapshot"; expression={$_.IsSnapshot}},@{name="IsDeleted"; expression={$_.IsDeleted}},@{name="SnapshotQualifiedUri"; expression={$_.SnapshotQualifiedUri}},@{name="SnapshotQualifiedStorageUri"; expression={$_.SnapshotQualifiedStorageUri}},@{name="Name"; expression={$_.Name}},@{name="BlobType"; expression={$_.BlobType}}} | Export-Csv -NoTypeInformation -LiteralPath $folder$pathName".CSV"
            
                        # Check if the container is public, write to PublicFileURLs.txt
                        $publicStatus = Get-AzureStorageContainerAcl $container.Name | select PublicAccess
                        if (($publicStatus.PublicAccess -eq "Blob")){

                            #Write public file URL to list
                            $blobName = Get-AzureStorageBlob -Container $container.Name | select Name
                        
                            $pubfileName = $blobName.Name 
                            Write-Verbose "`t`t`tPublic File Found - $pubfileName"

                            $blobUrl = "https://$StorageAccountName.blob.core.windows.net/$containerName/"+$blobName.Name
                            # Write out available files within "Blob" containers
                            $blobUrl >> $folder"\Files\BlobFileURLs.txt"                            
                            }
                        if ($publicStatus.PublicAccess -eq "Container"){
                            Write-Verbose "`t`t`t$containerName Container is Public" 
                            #Write public container URL to list
                            $blobName = Get-AzureStorageBlob -Container $container.Name | select Name
                            $blobUrl = "https://$StorageAccountName.blob.core.windows.net/$containerName/"
                            $blobUrl >> $folder"\Files\PublicContainers.txt"
                            # Write out available files within "Container" containers
                            foreach ($blobfile in $blobName){                                
                                $blobUrl = "https://$StorageAccountName.blob.core.windows.net/$containerName/"+$blobfile.Name
                                $blobUrl >> $folder"\Files\ContainersFileUrls.txt"
                                }
                            
                            }
                    }

                    #Go through each File Service endpoint
                    Try{
                        $AZFileShares = Get-AzureStorageShare -ErrorAction Stop | select Name
                        if($AZFileShares.Length -gt 0){
                            Write-Verbose "`tListing out File Service files for the $StorageAccountName storage account..."
                            foreach ($share in $AZFileShares) {
                                $shareName = $share.Name
                                Write-Verbose "`tListing files for the $shareName share"
                                Get-AzureStorageFile -ShareName $shareName | select Name | Export-Csv -NoTypeInformation -LiteralPath $folder"\Files\"$strgName"\File_Service_Files-"$shareName".CSV" -Append
                                }
                            }
                        else{Write-Verbose "`tNo available File Service files for the $StorageAccountName storage account..."}
                        }
                    Catch{
                        Write-Verbose "`tNo available File Service files for the $StorageAccountName storage account..."
                        }
                    finally{
                        $ErrorActionPreference = "Continue"
                        }

                    #Go through each Storage Table endpoint
                    Try{            
                        $tableList = Get-AzureStorageTable -ErrorAction Stop 
                        if ($tableList.Length -gt 0){
                            $tableList | Export-Csv -NoTypeInformation -LiteralPath $folder"\Files\"$strgName"\Data_Tables.CSV"
                            Write-Verbose "`tListing out Data Tables for the $StorageAccountName storage account..."
                            }
                        else {Write-Verbose "`tNo available Data Tables for the $StorageAccountName storage account..."}
                        }
                    Catch{
                        Write-Verbose "`tNo available Data Tables for the $StorageAccountName storage account..."
                        }
                    finally{
                        $ErrorActionPreference = "Continue"
                        }
                    }
                
                catch{Write-Verbose "`t`tThe current user does not have rights to $StorageAccountName storage account"}

                }
        }
        $storeCount = $storageAccountLists.count
        Write-Verbose "`t$storeCount storage accounts were found."
    }

    if($Resources -eq "Y"){
        # Create folder for resources for cleaner output
        if(Test-Path $folder"\Resources"){}
        else{New-Item -ItemType Directory $folder"\Resources\" | Out-Null}

        # Get/Write AD Authentication Endpoints
        $ADApps = Get-AzureRmADApplication
        $ADApps | select DisplayName,@{name="IdentifierUris";expression={$_.IdentifierUris}},HomePage,Type,@{name="ReplyUrl";expression={$_.ReplyUrls}} | Export-Csv -NoTypeInformation -LiteralPath $folder"\Resources\Domain_Auth_EndPoints.CSV"
        $ADAppsCount = $ADApps.Count
        Write-Verbose "`t$ADAppsCount Domain Authentication endpoints were enumerated."

        # Get/Write Service Principals
        Write-Verbose "Getting Domain Service Principals..."
        $principals = Get-AzureRmADServicePrincipal | select DisplayName,ApplicationId,Id,Type
        $principals | Export-Csv -NoTypeInformation -LiteralPath $folder"\Resources\Domain_SPNs.CSV"
        $principalCount = $principals.Count
        Write-Verbose "`t$principalCount service principals were enumerated."
    
        # Get/Write Available resource groups
        Write-Verbose "Getting Azure Resource Groups..."
        $resourceGroups = Get-AzureRmResourceGroup
        if($resourceGroups){
            $resourceGroups | select ResourceGroupName,Location,ProvisioningState,ResourceId | Export-Csv -NoTypeInformation -LiteralPath $folder"\Resources\Resource_Groups.CSV"
            $resourceGroupsCount = $resourceGroups.Count
            Write-Verbose "`t$resourceGroupsCount Resource Groups were enumerated."
        }
        else{Write-Verbose "`tNo Resource Groups were enumerated."}

        # Get/Write Available resources
        Write-Verbose "Getting Azure Resources..."
        $resourceLists = Get-AzureRmResource
        $resourceLists | Export-Csv -NoTypeInformation -LiteralPath $folder"\Resources\All_Resources.CSV"
        $resourceCount = $resourceLists.Count
        Write-Verbose "`t$resourceCount Resources were enumerated."

        # Get/Write Available AzureSQL DBs
        Write-Verbose "Getting AzureSQL Resources..."
        $azureSQLServers = Get-AzureRmResource | where {$_.ResourceType -Like "Microsoft.Sql/servers"}
        $azureSQLServersCount = @($azureSQLServers).Count
        $azureSQLDatabasesCount = 0

        # Write Databases (per server) out to file
        foreach ($sqlServer in $azureSQLServers){
            $SQLPath = '\Resources\'+$sqlServer.Name
            $azureSQLDatabases = Get-AzureRmSqlDatabaseExpanded -ServerName $sqlServer.Name -ResourceGroupName $sqlServer.ResourceGroupName 
            $azureSQLDatabasesCount += $azureSQLDatabases.Count
            $azureSQLDatabases | Export-Csv -NoTypeInformation -LiteralPath $folder$SQLPath'_SQL_Databases.CSV'

            Get-AzureRmSqlServerFirewallRule -ServerName $sqlServer.Name -ResourceGroupName $sqlServer.ResourceGroupName | Export-Csv -NoTypeInformation -LiteralPath $folder$SQLPath"_SQL_FW_Rules.csv"

            # List AzureAD admins for each
            $adminSQL = $azureSQLServers | ForEach-Object { Get-AzureRmSqlServerActiveDirectoryAdministrator -ServerName $_.Name -ResourceGroupName $_.ResourceGroupName}
            $adminSQL | Export-Csv -NoTypeInformation -LiteralPath $folder$SQLPath"_SQL_Admins.csv"

            }

        # Write Servers to file
        $azureSQLServers | Export-Csv -NoTypeInformation -LiteralPath $folder"\Resources\SQL_Servers.CSV"
        
        Write-Verbose "`t$azureSQLServersCount AzureSQL servers were enumerated."
        Write-Verbose "`t$azureSQLDatabasesCount AzureSQL databases were enumerated."

        Write-Verbose "Getting Azure App Services..."

        # Get App Services 
        if($ResourceGroup){
            foreach($rg in $ResourceGroup){
                $appServs += Get-AzureRmWebApp -ResourceGroupName $rg
            }
        }
        else{$appServs = Get-AzureRmWebApp}
        $appServsCount = $appServs.Count

        $appServs | select State,@{name="HostNames";expression={$_.HostNames}},RepositorySiteName,UsageState,Enabled,@{name="EnabledHostNames";expression={$_.EnabledHostNames}},AvailabilityState,@{name="HostNameSslStates";expression={$_.HostNameSslStates}},ServerFarmId,Reserved,LastModifiedTimeUtc,SiteConfig,TrafficManagerHostNames,ScmSiteAlsoStopped,TargetSwapSlot,HostingEnvironmentProfile,ClientAffinityEnabled,ClientCertEnabled,HostNamesDisabled,OutboundIpAddresses,PossibleOutboundIpAddresses,ContainerSize,DailyMemoryTimeQuota,SuspendedTill,MaxNumberOfWorkers,CloningInfo,SnapshotInfo,ResourceGroup,IsDefaultContainer,DefaultHostName,SlotSwapStatus,HttpsOnly,Identity,Id,Name,Kind,Location,Type,Tags | Export-Csv -NoTypeInformation -LiteralPath $folder"\Resources\AppServices.CSV"
        
        Write-Verbose "`t$appServsCount App Services enumerated."

        # Get list of Disks
        Write-Verbose "Getting Azure Disks..."
        $disks = Get-AzureRmDisk
        $disksCount = $disks.Count
        Write-Verbose "`t$disksCount Disks were enumerated."
        # Write Disk info to file
        $disks | Export-Csv -NoTypeInformation -LiteralPath $folder"\Resources\Disks.CSV"
        $disks | ForEach-Object{if($_.EncryptionSettings -eq $null){$_.Name | Out-File -LiteralPath $folder"\Resources\Disks-NoEncryption.txt"}}
        
        # Get Deployments and Parameters
        Write-Verbose "Getting Azure Deployments and Parameters..."
        Get-AzureRmResourceGroup | Get-AzureRmResourceGroupDeployment |  Out-File -LiteralPath $folder"\Resources\Deployments.txt"
    }

    if ($VMs -eq "Y"){
        Write-Verbose "Getting Virtual Machines..."

        $VMList = Get-AzureRmVM
        $VMCount = $VMList.count

        # Create folder for VM Info for cleaner output
        if(Test-Path $folder"\VirtualMachines"){}
        else{New-Item -ItemType Directory $folder"\VirtualMachines\" | Out-Null}

        $VMList | select ResourceGroupName,Name,Location,ProvisioningState,Zone | Export-Csv -NoTypeInformation -LiteralPath $folder"\VirtualMachines\VirtualMachines-Basic.csv"

        Write-Verbose "`t$VMCount Virtual Machines enumerated."

        Write-Verbose "Getting Virtual Machine Scale Sets..."

        $scaleSets = Get-AzureRmVmss
 
        # Set Up Data Table
        $vmssDT = New-Object System.Data.DataTable("vmssVMs")
        $columns = @("Name","ComputerName","PrivateIP","AdminUser","AdminPassword","Secrets","ProvisioningState")
        foreach ($col in $columns) {$vmssDT.Columns.Add($col) | Out-Null}
        $vmssCount = $scaleSets.Count
        foreach($sSet in $scaleSets){
            $instanceIds = Get-AzureRmVmssVM -ResourceGroupName $sSet.ResourceGroupName -VMScaleSetName $sSet.Name 
            foreach($sInstance in $instanceIds){

                $vmssVMs = Get-AzureRmVmssVM -ResourceGroupName $sInstance.ResourceGroupName -VMScaleSetName $sSet.Name -InstanceId $sInstance.InstanceId
                $nicName = ($vmssVMs.NetworkProfile.NetworkInterfaces[0].Id).Split('/')[-1]

                # Correct the resource name
                $resourceName = $sSet.Name + "/" + $vmssVMs.InstanceId + "/" + $nicName
                
                # Get resource interface config
                $target = Get-AzureRmResource -ResourceGroupName $sInstance.ResourceGroupName -ResourceType Microsoft.Compute/virtualMachineScaleSets/virtualMachines/networkInterfaces -ResourceName $resourceName -ApiVersion 2017-03-30

                # Write the Data Table to the file
                $vmssDT.Rows.Add($vmssVMs.Name,$vmssVMs.OsProfile.ComputerName,$target.Properties.ipConfigurations[0].properties.privateIPAddress,$vmssVMs.OsProfile.AdminUsername,$vmssVMs.OsProfile.AdminPassword,$vmssVMs.OsProfile.Secrets,$vmssVMs.ProvisioningState) | Out-Null
                                
            }
        }

        $vmssDT | Export-Csv -NoTypeInformation -LiteralPath $folder"\VirtualMachines\VirtualMachineScaleSets.csv"

        Write-Verbose "`t$vmssCount Virtual Machine Scale Sets enumerated."

    }

    if($NetworkInfo -eq "Y"){
        Write-Verbose "Getting Network Interfaces..."
        $NICList = Get-AzureRmNetworkInterface

        # Create folder for Network Interfaces for cleaner output
        if(Test-Path $folder"\Interfaces"){}
        else{New-Item -ItemType Directory $folder"\Interfaces\" | Out-Null}

        # List each interface and export to CSV
        $NICList | ForEach-Object{
            $NicName = $_.Name
            foreach($ipconfig in $_.IpConfigurations){
                $ipconfig | select PrivateIpAddressVersion,Primary,LoadBalancerBackendAddressPoolsText,LoadBalancerInboundNatRulesText,ApplicationGatewayBackendAddressPoolsText,ApplicationSecurityGroupsText,PrivateIpAddress,PrivateIpAllocationMethod,ProvisioningState,SubnetText,PublicIpAddressText,Name,Etag,Id | Export-Csv -NoTypeInformation -LiteralPath $folder"\Interfaces\"$NicName"-ipConfig.csv"
                }
            $_ | select Name,ResourceGroupName,Location,Id,etag,ResourceGuid,ProvisioningState,Tags,DnsSettings,EnableIPForwarding,EnableAcceleratedNetworking,NetworkSecurityGroup,Primary,MacAddress | Export-Csv -NoTypeInformation -LiteralPath $folder"\Interfaces\"$NicName".csv"
            }


        # Create General NIC List
        $NICList | select @{name="VirtualMachine";expression={$_.VirtualMachineText}},@{name="IpConfigurations";expression={$_.IpConfigurationsText}},@{name="DnsSettings";expression={$_.DnsSettingsText}},MacAddress,Primary,EnableAcceleratedNetworking,EnableIPForwarding,@{name="NetworkSecurityGroup";expression={$_.NetworkSecurityGroupText}},ProvisioningState,VirtualMachineText,IpConfigurationsText,DnsSettingsText,NetworkSecurityGroupText,ResourceGroupName,Location,ResourceGuid,Type,@{name="Tag";expression={$_.Tag}},TagsTable,Name,Etag,Id | Export-Csv -NoTypeInformation -LiteralPath $folder"\NetworkInterfaces.csv"
        $NICListCount = $NICList.count
        Write-Verbose "`t$NICListCount Network Interfaces Enumerated..."


        # Create General NIC List
        Write-Verbose "`tGetting Public IPs for each Network Interface..."
        $pubIPs = Get-AzureRmPublicIpAddress | select Name,IpAddress,PublicIpAllocationMethod,ResourceGroupName
        $pubIPs | Export-Csv -NoTypeInformation -LiteralPath $folder"\PublicIPs.csv"

        Write-Verbose "Getting Network Security Groups..."
        $NSGList = Get-AzureRmNetworkSecurityGroup | select Name, ResourceGroupName, Location, SecurityRules, DefaultSecurityRules
        $NSGListCount = $NSGList.Count
        Write-Verbose "`t$NSGListCount Network Security Groups were enumerated."

        # Create data table to house results
        $RulesTempTbl = New-Object System.Data.DataTable 
        $RulesTempTbl.Columns.Add("NSGName") | Out-Null
        $RulesTempTbl.Columns.Add("ResourceGroupName") | Out-Null
        $RulesTempTbl.Columns.Add("Location") | Out-Null
        $RulesTempTbl.Columns.Add("RuleName") | Out-Null
        $RulesTempTbl.Columns.Add("Protocol") | Out-Null
        $RulesTempTbl.Columns.Add("SourcePortRange") | Out-Null
        $RulesTempTbl.Columns.Add("DestinationPortRange") | Out-Null
        $RulesTempTbl.Columns.Add("SourceAddressPrefix") | Out-Null
        $RulesTempTbl.Columns.Add("DestinationAddressPrefix") | Out-Null
        $RulesTempTbl.Columns.Add("Access") | Out-Null
        $RulesTempTbl.Columns.Add("Priority") | Out-Null
        $RulesTempTbl.Columns.Add("Direction") | Out-Null

        foreach ($NSG in $NSGList){
            $rules = $NSG.SecurityRules

            foreach ($rule in $rules){
                $RulesTempTbl.Rows.Add($NSG.Name, $NSG.ResourceGroupName, $NSG.Location, $rule.Name, $rule.Protocol, $rule.SourcePortRange -join ' ', $rule.DestinationPortRange  -join ' ', $rule.SourceAddressPrefix  -join ' ', $rule.DestinationAddressPrefix  -join ' ', $rule.Access, $rule.Priority, $rule.Direction) | Out-Null
            }
        }
        $RulesTempTbl | Export-Csv -NoTypeInformation -LiteralPath $folder"\FirewallRules.csv"

        $RulesTempTbl | where Direction -EQ 'Inbound' | where SourceAddressPrefix -eq '*' | where Access -EQ 'Allow' | Export-Csv -NoTypeInformation -LiteralPath $folder"\FirewallRules-AnySourceInboundAllow.csv"

        $RulesTempTbl | where Direction -EQ 'Inbound' | where SourceAddressPrefix -eq '*' | where Access -EQ 'Allow' | where DestinationAddressPrefix -EQ '*' | Export-Csv -NoTypeInformation -LiteralPath $folder"\FirewallRules-AnyAnyInboundAllow.csv"
        $AnyAnyRules = $RulesTempTbl | where Direction -EQ 'Inbound' | where SourceAddressPrefix -eq '*' | where Access -EQ 'Allow' | where DestinationAddressPrefix -EQ '*'
        $AnyRulesCounter = $AnyAnyRules | measure
        $AnyRulesCount = $AnyRulesCounter.Count

        $RulesCounter = $RulesTempTbl | measure
        $RulesCount = $RulesCounter.Count
        Write-Verbose "`t$RulesCount Network Security Group Firewall Rules were enumerated."
        Write-Verbose "`t`t$AnyRulesCount Inbound 'Any Any' Network Security Group Firewall Rules were enumerated."
    }

    if($RBAC -eq "Y"){
        Write-Verbose "Getting RBAC Users and Roles..."    

        # Check Output Path
        if(Test-Path $folder"\RBAC"){}
        else{New-Item -ItemType Directory $folder"\RBAC" | Out-Null}
                
        $roleAssignment = Get-AzureRmRoleAssignment

        # List the Owners and list out any users in groups
        $ownersList = $roleAssignment| where RoleDefinitionName -EQ Owner
        $ownerGroups = $ownersList | where ObjectType -EQ group
        $ownerInherits = foreach ($ownerGroup in $ownerGroups){Get-AzureRmADGroupMember -GroupObjectId $ownerGroup.objectId}
        
        # Write results to file
        if ($ownersList) {
                $ownersList | Export-Csv -NoTypeInformation -LiteralPath $folder"\RBAC\Owners.csv"
                # Write-verbose the counts
                $ownerCounts = ($ownersList| where ObjectType -EQ user).Count
                Write-Verbose "`t$ownerCounts Users with 'Owner' permissions were enumerated."
            }
        if ($ownerInherits){
                $ownerInherits | Export-Csv -NoTypeInformation -LiteralPath $folder"\RBAC\InheritedOwners.csv"
                # Write-verbose the counts
                $ownerCounts = $ownerInherits.Count
                Write-Verbose "`t$ownerCounts Users with group inherited 'Owner' permissions were enumerated."
            }
        
        # Get the Roles, write them out
        $roles = Get-AzureRmRoleDefinition 
        if($roles){$roles | select Name,Id,IsCustom,Description | Export-Csv -NoTypeInformation -LiteralPath $folder"\RBAC\Roles.csv"; $rolesCount = $roles.Count; Write-Verbose "`t$rolesCount roles were enumerated."}

        # Get the Contributors, write them out
        $contributors = $roleAssignment | where RoleDefinitionName -EQ Contributor
        if ($contributors){
            # Output to file
            $contributors | Export-Csv -NoTypeInformation -LiteralPath $folder"\RBAC\Contributors.csv"

            # Contributors that are Group Members
            $contributors | where ObjectType -EQ Group | ForEach-Object{
                $contributorGroupMembers = Get-AzureRmADGroupMember -GroupObjectId $_.ObjectId
                $objDisplayname = (Get-AzureRmADGroup -ObjectId $_.ObjectId).DisplayName
                if ($contributorGroupMembers){
                        $contributorGroupMembers | Export-Csv -NoTypeInformation -LiteralPath $folder"\RBAC\"$objDisplayname"_InheritedContributors.csv"
                        $contributorCounts = $contributorGroupMembers.Count
                        Write-Verbose "`t$contributorCounts Users with 'Contributor' permissions were enumerated."
                    }
                }

        }

    }
    
    Write-Verbose "Done with all tasks for the '$Subscription' Subscription.`n"
}

