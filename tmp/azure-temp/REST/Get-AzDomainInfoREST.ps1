#Offload nextLink parsing to a separate function to avoid bloat
Function Get-RESTReq {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="The management scoped token")]
        [string]$managementToken,
        [Parameter(Mandatory=$true)]
        [string]$resourceURI
    )

    $runningList = @()

    $list = ((Invoke-WebRequest -Uri $resourceURI -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json)

    $runningList += $list.value

    $nextKeys = $list.nextLink

    #If we have a nextKeys param, loop until we exhaust it
    while($nextKeys -ne $null){
        $getNext = ((Invoke-WebRequest -Uri $nextKeys -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content | ConvertFrom-Json)
        $nextKeys = $getNext.nextLink
        $list += $getNext.value
    }

    $runningList
}

Function Get-AzDomainInfoREST {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription ID")]
        [string]$SubscriptionId,

        [Parameter(Mandatory=$false,
        HelpMessage="The management scoped token")]
        [string]$managementToken,
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
        [String]$RBAC = "Y"

    )

    if ($SubscriptionId -eq ''){

        # List all subscriptions for a tenant
        $subscriptions = ((Invoke-WebRequest -Uri ('https://management.azure.com/subscriptions?api-version=2019-11-01') -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json).value
        # Select which subscriptions to dump info for
        $subChoice = $subscriptions | out-gridview -Title "Select One or More Subscriptions" -PassThru
        if($subChoice.count -eq 0){Write-Verbose 'No subscriptions selected, exiting'; break}
        $SubscriptionId = $subChoice.subscriptionId

    }
    else{$subChoice = $SubscriptionId; $noLoop = 1}

    Write-Verbose "Dumping information for subscription $SubscriptionID"

    # Folder Parameter Checking - Creates Az folder to separate from MSOL folder
    if ($folder){
        if(Test-Path $folder){
            if(Test-Path $folder"\Az"){}
            else{New-Item -ItemType Directory $folder"\Az"|Out-Null}}
        else{New-Item -ItemType Directory $folder|Out-Null ; New-Item -ItemType Directory $folder"\Az"|Out-Null}; $folder = -join ($folder, "\Az")}
    else{if(Test-Path Az){}else{New-Item -ItemType Directory Az|Out-Null};$folder= -join ($pwd, "\Az")}

    $resourceGroups = ((Invoke-WebRequest -uri (-join ("https://management.azure.com/subscriptions/",$SubscriptionId,"/resourcegroups?api-version=2020-10-01") ) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json).value

    $subName = $subChoice.displayName


    #Quirk here: not sure if it's possible to enumerate files via REST
    if($StorageAccounts -eq "Y"){

        #Get list of storage accounts
        Write-Verbose "Getting Storage Accounts..."

        $storageACCTs = Get-RESTReq -managementToken $managementToken -resourceURI (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,'/providers/Microsoft.Storage/storageAccounts?api-version=2019-06-01'))


        # Check Output Path
        if(Test-Path $folder"\Files"){}
        else{New-Item -ItemType Directory $folder"\Files" | Out-Null}

        foreach($account in $storageACCTs){

            #Check output path
            if(Test-Path $folder"\Files\"$strgName){}
            else{New-Item -ItemType Directory $folder"\Files\"$strgName | Out-Null}

            $strgName = $account.name

            Write-Verbose "`tGetting containers for $strgName storage account"

            #Get list of containers and iterate through them
            $containers = Get-RESTReq -managementToken $managementToken -resourceURI (-join ("https://management.azure.com", $account.id,"/blobservices/default/containers?api-version=2021-01-01"))
            foreach($container in $containers){
                $pathName = "\Files\"+$strgName+"\Blob_Files_"+$container.Name

                #Check if the container is public and write it to a file
                if($container.properties.publicAccess -eq "Container"){
                    $containerName = $container.name
                    $blobUrl = (-join ("https://$strgName.blob.core.windows.net/$containerName/"))
                    Write-Verbose "`t`t$containerName container is Public"
                    $blobUrl >> $folder"\Files\ContainersFileUrls.txt"
                }
            }

            #Enumerate through other storage resources
            $shares = Get-RESTReq -managementToken $managementToken -resourceURI (-join ("https://management.azure.com", $account.id,"/fileServices/default/shares?api-version=2021-01-01"))
            foreach($share in $shares){
                #Write-Output (-join ("Storage account ",$strgName, " has share ", $share.name))
            }
            $tables =  Get-RESTReq -managementToken $managementToken -resourceURI (-join ("https://management.azure.com", $account.id,"/tableServices/default/tables?api-version=2021-01-01"))
            foreach($table in $tables){
                #Write-Output (-join ("Storage account ", $strgName, " has share ", $table.name))
            }
            $queues = Get-RESTReq -managementToken $managementToken -resourceURI (-join ("https://management.azure.com", $account.id,"/queueServices/default/queues?api-version=2021-01-01"))
            foreach($queue in $queues){
                #Write-Output (-join ("Storage account ", $strgName, " has queue ", $queue.name))
            }
        }
        $storageCount = $StorageACCTs.count
        Write-Verbose "`t$storageCount storage accounts were found."
    }


    if($Resources -eq "Y"){

    if(Test-Path $folder"\Resources"){}
    else{New-Item -ItemType Directory $folder"\Resources\" | Out-Null}

    Write-Verbose "Getting AzureSQL Resources..."

    $sqlServers = Get-RESTReq -managementToken $managementToken -resourceURI (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/providers/Microsoft.Sql/servers?api-version=2020-08-01-preview"))
    Write-Output $sqlServers
    $count = $sqlServers.count
    Write-Verbose "`t$azureSQLServersCount AzureSQL servers were enumerated."
    #Need to loop back to this since I don't have any spun up on my infra
    #foreach($server in $sqlServers){
    #    $databases = (((Invoke-WebRequest -Uri (-join ('https://management.azure.com',$server.id,'/databases?api-version=2020-08-01-preview')) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).Content) | ConvertFrom-Json).value
    #}


    Write-Verbose "Getting Azure App Services..."
    $appServices = Get-RESTReq -managementToken $managementToken -resourceURI (-join ("https://management.azure.com/subscriptions/",$SubscriptionId,"/providers/Microsoft.Web/sites?api-version=2019-08-01"))
    foreach($app in $appServices){
       $app.properties | select State,@{name="HostNames";expression={$_.HostNames}},RepositorySiteName,UsageState,Enabled,@{name="EnabledHostNames";expression={$_.EnabledHostNames}},AvailabilityState,@{name="HostNameSslStates";expression={$_.hostNameSslStates}},ServerFarmId,Reserved,LastModifiedTimeUtc,SiteConfig,TrafficManagerHostNames,ScmSiteAlsoStopped,targetSwapSlot,hostingEnvironmentProfile,ClientAffinityEnabled,ClientCertEnabled,HostNamesDisabled,OutboundIpAddresses,PossibleOutboundIpAddresses,ContainerSize,DailyMemoryTimeQuota,SuspendedTill,MaxNumberOfWorkers,CloningInfo,SnapshotInfo,ResourceGroup,IsDefaultContainer,DefaultHostName,SlotSwapStatus,HttpsOnly,Identity,@{name="ID";expression={$app.id}},@{name="Name";expression={$app.name}},@{name="Kind";expression={$app.kind}},@{name="Location";expression={$app.location}},@{name="Type";expression={$app.type}},@{name="Tags";expression={$app.tags}} | Export-Csv -NoTypeInformation -LiteralPath $folder"\Resources\AppServices.CSV"
    }
    $count = $appServices.count
    Write-Verbose "`t$count App Services enumerated"


    Write-Verbose "Getting Azure Disks..."
    $disks = Get-RESTReq -managementToken $managementToken -resourceURI (-join ("https://management.azure.com/subscriptions/",$SubscriptionId,"/providers/Microsoft.Compute/disks?api-version=2020-12-01"))
    $disks | Export-CSV -NoTypeInformation -LiteralPath $folder"\Resources\Disks.CSV"
    $disks | ForEach-Object{if($_.properties.encryption -eq ""){$_.Name | Out-File -LiteralPath $folder"\Resources\Disks-NoEncryption.txt"}}

    $diskDT = New-Object System.Data.DataTable("disks")
    $columns = @("ResourceGroupName", "TimeCreated", "OsType", "DiskSizeGB", "DiskSizeBytes", "UniqueId", "ProvisioningState", "DiskIOPSReadWrite", "DiskMBpsReadWrite", "DiskState", "Id", "Name", "Location", "Encryption")
    foreach($col in $columns){$diskDT.Columns.Add($col) | Out-Null}
    foreach($disk in $disks){

        $diskProps = $disk.properties
        $diskDT.Rows.Add($disk.name, $diskProps.timeCreated, $diskProps.osType, $diskProps.diskSizeGB, $diskProps.diskSizeBytes, $diskProps.uniqueId, $diskProps.provisioningState, $diskProps.diskIOPSReadWrite, $diskProps.diskMBpsReadWrite, $diskProps.diskState, $disk.id, $disk.name, $disk.location, $diskProps.encryption) | Out-Null
    }

    $diskDT | Export-Csv -NoTypeInformation -LiteralPath $folder"\Resources\Disks.csv"
    $count = $disks.count
    Write-Verbose "`t$count Disks were enumerated."

    #TODO: Deployments

    Write-Verbose "Getting Key Vault Policies..."

    $keyVaults = Get-RESTReq -managementToken $managementToken -resourceURI (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/resources?`$filter=resourceType eq 'Microsoft.KeyVault/vaults'&api-version=2019-09-01"))
    foreach($vault in $keyVaults){
        $vaultDetails = ((Invoke-WebRequest -Uri (-join ("https://management.azure.com",$vault.id,"?api-version=2019-09-01")) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | convertfrom-json)
        $vaultPerms = $vaultDetails.properties.accessPolicies.permissions
        #Bit of a hack to expand the objects in our CSV
        [pscustomobject]@{
            Keys = $vaultPerms.keys -join ','
            Secrets = $vaultPerms.secrets -join ','
            Certificates = $vaultPerms.certificates -join ','
        } | Export-Csv -NoTypeInformation -LiteralPath (-join ($folder,'\Resources\',$vault.name,'-Vault_Policies.csv'))
    }

    #Write-Verbose "Getting Resource Groups..."
    #$resourceGroups = ((Invoke-WebRequest -uri (-join ("https://management.azure.com/subscriptions/",$SubscriptionId,"/resourcegroups?api-version=2020-10-01") ) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | ConvertFrom-Json).value
    #foreach($rg in $resourceGroups){
    #    $rg | select ResourceGroupName,Location,ProvisioningState,ResourceId | Export-CSV -NoTypeInformation -LiteralPath $folder"\Resources\Resource_Groups.CSV"
    #}

    Write-Verbose "Getting Automation Account Runbooks and Variables..."

    $automationAccounts = Get-RESTReq -managementToken $managementToken -resourceURI (-join ("https://management.azure.com/subscriptions/",$SubscriptionId,"/providers/Microsoft.Automation/automationAccounts?api-version=2015-10-31"))
    if($automationAccounts){
        if(Test-Path $folder"\Resources\AutomationAccounts"){}
        else{New-Item -ItemType Directory $folder"\Resources\AutomationAccounts" | Out-Null}
    }
    foreach($account in $automationAccounts){
        if(Test-Path (-join ($folder,"\Resources\AutomationAccounts\",$account.name))){}
        else{New-Item -ItemType Directory (-join ($folder,"\Resources\AutomationAccounts\",$account.name)) | Out-Null}
        $runbooks = Get-RESTReq -managementToken $managementToken -resourceURI (-join ("https://management.azure.com" + $account.id + "/runbooks?api-version=2015-10-31"))
        foreach($runbook in $runbooks){
            try{
            $content = (Invoke-WebRequest -uri (-join ("https://management.azure.com" + $runbook.id + "/content?api-version=2015-10-31") ) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing)
            if($content.Headers["Content-Type"] -eq "text/powershell"){
                $content.Content | Out-File -FilePath (-join ($folder,"\Resources\AutomationAccounts\",$account.name,"\",$runbook.name,".txt"))
                }
            }
            #We get a 404 on runbooks that haven't been published yet, might change this to just create an empty text file
            catch [System.Net.WebException]{
            }
        }
        $variables = Get-RESTReq -managementToken $managementToken -resourceURI (-join ("https://management.azure.com" + $account.id + "/variables?api-version=2015-10-31") )
        $variables | Select name, properties | Out-File -FilePath (-join ($folder,"\Resources\AutomationAccounts\",$account.name,"\","Variables.txt")) #-Append
    }
    $count = $automationAccounts.count
    Write-Verbose "`t$count Automation Accounts were enumerated."

    }

    if($NetworkInfo -eq "Y"){
    Write-Verbose "Getting Network Interfaces..."
    if(Test-Path $folder"\Interfaces"){}
    else{New-Item -ItemType Directory $folder"\Interfaces\" | Out-Null}

    $networkInterfaces = Get-RESTReq -managementToken $managementToken -resourceURI (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/providers/Microsoft.Network/networkInterfaces?api-version=2020-11-01"))
    foreach($interface in $networkInterfaces){
        $NICName = $interface.name
        foreach($prop in $interface.properties){
            $prop.ipConfigurations.properties | select PrivateIpAddressVersion,Primary,LoadBalancerBackendAddressPoolsText,LoadBalancerInboundNatRulesText,ApplicationGatewayBackendAddressPoolsText,ApplicationSecurityGroupsText,PrivateIpAddress,PrivateIpAllocationMethod,ProvisioningState,SubnetText,PublicIpAddressText,Name,Etag,Id | Export-Csv -NoTypeInformation -LiteralPath $folder"\Interfaces\"$NICName"-ipConfig.csv"
        }

     }
    Write-Verbose("`tGetting Public IPs for each network interface...")

    $publicIpTbl = New-Object System.Data.DataTable
    $publicIpTbl.Columns.Add("Name") | Out-Null
    $publicIpTbl.Columns.Add("IPAddress") | Out-Null
    $publicIpTbl.Columns.Add("PublicIPAllocationMethod") | Out-Null
    $publicIpTbl.Columns.Add("ResourceGroup") | Out-Null

    $publicIps = Get-RESTReq -managementToken $managementToken -resourceURI (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/providers/Microsoft.Network/publicIPAddresses?api-version=2020-11-01"))

    $publicIpCount = 0
    foreach($ip in $publicIps){
        if($ip.properties.ipAddress){
            $publicIpTbl.Rows.Add($ip.name, $ip.properties.IPAddress, $ip.properties.publicIPAllocationMethod, $ip.id.split('/')[4]) | Out-Null
            $publicIpCount += 1
        }
    }
    $publicIpTbl | Export-Csv -NoTypeInformation -LiteralPath $folder"\PublicIPs.csv"
    Write-Verbose("`t$publicIPCount Public IP Addresses were found")

    Write-Verbose "`tGetting Network Security Groups..."
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

    $networkSecurityGroups = Get-RESTReq -managementToken $managementToken -resourceURI (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/providers/Microsoft.Network/networkSecurityGroups?api-version=2020-11-01"))
    foreach($group in $networkSecurityGroups){
        $NSGName = $group.name
        $NSGRG = $group.id.split('/')[4]
        $NSGLocation = $group.location
        foreach($rule in $group.properties.securityRules){
            $RulesTempTbl.Rows.Add($NSGName, $NSGRG, $NSGLocation, $rule.name, $rule.properties.protocol, $rule.properties.sourcePortRange -join ' ', $rule.properties.DestinationPortRange -join ' ', $rule.properties.SourceAddressPrefix -join ' ', $rule.properties.DestinationAddressPrefix -join ' ', $rule.properties.Access, $rule.properties.priority, $rule.properties.direction) | Out-Null
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

    if($VMs -eq "Y"){


    # Create folder for VM Info for cleaner output
    if(Test-Path $folder"\VirtualMachines"){}
    else{New-Item -ItemType Directory $folder"\VirtualMachines\" | Out-Null}

    $virtualMachines = Get-RESTReq -managementToken $managementToken -resourceURI (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/providers/Microsoft.Compute/virtualMachines?api-version=2020-06-01"))
    $vmDT = New-Object System.Data.DataTable("vms")
    $columns = @("ResourceGroupName","Name","Location","ProvisioningState")
    foreach($col in $columns){$vmDT.Columns.Add($col) | Out-Null}
    foreach($vm in $virtualMachines){
        $vmDetails = (Invoke-WebRequest -uri (-join ("https://management.azure.com" + $vm.id + "?api-version=2020-06-01") ) -Verbose:$false -Method GET -Headers @{ Authorization ="Bearer $managementToken"} -UseBasicParsing).content | convertfrom-json
        $vmDT.Rows.Add($vmDetails.id, $vmDetails.name, $vmDetails.location, $vmDetails.properties.provisioningState) | Out-Null
    }

    $vmDT | Export-Csv -NoTypeInformation -LiteralPath $folder"\VirtualMachines\VirtualMachines-Basic.csv"

    $count = $virtualMachines.count
    Write-Verbose "`t$count Virtual Machines enumerated."
   }

   if($RBAC -eq "Y"){

    if(Test-Path $folder"\RBAC"){}
    else{New-Item -ItemType Directory $folder"\RBAC\" | Out-Null}

    $principalPermissionsTbl = New-Object System.Data.DataTable
    $principalPermissionsTbl.Columns.Add("PrincipalID") | Out-Null
    $principalPermissionsTbl.Columns.Add("RoleName") | Out-Null
    $principalPermissionsTbl.Columns.Add("Scope") | Out-Null


    #Can just grab our identity's principal ID from our JWT
    $tokenPayload = $managementToken.split('.')[1]
    while($tokenPayload.Length % 4){$tokenPayload += "="}
    $tokenJson = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenPayload)) | ConvertFrom-Json
    $currentPrincipalID = $tokenJson.oid
    $roleDefinitions = Get-RESTReq -managementToken $managementToken -resourceURI (-join('https://management.azure.com/subscriptions/',$SubscriptionID,'/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01'))
    $ownerGUID = ($roleDefinitions | ForEach-Object{ if ($_.properties.RoleName -eq 'Owner'){$_.name}})
    $rbacAssignments = Get-RESTReq -managementToken $managementToken -resourceURI (-join ('https://management.azure.com/subscriptions/',$SubscriptionId,"/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01"))
    foreach($def in $rbacAssignments.properties){
       $roleDefID = $def.roleDefinitionId.split("/")[6]


        $roleName = ($roleDefinitions | foreach-object {if ($_.name -eq $roleDefID){$_.properties.RoleName}})
        if($roleName){
            $principalPermissionsTbl.Rows.Add($def.principalId, $roleName, $def.scope) | out-null
            if($def.principalId -eq $currentPrincipalID){
                Write-Verbose (-join ("Current identity has permission ", $roleName, " on scope ", $def.scope))
            }
            else{
                #Write-Verbose (-join ("Principal ", $def.principalId, " has permission ", $roleName, " on scope ", $def.scope))
            }
        }
     }

     $readers = $principalPermissionsTbl.Select("RoleName = 'Reader'")
     if($readers){$readers | Export-CSV -NoTypeInformation -LiteralPath $folder"\RBAC\Readers.csv"}
     $contributors = $principalPermissionsTbl.Select("RoleName = 'Contributor'")
     if($contributors){$contributors | Export-CSV -NoTypeInformation -LiteralPath $folder"\RBAC\Contributors.csv"}
     $owners = $principalPermissionsTbl.Select("RoleName = 'Owner'")
     if($owners){$owners | Export-CSV -NoTypeInformation -LiteralPath $folder"\RBAC\Owners.csv"}
     $currentIdentityPerms = $principalPermissionsTbl.Select("PrincipalID = '$currentPrincipalID'")
     if($currentIdentityPerms){$currentIdentityPerms | Export-CSV -NoTypeInformation -LiteralPath $folder"\RBAC\CurrentIdentity.csv"}

   }
}
