<#
    File: Get-AzMachineLearningData.ps1
    Author: Christian Bortone (@xybytes) - 2025
    Description: PowerShell functions for dumping Azure Machine Learning Workspace information.
#>

function Get-AzMachineLearningData {

<#
    .SYNOPSIS
        PowerShell function for dumping information from Azure Machine Learning Workspaces.
    .DESCRIPTION
        The function will dump available information for an Azure ML Workspace. This includes compute instances, resources, models, keys, jobs, endpoints, etc.
    .PARAMETER ResourceGroupName
        Resource group name to use.
    .PARAMETER Subscription
        Subscription to use.
    .PARAMETER folder
        The folder to output to.
    .EXAMPLE
        PS C:\> Get-AzMachineLearningData -folder MLOutput -Verbose
        VERBOSE: Logged In as christian@xybytes.com
        VERBOSE: Dumping Workspaces from the "main-subscription" Subscription
        VERBOSE:  1 Workspace(s) Enumerated
        VERBOSE:   Attempting to dump data from the space03 workspace
        VERBOSE:    Attempting to dump compute data
        VERBOSE:     3 Compute Resource(s) Enumerated
        VERBOSE:    Attempting to dump endpoint data
        VERBOSE:     1 Endpoint(s) Enumerated
        VERBOSE:    Attempting to dump jobs data
        VERBOSE:     2 Compute Job(s) Enumerated
        VERBOSE:    Attempting to dump Models
        VERBOSE:     3 Model(s) Enumerated
        VERBOSE:    Attempting to dump Connection(s)
        VERBOSE:     2 Connection(s) Enumerated
        VERBOSE:      Attempting to dump secret for connection(s)
        VERBOSE:   Completed dumping of the space03 workspace
#>

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory=$false, HelpMessage="Subscription to use.")]
        [string]$Subscription = "",

        [Parameter(Mandatory=$false, HelpMessage="Folder to output to.")]
        [string]$folder = ""
    )

    # Check login status and authenticate if necessary
    $LoginStatus = Get-AzContext
    $accountName = ($LoginStatus.Account).Id
    if ($LoginStatus.Account -eq $null) {
        Write-Warning "No active login. Prompting for login."
        try {
            Connect-AzAccount -ErrorAction Stop
        } catch {
            Write-Warning "Login process failed."
        }
    }

    # Ensure subscription context is set
    if ($Subscription) {
        Select-AzSubscription -SubscriptionName $Subscription | Out-Null
    } else {
        # Prompt user to select subscription(s) if not provided
        $Subscriptions = Get-AzSubscription -WarningAction SilentlyContinue
        $subChoice = $Subscriptions | Out-GridView -Title "Select One or More Subscriptions" -PassThru
        foreach ($sub in $subChoice) {
            Get-AzBatchAccountData -Subscription $sub -folder $folder
        }
        return
    }

    Write-Verbose "Logged In as $accountName"

    # Setup output folder, create if it does not exist
    if ($folder -ne "") {
        if (!(Test-Path $folder)) {
            New-Item -ItemType Directory $folder | Out-Null
        }
    } else {
        $folder = $PWD.Path
    }

    # Suppress breaking change warnings from Az module
    Update-AzConfig -DisplayBreakingChangeWarning $false | Out-Null

    Write-Verbose -Message ('Dumping Workspaces from the "' + (Get-AzContext).Subscription.Name + '" Subscription')

    # Retrieve all ML Workspaces in the specified resource group
    #$workspaces = Get-AzMLWorkspace -ResourceGroupName $ResourceGroupName

    $workspaces = Get-AzResource -ResourceType Microsoft.MachineLearningServices/workspaces

    Write-Verbose "`t$($workspaces.Count) Workspace(s) Enumerated"

    # Iterate through each workspace
    $workspaces | ForEach-Object {

        $currentWorkspace = $_.Name
        $ResourceGroupName = $_.ResourceGroupName

        Write-Verbose "`t`tAttempting to dump data from the $currentWorkspace workspace"

        # Retrieve and save compute resources
        try {
            Write-Verbose "`t`t`tAttempting to dump compute data"
            $computes = Get-AzMLWorkspaceCompute -ResourceGroupName $ResourceGroupName -WorkspaceName $_.Name |
                ForEach-Object {
                    $propAsObj = $_.Property | ConvertFrom-Json

                    [PSCustomObject]@{
                        Name                                 = $_.Name
                        computeType                          = $propAsObj.properties.computeType
                        Id                                   = $_.Id
                        IdentityType                         = $_.IdentityType
                        Location                             = $_.Location
                        createdOn                            = $propAsObj.createdOn
                        modifiedOn                           = $propAsObj.modifiedOn
                        isAttachedCompute                    = $propAsObj.isAttachedCompute
                        disableLocalAuth                     = $propAsObj.disableLocalAuth
                        subnet                               = $propAsObj.properties.subnet.id
                        sshPublicAccess                      = $propAsObj.properties.sshSettings.sshPublicAccess
                        adminUserName                        = $propAsObj.properties.sshSettings.adminUserName
                        sshPort                              = $propAsObj.properties.sshSettings.sshPort
                        publicIpAddress                      = $propAsObj.properties.connectivityEndpoints.publicIpAddress
                        privateIpAddress                     = $propAsObj.properties.connectivityEndpoints.privateIpAddress
                        lastOperation                        = $propAsObj.properties.lastOperation.operationTime
                        schedules                            = $propAsObj.properties.schedules.computeStartStop
                        vmSize                               = $propAsObj.properties.vmSize
                        applicationSharingPolicy             = $propAsObj.properties.applicationSharingPolicy
                        endpointUri                          = $propAsObj.properties.applications.endpointUri
                        state                                = $propAsObj.properties.state
                    }
                }

            Write-Verbose "`t`t`t`t$($computes.Count) Compute Resource(s) Enumerated"
            $computes | Out-File -Append "$folder\$currentWorkspace-Computes.txt"
        } catch {
            Write-Warning "Failed to retrieve compute instances for workspace: $currentWorkspace"
        }

        # Retrieve and save online endpoints
        try {
            Write-Verbose "`t`t`tAttempting to dump endpoint data"
            $workspace_name = $_.Name
            $endpoints = Get-AzMLWorkspaceOnlineEndpoint -ResourceGroupName $ResourceGroupName -WorkspaceName $workspace_name |
                ForEach-Object {

                    $propAsObj = $_.EndpointPropertiesBaseProperty | ConvertFrom-Json
                    $sysdataAsObj = $_.SystemData | ConvertFrom-Json
                    $keys = Get-AzMLWorkspaceOnlineEndpointKey -ResourceGroupName $ResourceGroupName -WorkspaceName $workspace_name -Name $_.Name

                    [PSCustomObject]@{
                        Name                            = $_.Name
                        Id                              = $_.Id
                        Description                     = $_.Description
                        AuthMode                        = $_.AuthMode
                        Type                            = $_.Type
                        ScoringUri                      = $_.ScoringUri
                        SwaggerUri                      = $_.SwaggerUri
                        CreatedBy                       = $sysdataAsObj.createdBy
                        CreatedAt                       = $sysdataAsObj.createdAt
                        LastModifiedAt                  = $sysdataAsObj.lastModifiedAt
                        SystemDataCreatedAt             = $_.SystemDataCreatedAt
                        Onlineendpointid                = $propAsObj.'azureml.onlineendpointid'
                        AzureAsyncOperationUri          = $propAsObj.AzureAsyncOperationUri
                        PrimaryKey                      = $keys.PrimaryKey
                        SecondaryKey                    = $keys.SecondaryKey
                    }
                }

            Write-Verbose "`t`t`t`t$($_.Name.Count) Endpoint(s) Enumerated"
            $endpoints | Out-File -Append "$folder\$currentWorkspace-Endpoints.txt"
        } catch {
            Write-Warning "Failed to retrieve endpoints for workspace: $currentWorkspace"
        }

        # Retrieve and save jobs
        try {
            Write-Verbose "`t`t`tAttempting to dump jobs data"
            $jobs = Get-AzMLWorkspaceJob -ResourceGroupName $ResourceGroupName -WorkspaceName $_.Name |
                ForEach-Object {

                    $propAsObj = $_.Property | ConvertFrom-Json

                    [PSCustomObject]@{
                        Name                            = $_.Name
                        Id                              = $_.Id
                        SystemDataCreatedAt             = $_.SystemDataCreatedAt
                        SystemDataCreatedBy             = $_.SystemDataCreatedBy
                        jobType                         = $propAsObj.jobType
                        endpoint                        = $propAsObj.services.Studio.endpoint
                        command                         = $propAsObj.command
                        environmentId                   = $propAsObj.environmentId
                        outputs                         = $propAsObj.outputs.default
                    }
                }

            Write-Verbose "`t`t`t`t$($jobs.Count) Compute Job(s) Enumerated"
            $jobs | Out-File -Append "$folder\$currentWorkspace-Jobs.txt"
        } catch {
            Write-Warning "Failed to retrieve jobs for workspace: $currentWorkspace"
        }

        # Retrieve and save models
        try {
            Write-Verbose "`t`t`tAttempting to dump Models"
            $models = Get-AzMLWorkspaceModelContainer -ResourceGroupName $ResourceGroupName -WorkspaceName $_.Name |
                ForEach-Object {

                    [PSCustomObject]@{
                        Name                            = $_.Name
                        Id                              = $_.Id
                        SystemDataCreatedAt             = $_.SystemDataCreatedAt
                        Type                            = $_.Type
                        ProvisioningState               = $_.ProvisioningState
                        IsArchived                      = $_.IsArchived
                    }
                }

            Write-Verbose "`t`t`t`t$($models.Count) Model(s) Enumerated"
            $models | Out-File -Append "$folder\$currentWorkspace-Models.txt"
        } catch {
            Write-Warning "Failed to retrieve models for workspace: $currentWorkspace"
        }

        # Gather and store connections and keys
        Write-Verbose "`t`t`tAttempting to dump Connection(s)"
        $url = "https://management.azure.com/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/Microsoft.MachineLearningServices/workspaces/$currentWorkspace/connections?api-version=2023-08-01-preview"

        try {
            $AccessToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
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
            if (-not $Token) {
                Write-Error "Unable to retrieve the access token. Make sure you are logged in using Az PowerShell."
                exit 1
            }
        } catch {
            Write-Error "Error while obtaining the access token: $_"
            exit 1
        }

        # HTTP headers
        $headers = @{ 
            "Authorization" = "Bearer $Token"
            "Content-Type"  = "application/json"
        }

        try {
            # HTTP request to access connections within the workspace.
            $connectionsResponse = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop
            Write-Verbose "`t`t`t`t$($connectionsResponse.value.Count) Connection(s) Enumerated"
        } catch {
            Write-Error "Error while fetching connections: $_"
            exit 1
        }

        # For each connection, retrieve the secret.
        Write-Verbose "`t`t`t`t`tAttempting to dump secret for connection(s)"
        foreach ($connection in $connectionsResponse.value) {
            try {
                $connectionName = $connection.name
                $secretUrl = "https://management.azure.com/subscriptions/$Subscription/resourceGroups/$ResourceGroupName/providers/Microsoft.MachineLearningServices/workspaces/$currentWorkspace/connections/$connectionName/listsecrets?api-version=2023-08-01-preview"
                $secretsResponse = Invoke-RestMethod -Uri $secretUrl -Method Post -Headers $headers -ErrorAction Stop -Verbose:$false 4>$null

                $connectionObject = [PSCustomObject]@{
                    Name   = $connection.name
                    Type   = $connection.type
                    Secret = $secretsResponse.properties.credentials.key
                }

                $connectionObject | Out-File -Append "$folder\$currentWorkspace-Connections.txt"
            } catch {
                Write-Error "Error processing connection '$($connection.name)': $_"
            }
        }

        Write-Verbose "`t`tCompleted dumping of the $currentWorkspace workspace"
    }
}