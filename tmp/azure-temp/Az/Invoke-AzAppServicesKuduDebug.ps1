<#
    File: Invoke-AzAppServicesKuduDebug.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2024
    Description: PowerShell function for running commands against a Windows Container App Services host, via the Kudu Debug Console (PowerShell or CMD) Shell

#>

Function Invoke-AzAppServicesKuduDebug {
<#
    .SYNOPSIS
        Runs a command against a Windows Container App Services host via the Kudu Debug Console (PowerShell or CMD Shell).
    .DESCRIPTION
        This function will run a command against a Windows Container App Services host. This can aid in enumerating environment variables for secrets, obtaining Managed Identities tokens at scale, or searching file systems for configuration files.
    .PARAMETER command
        The command to run against the host.
    .PARAMETER appName
        The name of the application to target.
    .PARAMETER Username
        The username for connecting to host. The script will attempt to fetch a username from the publishing profile if not provided.
    .PARAMETER password
        The Password for connecting to the host. The script will attempt to fetch a password from the publishing profile if not provided.
    .EXAMPLE
        To run against a single host with the Username and Password
        PS C:\MicroBurst> Invoke-AzAppServicesKuduDebug -Verbose -command "dir D:\home" -AppName "Target-App"  -Username "`$Target-App" -Password "[redacted]"
    .EXAMPLE
        To run as the authenticated Az PowerShell user and select multiple hosts to run commands against
        PS C:\MicroBurst> Invoke-AzAppServicesKuduDebug -Verbose -command "dir D:\home"
        
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Subscription to use.")]
        [string]$Subscription = "",
        
        [Parameter(Mandatory=$true,
        HelpMessage="The command to run.")]
        [string]$Command = "",

        [Parameter(Mandatory=$false,
        HelpMessage="The name of the App to target.")]
        [string]$AppName = "",

        [Parameter(Mandatory=$false,
        HelpMessage="The type of prompt to use.")]
        [ValidateSet("powershell","CMD")]
        [string]$PromptType = "powershell",

        [Parameter(Mandatory=$false,
        HelpMessage="The username for connecting to the App Service. The script will attempt to fetch a username from the publishing profile if not provided.")]
        [string]$Username = "",

        [Parameter(Mandatory=$false,
        HelpMessage="The password for connecting to the App Service. The script will attempt to fetch a password from the publishing profile if not provided.")]
        [string]$Password = "",

        [Parameter(Mandatory=$false,
        HelpMessage="The flag for using your existing user's RBAC role permissions to execute the command. Generates a management token to use against the Kudu APIs")]
        [switch]$rbac

    )
   
    # If no User/Pass provided
    if(($Username -eq "") -and ($Password -eq "")){

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
            foreach ($sub in $subChoice) {
                if ($rbac){Invoke-AzAppServicesKuduDebug -Subscription $sub -Command $Command -AppName $AppName -Username $Username -Password $Password -PromptType $PromptType -rbac}
                else{Invoke-AzAppServicesKuduDebug -Subscription $sub -Command $Command -AppName $AppName -Username $Username -Password $Password -PromptType $PromptType}
            }
            break
        }

        Write-Verbose "Logged In as $accountName"

        # List Apps in the subscription, pipe out to gridview selection
        $ProgressPreference = "SilentlyContinue"
        
        $subName = (Get-AzSubscription -SubscriptionId $Subscription).Name
        Write-Verbose "Enumerating running App Services Applications with Windows Containers in the `"$subName`" Subscription"

        # Filter on App Services Container type - This funciton only supports Windows images
        $appsList = Get-AzWebApp | where state -EQ "Running" | where Kind -NotMatch "linux" | select Name,ResourceGroup,Kind | sort Name
        $appChoice = $appsList | out-gridview -Title "Select One or More Applications" -PassThru
        if($null -eq $appChoice){Write-Verbose "No Apps Selected"; break}

        # For each app, grab the publish profile
        foreach ($app in $appChoice){
            $appObject = Get-AzWebApp -Name $app.Name

            if(!$rbac){
                Write-Verbose "`tAttempting to run the `"$Command`" command (via $PromptType) on the container for the `"$($app.Name)`" application using publishing credentials"
                try{
                    [xml]$publishProfile = Get-AzWebAppPublishingProfile -Name $appObject.Name -ResourceGroupName $appObject.ResourceGroup
    
                    #They should all be the same so we can just grab the first
                    if($publishProfile){
                        $Username = $publishProfile.publishData.publishProfile[0].userName
                        $Password = $publishProfile.publishData.publishProfile[0].userPWD
                    }
                }
                catch{
                    Write-Error "$AppName - Either no publishing credentials were available or you have insufficient permissions"
                    break
                }
                Invoke-AzAppServKuduCMDExec -command $Command -username $Username -password $Password -appName $appObject.Name -PromptType $PromptType -AppHost $($appObject.EnabledHostNames | Where-Object {$_ -like "*.scm.*"})
            }
            else{
                Write-Verbose "`tAttempting to run the `"$Command`" command (via $PromptType) on the container for the `"$($app.Name)`" application using RBAC permissions"
                Invoke-AzAppServKuduCMDExec -command $Command -appName $appObject.Name -PromptType $PromptType -AppHost $($appObject.EnabledHostNames | Where-Object {$_ -like "*.scm.*"}) -rbac
            }
        }
        Write-Verbose "App Services Command Execution Completed in the `"$subName`" Subscription"
    }
    elseif(($AppName -eq "") -or ($Username -eq "") -or ($Password -eq "")){
        Write-Host "If publish profile username and password are in use, AppName is a required parameter. Check your parameters."
        break
    }
    elseif($rbac){
        # Run the command with RBAC
        Write-Verbose "`tAttempting to run the `"$Command`" command (via $PromptType) on the container for the $AppName application using RBAC permissions"
        Invoke-AzAppServKuduCMDExec -command $Command -username $Username -password $Password -appName $AppName -PromptType $PromptType -rbac

    }
    else{
        # Run the command with User/Pass
        Write-Verbose "`tAttempting to run the `"$Command`" command (via $PromptType) on the container for the $AppName application using publishing credentials"
        Invoke-AzAppServKuduCMDExec -command $Command -username $Username -password $Password -appName $AppName -PromptType $PromptType
    }
}


Function Invoke-AzAppServKuduCMDExec {
<#
    Supporting Function        
#>
    [CmdletBinding()]
    Param(
        
        [Parameter(Mandatory=$true,
        HelpMessage="The command to run.")]
        [string]$command = "",

        [Parameter(Mandatory=$false,
        HelpMessage="The name of the App to target.")]
        [string]$appName = "",

        [Parameter(Mandatory=$false,
        HelpMessage="The SCM hostname of the App to target.")]
        [string]$AppHost = "",
        
        [Parameter(Mandatory=$false,
        HelpMessage="The type of prompt to use.")]
        [string]$PromptType = "powershell",

        [Parameter(Mandatory=$false,
        HelpMessage="The username for connecting to the App Service. The script will attempt to fetch a username from the publishing profile if not provided.")]
        [string]$username = "",

        [Parameter(Mandatory=$false,
        HelpMessage="The password for connecting to the App Service. The script will attempt to fetch a password from the publishing profile if not provided.")]
        [string]$password = "",

        [Parameter(Mandatory=$false,
        HelpMessage="The flag for using your existing user's RBAC role permissions to execute the command. Generates a management token to use against the Kudu APIs")]
        [switch]$rbac

    )

    if($rbac){
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
        $authHeader = @{Authorization="Bearer $mgmtToken"}
    }
    else{
        # Convert these to a basic authentication header
        $basicHeader = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes((-join($username,":",$password))))
        $authHeader = @{Authorization="Basic $basicHeader"}
    }

    $tid = get-random -Minimum 0 -Maximum 10
    $timeStamp = Get-Date -UFormat %s -Millisecond 0


    # Send the Negotiate Request
    $cmdReq = Invoke-WebRequest -Verbose:$false -Method Get -Uri (-join ("https://",$AppHost,"/api/commandstream/negotiate?clientProtocol=1.4&shell=$promptType&_=0")) -Headers $authHeader 
    $cmdResult = ($cmdReq.Content | ConvertFrom-Json)
    Add-Type -AssemblyName System.Web
    $connectionToken = ([System.Web.HttpUtility]::UrlPathEncode($cmdResult.ConnectionToken)).Replace('+',"%2b")

    # Send the Message ID Request
    $cmdLongPollReq = Invoke-WebRequest -Verbose:$false -Method Get -Uri (-join ("https://",$AppHost,"/api/commandstream/connect?transport=longPolling&clientProtocol=1.4&shell=$promptType&connectionToken=$connectionToken&tid=$tid&_=$timeStamp")) -Headers $authHeader -ContentType 'application/json; charset=UTF-8'
    $messageId = ($cmdLongPollReq.Content |ConvertFrom-Json).C

    # Start the command stream
    $cmdSendReq = Invoke-WebRequest -Verbose:$false -Method Get -Uri (-join ("https://",$AppHost,"/api/commandstream/start?transport=longPolling&clientProtocol=1.4&shell=$promptType&connectionToken=$connectionToken")) -Headers $authHeader -ContentType 'application/json; charset=UTF-8'

    # Send the Send Command Request
    $postParams = @{data=$(-join($command,"`n"))}
    $cmdSendReq = Invoke-WebRequest -Verbose:$false -Method Post -Uri (-join ("https://",$AppHost,"/api/commandstream/send?transport=longPolling&clientProtocol=1.4&shell=$promptType&connectionToken=$connectionToken")) -Body $postParams -Headers $authHeader -ContentType 'application/x-www-form-urlencoded; charset=UTF-8'

    # Send the Poll Request
    $mValueNext = ""
    $messageIdCurrent = $messageId
    $outputString = ""

    while(1)
    {
        # Grab random TID and set epoch timestamp
        $tid = get-random -Minimum 0 -Maximum 10
        $timeStamp = Get-Date -UFormat %s -Millisecond 0
    
        # Try the poll request, fail on timeout
        try{
            $cmdPollReq = Invoke-WebRequest -Verbose:$false -Method Get -Uri (-join ("https://",$AppHost,"/api/commandstream/poll?transport=longPolling&messageId=$messageIdCurrent&clientProtocol=1.4&shell=$promptType&connectionToken=$connectionToken&tid=$tid&_=$timeStamp")) -Headers $authHeader -TimeoutSec 2 -ErrorAction Continue
        }
        Catch{}
    
        # Capture next message ID
        $mValueNext = ($cmdPollReq.Content | ConvertFrom-Json).C
    
        # If new message ID matches the current/old one, then break
        if($mValueNext -eq $messageIdCurrent){
            break
        }
        else{$messageIdCurrent = $mValueNext}

        # Write output
        $outputString += ($cmdPollReq.Content | ConvertFrom-Json).M.Output

    }

    # end the session on the container
    $cmdAbortReq = Invoke-WebRequest -Verbose:$false -Method Post -Uri (-join ("https://",$AppHost,"/api/commandstream/abort?transport=longPolling&clientProtocol=1.4&shell=$promptType&connectionToken=$connectionToken")) -Headers $authHeader -ContentType 'application/json; charset=UTF-8'
    Write-Host "`nOutput from the `"$appName`" Command Execution:"
    $outputString
}

