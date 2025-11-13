# PowerShell code to POST to the automation runbook for adding a new AzureAD user with Owner rights on the current subscription
# Change the URI, Username, and Password for your appropriate values

$uri = "https://s15events.azure-automation.net/webhooks?token=[REPLACE WITH YOUR WEBHOOK]"
$AccountInfo  = @(@{RequestBody=@{Username="AzureOwnerAccount";Password="Password123"}})
$body = ConvertTo-Json -InputObject $AccountInfo
$response = Invoke-WebRequest -Method Post -Uri $uri -Body $body
