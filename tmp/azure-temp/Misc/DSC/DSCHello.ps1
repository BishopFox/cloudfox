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

Configuration DSCHello
{
	Node localhost
	{
		Script ScriptExample
		{
			SetScript = {
				echo "Hello from DSC. I'm running as $(whoami)" > C:\dsc_hello.txt
			}
			TestScript = { 
				return Test-Path C:\dsc_hello.txt 
			}
			GetScript = { @{ Result = (Get-Content C:\dsc_hello.txt) } }
		}
	}
}

