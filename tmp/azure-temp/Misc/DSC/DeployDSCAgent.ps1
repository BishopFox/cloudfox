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

Configuration DeployDSCAgent
{
	
    param
    (
        [String]
        $AgentURL
    )
	
	Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

	Node localhost
	{
		#A directory to drop the agent into
		File DropDirectory
		{
			Ensure = "Present"
			Type = "Directory"
			DestinationPath = "C:\WindowsAzure\SecAgent"
		}

		#Create a Defender exclusion so we can write into the directory
		Script CreateDropFolderExclusion
		{
			SetScript = {
				 Add-MpPreference -ExclusionPath "C:\WindowsAzure\SecAgent"
			}
			TestScript = { 
				 $exclusions = Get-MpPreference | select -Property ExclusionPath -ExpandProperty ExclusionPath
				 return $exclusions -ne $null -and $exclusions.contains("C:\WindowsAzure\SecAgent") 	
			}
			GetScript = { return @{result = 'result'} }
			DependsOn = "[File]DropDirectory" 
		}

		#Create a Defender exclusion for the full path of the executable
		Script CreatePathExclusion
		{
			SetScript = {
				 Add-MpPreference -ExclusionPath "C:\WindowsAzure\SecAgent\Agent.exe"
			}
			TestScript = { 
				 $exclusions = Get-MpPreference | select -Property ExclusionPath -ExpandProperty ExclusionPath
				 return $exclusions -ne $null -and $exclusions.contains("C:\WindowsAzure\SecAgent\Agent.exe") 	
			}
			GetScript = { return @{result = 'result'} }
			DependsOn = "[File]CreateDropFolderExclusion"
		}

		#Create a Defender exclusion so we can run the executable
		Script CreateProcessExclusion
		{
			SetScript = {
				 Add-MpPreference -ExclusionProcess "C:\WindowsAzure\SecAgent\Agent.exe"
			}
			TestScript = { 
				 $exclusions = Get-MpPreference | select -Property ExclusionProcess -ExpandProperty ExclusionProcess
				 return $exclusions -ne $null -and $exclusions.contains("C:\WindowsAzure\SecAgent\Agent.exe") 	
			}
			GetScript = { return @{result = 'result'} }
			DependsOn = "[Script]CreatePathExclusion"
		}

		#Download the agent
		Script DownloadAgent
		{
			SetScript = {
				 Invoke-WebRequest -URI $using:AgentURL -OutFile "C:\WindowsAzure\SecAgent\Agent.exe"
			}
			TestScript = { 
				 return Test-Path "C:\WindowsAzure\SecAgent\Agent.exe" 	
			}
			GetScript = { return @{result = 'result'} }
			DependsOn = "[Script]CreateProcessExclusion"
		}

		#Run the executable.
		WindowsProcess RunAgent
		{
			Path = "C:\WindowsAzure\SecAgent\Agent.exe" 
			Arguments = ""
			Ensure = "Present"
			DependsOn = "[Script]DownloadAgent"
		}
	}
}
