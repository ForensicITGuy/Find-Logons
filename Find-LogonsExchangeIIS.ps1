# Find-LogonsExchangeIIS.ps1
# author: Tony M Lambert
#
# params: -user <username> -emailAddress <email address> -outPath <folder>
# <username> refers the user's Active Directory username without the AD prefix.
# <email address> refers to the user's Exchange email address
# <outPath>  refers to the desired output folder
#
# Parses Microsoft Exchange IIS logs for particular username or email address
# Meant to run on an Exchange server

param ([Parameter(Mandatory=$True)][string]$user,[Parameter(Mandatory=$True)][string]$emailAddress, [Parameter(Mandatory=$True)][string]$logPath, [Parameter(Mandatory=$True)][string]$outPath)

#Detect if log path is valid
#If not, exit script
if(!(Test-Path -Path $logPath ))
{
    Write-Host "Log path is invalid"
    Return
}

#Detect if output path is valid
#If not, create it
if(!(Test-Path -Path $outPath ))
{
    New-Item -ItemType directory -Path $outPath | Out-Null
}

$logFiles = Get-ChildItem -File -Path $logPath\* -Include *.log
foreach ($logFile in $logFiles)
{
    $logFileName = $logFile.Name
    $fileStreamReader = New-Object System.IO.StreamReader($logFile)
    while (($line = $fileStreamReader.ReadLine()) -ne $null) 
    {
        if (($line -match $user) -or ($line -match $emailAddress))
        {
           $line `
           | Out-File -Append $outPath\$logFileName.$user.txt
        }
    }
    $fileStreamReader.Close()
}