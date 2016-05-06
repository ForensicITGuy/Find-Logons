# Find-Logons.ps1
# author: Tony M Lambert
#
# params: -user <username> -outPath <folder>
# <username> refers the user's Active Directory username without the AD prefix.
# <outPath>  refers to the desired output folder
#
# Queries user details such as lockout time and bad password time
#
# Finds the current and archived netlogon log for each local domain controller and 
# performs a text search for a particular username. Username value is mandatory.

param ([Parameter(Mandatory=$True)][string]$user, [Parameter(Mandatory=$True)][string]$outPath)

# Hash table containing failed logon substatus codes
$logonSubstatusTable = @{'C0000064'='user name does not exist';
                    'C000006A'='user name is correct but the password is wrong';
                    'C0000234'='user is currently locked out';
                    'C0000072'='account is currently disabled';
                    'C000006F'='user tried to logon outside his day of week or time of day restrictions';
                    'C0000070'='workstation restriction';
                    'C0000193'='account expiration';
                    'C0000071'='expired password';
                    'C0000133'='clocks between DC and other computer too far out of sync';
                    'C0000224'='user is required to change password at next logon';
                    'C0000225'='evidently a bug in Windows and not a risk';
                    'C000015b'='The user has not been granted the requested logon type (aka logon right) at this machine}';}

# Hash table containing failed kerberos preauth status codes
$kerberosStatusTable = @{'1'="Client's entry in database has expired"
                            '2'="Server's entry in database has expired"
                            '3'="Requested protocol version # not supported"
                            '4'="Client's key encrypted in old master key"
                            '5'="Server's key encrypted in old master key"
                            '6'="Client not found in Kerberos database"
                            '7'="Server not found in Kerberos database"
                            '8'="Multiple principal entries in database"
                            '9'="The client or server has a null key"
                            'A'="Ticket not eligible for postdating"
                            'B'="Requested start time is later than end time"
                            'C'="KDC policy rejects request	Workstation restriction"
                            'D'="KDC cannot accommodate requested option"
                            'E'="KDC has no support for encryption type"
                            'F'="KDC has no support for checksum type"
                            '10'="KDC has no support for padata type"
                            '11'="KDC has no support for transited type"
                            '12'="Clients credentials have been revoked"
                            '13'="Credentials for server have been revoked"
                            '14'="TGT has been revoked"
                            '15'="Client not yet valid - try again later"
                            '16'="Server not yet valid - try again later"
                            '17'="Password has expired"
                            '18'="Pre-authentication information was invalid"
                            '19'="Additional pre-authentication required*"
                            '1F'="Integrity check on decrypted field failed"
                            '20'="Ticket expired"
                            '21'="Ticket not yet valid"
                            '22'="Request is a replay"
                            '23'="The ticket isn't for us"
                            '24'="Ticket and authenticator don't match"
                            '25'="Clock skew too great"
                            '26'="Incorrect net address"
                            '27'="Protocol version mismatch"
                            '28'="Invalid msg type"
                            '29'="Message stream modified"
                            '2A'="Message out of order"
                            '2C'="Specified version of key is not available"
                            '2D'="Service key not available"
                            '2E'="Mutual authentication failed"
                            '2F'="Incorrect message direction"
                            '30'="Alternative authentication method required*"
                            '31'="Incorrect sequence number in message"
                            '32'="Inappropriate type of checksum in message"
                            '3C'="Generic error"
                            '3D'="Field is too long for this implementation"}

# Find the PDC for domain
$currentDNSRoot = (Get-ADDomain).DNSRoot
$PDC = Get-ADDomainController -Discover -Service PrimaryDC

# Find domain controllers for domain

$domainControllers = (Get-ADDomainController -Filter * -Server $currentDNSRoot) 

#Detect if output path is valid
#If not, create it
if(!(Test-Path -Path $outPath ))
{
    New-Item -ItemType directory -Path $outPath | Out-Null
}


#--------------- AD User Properties Lookup --------------#
try
{
    Write-Host "Looking up user properties..."
    $userProperties = Get-ADUser -Identity $user -Properties * -ErrorAction Stop 
    $userProperties | Out-File -Append $outPath\$user.properties.txt -width 250
    Write-Host "Done! Output at $outPath\$user.properties.txt"
}
catch
{
    $errorMessage = $_.Exception.Message
    throw "User lookup Failed"
}

#--------------- End AD User Properties Lookup --------------#

#--------------- Domain Lockout Lookup ----------------------#

# Get lockout events from PDC
Write-Host "Proceeding to look up lockout events..."

$lockoutEvents = get-winevent -computername $PDC -logname Security -FilterXPath "*[System[EventID=4740] and EventData[Data[@Name='TargetUserName']='$user']]" -ErrorAction SilentlyContinue `
| Select-Object TimeCreated,@{Name='User Name';Expression={$_.Properties[0].Value}},@{Name='Source Host';Expression={$_.Properties[1].Value}}`
| Format-Table -Property * -AutoSize
$lockoutEvents | out-file -Append $outPath\$user.lockouts.txt

Write-Host "Done! Output at $outPath\$user.lockouts.txt"

#------------ End Domain Lockout Lookup -------------#

#------------ Failed Domain Logon Lookup ------------#

# Get failed logon events from PDC
Write-Host "Proceeding to look up failed domain logon events..."

$failedDomainLogonEvents = get-winevent -computername $PDC -logname Security -FilterXPath "*[System[EventID=4625] and EventData[Data[@Name='TargetUserName']='$user']]" -ErrorAction SilentlyContinue `
| Select-Object TimeCreated,@{Name='User Name';Expression={$_.Properties[5].Value}},@{Name='Workstation Name';Expression={$_.Properties[13].Value}},@{Name='Source IP';Expression={$_.Properties[19].Value}},@{Name='Substatus';Expression={$_.Properties[9].Value.ToString('X2') + " - " + $logonSubstatusTable.Item($_.Properties[9].Value.ToString('X2'))}}`
| Format-Table -Property * -AutoSize
$failedDomainLogonEvents | out-file -Append $outPath\$user.failed-domain-logons.txt

Write-Host "Done! Output at $outPath\$user.failed-domain-logons.txt"

#------------ End Failed Domain Logon Lookup ---------------#

#------------ Kerberos Preauthentication Lookup ------------#

# Get failed kerberos preauthentication events from PDC
Write-Host "Proceeding to look up failed kerberos pre-auth events..."

$failedKerberosEvents = get-winevent -computername $PDC -logname Security -FilterXPath "*[System[EventID=4771] and EventData[Data[@Name='TargetUserName']='$user']]" -ErrorAction SilentlyContinue `
| Select-Object TimeCreated,@{Name='User Name';Expression={$_.Properties[0].Value}},@{Name='Source IP';Expression={$_.Properties[6].Value}},@{Name='Status';Expression={$_.Properties[4].Value.ToString('X2') + "-" + $kerberosStatusTable.Item($_.Properties[4].Value.ToString('X2'))}}`
| Format-Table -Property * -AutoSize
$failedKerberosEvents | out-file -Append $outPath\$user.failed-kerberos-preauth.txt

Write-Host "Done! Output at $outPath\$user.failed-kerberos-preauth.txt"

#------------ End Kerberos Preauthentication Lookup ------------#

#------------ NetLogon Entries Lookup --------------------------#

# If available, get logon attempts from netlogon logs from each domain controller
# Netlogon.log and Netlogon.bak
Write-Host "Proceeding to look up netlogon entries..."

foreach ($domainController in $domainControllers)
{
    $hostName = $domainController.HostName
    select-string -path "\\$hostName\ADMIN$\debug\netlogon.log" -pattern $user -ErrorAction SilentlyContinue `
    | out-file -Append $outPath\$user.netlogons.txt -width 250
    select-string -path "\\$hostName\ADMIN$\debug\netlogon.bak" -pattern $user -ErrorAction SilentlyContinue `
    | out-file -Append $outPath\$user.netlogons.txt -width 250
}

Write-Host "Done! Output at $outPath\$user.netlogons.txt"

#------------ End Netlogon Entries Lookup ------------#