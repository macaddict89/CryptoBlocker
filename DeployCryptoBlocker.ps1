# DeployCryptoBlocker.ps1
# Version: 1.1
# Changed from nexxai/CryptoBlocker to support PowerShell FSRM commands replacing deprecated filescrn.exe
#####

################################ USER CONFIGURATION ################################

# Names to use in FSRM
$fileGroupName = "CryptoBlockerGroup"
$fileTemplateName = "CryptoBlockerTemplate"
# set screening type to
# Active screening: Do not allow users to save unathorized files
$fileTemplateType = "Active"
# Passive screening: Allow users to save unathorized files (use for monitoring)
#$fileTemplateType = "Passive"

##TODO: Parameterize it to ignore if no message set
# Write the email options - comment out the entire block if no email notification should be set
$mTo="[Admin Email]" 
## Email Subject and Message
$mSubject="Unauthorized file from the [Violated File Group] file group detected"
$mBody="User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server."

# Write the event log options - comment out the entire block if no event notification should be set
$eEventType="Warning"
## Eventlog Message
$eBody="User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on the [Server] server. This file is in the [Violated File Group] file group, which is not permitted on the server."

##
#Run Limit Interval: Specifies the minimum interval, in minutes, before the server can run the action again. For example, if the interval expired since 
#the action last ran, the server runs the action again in response to an event; otherwise, the server cannot run the action again. 
#The default value, 60, specifies that there is no limit.
##
$aRunLimitInt=120

################################ USER CONFIGURATION ################################

################################ Functions ################################

Function ConvertFrom-Json20
{
    # Deserializes JSON input into PowerShell object output
    Param (
        [Object] $obj
    )
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    return ,$serializer.DeserializeObject($obj)
}

Function New-CBArraySplit
{
    <# 
        Takes an array of file extensions and checks if they would make a string >1Kb, 
        if so, turns it into several arrays
    #>
    param(
        $Extensions
    )

    $Extensions = $Extensions | Sort-Object -Unique

    $workingArray = @()
    $WorkingArrayIndex = 1
    $LengthOfStringsInWorkingArray = 0

    # FileServerResourceManager commandlets support maximum of 1KB Include/Exclude Patterns
    # Build small enough arrays to fit into command

    # Take the items from the input array and build up a 
    # temporary workingarray, tracking the length of the items in it and future commas
    $Extensions | ForEach-Object {

        if (($LengthOfStringsInWorkingArray + 1 + $_.Length) -gt 1000) 
        {   
            # Adding this item to the working array (with +1 for a comma)
            # pushes the contents past the 1KB limit
            # so output the workingArray
            [PSCustomObject]@{
                index = $WorkingArrayIndex
                FileGroupName = "$Script:FileGroupName$WorkingArrayIndex"
                array = $workingArray
            }
            
            # and reset the workingArray and counters
            $workingArray = @($_) # new workingArray with current Extension in it
            $LengthOfStringsInWorkingArray = $_.Length
            $WorkingArrayIndex++

        }
        else #adding this item to the workingArray is fine
        {
            $workingArray += $_
            $LengthOfStringsInWorkingArray += (1 + $_.Length)  #1 for imaginary joining comma
        }
    }

    # The last / only workingArray won't have anything to push it past 1Kb
    # and trigger outputting it, so output that one as well
    [PSCustomObject]@{
        index = ($WorkingArrayIndex)
        FileGroupName = "$Script:FileGroupName$WorkingArrayIndex"
        array = $workingArray
    }
}

################################ Functions ################################

################################ Program code ################################

# Identify Windows Server version, PowerShell version and install FSRM role
$majorVer = [System.Environment]::OSVersion.Version.Major
$minorVer = [System.Environment]::OSVersion.Version.Minor
$powershellVer = $PSVersionTable.PSVersion.Major

if ($powershellVer -le 2)
{
    Write-Host "`n####"
    Write-Host "ERROR: PowerShell v3 or higher required."
    exit
}

Write-Host "`n####"
Write-Host "Checking File Server Resource Manager.."

Import-Module ServerManager

if ($majorVer -ge 6)
{
    $checkFSRM = Get-WindowsFeature -Name FS-Resource-Manager

    if (($minorVer -ge 2 -or $majorVer -eq 10) -and $checkFSRM.Installed -ne "True")
    {
        # Server 2012 / 2016
        Write-Host "`n####"
        Write-Host "FSRM not found.. Installing (2012 / 2016).."

        $install = Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
	if ($? -ne $True)
	{
		Write-Host "Install of FSRM failed."
		exit
	}
    }
    elseif ($minorVer -ge 1 -and $checkFSRM.Installed -ne "True")
    {
        # Server 2008 R2
        Write-Host "`n####"
		Write-Host "FSRM not found.. Installing (2008 R2).."
        $install = Add-WindowsFeature FS-FileServer, FS-Resource-Manager
	if ($? -ne $True)
	{
		Write-Host "Install of FSRM failed."
		exit
	}
	
    }
}
else
{
    # Assume Server 2003/2008
    Write-Host "`n####"
	Write-Host "Unsupported version of Windows detected! Quitting.."
    return
}

## Enumerate shares
Write-Host "`n####"
Write-Host "Processing ProtectList.."
### move file from C:\Windows\System32 or whatever your relative path is to the directory of this script
if (Test-Path .\ProtectList.txt)
{
    Move-Item -Path .\ProtectList.txt -Destination $PSScriptRoot\ProtectList.txt -Force
}

if (Test-Path $PSScriptRoot\ProtectList.txt)
{
    $drivesContainingShares = Get-Content $PSScriptRoot\ProtectList.txt | ForEach-Object { $_.Trim() }
}
#If ProtectList not found, look for all shared folders
Else {
    $drivesContainingShares =   @(Get-WmiObject Win32_Share | 
                    Select Name,Path,Type | 
                    Where-Object { $_.Type -match '0|2147483648' } | 
                    Select -ExpandProperty Path | 
                    Select -Unique)
}


if ($drivesContainingShares.Count -eq 0)
{
    Write-Host "`n####"
    Write-Host "No drives containing shares were found. Exiting.."
    exit
}

Write-Host "`n####"
Write-Host "The following shares needing to be protected: $($drivesContainingShares -Join ",")"

# Download list of CryptoLocker file extensions
Write-Host "`n####"
Write-Host "Dowloading CryptoLocker file extensions list from fsrm.experiant.ca api.."

$jsonStr = Invoke-WebRequest -Uri https://fsrm.experiant.ca/api/v1/get
$monitoredExtensions = @(ConvertFrom-Json20 $jsonStr | ForEach-Object { $_.filters })

# Process SkipList.txt
Write-Host "`n####"
Write-Host "Processing SkipList.."
### move file from C:\Windows\System32 or whatever your relative path is to the directory of this script
if (Test-Path .\SkipList.txt)
{
    Move-Item -Path .\SkipList.txt -Destination $PSScriptRoot\SkipList.txt -Force
}

If (Test-Path $PSScriptRoot\SkipList.txt)
{
    $Exclusions = Get-Content $PSScriptRoot\SkipList.txt | ForEach-Object { $_.Trim() }
    $monitoredExtensions = $monitoredExtensions | Where-Object { $Exclusions -notcontains $_ }

}
Else 
{
    $emptyFile = @'
#
# Add one filescreen per line that you want to ignore
#
# For example, if *.doc files are being blocked by the list but you want 
# to allow them, simply add a new line in this file that exactly matches 
# the filescreen:
#
# *.doc
#
# The script will check this file every time it runs and remove these 
# entries before applying the list to your FSRM implementation.
#
'@
    Set-Content -Path $PSScriptRoot\SkipList.txt -Value $emptyFile
}

# Check to see if we have any local patterns to include
Write-Host "`n####"
Write-Host "Processing IncludeList.."
### move file from C:\Windows\System32 or whatever your relative path is to the directory of this script
if (Test-Path .\IncludeList.txt)
{
    Move-Item -Path .\IncludeList.txt -Destination $PSScriptRoot\IncludeList.txt -Force
}
If (Test-Path $PSScriptRoot\IncludeList.txt)
{
    $includeExt = Get-Content $PSScriptRoot\IncludeList.txt | ForEach-Object { $_.Trim() }
    $monitoredExtensions = $monitoredExtensions + $includeExt
}

# Split the $monitoredExtensions array into fileGroups of less than 1KB to allow processing by filescrn.exe
$fileGroups = @(New-CBArraySplit $monitoredExtensions)

# Perform these steps for each of the 1KB limit split fileGroups
Write-Host "`n####"
Write-Host "Adding/replacing File Groups.."
ForEach ($group in $fileGroups) {
   # Write-Host "Adding/replacing File Group [$($group.fileGroupName)] with monitored file [$($group.array -Join ",")].."
    Write-Host "`nFile Group [$($group.fileGroupName)] with monitored files from [$($group.array[0])] to [$($group.array[$group.array.GetUpperBound(0)])].."
	Remove-FsrmFileGroup -Name "$($group.fileGroupName)" -Confirm:$false
    New-FsrmFileGroup -Name "$($group.fileGroupName)" -IncludePattern @($group.array)
    #Create an array of file group names to place into screening template/others?
    $fileGroupNames += @($group.fileGroupName)
}

# Create File Screen Template with Notification
Write-Host "`n####"
Write-Host "Adding/replacing [$fileTemplateType] File Screen Template [$fileTemplateName] with eMail Notification and Event Notification ..."
Remove-FsrmFileScreenTemplate -Name "$fileTemplateName" -Confirm:$false
#Create Mail Notification Action if we have a to variable
if ($mTo -ne ""){
    $mNotification = New-FsrmAction -Type Email -MailTo $mTo -Subject $mSubject -Body $mBody -RunLimitInterval $aRunLimitInt
}
if ($eEventType -ne ""){
    $eNotification = New-FsrmAction -Type Event -EventType $eEventType -Body $eBody -RunLimitInterval $aRunLimitInt
}
##TODO: Better notification exemptions if no notifications. Causing errors without the notifications being created.
if ($fileTemplateType -eq "Active"){
    New-FsrmFileScreenTemplate -Name $fileTemplateName -Active -IncludeGroup @($fileGroupNames) -Notification ($mNotification,$eNotification)
    $fileTemplateName
    $fileGroupNames
}
else {
    New-FsrmFileScreenTemplate -Name "$fileTemplateName" -IncludeGroup @($fileGroupNames) -Notification @($mNotification,$eNotification)
}

# Create File Screens for every drive containing shares
Write-Host "`n####"
Write-Host "Adding/replacing File Screens.."
$drivesContainingShares | ForEach-Object {
    Write-Host "File Screen for [$_] with Source Template [$fileTemplateName].."
    Remove-FsrmFileScreen -Path "$_" -Confirm:$false
    New-FsrmFileScreen -Path "$_" -Template "$fileTemplateName"
}

# Add Folder Exceptions from ExcludeList.txt
Write-Host "`n####"
Write-Host "Processing ExcludeList.."
### move file from C:\Windows\System32 or whatever your relative path is to the directory of this script
if (Test-Path .\ExcludePaths.txt)
{
    Move-Item -Path .\ExcludePaths.txt -Destination $PSScriptRoot\ExcludePaths.txt -Force
}
If (Test-Path $PSScriptRoot\ExcludePaths.txt) {
    Get-Content $PSScriptRoot\ExcludePaths.txt | ForEach-Object {
        If (Test-Path $_) {
            New-FsrmFileScreenException -Path "$_" -IncludeGroup @($fileGroupNames)
        }
    }
}

Write-Host "`n####"
Write-Host "Done."
Write-Host "####"

################################ Program code ################################