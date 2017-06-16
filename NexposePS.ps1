########################################################
#
# Script to interact with NExpose API.
# Author: Ben Pollack 
# Parts of the script were borrowed from Kris Daugherty
# 
########################################################

##############################
#
# Session Functions
#
##############################

function Invoke-NexposeLogin{
<#
    .SYNOPSIS
        This script retrieves a session-ID from nexpose.
    .DESCRIPTION
        This script retrieves a session-ID from nexpose. It will ask for a username and password to pass to the Nexpose API. API version and server name can be changed using parameters.
    .PARAMETER server
        The Nexpose server to communicate with. this can be either IP or hostname.
    .PARAMETER api_version
        Allows the user to chooses what API version to use. Default Version: 1.1
    .EXAMPLE
        Invoke-NexposeLogin -server nexpose.mydomain.com

#>
Param (
    [String] 
    [Parameter(Mandatory=$true)]
    $server,
    [String]
    $api_version = '1.1'
)
$credential = Get-Credential

#Nexpose Instance
$user = $credential.UserName
$pwd = $credential.getnetworkcredential().password
$SCRIPT:uri = "https://${server}/api/${api_version}/xml"

#login request string
$login_request = "<LoginRequest synch-id='0' password ='$pwd' user-id = '$user' ></LoginRequest>"


# login and get the session id
$resp = Invoke-WebRequest -URI $uri -Body $login_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.LoginResponse.success -eq '0'){
    Write-Host 'ERROR: '$xmldata.LoginResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $SCRIPT:session_id = $xmldata.LoginResponse.'session-id'
    Write-Host "Login Successful" -ForegroundColor Green
    }
}

Function Invoke-NexposeLogout{
<#
    .SYNOPSIS
        Ends session with Nexpose.
    .DESCRIPTION
        Ends session with Nexpose.

    .EXAMPLE
        
        Invoke-NexposeLogout

#>
$logout_request = "<LogoutRequest synch-id='0' session-id ='$SCRIPT:session_id' ></LogoutRequest>"
$resp = Invoke-WebRequest -URI $uri -Body $logout_request -ContentType 'text/xml' -Method post
$resp
}

Function Confirm-Session{

if ($SCRIPT:session_id -eq $null){
    Write-Host "You need to login firts. Try 'Invoke-NexposeLogin'." -ForegroundColor Red
    break;
    }


}

##############################
#
# Asset Group Functions
#
##############################

Function Get-AssetGroupConfig{
<#
    .SYNOPSIS
        Retrieves asset group summaries out of Nexpose by asset group ID.
    .DESCRIPTION
        Retrieves asset group summaries out of Nexpose by asset group ID. The summary contains asset group id, name and riskscore. Devices in the asset group can also be retrieved.
    .PARAMETER assetgroupid
        Asset group ID to lookup
    
    .EXAMPLE
        
        Get-AssetGroupConfig 1788

        returns list of device for the site:
        (Get-AssetGroupConfig 1788).Devices.device

#>
param([String]$assetgroupid)
# Request by ID
Confirm-Session
$sites_request = "<AssetGroupConfigRequest session-id='$SCRIPT:session_id' group-id= '$assetgroupid'/>"

$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.AssetGroupConfigResponse.success -eq '0'){
    Write-Host 'ERROR: '$xmldata.AssetGroupConfigResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $xmldata.AssetGroupConfigResponse.AssetGroup
    }
}

Function Get-AssetGroupListing{
<#
    .SYNOPSIS
        Retrieves a list of all asset groups.
    .DESCRIPTION
        Retrieves a list of all asset groups.
    
    .EXAMPLE
        
        Get-AssetGroupListing
#>
Confirm-Session
# Get list of asset groups
$sites_request = "<AssetGroupListingRequest session-id='$SCRIPT:session_id'/>"
$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.AssetGroupListingResponse.success -eq '0'){
    Write-Host 'ERROR: '$xmldata.AssetGroupListingResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $xmldata.AssetGroupListingResponse.AssetGroupSummary
    }
}

Function Get-AssetGroupByName{
<#
    .SYNOPSIS
        Find asset groups by name. Accepts wildcards.
    .DESCRIPTION
        Finds name of an asset group and returns the config of all that match. Accepts wildcard.
    .PARAMETER $Assetgroupname
        String to be used to search for.Wildcards accepted.
    
    .EXAMPLE
        
        Get-AssetGroupByName assetgroupname

#>
Param([string]$Assetgroupname)
Confirm-Session
$AssetGroupID = Get-AssetGroupListing | where { $_.name -like "$Assetgroupname" } | select id -ExpandProperty id

Foreach($ID in $AssetGroupID){
    Get-AssetGroupConfig $ID.id
    }

}

##############################
#
# Site Functions
#
##############################

Function Get-SiteListing{
<#
    .SYNOPSIS
        retrieves a list of sites.
    .DESCRIPTION
        Gets a list of sites including id, name, description, riskfactor and riskscore.
    
    .EXAMPLE
        
        Get-SiteListing

#>
Confirm-Session
# Get list of sites
$sites_request = "<SiteListingRequest session-id='$SCRIPT:session_id'/>"
$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.SiteListingResponse.success -eq '0'){
    Write-Host 'ERROR: '$xmldata.SiteListingResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $xmldata.SiteListingResponse.SiteSummary
    }
}


Function Get-SiteConfig{
<#
    .SYNOPSIS
        Returns site information by site ID.
    .DESCRIPTION
        Returns site information by site ID. Contains site id, name, description, riskfactor, isdynamic, hosts, credentials, alerting, scanConfig
    .PARAMETER SiteID
        Just the site ID
    
    .EXAMPLE
        
        Get-SiteConfig 285

        Gets Scan configuration:
        (Get-SiteConfig 285).scanconfig

#>
Param([string]$SiteID)
Confirm-Session
# Get sites configurations
$sites_request = "<SiteConfigRequest session-id='$SCRIPT:session_id' site-id='$SiteID'/>"
$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.SiteConfigResponse.success -eq '0'){
    Write-Host 'ERROR: '$xmldata.SiteConfigResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $xmldata.SiteConfigResponse.Site
    }
}

##############################
#
# Scan Functions
#
##############################

Function Get-ScanActivity{
<#
    .SYNOPSIS
        Returns list of Active scans.
    .DESCRIPTION
        Returns list of Active scans.

    .EXAMPLE
        
        Get-ScanActivity

#>
Confirm-Session
# Get list of Current Scans
$sites_request = "<ScanActivityRequest session-id='$SCRIPT:session_id'/>"
$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.ScanActivityResponse.success -like '0'){
    Write-host 'ERROR: '$xmldata.ScanActivityResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $xmldata.ScanActivityResponse.ScanSummary
    }
}

Function Get-ScanStatus{

param([string]$ScanID)
Confirm-Session
# Gets data on a specific scan currently running
$sites_request = "<ScanStatusRequest session-id='$SCRIPT:session_id' scan-id='$ScanID'/>"
$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.ScanStatusResponse.success -like '0'){
    Write-host 'ERROR: '$xmldata.ScanStatusResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $xmldata.ScanStatusResponse.Scan
    }
}


Function Get-ScanStatistics{
<#
    .SYNOPSIS
        Returns scan information given a scan ID.
    .DESCRIPTION
        Returns scan information given a scan ID. Can also use scan ID of a scan that completed. Information includes scan-id, site-id, name, startTime, endTime, status, tasks, nodes and vulnerabilities
    .PARAMETER ScanID
        Just the scan ID

    .PARAMETER EngineID
        Engine ID for scan. This is not need.
    
    .EXAMPLE
        
        Get-ScanStatistics 77540

#>
param([string]$ScanID, [String]$EngineID)
Confirm-Session
# Gets statistics on any scan ID
$sites_request = "<ScanStatisticsRequest session-id='$SCRIPT:session_id' engine-id ='$EngineID' scan-id='$ScanID'/>"
$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.ScanStatisticsResponse.success -like '0'){
    Write-host 'ERROR: '$xmldata.ScanStatisticsResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $xmldata.ScanStatisticsResponse.ScanSummary
    }
}

##############################
#
# Engine Functions
#
##############################

Function Get-EngineListing{
<#
    .SYNOPSIS
        Returns a list of Nexpose engines
    .DESCRIPTION
        Returns a list of Nexpose engines
    
    .EXAMPLE
        
        Get-EngineListing

#>
Confirm-Session
# Gets data on a specific scan currently running
$sites_request = "<EngineListingRequest session-id='$SCRIPT:session_id'/>"
$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.EngineListingResponse.success -like '0'){
    Write-host 'ERROR: '$xmldata.EngineListingResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $xmldata.EngineListingResponse.EngineSummary
    }
}

##############################
#
# System Functions
#
##############################

Function Get-SystemInformation{
<#
    .SYNOPSIS
        Returns System information. need to be an admin
    .DESCRIPTION
        Returns System information. need to be an admin
    
    .EXAMPLE
        
        Get-SystemInformation

#>
Confirm-Session
# Gets data on a specific scan currently running
$sites_request = "<SystemInformationRequest session-id='$SCRIPT:session_id'/>"
$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.SystemInforamtionResponse.success -like '0'){
    Write-host 'ERROR: '$xmldata.SystemInforamtionResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $xmldata.SystemInformationResponse.StatisticsInformationSummary.Statistic
    
    }
}

##############################
#
# Vulnerability Functions
#
##############################

Function Get-VulnerabilityListing{
<#
    .SYNOPSIS
        Returns list of all vulnerabilities nexpose has checks for. 
    .DESCRIPTION
        Returns list of all vulnerabilities nexpose has checks for. Added VulnTitle parameter to search for a specific vulnerability.

    .PARAMETER VulnTitle
        Can be used to search for specific vulnerability by title.
    
    
    .EXAMPLE
        Returns all vulnerabilities:
        Get-VulnerabilityListing

        Returns only vulnerabilities matching string:
        Get-VulnerabilityListing *aix*

#>
Param([String]$VulnTitle = '*')
Confirm-Session
# Gets vulnerability listing
$sites_request = "<VulnerabilityListingRequest session-id='$SCRIPT:session_id'/>"
$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.VulnerabilityListingResponse.success -like '0'){
    Write-host 'ERROR: '$xmldata.VulnerabilityListingResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $xmldata.VulnerabilityListingResponse.VulnerabilitySummary | where { $_.title -like "$VulnTitle" }
    }
} 

Function Get-VulnerabilityDetails{
<#
    .SYNOPSIS
        Returns vulnerability information for a Vulnerability ID.

    .DESCRIPTION
        Returns vulnerability information for a Vulnerability ID. Information includes VulnID, VulnTitle, VulnSeverity, VulnCvssScore, VulnCvssVector, VulnPublished, VulnAdded, VulnModified, VulnDescription, VulnReference and VulnSolution 

    .PARAMETER VulnID
        just the vulnID. can be retrieved with the Get-VulnerabilityListing module.    
    
    .EXAMPLE
        
        Get-VulnerabilityDetails 'aix-6_1-u857818'

#>
Param([String]$VulnID)
Confirm-Session
# Gets vulnerability listing
$sites_request = "<VulnerabilityDetailsRequest session-id='$SCRIPT:session_id' vuln-id='$VulnID'/>"
$resp = Invoke-WebRequest -URI $uri -Body $sites_request -ContentType 'text/xml' -Method post
[xml]$xmldata = $resp.content
if($xmldata.VulnerabilityDetailsResponse.success -like '0'){
    Write-host 'ERROR: '$xmldata.VulnerabilityDetailsResponse.Failure.message -ForegroundColor Red
    }
    Else{
    $val = New-Object psobject;
    $val | Add-Member -MemberType NoteProperty -Name VulnID -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.id
    $val | Add-Member -MemberType NoteProperty -Name VulnTitle -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.title
    $val | Add-Member -MemberType NoteProperty -Name VulnSeverity -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.severity
    $val | Add-Member -MemberType NoteProperty -Name VulnCvssScore -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.cvssScore
    $val | Add-Member -MemberType NoteProperty -Name VulnCvssVector -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.cvssVector
    $val | Add-Member -MemberType NoteProperty -Name VulnPublished -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.published
    $val | Add-Member -MemberType NoteProperty -Name VulnAdded -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.added
    $val | Add-Member -MemberType NoteProperty -Name VulnModified -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.modified
    $val | Add-Member -MemberType NoteProperty -Name VulnDescription -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.description.p
    $val | Add-Member -MemberType NoteProperty -Name VulnReference -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.references.reference.'#text'
    $val | Add-Member -MemberType NoteProperty -Name VulnSolution -Value $xmldata.VulnerabilityDetailsResponse.Vulnerability.Solution.p
    $val
    }
}


##############################
#
# Report Functions to be added
#
##############################