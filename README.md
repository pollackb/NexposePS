# NexposePS
This is a first go at using PowerShell to interact with the Nexpose API. There will be more to come.

###Session Handling:
	Invoke-NexposeLogin 	-server nexpose.server - Logs in to Nexpose.
	Invoke-NexposeLogout 	- Logs out.

###Site Functions:

	Get-SiteListing 	- Retrieves a complete list of sites.
	Get-SiteConfig 123 	- Retrieves site information by site ID.

###Asset Group Functions:

	Get-AssetGroupListing 					- Retrieves all asset groups.
	Get-AssetGroupConfig 123				- Retrieves asset group information by ID.
	Get-AssetGroupByName assetgroupname		- Retrieves asset group by name. Accepts wildcards.

###Scan Functions:

	Get-ScanActivity 		- Retrieves list of Active scans.
	Get-ScanStatus 123 		- Retrieves data on a specific scan currently running. Requires scan ID.
	Get-ScanStatistics 123 	- Returns scan information given a scan ID.

###Engine Functions:

	Get-SystemInformation 	- Returns a list of Nexpose engines
	Get-SystemInformation 	- Returns System information. Need to be a global admin.

###Vulnerability Functions:

	Get-VulnerabilityListing		- Returns list of all vulnerabilities nexpose has checks for.
	Get-VulnerabilityDetails 123	- Returns vulnerability information by Vulnerability ID.