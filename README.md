# NexposePS
This is a first go at using PowerShell to interact with the Nexpose API. There will be more to come.

### Session Handling:
	Invoke-NexposeLogin 	-server nexpose.server - Logs in to Nexpose.
	Invoke-NexposeLogout 	- Logs out.

### Site Functions:

	Get-SiteListing 	- Retrieves a complete list of sites.
	Get-SiteConfig 	- Retrieves site information by site ID.

### Asset Group Functions:

	Get-AssetGroupListing	- Retrieves all asset groups.
	Get-AssetGroupConfig	- Retrieves asset group information by ID.
	Get-AssetGroupByName assetgroupname	- Retrieves asset group by name. Accepts wildcards.

### Scan Functions:

	Get-ScanActivity 	- Retrieves list of Active scans.
	Get-ScanStatus 	- Retrieves data on a specific scan currently running. Requires scan ID.
	Get-ScanStatistics 	- Returns scan information given a scan ID.

### Engine Functions:

	Get-SystemInformation 	- Returns a list of Nexpose engines
	Get-SystemInformation 	- Returns System information. Need to be a global admin.

### Vulnerability Functions:

	Get-VulnerabilityListing	- Returns list of all vulnerabilities nexpose has checks for.
	Get-VulnerabilityDetails	- Returns vulnerability information by Vulnerability ID.

### Reporting Functions:	

	Get-NexposeReportTemplateListing		- Returns list of all Report Templates.
	Get-NexposeReportListing	- Returns list of all reports or a report can be specified by name, ID, status and time generated.
	Get-NexposeReportConfig		- Returns the configuration of a report.
	Get-NexposeReportHistory	- Returns the run history of a report.
	Get-NexposeReportSave		- Save the configuration for a report definition.
	Get-NexposeReport		- Pulls generated report from Nexpose by name.

### Tag Functions:

	Get-TagListing	- Pulls a list of all tags or specify a name.
	Get-TagDetails	- Returns detailed info on tags
	
### Misc. scripts:

	Get-NexposeOSInfo	- Returns a list of operating systems and the number of instances