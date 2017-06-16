# NexposePS
This is a first go at using PowerShell to interact with the Nexpose API. There will be more to come.

Login to your nexpose instance.

#### `Invoke-NexposeLogin -server nexpose.server`

End the session with your Nexpose server.

#### `Invoke-NexposeLogout`

Retrieves a list of all asset groups.

#### `Get-AssetGroupListing`

Retrieves asset group summaries out of Nexpose by asset group ID.

#### `Get-AssetGroupConfig 123`

Find asset groups by name. Accepts wildcards.

#### `Get-AssetGroupByName assetgroupname`

Retrieves a complete list of sites.

#### `Get-SiteListing`

Returns site information by site ID.

#### `Get-SiteConfig 123`

Returns list of Active scans.

#### `Get-ScanActivity`

Gets data on a specific scan currently running. requires scan ID.

#### `Get-ScanStatus 123`

Returns scan information given a scan ID.

#### `Get-ScanStatistics`

Returns a list of Nexpose engines


Returns System information. Need to be a global admin.

#### `Get-SystemInformation`

Returns list of all vulnerabilities nexpose has checks for.

#### `Get-VulnerabilityListing`

Returns vulnerability information for a Vulnerability ID.

#### `Get-VulnerabilityDetails 123`