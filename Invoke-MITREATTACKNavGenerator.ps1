<#
.SYNOPSIS
    Generates a MITRE ATT&CK Navigator layer template JSON with technique IDs from a specified file.

.DESCRIPTION
    This script reads a list of MITRE ATT&CK technique IDs from a specified text file and generates a JSON template 
    for the MITRE ATT&CK Navigator. It allows customization of the assigned scores and colors for each technique.
    The updated JSON is then saved to a specified output file.
	Author: Jan Marek, Cyber Rangers, https://www.cyber-rangers.com
	Version: 1.0

.PARAMETER techniquesFile
    The path to the text file containing the list of MITRE ATT&CK technique IDs. Each ID should be on a new line.
	
	Example of the file content:
	T1055
	T1220
	T1546.003
	T1059.001
	T1069

    This parameter is mandatory.

.PARAMETER scoreToAssign
    The score to assign to each technique in the Navigator. Default is 1.

.PARAMETER colorToAssign
    The color to assign to each technique in the Navigator. This should be in hex format (e.g., '#ffffff'). 
    Default is an empty string, indicating no color.

.PARAMETER outputFile
    The path where the updated JSON file will be saved. Default is 'output.json'.

.EXAMPLE
    .\Invoke-MITREATTACKNavGenerator.ps1 -techniquesFile 'techniques.txt'
    This command updates the default template using technique IDs from 'techniques.txt', with the default score of 1, 
    no color (empty string), and writes the output to 'output.json'.

.EXAMPLE
    .\Invoke-MITREATTACKNavGenerator.ps1 -techniquesFile 'list.txt' -scoreToAssign 5 -colorToAssign '#ff0000' -outputFile 'newLayer.json'
    This command reads 'list.txt', sets each technique's score to 5 and color to red ('#ff0000'), 
    and saves the updated layer to 'newLayer.json'.

.EXAMPLE
    .\Invoke-MITREATTACKNavGenerator.ps1 -techniquesFile 'input.txt' -scoreToAssign 3 -colorToAssign '#0000ff' -outputFile 'customLayer.json'
    This command uses 'input.txt' for technique IDs, assigns a score of 3 and a blue color ('#0000ff') to each, 
    and outputs the result to 'customLayer.json'.

.EXAMPLE
    .\Invoke-MITREATTACKNavGenerator.ps1 -techniquesFile 'C:\Path\To\Your\TechniquesFile.txt' -scoreToAssign 2 -colorToAssign '#00ff00' -outputFile 'C:\Path\To\Your\OutputFile.json'
    This command demonstrates using full paths for files. It reads MITRE ATT&CK technique IDs from a specified file in a different directory, 
    applies a score of 2 and a green color ('#00ff00') to each technique, and saves the output to a specified location.

.NOTES
	This script is provided as-is, without any warranties or guarantees. Also this script is provided under the GNU General Public License v3.0 (https://www.gnu.org/licenses/gpl-3.0.html)
    This script assumes the 'techniquesFile' contains valid MITRE ATT&CK technique IDs, one per line.
    It's tailored to work with enterprise-attack domain but can be adapted for other domains with slight modifications.
#>
[CmdletBinding()]
[OutputType([System.IO.FileSystemInfo])]
param(
	[Parameter(Mandatory = $true)]
	[ValidateScript({ Test-Path $_ -PathType Leaf })]
	[string]$techniquesFile,
	[string]$templateFile = "template.json",
	[int]$scoreToAssign = 1,
	[string]$colorToAssign = "",
	[string]$outputFile = "output.json"
)

# Read the list of MITRE IDs from the text file
Write-Verbose ('Reading technique IDs from {0}' -f $techniquesFile)
try { $mitreIds = Get-Content -Path $techniquesFile -ErrorAction Stop }
catch { throw ('Failed to read technique IDs from {0}. {1}' -f $techniquesFile, $_.Exception.Message) }

# Prepare the techniques object structure
Write-Verbose ('Preparing techniques object structure')
$techniques = @()
foreach ($id in $mitreIds) {
	if ($id -like "*.*") {
		$techniques += @{ "techniqueID" = $id.split('.')[0]; "score" = $scoreToAssign; "color" = "$colorToAssign" } # Adjust score and color as needed
	}
	$techniques += @{ "techniqueID" = $id; "score" = $scoreToAssign; "color" = "$colorToAssign" } # Adjust score and color as needed
}

$templateNavigator = @'
{
	"name": "layer",
	"versions": {
		"attack": "14",
		"navigator": "4.9.4",
		"layer": "4.5"
	},
	"domain": "enterprise-attack",
	"description": "",
	"filters": {
		"platforms": [
			"Linux",
			"macOS",
			"Windows",
			"Network",
			"PRE",
			"Containers",
			"Office 365",
			"SaaS",
			"Google Workspace",
			"IaaS",
			"Azure AD"
		]
	},
	"sorting": 0,
	"layout": {
		"layout": "side",
		"aggregateFunction": "average",
		"showID": false,
		"showName": true,
		"showAggregateScores": false,
		"countUnscored": false,
		"expandedSubtechniques": "none"
	},
	"hideDisabled": false,
	"techniques": [],
	"gradient": {
		"colors": [
			"#ff6666ff",
			"#ffe766ff",
			"#8ec843ff"
		],
		"minValue": 0,
		"maxValue": 100
	},
	"legendItems": [],
	"metadata": [],
	"links": [],
	"showTacticRowBackground": false,
	"tacticRowBackground": "#dddddd",
	"selectTechniquesAcrossTactics": true,
	"selectSubtechniquesWithParent": false,
	"selectVisibleTechniques": false
}
'@

# Load the template
Write-Verbose ('Loading Navigator template')
$templateJson = $templateNavigator | ConvertFrom-Json

# Update the techniques section in the template
Write-Verbose ('Updating techniques section')
$templateJson.techniques = $techniques

# Convert the modified object back to JSON
Write-Verbose ('Converting the updated JSON to a string')
$finalJson = $templateJson | ConvertTo-Json -Depth 100

# Save the updated JSON to a new file
Write-Verbose ('Saving the updated JSON to {0}' -f $outputFile)
try { 
	$finalJson | Set-Content -Path $outputFile -ErrorAction Stop -Force -Confirm:$false 
}
catch {
 throw ('Failed to save the updated JSON to {0}. {1}' -f $outputFile, $_.Exception.Message) 
}

# Get the output file as an object
$outputFileObject = Get-Item -Path $outputFile

# Return the output file
return $outputFileObject