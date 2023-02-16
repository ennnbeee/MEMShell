Function Export-JSONData() {

    <#
    .SYNOPSIS
    This function is used to export JSON data returned from Graph
    .DESCRIPTION
    This function is used to export JSON data returned from Graph
    .EXAMPLE
    Export-JSONData -JSON $JSON
    Export the JSON inputted on the function
    .NOTES
    NAME: Export-JSONData
    #>

    [cmdletbinding()]
    param (
        [parameter(Mandatory = $true)]
        $JSON,

        [parameter(Mandatory = $true)]
        [string]$ExportPath
    )

    try {
        if (!(Test-Path $ExportPath)) {
            Write-Error "$ExportPath doesn't exist, can't export JSON Data"
            Break
        }
        else {

            $JSON = ConvertTo-Json $JSON -Depth 5
            $JSON_Convert = $JSON | ConvertFrom-Json
            $displayName = $JSON_Convert.displayName

            # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
            $DisplayName = $DisplayName -replace '\<|\>|:|"|/|\\|\||\?|\*', '_'
            $FileName_JSON = "$DisplayName" + '_' + $(Get-Date -f dd-MM-yyyy-H-mm-ss) + '.json'

            $JSON | Set-Content -LiteralPath "$ExportPath\$FileName_JSON"
            Write-Information "JSON created in $ExportPath\$FileName_JSON..."
        }
    }
    catch {
        $_.Exception
    }
}