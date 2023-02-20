Function Invoke-EnrolmentRestriction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Path,

        [ValidateSet('Windows', 'Android', 'iOS', 'macOS')]
        [string[]]$OS,

        [ValidateSet('Corporate', 'Personal', 'Both')]
        [string]$Enrolment,

        [ValidateSet('CE', 'NCSC', 'MS')]
        [string]$Engagement
    )

    $Files = Get-ChildItem -Path $Path -Filter *.json | Where-Object { ($_.name -like "*$OS*") -and ($_.name -like "*$Enrolment*") -and ($_.name -like "*_$($Engagement)_*") }

    foreach ($file in $files) {
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        # Excluding entries that are not required - id,createdDateTime,lastModifiedDateTime,version
        $JSON_Convert = $JSON_Data | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, roleScopeTagIds
        $DisplayName = $JSON_Convert.displayName

        if (($OS -eq 'Android') -or ($DisplayName -like '*Android*')) {

            if (Get-EnrolmentRestriction | Where-Object { ($_.platformType -eq $JSON_Convert.platformType ) } ) {
                Write-Information "Enrolment Restriction $DisplayName already exists."
            }
            Else {
                $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
                Write-Information "Adding Enrolment Restriction $DisplayName"
                New-EnrolmentRestriction -JSON $JSON_Output
                Write-Information "Sucessfully Added Enrolment Restriction $DisplayName"
            }

        }
        else {
            if (Get-EnrolmentRestriction | Where-Object { ($_.displayName).equals($DisplayName) }) {

                Write-Information "Enrolment Restriction $DisplayName already exists"
            }

            else {

                $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5
                Write-Information "Adding Enrolment Restriction '$DisplayName'"
                New-EnrolmentRestriction -JSON $JSON_Output
                Write-Information "Sucessfully Added Enrolment Restriction $DisplayName"
            }
        }
    }
}