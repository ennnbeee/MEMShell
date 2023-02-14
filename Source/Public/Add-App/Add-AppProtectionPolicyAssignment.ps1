Function Add-AppProtectionPolicyAssignment() {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthTokenMSAL
    Authenticates you with the Graph API interface using MSAL.PS module
    .NOTES
    NAME: Get-AuthTokenMSAL
    #>

    [cmdletbinding()]

    param
    (
        [Parameter(Mandatory = $true)]
        $Id,
        $TargetGroupId,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Android', 'iOS')]
        [string]$OS,
        [ValidateSet('Include', 'Exclude')]
        [ValidateNotNullOrEmpty()]
        [string]$AssignmentType
    )

    $graphApiVersion = 'Beta'

    try {
        $TargetGroup = New-Object -TypeName psobject

        if ($TargetGroupId) {
            if ($AssignmentType -eq 'Exclude') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
            }
            elseif ($AssignmentType -eq 'Include') {
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
            }

            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
        }

        else {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.allLicensedUsersAssignmentTarget'
        }

        $Target = New-Object -TypeName psobject
        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

        $TargetGroups = $Target

        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        $JSON = $Output | ConvertTo-Json -Depth 3

        if ($OS -eq 'Android') {
            $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/androidManagedAppProtections('$ID')/assign"
        }

        elseif ($OS -eq 'iOS') {
            $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/iosManagedAppProtections('$ID')/assign"
        }

        Invoke-RestMethod -Uri $uri -Method Post -ContentType 'application/json' -Body $JSON -Headers $authToken
    }
    catch {
        $exs = $Error.ErrorDetails
        $ex = $exs[0]
        Write-Host "Response content:`n$ex" -f Red
        Write-Host
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Message)"
        Write-Host
        break
    }
}