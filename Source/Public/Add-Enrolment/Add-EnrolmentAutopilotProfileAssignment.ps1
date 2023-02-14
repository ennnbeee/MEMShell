Function Add-EnrolmentAutopilotProfileAssignment() {

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
        [parameter(Mandatory = $true)]
        $Id,
        [parameter(Mandatory = $true)]
        $TargetGroupId,
        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        $AssignmentType
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles/$Id/assignments"

    try {
        $TargetGroup = New-Object -TypeName psobject

        if ($AssignmentType -eq 'Exclude') {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
        }
        elseif ($AssignmentType -eq 'Include') {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
        }

        $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $TargetGroupId

        $Target = New-Object -TypeName psobject
        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup

        $JSON = $Target | ConvertTo-Json -Depth 3

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType 'application/json'
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