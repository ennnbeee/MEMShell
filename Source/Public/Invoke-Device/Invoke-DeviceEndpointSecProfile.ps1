Function Invoke-DeviceEndpointSecProfile {

    <#
    .SYNOPSIS
    This function is used to get Deivce Enrollment Configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets Device Enrollment Configurations
    .EXAMPLE
    Get-DeviceEnrollmentConfigurations
    Returns Device Enrollment Configurations configured in Intune
    .NOTES
    NAME: Get-DeviceEnrollmentConfigurations
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$Path,
        [ValidateSet('Windows', 'Android', 'iOS', 'macOS')]
        [string[]]$OS,
        [ValidateSet('Corporate', 'Personal')]
        [string]$Enrolment,
        [ValidateSet('CE', 'NCSC', 'MS')]
        [string]$Engagement
    )

    $Files = Get-ChildItem -Path $Path -Filter *.json | Where-Object { ($_.name -like "*$OS*") -and ($_.name -like "*$Enrolment*") -and ($_.name -like "*_$($Engagement)_*") }

    foreach ($file in $files) {
        $ImportPath = $file.FullName
        $JSON_Data = Get-Content "$ImportPath"
        $JSON_Convert = $JSON_Data | ConvertFrom-Json
        $JSON_DN = $JSON_Convert.displayName
        $JSON_TemplateDisplayName = $JSON_Convert.TemplateDisplayName
        $JSON_TemplateId = $JSON_Convert.templateId

        Write-Host "Endpoint Security Policy '$JSON_DN' found..." -ForegroundColor Cyan
        Write-Host "Template Display Name: $JSON_TemplateDisplayName"
        Write-Host "Template ID: $JSON_TemplateId"
        $Templates = Get-DeviceEndpointSecTemplate
        $ES_Template = $Templates | Where-Object { $_.id -eq $JSON_TemplateId }

        # If template is a baseline Edge, MDATP or Windows, use templateId specified
        if (($ES_Template.templateType -eq 'microsoftEdgeSecurityBaseline') -or ($ES_Template.templateType -eq 'securityBaseline') -or ($ES_Template.templateType -eq 'advancedThreatProtectionSecurityBaseline')) {

            $TemplateId = $JSON_Convert.templateId

        }

        # Else If not a baseline, check if template is deprecated
        elseif ($ES_Template) {

            # if template isn't deprecated use templateId
            if ($ES_Template.isDeprecated -eq $false) {

                $TemplateId = $JSON_Convert.templateId

            }

            # If template deprecated, look for lastest version
            elseif ($ES_Template.isDeprecated -eq $true) {

                $Template = $Templates | Where-Object { $_.displayName -eq "$JSON_TemplateDisplayName" }

                $Template = $Template | Where-Object { $_.isDeprecated -eq $false }

                $TemplateId = $Template.id

            }

        }

        # Else If Imported JSON template ID can't be found check if Template Display Name can be used
        elseif ($null -eq $ES_Template) {

            Write-Host "Didn't find Template with ID $JSON_TemplateId, checking if Template DisplayName '$JSON_TemplateDisplayName' can be used..." -ForegroundColor Yellow
            $ES_Template = $Templates | Where-Object { $_.displayName -eq "$JSON_TemplateDisplayName" }

            If ($ES_Template) {

                if (($ES_Template.templateType -eq 'securityBaseline') -or ($ES_Template.templateType -eq 'advancedThreatProtectionSecurityBaseline')) {

                    Write-Host
                    Write-Host "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -ForegroundColor Yellow
                    Write-Host 'Importing using the updated template could fail as settings specified may not be included in the latest template...' -ForegroundColor Yellow
                    Write-Host
                    break

                }

                else {

                    $Template = $ES_Template | Where-Object { $_.isDeprecated -eq $false }

                    $TemplateId = $Template.id

                }

            }

            else {

                Write-Host
                Write-Host "TemplateID '$JSON_TemplateId' with template Name '$JSON_TemplateDisplayName' doesn't exist..." -ForegroundColor Red
                Write-Host 'Importing using the updated template could fail as settings specified may not be included in the latest template...' -ForegroundColor Red
                Write-Host


            }

        }

        # Excluding certain properties from JSON that aren't required for import
        $JSON_Convert = $JSON_Convert | Select-Object -Property * -ExcludeProperty TemplateDisplayName, TemplateId, versionInfo

        $DisplayName = $JSON_Convert.displayName

        if (Get-DeviceEndpointSecProfile | Where-Object { ($_.displayName).equals($DisplayName) }) {
            Write-Host "Endpoint Security Profile '$DisplayName' already exists..." -ForegroundColor Cyan

        }
        else {

            $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5

            Write-Host "Adding Endpoint Security Policy '$DisplayName'" -ForegroundColor Cyan
            New-DeviceEndpointSecProfile -TemplateId $TemplateId -JSON $JSON_Output
            Write-Host "Sucessfully Added Endpoint Security Profile '$DisplayName'" -ForegroundColor Green
        }
    }
}