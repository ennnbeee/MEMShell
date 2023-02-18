@{

    # Script module or binary module file associated with this manifest.
    RootModule        = 'MEMShell.psm1'

    # Version number of this module.
    ModuleVersion     = '0.1.2'

    PrivateData       = @{
        # PrivateData.PSData is the PowerShell Gallery data
        PSData = @{
            # Prerelease string should be here, so we can set it
            Prerelease   = ''

            # Release Notes have to be here, so we can update them
            ReleaseNotes = ''

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = 'PSEdition_Desktop', 'PSEdition_Core'

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/ennnbeee/memshell/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/ennnbeee/memshell'

            # A URL to an icon representing this module.
            IconUri      = 'https://raw.githubusercontent.com/ennnbeee/memshell/main/MEMShell.png'
        } # End of PSData
    } # End of PrivateData
    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID              = 'ba8852b0-64fc-477e-b8f1-a3dfc9bfa694'
    Description       = 'A module for managed Microsoft Intune'

    # Author of this module
    Author            = 'Nick Benton'
    CompanyName       = 'MEM v ENNBEE'
    Copyright         = '(c) Nick Benton. All rights reserved.'


    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules   = @( @{
            ModuleName    = 'MSAL.PS'
            ModuleVersion = '4.37.0'
        }
    )

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @('Add-AppCategory','Add-AppConfigPolicyDeviceAssignment','Add-AppMobileAppAssignment','Add-AppMobileAppCategory','Add-AppProtectionPolicyAssignment','Add-DeviceCompliancePolicyAssignment','Add-DeviceConfigProfileAssignment','Add-DeviceEndpointSecProfileAssignment','Add-DeviceSettingsCatalogAssignment','Add-EnrolmentADEProfileAssignment','Add-EnrolmentAutopilotProfileAssignment','Add-EnrolmentESPAssignment','Add-EnrolmentRestrictionAssignment','Get-AppCategory','Get-AppConfigPolicyApp','Get-AppConfigPolicyDevice','Get-AppMobileApp','Get-AppMobileAppAssignment','Get-AppMobileAppCategory','Get-AppProtectionPolicy','Get-DeviceAutopilot','Get-DeviceCompliancePolicy','Get-DeviceCompliancePolicyScript','Get-DeviceConfigProfile','Get-DeviceConfigProfileAssignment','Get-DeviceEndpointSecProfile','Get-DeviceEndpointSecTemplate','Get-DeviceEnrolmentRestriction','Get-DeviceFilter','Get-DeviceManagedDevice','Get-DeviceNotificationMessage','Get-DeviceNotificationTemplate','Get-DeviceScript','Get-DeviceScriptAssignment','Get-DeviceSettingsCatalog','Get-DeviceUpdatePolicy','Get-EnrolmentADEProfile','Get-EnrolmentADEToken','Get-EnrolmentAPProfile','Get-EnrolmentAPProfileAssignment','Get-EnrolmentESP','Get-EnrolmentESPAssignment','Get-MEMGroup','Get-MEMGroupMember','New-AppConfigPolicyApp','New-AppConfigPolicyDevice','New-AppManagedGooglePlayApp','New-AppProtectionPolicy','New-DeviceCompliancePolicy','New-DeviceConfigProfile','New-DeviceEndpointSecProfile','New-DeviceFilter','New-DeviceNotificationMessage','New-DeviceNotificationTemplate','New-DeviceScript','New-DeviceSettingCatalog','New-EnrolmentAPProfile','New-EnrolmentESP','Remove-AppConfigPolicyApp','Remove-AppConfigPolicyDevice','Remove-AppMobileAppAssignment','Remove-AppMobileAppCategory','Remove-AppProtectionPolicy','Remove-DeviceCompliancePolicy','Remove-DeviceConfigProfile','Remove-DeviceFilter','Remove-DeviceScript','Remove-DeviceSettingsCatalog','Start-AppAppleVPPAppSync','Start-AppGooglePlayAppSync','Update-DeviceAPDevice','Update-DeviceCompliancePolicy','Update-DeviceManagedDeviceName','Update-DeviceOwnership')

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}
