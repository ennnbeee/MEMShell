@{

    # Script module or binary module file associated with this manifest.
    RootModule           = 'MEMShell.psm1'

    # Version number of this module.
    ModuleVersion        = '0.0.1'

    PrivateData          = @{
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
    GUID                 = 'ba8852b0-64fc-477e-b8f1-a3dfc9bfa694'
    Description          = 'A module for managed Microsoft Intune'

    # Author of this module
    Author               = 'Nick Benton'
    CompanyName          = 'MEM v ENNBEE'
    Copyright            = '(c) Nick Benton. All rights reserved.'


    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules      = @('MSAL.PS')

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
    FunctionsToExport    = @()

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport      = @()

    # Variables to export from this module
    VariablesToExport    = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = @()

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