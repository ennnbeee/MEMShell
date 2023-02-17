#$Functions = Get-ChildItem -Path $PSScriptRoot\functions\*.ps1
$Functions = Get-ChildItem -Path $PSScriptRoot -Recurse -Filter '*.ps1'

foreach ($Function in $Functions) {
    try {
        Write-Verbose "Importing $($Function.FullName)"
        . $Function.FullName
    }
    catch {
        Write-Error "Failed to import function $($Function.FullName): $_"
    }
} #foreach

foreach ($File in $Functions) {
    Export-ModuleMember -Function $File.BaseName
} #foreach