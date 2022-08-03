<#
.NAME Get-HelloTPMProtectionStatusSystem

.SYNOPSIS
Enumerates all Windows Hello credentials registered on a system, and reports whether or not
the credential is backed by a trusted platform module.  Requires LocalSystem privileges to run.

.INPUTS
None.

.OUTPUTS
PSCustomObject

This cmdlet returns a PSCustomObject object that contains the following information:

-- UserName. The name of the user account associated with the credential in DOMAIN\username form
-- TpmProtected. Whether the credential is backed with a trusted platform module
-- TpmPresent. Whether there is a TPM on the current computer
#>

$ngc = Get-ChildItem -Path ($ENV:SystemRoot + '\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc')
foreach($entry in $ngc){
    $sidBytes = Get-Content -Raw -Encoding Byte (Join-Path $entry.FullName -ChildPath '1.dat')
    $sidBytes = [System.Text.Encoding]::Convert([System.Text.Encoding]::Unicode, [System.Text.Encoding]::ASCII, $sidBytes)
    $sid = [System.Text.Encoding]::ASCII.GetString($sidBytes)
    $username = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
    $tpmProtected = (Get-Content (Join-Path $entry.FullName -ChildPath '7.dat')) -eq 'Microsoft Platform Crypto Provider'
    $tpmStatus = Get-Tpm
    [PSCustomObject]@{
        UserName = $username
        TpmProtected = $tpmProtected
        TpmPresent = $tpmStatus.TpmPresent
        TpmReady = $tpmStatus.TpmReady        
        TpmEnabled = $tpmStatus.TpmEnabled
        TpmActivated = $tpmStatus.TpmActivated
        TpmOwned = $tpmStatus.TpmOwned
    }
}