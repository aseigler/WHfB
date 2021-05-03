<#
.SYNOPSIS
Generates a certificate request .inf file as well as a certificate request .req file for a
client authentication certificate whose private key is protected by the Windows Hello for
Business gesture.
 
.DESCRIPTION
Generates a certificate request .inf file as well as a certificate request .req file for a
client authentication certificate whose private key is protected by the Windows Hello for
Business gesture.
 
The private key is stored in the "Microsoft Passport Key Storage Provider"
    
.PARAMETER INFPath
Specifies the file path where the certificate request .inf file will be written
e.g. C:\Temp\CertReq.inf
 
.PARAMETER CSRPath
Specifies the file path where the certificate request .req file will be written
e.g. C:\Temp\CertReq.req
 
.PARAMETER WindowsCA
If specified, indicates the certificate request will be to a Windows Enterprise Certificate
Authority
 
.PARAMETER CertificateTemplate
Only required when WindowsCA is provided. Specifies the certificate template used for the
certificate request
e.g. WHfBCertificateAuthentication
 
.INPUTS
System.String
Path name for Generates a certificate request .inf file as well as a certificate request .req
file whose private key is protected by the Windows Hello for Business gesture. Optionally the
certificate template name that will be used for the request against a Windows Enterprise
Certificate Authority.
 
.OUTPUTS
None. Generate-WHfBCertificateRequest.ps1 does not generate any output.
 
.EXAMPLE
C:\PS> .\Generate-WHfBCertificateRequest.ps1 -INFPath .\CertReq.inf -CSRPath .\CertReq.req
 
Description
-----------
This command generates the certificate request .inf and .req (CSR) files for a client
authentication certificate whose private key is protected with the Windows Hello for
Business gesture.
 
.EXAMPLE
C:\PS> .\Generate-WHfBCertificateRequest.ps1 -INFPath .\CertReq.inf -CSRPath .\CertReq.req -WindowsCA -CertificateTemplate WHfBCertificateAuthentication
 
Description
-----------
This command generates the certificate request .inf and .req (CSR) files for a client
authentication certificate whose private key is protected with the Windows Hello for
Business gesture.
 
Here the WindowsCA switch indicates that a Windows Enterprise Certificate Authority will be
used and that the certificate template for the request is called "WHfBCertificateAuthentication".
 
#>

[CmdletBinding(DefaultParametersetName='None')] 
param( 
    [Parameter(Position=0,Mandatory=$false)] [string]$INFPath = (Join-Path -Path $env:TEMP -ChildPath "WHfBCertificate.inf"), 
    [Parameter(Position=1,Mandatory=$false)] [string]$CSRPath = (Join-Path -Path $env:TEMP -ChildPath "WHfBCertificate.req"), 
    [Parameter(ParameterSetName='Extra',Mandatory=$false)][switch]$WindowsCA,      
    [Parameter(ParameterSetName='Extra',Mandatory=$true)][string]$CertificateTemplate
)

# Initialize variables
$ngcKeyName = $null
$UPN = $null
$keyContainer = $null
$template = $null

if ($WindowsCA -eq $true){
    $template =
@"
[RequestAttributes]
CertificateTemplate = $certificateTemplate
"@  
}

try {
    # Check whether this version of Windows will allow use of DSRegCmd.exe
    $OSVersion = ([environment]::OSVersion.Version).Major
    $OSBuild = ([environment]::OSVersion.Version).Build

    if (($OSVersion -ge 10) -and ($OSBuild -ge 1511)){
        $dsReg = dsregcmd.exe /status    # Retrieve DSRegCmd.exe /status data
    }
    else{
        # DSRegCmd.exe will not work.
        throw "The device has a Windows down-level OS version. Run this test on current OS versions e.g. Windows 10, Server 2016 and above."
    }

    # Retrieve the current user's UPN from $dsReg
    $exAccName = $dsReg | Select-String "Executing Account Name"
    if ($null -ne $exAccName){
        $exAccAliases = ($exAccName.ToString() -split " ")[-1]
        foreach ($exAccAlias in $exAccAliases)
        {
            if ($exAccAlias -like "*@*")
            {
                $UPN = $exAccAlias.Trim()
            }
        }
    }

    $ngcKeyName = $dsReg | Select-String "NgcKeyName"
    if ($null -ne $ngcKeyName){
        $UPN = (($ngcKeyName.ToString() -split "/")[-1])
    }

    if ($null -eq $UPN){
       throw "The UPN for the current user could not be retrieved."
    }

    # Retrieve the current user's WHfB Key Container from certutil.exe
    $certUtl = certutil.exe -user -csp "Microsoft Passport Key Storage Provider" -key
    foreach ($certRow in $certUtl){
        if ($certRow -like "*$UPN"){
            $keyContainer = $certRow.Trim()
        }
    }

    if ($null -eq $keyContainer){
        throw "Windows Hello for Business is not deployed to this device."
    }

    # Build certificate request .inf file
    $INF =
@"
[Version]
Signature = "`$Windows NT`$"
  
[NewRequest]
Subject = "CN=$UPN"
ProviderName = "Microsoft Passport Key Storage Provider"
KeyContainer = $keyContainer
UseExistingKeySet = TRUE
RequestType = PKCS10
 
[EnhancedKeyUsageExtension]
OID = 1.3.6.1.4.1.311.20.2.2 ; Smart Card Logon
OID = 1.3.6.1.5.5.7.3.2 ; Client auth
 
$template
 
[Extensions]
2.5.29.17 = {text}
_continue_ = "UPN=$UPN&"
"@

    Write-Output "Certificate Request is being generated"
    $INF | Out-File -Filepath $INFPath -Force
    #certreq -new $INFPath $CSRPath
    Write-Output "Certificate Request has been generated"

}
catch{
    $PSCmdlet.ThrowTerminatingError($PSItem)
}
Write-Output "Script completed successfully."