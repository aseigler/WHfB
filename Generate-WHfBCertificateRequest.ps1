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

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

public class NetAPI32{

	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DSREG_USER_INFO {
        [MarshalAs(UnmanagedType.LPWStr)] public string UserEmail;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserKeyId;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserKeyName;
    }

	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DSREG_JOIN_INFO
    {
        public int joinType;
        public IntPtr pJoinCertificate;
        [MarshalAs(UnmanagedType.LPWStr)] public string DeviceId;
        [MarshalAs(UnmanagedType.LPWStr)] public string IdpDomain;
        [MarshalAs(UnmanagedType.LPWStr)] public string TenantId;
        [MarshalAs(UnmanagedType.LPWStr)] public string JoinUserEmail;
        [MarshalAs(UnmanagedType.LPWStr)] public string TenantDisplayName;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmEnrollmentUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmTermsOfUseUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string MdmComplianceUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserSettingSyncUrl;
        public IntPtr pUserInfo;
    }

    [DllImport("netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern void NetFreeAadJoinInformation(
            IntPtr pJoinInfo);

    [DllImport("netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int NetGetAadJoinInformation(
            string pcszTenantId,
            out IntPtr ppJoinInfo);
}
'@

$pcszTenantId = $null
$ptrJoinInfo = [IntPtr]::Zero

# https://docs.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation
#[NetAPI32]::NetFreeAadJoinInformation([IntPtr]::Zero);
$retValue = [NetAPI32]::NetGetAadJoinInformation($pcszTenantId, [ref]$ptrJoinInfo);

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
if ($retValue -eq 0) 
{
    # https://support.microsoft.com/en-us/help/2909958/exceptions-in-windows-powershell-other-dynamic-languages-and-dynamical
    $ptrJoinInfoObject = New-Object NetAPI32+DSREG_JOIN_INFO
    $joinInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrJoinInfo, [System.Type] $ptrJoinInfoObject.GetType())

    $ptrUserInfo = $joinInfo.pUserInfo
    $ptrUserInfoObject = New-Object NetAPI32+DSREG_USER_INFO
    $userInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrUserInfo, [System.Type] $ptrUserInfoObject.GetType())

    $UPN = $userInfo.UserEmail
    $keyContainer = $userInfo.UserKeyName
    #Release pointers
    if ([IntPtr]::Zero -ne $ptrJoinInfo)
    {
        [NetAPI32]::NetFreeAadJoinInformation($ptrJoinInfo)
    }
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
certreq.exe -new $INFPath $CSRPath
Write-Output "Certificate Request has been generated at $CSRPath"
