<#
.NAME Get-HelloForBusinessTPMProtectionStatusUser

.SYNOPSIS
Enumerates Windows Hello for Business credential registered to the current user, and reports whether or not
the credential is backed by a trusted platform module.  Requires no special privileges to run.

.INPUTS
None.

.OUTPUTS
PSCustomObject

This cmdlet returns a PSCustomObject object that contains the following information:

-- UserName. The name of the user account associated with the credential in DOMAIN\username form
-- TpmProtected. Whether the credential is backed with a trusted platform module
-- UPN. The name of the user account associated with the credential in user@example.org form
#>

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

public class Crypt32 {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CRYPT_KEY_PROV_INFO
    {
        public string pwszContainerName;
        public string pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    public static readonly int CERT_KEY_PROV_INFO_PROP_ID = 2;

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern
    bool CertGetCertificateContextProperty(IntPtr pCertContext,
                                           uint dwPropId,
                                           IntPtr pvData,
                                           ref int pcbData);
}

public class NetAPI32 {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct DSREG_JOIN_INFO {
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
$retValue = [NetAPI32]::NetGetAadJoinInformation($pcszTenantId, [ref]$ptrJoinInfo)
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
if ($retValue -eq 0) {
    # https://support.microsoft.com/en-us/help/2909958/exceptions-in-windows-powershell-other-dynamic-languages-and-dynamical
    $ptrJoinInfoObject = New-Object NetAPI32+DSREG_JOIN_INFO
    $joinInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrJoinInfo, [System.Type] $ptrJoinInfoObject.GetType())

    $ptrProvInfo = [IntPtr]::Zero
    $provSize = 0
    $retValue = [Crypt32]::CertGetCertificateContextProperty($joinInfo.pJoinCertificate, [Crypt32]::CERT_KEY_PROV_INFO_PROP_ID, $ptrProvInfo, [ref] $provSize)
    if ($true -eq $retValue) {
        $ptrProvInfo = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($provSize)
        $retValue = [Crypt32]::CertGetCertificateContextProperty($joinInfo.pJoinCertificate, [Crypt32]::CERT_KEY_PROV_INFO_PROP_ID, $ptrProvInfo, [ref] $provSize)
        if ($true -eq $retValue) {
            $ptrProvInfoObject = New-Object Crypt32+CRYPT_KEY_PROV_INFO
            $provInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptrProvInfo, [System.Type] $ptrProvInfoObject.GetType())

            $result = [PSCustomObject]@{
                UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                TpmProtected = $provInfo.pwszProvName -eq 'Microsoft Platform Crypto Provider'
                UPN = $joinInfo.JoinUserEmail
            }
        }
    }
    #Release pointers
    if ([IntPtr]::Zero -ne $provInfo)
    {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptrProvInfo)
    }

    if ([IntPtr]::Zero -ne $ptrJoinInfo)
    {
        [NetAPI32]::NetFreeAadJoinInformation($ptrJoinInfo)
    }

    $result
}