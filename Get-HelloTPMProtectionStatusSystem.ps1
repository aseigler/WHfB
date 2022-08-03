$ngc = Get-ChildItem -Path ($ENV:SystemRoot + '\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc')
foreach($entry in $ngc){
    $sidBytes = Get-Content -Raw -Encoding Byte (Join-Path $entry.FullName -ChildPath '1.dat')
    $sidBytes = [System.Text.Encoding]::Convert([System.Text.Encoding]::Unicode, [System.Text.Encoding]::ASCII, $sidBytes)
    $sid = [System.Text.Encoding]::ASCII.GetString($sidBytes)
    $username = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
    $tpmProtected = (Get-Content (Join-Path $entry.FullName -ChildPath '7.dat')) -eq 'Microsoft Platform Crypto Provider'
    Write-Host $username, $tpmProtected
}