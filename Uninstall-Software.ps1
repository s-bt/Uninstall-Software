# Check  if we are running in PowerShell FullLanguage mode
if (-not ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage')){
    Write-Host "[-] Cannot run in PowerShell language mode '$($ExecutionContext.SessionState.LanguageMode)'" -ForegroundColor Red
    return -1
}

# Check  if we are running with an eleavted admin token
try {
    if (-not ([System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[-] You need admin rights to run this script" -ForegroundColor Red
        Read-Host -Prompt "`npress any key to exit"
        return -1
    }
} catch {
    Write-Host "[-] You need admin rights to run this script" -ForegroundColor Red
    Read-Host -Prompt "`npress any key to exit"
    return -1
}

# Will hold all software elements found in the registry
$AllSoftware =  [System.Collections.ArrayList]::new()

Write-host "[*] Getting installed software from registry" -ForegroundColor Gray

# Search for x64 software
$InstalledSoftwarex64 = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"

# Search for x86 software
$InstalledSoftwarex86 = Get-ChildItem "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

foreach($obj in $InstalledSoftwarex86){
    # If we cannot find a display name, we ignore this item
    if ($obj.GetValue('DisplayName') -eq $null) {
        continue
    }
    
    $outobj = [PSCustomObject]::new()
    $outobj | Add-Member -MemberType NoteProperty -Name Name -Value $obj.GetValue('DisplayName')
    $outobj | Add-Member -MemberType NoteProperty -Name Version -Value $obj.GetValue('DisplayVersion')
    $outobj | Add-Member -MemberType NoteProperty -Name UninstallString -Value $obj.GetValue('UninstallString')
    # If there is no UninstallString key/value pair, we use ModifyPath instead
    if ($obj.GetValue('UninstallString') -eq $null) {
        $outobj | Add-Member -MemberType NoteProperty -Name UninstallString -Value $obj.GetValue('ModifyPath') -Force
    }
   
    [void]$AllSoftware.Add($outobj)
}

foreach($obj in $InstalledSoftwarex64){
    # If we cannot find a display name, we ignore this item
    if ($obj.GetValue('DisplayName') -eq $null) {
        continue
    }
    $outobj = [PSCustomObject]::new()
    $outobj | Add-Member -MemberType NoteProperty -Name Name -Value $obj.GetValue('DisplayName')
    $outobj | Add-Member -MemberType NoteProperty -Name Version -Value $obj.GetValue('DisplayVersion')
    $outobj | Add-Member -MemberType NoteProperty -Name UninstallString -Value $obj.GetValue('UninstallString')
    # If there is no UninstallString key/value pair, we use ModifyPath instead
    if ($obj.GetValue('UninstallString') -eq $null) {
        $outobj | Add-Member -MemberType NoteProperty -Name UninstallString -Value $obj.GetValue('ModifyPath') -Force
    }
    [void]$AllSoftware.Add($outobj)
}

# Display software for selection using the Out-GridView cmdlet
# You can select a single item or multple items using eith the shift or control key
$SoftwareToUninstall = $AllSoftware | sort name | ogv -PassThru

Foreach ($s in $SoftwareToUninstall) {
    Write-Host "[*] Trying to uninstall '$($s.Name)' with command '$($s.UninstallString)'" -ForegroundColor Gray
    try {
        & $s.UninstallString
    } catch {
        try {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C $($s.UninstallString)" -Wait -ErrorAction Stop -NoNewWindow
        } catch {
            Write-Host "[-] That did not work, try running the commad $($s.UninstallString) manually" -ForegroundColor Red
        }
    }
}
