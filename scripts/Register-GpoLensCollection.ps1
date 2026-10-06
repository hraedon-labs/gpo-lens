<#
.SYNOPSIS
  Register a least-privilege, scheduled offline GPO collection.
.DESCRIPTION
  Run elevated on a Windows DC/RSAT host. The gMSA must already be installed
  and usable on this host. Both modes use Password logon (network access);
  Windows manages the gMSA password. A normal account prompts with Get-Credential
  unless -Credential is supplied. No password is written to a script or file.
  Task Scheduler protects normal-account credentials in its Windows store.
  Registration changes only a local scheduled task, never AD.
.PARAMETER InventoryPath
  Optional authoritative gpo-inventory.json from a separate privileged export.
  The runner substitutes it into each routine folder AND ZIP before delivery.
.PARAMETER ExecutionTimeLimit
  Hard runtime limit, default 02:00:00. Zero/unlimited limits are rejected.
.EXAMPLE
  .\Register-GpoLensCollection.ps1 -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot C:\GpoExport
.EXAMPLE
  .\Register-GpoLensCollection.ps1 -ServiceAccount 'LABDOMAIN\svc-collector' -OutputRoot C:\GpoExport
.EXAMPLE
  .\Register-GpoLensCollection.ps1 -Unregister -WhatIf
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Gmsa')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Gmsa')]
    [ValidatePattern('^[^\\]+\\[^\\]+\$$')]
    [string]$GmsaAccount,
    [Parameter(Mandatory, ParameterSetName = 'Service')]
    [ValidatePattern('^[^\\]+\\[^\\$]+$')]
    [string]$ServiceAccount,
    [Parameter(ParameterSetName = 'Service')]
    [pscredential]$Credential,
    [Parameter(Mandatory, ParameterSetName = 'Remove')]
    [switch]$Unregister,
    [Parameter(Mandatory, ParameterSetName = 'Gmsa')]
    [Parameter(Mandatory, ParameterSetName = 'Service')]
    [string]$OutputRoot,
    [string]$TaskName = 'GpoLensCollection',
    [string]$CollectorPath = (Join-Path $PSScriptRoot 'Export-GpoEstate.ps1'),
    [ValidateRange(1, 365)]
    [int]$EveryDays = 1,
    [string]$At = '02:00',
    [ValidateScript({ $_ -gt [timespan]::Zero -and $_ -le [timespan]::FromDays(365) })]
    [timespan]$ExecutionTimeLimit = [timespan]::FromHours(2),
    [ValidateRange(1, 1000)]
    [int]$Retention = 14,
    [string]$CopyTo,
    [string]$InventoryPath,
    [ValidateRange(1024, 104857600)]
    [int]$LogMaxBytes = 5242880,
    [ValidateRange(1, 100)]
    [int]$LogFiles = 5
)

function ConvertTo-GpoLensTaskArgument {
    param([string]$Value)
    if ($Value -match '["\r\n]') { throw 'Task paths cannot contain quotes or newlines.' }
    # Windows command-line quoting: double trailing backslashes before the quote.
    return '"' + ($Value -replace '(\\+)$', '$1$1') + '"'
}

function ConvertTo-GpoLensAbsolutePath {
    param([string]$Value)
    # Preserve Windows UNC/drive paths when unit tests run on Linux.
    if ($Value -match '^(?:[A-Za-z]:[\\/]|\\\\)') { return $Value }
    return [IO.Path]::GetFullPath($Value)
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    if ($Unregister) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister collection task')) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Host "Unregistered task: $TaskName (exports and logs retained)"
        }
        return
    }
    $scheduleTime = [datetime]::MinValue
    if (-not [datetime]::TryParseExact($At, 'HH:mm', [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$scheduleTime)) {
        throw '-At must use HH:mm (24-hour local time).'
    }
    $CollectorPath = (Resolve-Path -LiteralPath $CollectorPath).ProviderPath
    $runner = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'Run-GpoLensCollection.ps1')).ProviderPath
    $OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
    $taskArgs = '-NoProfile -NonInteractive -File ' + (ConvertTo-GpoLensTaskArgument $runner) +
        ' -CollectorPath ' + (ConvertTo-GpoLensTaskArgument $CollectorPath) +
        ' -OutputRoot ' + (ConvertTo-GpoLensTaskArgument $OutputRoot) +
        " -Retention $Retention -LogMaxBytes $LogMaxBytes -LogFiles $LogFiles"
    if ($CopyTo) { $taskArgs += ' -CopyTo ' + (ConvertTo-GpoLensTaskArgument (ConvertTo-GpoLensAbsolutePath $CopyTo)) }
    if ($InventoryPath) { $taskArgs += ' -InventoryPath ' + (ConvertTo-GpoLensTaskArgument (ConvertTo-GpoLensAbsolutePath $InventoryPath)) }
    $account = if ($GmsaAccount) { $GmsaAccount } else { $ServiceAccount }
    if (-not $PSCmdlet.ShouldProcess($TaskName, "Register collection as $account every $EveryDays day(s) at $At; limit $ExecutionTimeLimit")) {
        return
    }
    # Password is the task logon type for domain accounts, including gMSAs.
    # ServiceAccount logon is for built-in SYSTEM/LocalService/NetworkService.
    $principal = New-ScheduledTaskPrincipal -UserId $account -LogonType Password -RunLevel Limited
    $windowsRoot = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
    $action = New-ScheduledTaskAction -Execute "$windowsRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument $taskArgs -WorkingDirectory $PSScriptRoot
    $trigger = New-ScheduledTaskTrigger -Daily -DaysInterval $EveryDays -At $scheduleTime
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit $ExecutionTimeLimit `
        -MultipleInstances IgnoreNew -StartWhenAvailable
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Read-only GPO export, bounded retention, rotating logs and optional ZIP delivery.'
    if ($GmsaAccount) {
        Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    } else {
        if (-not $Credential) { $Credential = Get-Credential -UserName $ServiceAccount -Message 'Collection task credentials (saved only by Windows Task Scheduler)' }
        if (-not $Credential -or $Credential.UserName -ne $ServiceAccount) { throw 'Credential username must match -ServiceAccount.' }
        $taskPassword = $Credential.GetNetworkCredential().Password
        try {
            Register-ScheduledTask -TaskName $TaskName -InputObject $task -User $ServiceAccount -Password $taskPassword -Force | Out-Null
        } finally {
            $taskPassword = $null
            $Credential = $null
        }
    }
    Write-Host "Registered task: $TaskName"
    Write-Host "  Account: $account; every $EveryDays day(s) at $At (host local time)"
    Write-Host "  Hard time limit: $ExecutionTimeLimit; retain $Retention exports"
    Write-Host "  Output: $OutputRoot; log: $(Join-Path $OutputRoot 'collection.log')"
    if ($CopyTo) { Write-Host "  ZIP delivery: $CopyTo (ingest separately)" }
    Write-Host "Verify with: Get-ScheduledTaskInfo -TaskName '$TaskName'"
}
