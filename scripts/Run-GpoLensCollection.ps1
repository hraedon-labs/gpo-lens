<#
.SYNOPSIS
  Scheduled collection runner: export, inventory overlay, ZIP delivery and retention.
.DESCRIPTION
  Invoked by Register-GpoLensCollection.ps1. Dedicated output root per task.
  Only completed timestamp-named collector ZIPs with matching export folders
  are retained/pruned. Delivery uses a temporary file and rename; it does not
  ingest data. Errors exit nonzero so Task Scheduler reports failure.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
    [string]$TaskName = 'GpoLensCollection',
    [string]$CollectorPath = (Join-Path $PSScriptRoot 'Export-GpoEstate.ps1'),
    [ValidateRange(1, 1000)]
    [int]$Retention = 14,
    [string]$CopyTo,
    [string]$InventoryPath,
    [ValidateRange(1024, 104857600)]
    [int]$LogMaxBytes = 5242880,
    [ValidateRange(1, 100)]
    [int]$LogFiles = 5
)

function Write-GpoLensCollectionLog {
    param([string]$LogPath, [string]$Message, [int]$LogMaxBytes, [int]$LogFiles)
    $encoding = [Text.UTF8Encoding]::new($false)
    $line = "$(Get-Date -Format o) $Message`r`n"
    # Bound a single record as well as the file; verbose collector lines can be long.
    $maxChars = [math]::Max(1, [int]($LogMaxBytes / 4) - 40)
    if ($line.Length -gt $maxChars) { $line = $line.Substring(0, $maxChars) + " [truncated]`r`n" }
    $bytes = $encoding.GetByteCount($line)
    if ((Test-Path -LiteralPath $LogPath) -and (Get-Item -LiteralPath $LogPath).Length + $bytes -gt $LogMaxBytes) {
        for ($i = $LogFiles; $i -ge 1; $i--) {
            $old = if ($i -eq 1) { $LogPath } else { "$LogPath.$($i - 1)" }
            $next = "$LogPath.$i"
            if (Test-Path -LiteralPath $next) { Remove-Item -LiteralPath $next -Force -ErrorAction Stop }
            if (Test-Path -LiteralPath $old) { Move-Item -LiteralPath $old -Destination $next -ErrorAction Stop }
        }
    }
    [IO.File]::AppendAllText($LogPath, $line, $encoding)
}

function Get-GpoLensCompletedExports {
    param([string]$OutputRoot)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $candidates = @(Get-ChildItem -LiteralPath $OutputRoot -File -Filter '*.zip' -ErrorAction Stop |
        Where-Object {
            $_.BaseName -match '^.+-\d{8}-\d{6}$' -and
            (Test-Path -LiteralPath (Join-Path (Join-Path $OutputRoot $_.BaseName) 'AllGPOs.xml') -PathType Leaf)
        } | Sort-Object @{ Expression = { $_.BaseName.Substring($_.BaseName.Length - 15) }; Descending = $true }, Name)
    foreach ($archive in $candidates) {
        $zip = $null
        try {
            $zip = [IO.Compression.ZipFile]::OpenRead($archive.FullName)
            if ($zip.GetEntry('AllGPOs.xml')) { $archive }
            else { Write-Warning "Skipping incomplete ZIP (no estate report): $($archive.Name)" }
        } catch {
            Write-Warning "Skipping unreadable/incomplete ZIP: $($archive.Name)"
        } finally { if ($zip) { $zip.Dispose() } }
    }
}

function Assert-GpoLensRegularTree {
    param([string]$Root)
    # PS 5.1 recursive removal can follow nested junctions. Enumerate one level
    # at a time and refuse every reparse point before retention deletes anything.
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $item = Get-Item -LiteralPath $directory -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Retention refuses a linked export folder or file.'
        }
        foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Retention refuses a linked export folder or file.'
            }
            if ($child.PSIsContainer) { $pending.Push($child.FullName) }
        }
    }
}

function Assert-GpoLensCollectionOwner {
    param([string]$OutputRoot, [string]$TaskName)
    $marker = Join-Path $OutputRoot '.gpo-lens-collection-owner'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw 'Collection refuses an output root without an owner marker. Re-register the task.'
    }
    if ((Get-Item -LiteralPath $marker -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Collection refuses a linked owner marker.'
    }
    $owner = [IO.File]::ReadAllText($marker).TrimEnd([char[]]"`r`n")
    if (-not [string]::Equals($owner, $TaskName, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Collection refuses output root owner '$owner' for task '$TaskName'."
    }
}

function Invoke-GpoLensCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][string]$CollectorPath,
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string]$TaskName = 'GpoLensCollection',
        [ValidateRange(1, 1000)][int]$Retention = 14,
        [string]$CopyTo,
        [string]$InventoryPath,
        [ValidateRange(1024, 104857600)][int]$LogMaxBytes = 5242880,
        [ValidateRange(1, 100)][int]$LogFiles = 5
    )
    $ErrorActionPreference = 'Stop'
    if ((Test-Path -LiteralPath $OutputRoot) -and
        ((Get-Item -LiteralPath $OutputRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Collection refuses a linked output root.'
    }
    # Refuse before creating any root, logs or running the collector.
    Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName
    # Protect retention and log rotation from concurrent manual/task runs.
    $lock = [IO.File]::Open((Join-Path $OutputRoot 'collection.lock'), [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $logArgs = @{LogPath=(Join-Path $OutputRoot 'collection.log'); LogMaxBytes=$LogMaxBytes; LogFiles=$LogFiles}
    try {
        Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName
        Write-GpoLensCollectionLog @logArgs -Message 'Collection started'
        if ($InventoryPath) {
            # Capture once: later file changes cannot diverge from validated bytes.
            $inventoryBytes = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $InventoryPath).ProviderPath)
            $inventory = [Text.Encoding]::UTF8.GetString($inventoryBytes).TrimStart([char]0xFEFF) | ConvertFrom-Json
            if (-not $inventory) { throw 'Authoritative inventory must not be empty.' }
            $ids = [Collections.Generic.HashSet[guid]]::new()
            foreach ($entry in @($inventory)) {
                $id = [guid]::Empty
                if (-not [guid]::TryParse([string]$entry.Id, [ref]$id) -or $id -eq [guid]::Empty) {
                    throw 'Authoritative inventory entries must have valid GPO GUID Id fields.'
                }
                if (-not $ids.Add($id)) { throw 'Authoritative inventory contains duplicate GPO IDs.' }
            }
        }
        $previous = @{}
        Get-ChildItem -LiteralPath $OutputRoot -File -Filter '*.zip' | ForEach-Object { $previous[$_.FullName] = $true }
        & $CollectorPath -OutputRoot $OutputRoot *>&1 | ForEach-Object {
            Write-GpoLensCollectionLog @logArgs -Message ($_ | Out-String).TrimEnd()
        }
        $created = @(Get-GpoLensCompletedExports -OutputRoot $OutputRoot | Where-Object { -not $previous.ContainsKey($_.FullName) })
        if ($created.Count -ne 1) { throw "Collector must create exactly one new complete ZIP; found $($created.Count)." }
        $newest = $created[0]
        $exportDir = Join-Path $OutputRoot $newest.BaseName
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = $null
        try {
            $zip = [IO.Compression.ZipFile]::Open($newest.FullName, 'Update')
            if (-not $zip.GetEntry('AllGPOs.xml')) { throw 'New ZIP has no AllGPOs.xml.' }
            if ($InventoryPath) {
                [IO.File]::WriteAllBytes((Join-Path $exportDir 'gpo-inventory.json'), $inventoryBytes)
                $entry = $zip.GetEntry('gpo-inventory.json')
                if ($entry) { $entry.Delete() }
                $entry = $zip.CreateEntry('gpo-inventory.json')
                $stream = $entry.Open()
                try { $stream.Write($inventoryBytes, 0, $inventoryBytes.Length) } finally { $stream.Dispose() }
            }
        } catch {
            if ($zip) { $zip.Dispose() }
            Remove-Item -LiteralPath $newest.FullName -Force
            throw
        } finally { if ($zip) { $zip.Dispose() } }
        if ($CopyTo) {
            New-Item -ItemType Directory -Path $CopyTo -Force | Out-Null
            $delivery = Join-Path $CopyTo $newest.Name
            $partial = "$delivery.$([guid]::NewGuid().ToString('N')).partial"
            try {
                Copy-Item -LiteralPath $newest.FullName -Destination $partial
                Move-Item -LiteralPath $partial -Destination $delivery -Force
            } finally {
                if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
            }
            Write-GpoLensCollectionLog @logArgs -Message "ZIP delivered: $delivery"
        }
        # Bind retention to the exact prefix of the export just collected.
        # Never treat a similarly named producer as owned by this run.
        Assert-GpoLensCollectionOwner -OutputRoot $OutputRoot -TaskName $TaskName
        $producerPrefix = $newest.BaseName.Substring(0, $newest.BaseName.Length - 16)
        $expired = @(Get-GpoLensCompletedExports -OutputRoot $OutputRoot |
            Where-Object {
                [string]::Equals($_.BaseName.Substring(0, $_.BaseName.Length - 16),
                    $producerPrefix, [StringComparison]::Ordinal)
            } | Select-Object -Skip $Retention)
        foreach ($archive in $expired) {
            $folder = Join-Path $OutputRoot $archive.BaseName
            Assert-GpoLensRegularTree -Root $folder
            Remove-Item -LiteralPath $archive.FullName -Force
            Remove-Item -LiteralPath $folder -Recurse -Force
        }
        Write-GpoLensCollectionLog @logArgs -Message "Collection succeeded: $($newest.Name); retained at most $Retention exports"
        Write-Host "Collection succeeded: $($newest.FullName)"
    } catch {
        $failure = $_
        try {
            Write-GpoLensCollectionLog @logArgs -Message "Collection failed: $($failure.Exception.Message)"
        } catch { Write-Warning 'Unable to write collection failure log.' }
        throw $failure
    } finally { $lock.Dispose() }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        if (-not $OutputRoot) { throw '-OutputRoot is required.' }
        Invoke-GpoLensCollection -OutputRoot $OutputRoot -CollectorPath $CollectorPath `
            -TaskName $TaskName `
            -Retention $Retention -CopyTo $CopyTo -InventoryPath $InventoryPath `
            -LogMaxBytes $LogMaxBytes -LogFiles $LogFiles
    } catch {
        Write-Error "Collection failed: $($_.Exception.Message)" -ErrorAction Continue
        exit 1
    }
}
