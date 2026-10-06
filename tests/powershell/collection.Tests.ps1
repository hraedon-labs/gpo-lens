# Pester 5 mocks: these tests never contact AD or register a real task.
Describe 'Collection scheduling' {
    BeforeAll {
        $script:RegisterPath = "$PSScriptRoot/../../scripts/Register-GpoLensCollection.ps1"
        $script:RunnerPath = "$PSScriptRoot/../../scripts/Run-GpoLensCollection.ps1"
        # ScheduledTasks is Windows-only. Stubs give Pester a command to mock on Linux.
        function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) }
        function New-ScheduledTaskAction { param($Execute, $Argument, $WorkingDirectory) }
        function New-ScheduledTaskTrigger { param([switch]$Daily, $DaysInterval, $At) }
        function New-ScheduledTaskSettingsSet { param($ExecutionTimeLimit, $MultipleInstances, [switch]$StartWhenAvailable) }
        function New-ScheduledTask { param($Action, $Trigger, $Principal, $Settings, $Description) }
        function Register-ScheduledTask { param($TaskName, $InputObject, $User, $Password, [switch]$Force) }
        function Unregister-ScheduledTask { param($TaskName, [switch]$Confirm) }
        . $script:RegisterPath -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot $TestDrive
        . $script:RunnerPath
    }
    BeforeEach {
        Mock New-ScheduledTaskPrincipal { [pscustomobject]@{UserId=$UserId; LogonType=$LogonType; RunLevel=$RunLevel} }
        Mock New-ScheduledTaskAction { [pscustomobject]@{Execute=$Execute; Argument=$Argument; WorkingDirectory=$WorkingDirectory} }
        Mock New-ScheduledTaskTrigger { [pscustomobject]@{Daily=$Daily; DaysInterval=$DaysInterval; At=$At} }
        Mock New-ScheduledTaskSettingsSet { [pscustomobject]@{ExecutionTimeLimit=$ExecutionTimeLimit; MultipleInstances=$MultipleInstances; StartWhenAvailable=$StartWhenAvailable} }
        Mock New-ScheduledTask { [pscustomobject]@{Action=$Action; Trigger=$Trigger; Principal=$Principal; Settings=$Settings; Description=$Description} }
        Mock Register-ScheduledTask { $InputObject }
        Mock Unregister-ScheduledTask { }
        Mock Get-Credential { throw 'Unexpected credential prompt' }
        $script:Root = Join-Path $TestDrive 'exports'
    }
    It 'registers a gMSA Password principal without supplying a password' {
        & $script:RegisterPath -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot $script:Root
        Should -Invoke New-ScheduledTaskPrincipal -Exactly 1 -ParameterFilter {
            $UserId -eq 'LABDOMAIN\collector$' -and $LogonType -eq 'Password' -and $RunLevel -eq 'Limited'
        }
        Should -Invoke Register-ScheduledTask -Exactly 1 -ParameterFilter {
            $TaskName -eq 'GpoLensCollection' -and -not $Password -and -not $User -and
            $InputObject.Settings.ExecutionTimeLimit -eq [timespan]::FromHours(2) -and
            $InputObject.Settings.MultipleInstances -eq 'IgnoreNew' -and
            $InputObject.Settings.StartWhenAvailable -and
            $InputObject.Trigger.Daily -and $InputObject.Trigger.DaysInterval -eq 1
        }
        Should -Invoke Get-Credential -Exactly 0
    }
    It 'passes quoted paths, retention, copy and inventory to the runner with configurable limits' {
        & $script:RegisterPath -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot "$script:Root with spaces" `
            -CopyTo '\\lab.example.com\drop' -InventoryPath "$TestDrive\inventory.json" -Retention 3 `
            -ExecutionTimeLimit '03:00:00' -EveryDays 7 -At '04:30' -LogMaxBytes 2048 -LogFiles 2
        Should -Invoke New-ScheduledTaskAction -Exactly 1 -ParameterFilter {
            $Argument -like '*-NoProfile -NonInteractive -File "*Run-GpoLensCollection.ps1"*' -and
            $Argument -like '*-OutputRoot "*with spaces"*' -and
            $Argument -like '*-Retention 3*' -and $Argument -like '*-CopyTo "\\lab.example.com\drop"*' -and
            $Argument -like '*-InventoryPath "*inventory.json"*' -and
            $Argument -like '*-LogMaxBytes 2048 -LogFiles 2*'
        }
        Should -Invoke New-ScheduledTaskSettingsSet -Exactly 1 -ParameterFilter { $ExecutionTimeLimit.TotalHours -eq 3 }
        Should -Invoke New-ScheduledTaskTrigger -Exactly 1 -ParameterFilter { $DaysInterval -eq 7 -and $At.Hour -eq 4 -and $At.Minute -eq 30 }
    }
    It 'registers a service account with a credential supplied only to Task Scheduler' {
        $credential = [pscredential]::new('LABDOMAIN\svc-collector', (ConvertTo-SecureString 'synthetic-password' -AsPlainText -Force))
        & $script:RegisterPath -ServiceAccount 'LABDOMAIN\svc-collector' -Credential $credential -OutputRoot $script:Root
        Should -Invoke Register-ScheduledTask -Exactly 1 -ParameterFilter {
            $User -eq 'LABDOMAIN\svc-collector' -and $Password -eq 'synthetic-password' -and
            $InputObject.Principal.LogonType -eq 'Password' -and $InputObject.Action.Argument -notmatch 'synthetic-password'
        }
        Test-Path $script:Root | Should -BeFalse
    }
    It 'prompts securely when a service account credential is omitted' {
        Mock Get-Credential { [pscredential]::new('LABDOMAIN\svc-collector', (ConvertTo-SecureString 'synthetic-password' -AsPlainText -Force)) }
        & $script:RegisterPath -ServiceAccount 'LABDOMAIN\svc-collector' -OutputRoot $script:Root
        Should -Invoke Get-Credential -Exactly 1
        Should -Invoke Register-ScheduledTask -Exactly 1
    }
    It 'rejects a mismatched credential' {
        $credential = [pscredential]::new('LABDOMAIN\wrong', (ConvertTo-SecureString 'synthetic' -AsPlainText -Force))
        { & $script:RegisterPath -ServiceAccount 'LABDOMAIN\svc-collector' -Credential $credential -OutputRoot $script:Root } | Should -Throw '*match*'
        Should -Invoke Register-ScheduledTask -Exactly 0
    }
    It 'WhatIf neither prompts nor registers nor creates files' {
        & $script:RegisterPath -ServiceAccount 'LABDOMAIN\svc-collector' -OutputRoot $script:Root -WhatIf
        Should -Invoke Get-Credential -Exactly 0
        Should -Invoke Register-ScheduledTask -Exactly 0
        Test-Path $script:Root | Should -BeFalse
    }
    It 'unregisters only the named task and honors WhatIf' {
        & $script:RegisterPath -TaskName 'LabCollection' -Unregister -WhatIf
        Should -Invoke Unregister-ScheduledTask -Exactly 0
        & $script:RegisterPath -TaskName 'LabCollection' -Unregister -Confirm:$false
        Should -Invoke Unregister-ScheduledTask -Exactly 1 -ParameterFilter { $TaskName -eq 'LabCollection' }
    }
    It 'rejects an unlimited or zero runtime and invalid account and trigger inputs' {
        { & $script:RegisterPath -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot $script:Root -ExecutionTimeLimit '00:00:00' } | Should -Throw
        { & $script:RegisterPath -GmsaAccount 'LABDOMAIN\collector' -OutputRoot $script:Root } | Should -Throw
        { & $script:RegisterPath -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot $script:Root -At '99:99' } | Should -Throw
        Should -Invoke Register-ScheduledTask -Exactly 0
    }
}

Describe 'Collection runner' {
    BeforeAll {
        # Windows PowerShell 5.1 does not preload System.IO.Compression.FileSystem.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        . "$PSScriptRoot/../../scripts/Run-GpoLensCollection.ps1"
    }
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:Root | Out-Null
        $script:Collector = Join-Path $TestDrive 'synthetic-collector.ps1'
        @'
param($OutputRoot)
$export = Join-Path $OutputRoot 'lab.example.com-20261006-120000'
New-Item -ItemType Directory -Path $export | Out-Null
'<GPOs/>' | Set-Content (Join-Path $export 'AllGPOs.xml')
'[]' | Set-Content (Join-Path $export 'gpo-inventory.json')
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($export, "$export.zip")
Write-Output 'synthetic export complete'
'@ | Set-Content $script:Collector
    }
    It 'keeps the last N successful exports, preserves unrelated files and copies the current ZIP' {
        foreach ($stamp in @('20261003-120000','20261004-120000','20261005-120000')) {
            $dir = Join-Path $script:Root "lab.example.com-$stamp"
            New-Item -ItemType Directory -Path $dir | Out-Null
            '<GPOs/>' | Set-Content (Join-Path $dir 'AllGPOs.xml')
            [IO.Compression.ZipFile]::CreateFromDirectory($dir, "$dir.zip")
        }
        'unrelated' | Set-Content (Join-Path $script:Root 'notes.zip')
        $drop = Join-Path $TestDrive 'drop'
        Invoke-GpoLensCollection -OutputRoot $script:Root -CollectorPath $script:Collector -Retention 2 -CopyTo $drop
        @(Get-ChildItem $script:Root -Filter 'lab.example.com-*.zip').Count | Should -Be 2
        @(Get-ChildItem $script:Root -Directory).Count | Should -Be 2
        Test-Path (Join-Path $script:Root 'notes.zip') | Should -BeTrue
        Test-Path (Join-Path $drop 'lab.example.com-20261006-120000.zip') | Should -BeTrue
        Get-Content (Join-Path $script:Root 'collection.log') -Raw | Should -Match 'Collection succeeded'
    }
    It 'injects the authoritative inventory into both the folder and the delivered ZIP' {
        $inventory = Join-Path $TestDrive 'privileged-inventory.json'
        '[{"Id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","DisplayName":"Lab baseline"}]' | Set-Content $inventory
        Invoke-GpoLensCollection -OutputRoot $script:Root -CollectorPath $script:Collector -InventoryPath $inventory
        $export = Join-Path $script:Root 'lab.example.com-20261006-120000'
        Get-Content (Join-Path $export 'gpo-inventory.json') -Raw | Should -Match 'Lab baseline'
        $zip = [IO.Compression.ZipFile]::OpenRead("$export.zip")
        try {
            $reader = [IO.StreamReader]::new($zip.GetEntry('gpo-inventory.json').Open())
            try { $reader.ReadToEnd() | Should -Match 'Lab baseline' } finally { $reader.Dispose() }
        } finally { $zip.Dispose() }
    }
    It 'does not deliver an old ZIP or prune exports when collection fails' {
        'old' | Set-Content (Join-Path $script:Root 'lab.example.com-20261005-120000.zip')
        "throw 'synthetic failure'" | Set-Content $script:Collector
        $drop = Join-Path $TestDrive 'failed-drop'
        { Invoke-GpoLensCollection -OutputRoot $script:Root -CollectorPath $script:Collector -CopyTo $drop -Retention 1 } | Should -Throw '*synthetic failure*'
        Test-Path $drop | Should -BeFalse
        Test-Path (Join-Path $script:Root 'lab.example.com-20261005-120000.zip') | Should -BeTrue
        Get-Content (Join-Path $script:Root 'collection.log') -Raw | Should -Match 'Collection failed'
    }
    It 'fails if the collector returns without a new complete archive' {
        "Write-Output 'no export'" | Set-Content $script:Collector
        { Invoke-GpoLensCollection -OutputRoot $script:Root -CollectorPath $script:Collector } | Should -Throw '*new*ZIP*'
    }
    It 'rotates a bounded number of log files' {
        $log = Join-Path $script:Root 'collection.log'
        1..30 | ForEach-Object { Write-GpoLensCollectionLog -LogPath $log -Message ('x' * 900) -LogMaxBytes 1024 -LogFiles 2 }
        @(Get-ChildItem $script:Root -Filter 'collection.log*').Count | Should -Be 3
        (Get-Item $log).Length | Should -BeLessOrEqual 1024
    }
    It 'preserves exports when copy fails' {
        $drop = Join-Path $TestDrive 'not-a-directory'
        'file' | Set-Content $drop
        { Invoke-GpoLensCollection -OutputRoot $script:Root -CollectorPath $script:Collector -CopyTo $drop } | Should -Throw
        Test-Path (Join-Path $script:Root 'lab.example.com-20261006-120000.zip') | Should -BeTrue
    }
}

Describe 'Collection inventory and retention boundaries' {
    BeforeAll {
        # Windows PowerShell 5.1 does not preload System.IO.Compression.FileSystem.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        . "$PSScriptRoot/../../scripts/Run-GpoLensCollection.ps1"
        $script:RealGetChildItem = Get-Command Get-ChildItem -CommandType Cmdlet
        $script:RealGetItem = Get-Command Get-Item -CommandType Cmdlet
    }
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:Root | Out-Null
        $script:Collector = Join-Path $TestDrive 'inventory-collector.ps1'
        @'
param($OutputRoot)
$export = Join-Path $OutputRoot 'lab.example.com-20261006-120000'
New-Item -ItemType Directory -Path $export | Out-Null
'<GPOs/>' | Set-Content (Join-Path $export 'AllGPOs.xml')
'[]' | Set-Content (Join-Path $export 'gpo-inventory.json')
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($export, "$export.zip")
'@ | Set-Content $script:Collector
    }
    It 'rejects empty, malformed or duplicate authoritative IDs before collection' -ForEach @(
        @{ Json = '[]' }, @{ Json = 'null' }, @{ Json = '[{"Id":"not-a-guid"}]' },
        @{ Json = '[{"Id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},{"Id":"{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"}]' }
    ) {
        $inventory = Join-Path $TestDrive 'invalid-inventory.json'
        $Json | Set-Content $inventory
        { Invoke-GpoLensCollection -OutputRoot $script:Root -CollectorPath $script:Collector -InventoryPath $inventory } | Should -Throw '*inventory*'
        @(Get-ChildItem $script:Root -Filter '*.zip').Count | Should -Be 0
    }
    It 'overlays exactly the inventory bytes validated before collection, even if source changes' {
        $inventory = Join-Path $TestDrive 'mutable-inventory.json'
        $expected = '[{"Id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","DisplayName":"Validated lab inventory"}]'
        $expected | Set-Content $inventory
        "'[]' | Set-Content -LiteralPath '$inventory'" | Add-Content $script:Collector
        Invoke-GpoLensCollection -OutputRoot $script:Root -CollectorPath $script:Collector -InventoryPath $inventory
        $folder = Join-Path $script:Root 'lab.example.com-20261006-120000'
        Get-Content (Join-Path $folder 'gpo-inventory.json') -Raw | Should -Match 'Validated lab inventory'
        $zip = [IO.Compression.ZipFile]::OpenRead("$folder.zip")
        try {
            $reader = [IO.StreamReader]::new($zip.GetEntry('gpo-inventory.json').Open())
            try { $reader.ReadToEnd() | Should -Match 'Validated lab inventory' } finally { $reader.Dispose() }
        } finally { $zip.Dispose() }
    }
    It 'refuses an output root that is a reparse point' {
        Mock Get-Item {
            if ($LiteralPath -eq $script:Root) {
                [pscustomobject]@{ Attributes = [IO.FileAttributes]::ReparsePoint }
            } else { & $script:RealGetItem -LiteralPath $LiteralPath -Force:$Force }
        }
        { Invoke-GpoLensCollection -OutputRoot $script:Root -CollectorPath $script:Collector } | Should -Throw '*linked*'
        Test-Path (Join-Path $script:Root 'collection.log') | Should -BeFalse
    }
    It 'refuses a nested reparse point before removing either expired folder or archive' {
        $script:Expired = Join-Path $script:Root 'lab.example.com-20261005-120000'
        New-Item -ItemType Directory -Path $script:Expired | Out-Null
        '<GPOs/>' | Set-Content (Join-Path $script:Expired 'AllGPOs.xml')
        [IO.Compression.ZipFile]::CreateFromDirectory($script:Expired, "$script:Expired.zip")
        Mock Get-ChildItem {
            if ($LiteralPath -eq $script:Expired) {
                [pscustomobject]@{FullName=(Join-Path $script:Expired 'junction'); PSIsContainer=$true; Attributes=[IO.FileAttributes]::ReparsePoint}
            } else {
                & $script:RealGetChildItem -LiteralPath $LiteralPath -File:$File -Force:$Force -Filter $Filter
            }
        }
        { Invoke-GpoLensCollection -OutputRoot $script:Root -CollectorPath $script:Collector -Retention 1 } | Should -Throw '*linked*'
        Test-Path $script:Expired | Should -BeTrue
        Test-Path "$script:Expired.zip" | Should -BeTrue
    }
    It 'does not count an interrupted ZIP towards retention or delete a valid older export for it' {
        $valid = Join-Path $script:Root 'lab.example.com-20261004-120000'
        New-Item -ItemType Directory -Path $valid | Out-Null
        '<GPOs/>' | Set-Content (Join-Path $valid 'AllGPOs.xml')
        [IO.Compression.ZipFile]::CreateFromDirectory($valid, "$valid.zip")
        $partial = Join-Path $script:Root 'lab.example.com-20261005-120000'
        New-Item -ItemType Directory -Path $partial | Out-Null
        '<GPOs/>' | Set-Content (Join-Path $partial 'AllGPOs.xml')
        'interrupted zip bytes' | Set-Content "$partial.zip"
        Invoke-GpoLensCollection -OutputRoot $script:Root -CollectorPath $script:Collector -Retention 2
        Test-Path "$valid.zip" | Should -BeTrue
        Test-Path $valid | Should -BeTrue
        Test-Path "$partial.zip" | Should -BeTrue
    }

}
