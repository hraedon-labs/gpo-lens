Describe 'Round 3 owner marker hard links' {
    BeforeAll {
        . "$PSScriptRoot/../../scripts/Register-GpoLensCollection.ps1" `
            -GmsaAccount 'LABDOMAIN\collector$' -OutputRoot $TestDrive
        . "$PSScriptRoot/../../scripts/Run-GpoLensCollection.ps1"
    }

    It 'rejects a hard-linked marker before registration: Force=<Force>' -ForEach @(
        @{Force=$false}, @{Force=$true}
    ) {
        $root = Join-Path $TestDrive "hardlink-$Force"
        New-Item -ItemType Directory -Path $root | Out-Null
        $outside = Join-Path $TestDrive "outside-$Force.txt"
        [IO.File]::WriteAllText($outside, 'TaskA')
        $marker = Join-Path $root '.gpo-lens-collection-owner'
        New-Item -ItemType HardLink -Path $marker -Target $outside | Out-Null
        $flag = Join-Path $TestDrive "registered-$Force.txt"
        { Set-GpoLensCollectionOwner -OutputRoot $root -TaskName 'TaskA' -Force:$Force -RegisterTask {
            [IO.File]::WriteAllText($flag, 'registered')
        } } | Should -Throw '*linked owner marker*'
        [IO.File]::ReadAllText($outside) | Should -Be 'TaskA'
        Test-Path -LiteralPath $flag | Should -BeFalse
    }

    It 'never changes the outside file during a forced ownership transfer' {
        $root = Join-Path $TestDrive 'forced-transfer'
        New-Item -ItemType Directory -Path $root | Out-Null
        $outside = Join-Path $TestDrive 'outside-transfer.txt'
        [IO.File]::WriteAllText($outside, 'ForeignTask')
        New-Item -ItemType HardLink -Path (Join-Path $root '.gpo-lens-collection-owner') -Target $outside | Out-Null
        { Set-GpoLensCollectionOwner -OutputRoot $root -TaskName 'TaskB' -Force -RegisterTask {} } |
            Should -Throw '*linked owner marker*'
        [IO.File]::ReadAllText($outside) | Should -Be 'ForeignTask'
    }

    It 'rejects a hard-linked marker before trusting the collector owner' {
        $root = Join-Path $TestDrive 'collector-hardlink'
        New-Item -ItemType Directory -Path $root | Out-Null
        $outside = Join-Path $TestDrive 'outside-collector.txt'
        [IO.File]::WriteAllText($outside, 'TaskA')
        New-Item -ItemType HardLink -Path (Join-Path $root '.gpo-lens-collection-owner') -Target $outside | Out-Null
        { Assert-GpoLensCollectionOwner -OutputRoot $root -TaskName 'TaskA' } |
            Should -Throw '*linked owner marker*'
        [IO.File]::ReadAllText($outside) | Should -Be 'TaskA'
    }

    It 'unlinks a substituted hard link before restoring the exact prior marker bytes' {
        $root = Join-Path $TestDrive 'rollback-hardlink'
        New-Item -ItemType Directory -Path $root | Out-Null
        $marker = Join-Path $root '.gpo-lens-collection-owner'
        $before = [Text.Encoding]::UTF8.GetBytes("TaskA`r`n")
        [IO.File]::WriteAllBytes($marker, $before)
        $outside = Join-Path $TestDrive 'outside-rollback.txt'
        [IO.File]::WriteAllText($outside, 'outside unchanged')
        { Set-GpoLensCollectionOwner -OutputRoot $root -TaskName 'TaskB' -Force -RegisterTask {
            [IO.File]::Delete($marker)
            New-Item -ItemType HardLink -Path $marker -Target $outside | Out-Null
            throw 'synthetic scheduler failure'
        } } | Should -Throw '*synthetic scheduler failure*'
        [IO.File]::ReadAllText($outside) | Should -Be 'outside unchanged'
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($marker)) |
            Should -Be ([Convert]::ToBase64String($before))
        [IO.File]::WriteAllText($marker, 'local edit')
        [IO.File]::ReadAllText($outside) | Should -Be 'outside unchanged'
    }

    It 'replaces an existing marker link without writing through it' {
        $root = Join-Path $TestDrive 'writer-hardlink'
        New-Item -ItemType Directory -Path $root | Out-Null
        $outside = Join-Path $TestDrive 'outside-writer.txt'
        [IO.File]::WriteAllText($outside, 'outside unchanged')
        $marker = Join-Path $root '.gpo-lens-collection-owner'
        New-Item -ItemType HardLink -Path $marker -Target $outside | Out-Null
        Write-GpoLensOwnerMarkerBytes -OutputRoot $root -Bytes ([Text.Encoding]::UTF8.GetBytes('TaskB'))
        [IO.File]::ReadAllText($marker) | Should -Be 'TaskB'
        [IO.File]::ReadAllText($outside) | Should -Be 'outside unchanged'
        Assert-GpoLensCollectionOwner -OutputRoot $root -TaskName 'TaskB'
    }

    It 'uses CreateNew so a marker substituted after unlink cannot be opened for writing' {
        # Static .NET methods cannot be mocked to inject a link into that gap.
        # Pin the exclusive creation mode for both registration and restoration.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            "$PSScriptRoot/../../scripts/GpoLensCollectionMarker.ps1", [ref]$null, [ref]$null)
        $writer = $ast.Find({ param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Write-GpoLensOwnerMarkerBytes'
        }, $true)
        $writer.Extent.Text | Should -Match '\[IO.FileMode\]::CreateNew'
        $writer.Extent.Text | Should -Not -Match '\[IO.FileMode\]::(?:Create|OpenOrCreate)\b'
    }
}
