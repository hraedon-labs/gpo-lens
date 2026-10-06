Describe "Installer estate guidance" {
    BeforeAll {
        . "$PSScriptRoot/../../scripts/install-windows.ps1"
    }
    BeforeEach {
        Mock Write-Host { }
    }
    It "explains ingest only when no database exists" {
        Write-InstallEstateMessage -InstallDir $TestDrive
        Should -Invoke Write-Host -Exactly 1 -ParameterFilter { "$Object" -match 'estate starts empty' }
        Should -Invoke Write-Host -Exactly 0 -ParameterFilter { "$Object" -match 'database was kept' }
    }
    It "explains preservation, migration and backup when the database exists" {
        Set-Content -LiteralPath "$TestDrive/gpo-lens.sqlite3" -Value 'synthetic database'
        Write-InstallEstateMessage -InstallDir $TestDrive
        Should -Invoke Write-Host -Exactly 0 -ParameterFilter { "$Object" -match 'estate starts empty|use Ingest' }
        Should -Invoke Write-Host -Exactly 1 -ParameterFilter { "$Object" -match 'database was kept and migrates automatically on first use' }
        Should -Invoke Write-Host -Exactly 1 -ParameterFilter { "$Object" -match 'Back up before first use' }
        Should -Invoke Write-Host -Exactly 1 -ParameterFilter { "$Object" -match 'https://.+/deploy/README.md#backup-restore-and-upgrade-rules' }
        Get-Content -LiteralPath "$TestDrive/gpo-lens.sqlite3" | Should -Be 'synthetic database'
    }
}

Describe "Collector ZIP completeness" {
    BeforeAll {
        # Load the real archive helper without running the AD collection body.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            "$PSScriptRoot/../../scripts/Export-GpoEstate.ps1", [ref]$null, [ref]$null)
        $helper = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'New-GpoExportZip'
        }, $true)
        . ([scriptblock]::Create($helper.Extent.Text))
    }
    BeforeEach {
        $script:ExportPath = Join-Path $TestDrive 'export'
        New-Item -ItemType Directory -Path "$script:ExportPath/nested" -Force | Out-Null
        Set-Content -LiteralPath "$script:ExportPath/nested/policy.xml" -Value '<synthetic/>'
        Mock Write-Host { }
    }
    It "creates a complete portable archive" {
        New-GpoExportZip -ExportPath $script:ExportPath
        $zip = [System.IO.Compression.ZipFile]::OpenRead("$script:ExportPath.zip")
        try {
            @($zip.Entries).Count | Should -Be 1
            $zip.Entries[0].FullName | Should -Be 'nested/policy.xml'
        } finally { $zip.Dispose() }
        Should -Invoke Write-Host -Exactly 1 -ParameterFilter { "$Object" -match '^Done:.*\(1 files\)' }
    }
    It "fails on a nonterminating enumeration error and removes any partial ZIP" {
        Set-Content -LiteralPath "$script:ExportPath.zip" -Value 'stale partial ZIP'
        Mock Get-ChildItem {
            Get-Item -LiteralPath "$script:ExportPath/nested/policy.xml"
            Write-Error 'synthetic path exceeds 260 characters' -ErrorAction Continue
        }
        { New-GpoExportZip -ExportPath $script:ExportPath } | Should -Throw '*enumeration error*-OutputRoot*-NoZip*'
        Test-Path -LiteralPath "$script:ExportPath.zip" | Should -BeFalse
        Test-Path -LiteralPath "$script:ExportPath/nested/policy.xml" | Should -BeTrue
        Should -Invoke Write-Host -Exactly 0
    }
    It "fails on a terminating enumeration error and removes any partial ZIP" {
        Set-Content -LiteralPath "$script:ExportPath.zip" -Value 'stale partial ZIP'
        Mock Get-ChildItem { throw 'synthetic enumeration failure' }
        { New-GpoExportZip -ExportPath $script:ExportPath } | Should -Throw '*synthetic enumeration failure*partial ZIP was removed*-OutputRoot*-NoZip*'
        Test-Path -LiteralPath "$script:ExportPath.zip" | Should -BeFalse
        Should -Invoke Write-Host -Exactly 0
    }
    It "removes a ZIP partially written before a file read fails" {
        Mock Get-ChildItem { @(
            Get-Item -LiteralPath "$script:ExportPath/nested/policy.xml"
            [pscustomobject]@{FullName="$script:ExportPath/missing.xml"}
        ) }
        { New-GpoExportZip -ExportPath $script:ExportPath } | Should -Throw '*ZIP creation failed*partial ZIP was removed*-NoZip*'
        Test-Path -LiteralPath "$script:ExportPath.zip" | Should -BeFalse
        Should -Invoke Write-Host -Exactly 0
    }
}
