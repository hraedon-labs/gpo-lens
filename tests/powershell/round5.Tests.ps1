# Sol round 5: `-TaskName '*' -Unregister` reached Unregister-ScheduledTask and
# removed every matching scheduled task. The shared TaskName validator must
# refuse wildcard/path/quote characters at parameter binding, before
# ShouldProcess or any ScheduledTasks cmdlet runs.

Describe 'Round 5 task-name validation' {
    BeforeAll {
        $script:Register = "$PSScriptRoot/../../scripts/Register-GpoLensCollection.ps1"
        $script:Runner = "$PSScriptRoot/../../scripts/Run-GpoLensCollection.ps1"
    }

    BeforeEach {
        $global:GpoLensUnregistered = @()
        function global:Unregister-ScheduledTask {
            param([string]$TaskName, [switch]$Confirm)
            $global:GpoLensUnregistered += $TaskName
        }
    }

    AfterEach {
        Remove-Item -Path Function:\Unregister-ScheduledTask -ErrorAction SilentlyContinue
        Remove-Variable -Name GpoLensUnregistered -Scope Global -ErrorAction SilentlyContinue
    }

    It 'refuses <Name> before Unregister-ScheduledTask runs' -ForEach @(
        @{Name='*'}, @{Name='Gpo*'}, @{Name='GpoLens?'}, @{Name='[A-Z]*'},
        @{Name='folder\task'}, @{Name="quote'name"}, @{Name=' leading'}
    ) {
        { & $script:Register -Unregister -TaskName $Name -Confirm:$false } |
            Should -Throw -ErrorId 'ParameterArgumentValidationError*'
        $global:GpoLensUnregistered | Should -BeNullOrEmpty
    }

    It 'still unregisters an ordinary task name' {
        & $script:Register -Unregister -TaskName 'Lab owner' -Confirm:$false | Out-Null
        $global:GpoLensUnregistered | Should -Be @('Lab owner')
    }

    It 'the runner refuses a wildcard task name too' {
        { & $script:Runner -OutputRoot $TestDrive -TaskName '*' } |
            Should -Throw -ErrorId 'ParameterArgumentValidationError*'
    }
}
