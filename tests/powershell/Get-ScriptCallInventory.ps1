<#
.SYNOPSIS
  Emit, as JSON, every command invocation and .NET member call in the given
  PowerShell scripts. Parses only; never executes the scripts it inspects.
.DESCRIPTION
  Consumed by tests/test_collector_readonly.py, which compares the inventory
  against an explicit allowlist. Uses the PowerShell language AST
  ([System.Management.Automation.Language.Parser]::ParseFile) and
  StaticParameterBinder, so parameters bind by name exactly as PowerShell would
  for commands available in this session (built-in cmdlets); for commands that
  are not available (AD/GroupPolicy/ScheduledTasks modules on a Linux runner)
  only the command name is recorded.
  Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Path)

$ErrorActionPreference = 'Stop'

function Get-Text {
    param($Ast)
    if ($null -eq $Ast) { return $null }
    return $Ast.Extent.Text
}

function Get-BoundParameters {
    param($CommandAst)
    $result = @{}
    try {
        $binding = [System.Management.Automation.Language.StaticParameterBinder]::BindCommand($CommandAst, $true)
    } catch {
        return $result
    }
    if ($null -eq $binding) { return $result }
    foreach ($key in $binding.BoundParameters.Keys) {
        $value = $binding.BoundParameters[$key]
        if ($null -ne $value.Value) {
            $result[$key] = $value.Value.Extent.Text
        } else {
            $result[$key] = $true
        }
    }
    return $result
}

function Get-StringValue {
    param($Ast)
    if ($Ast -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $Ast.Value }
    if ($Ast -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { return $Ast.Value }
    return $null
}

$sha = [System.Security.Cryptography.SHA256]::Create()
$files = @()
foreach ($file in $Path) {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors)

    $functions = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object { $_.Name })

    $commands = @()
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $node.GetCommandName()
        $record = [ordered]@{
            name = $name
            line = $node.Extent.StartLineNumber
            invocation = [string]$node.InvocationOperator
            text = $node.Extent.Text
            bound = (Get-BoundParameters $node)
            type_definition_sha256 = $null
        }
        if ($name -eq 'Add-Type') {
            # Inline C# is invisible to the PowerShell AST; pin its exact bytes
            # so any change to the compiled code needs a reviewed allowlist edit.
            $elements = $node.CommandElements
            for ($i = 1; $i -lt $elements.Count; $i++) {
                $el = $elements[$i]
                if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and
                    $el.ParameterName -eq 'TypeDefinition') {
                    $arg = if ($el.Argument) { $el.Argument } elseif ($i + 1 -lt $elements.Count) { $elements[$i + 1] } else { $null }
                    $value = Get-StringValue $arg
                    if ($null -ne $value) {
                        $normalized = $value -replace "`r`n", "`n"
                        $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
                        $record.type_definition_sha256 = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
                    }
                }
            }
        }
        $commands += [pscustomobject]$record
    }

    $members = @()
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
        $memberName = Get-StringValue $node.Member
        $typeName = $null
        if ($node.Static -and $node.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
            $typeName = $node.Expression.TypeName.FullName
        }
        $members += [pscustomobject][ordered]@{
            static = [bool]$node.Static
            type = $typeName
            member = $memberName
            line = $node.Extent.StartLineNumber
            first_argument = if ($node.Arguments -and $node.Arguments.Count -gt 0) { Get-Text $node.Arguments[0] } else { $null }
            text = $node.Extent.Text
        }
    }

    # Property writes on .NET objects (e.g. $entry.Attributes = ...) can mutate
    # state without any method call, so they are inventoried too.
    $memberAssignments = @()
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        $left = $node.Left
        while ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
        if ($left -is [System.Management.Automation.Language.MemberExpressionAst]) {
            $memberAssignments += [pscustomobject][ordered]@{
                line = $node.Extent.StartLineNumber
                target = $left.Extent.Text
            }
        }
    }

    $files += [pscustomobject][ordered]@{
        path = $file
        parse_errors = @($parseErrors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" })
        functions = $functions
        commands = $commands
        members = $members
        member_assignments = $memberAssignments
    }
}
$sha.Dispose()
ConvertTo-Json -InputObject @($files) -Depth 8 -Compress
