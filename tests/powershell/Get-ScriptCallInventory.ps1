<#
.SYNOPSIS
  Emit, as JSON, the security-relevant AST of PowerShell scripts: command
  invocations, .NET member calls (with receiver), property writes, variable
  assignments, redirections, using statements and type references. Parses only;
  never executes the scripts it inspects.
.DESCRIPTION
  Consumed by tests/test_collector_readonly.py, which checks the inventory
  against explicit per-script allowlists. Uses the PowerShell language AST
  ([System.Management.Automation.Language.Parser]::ParseFile) and
  StaticParameterBinder, so parameters bind by name exactly as PowerShell would
  for commands available in this session (built-in cmdlets); for commands that
  are not available (AD/GroupPolicy/ScheduledTasks modules on a Linux runner)
  only the command name and raw argument text are recorded.
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

# The variable a member call / assignment is ultimately rooted at, so the test
# can bind an allowlisted instance method to the receiver it is expected on.
function Get-RootVariable {
    param($Ast)
    $node = $Ast
    while ($null -ne $node) {
        if ($node -is [System.Management.Automation.Language.VariableExpressionAst]) {
            return $node.VariablePath.UserPath
        } elseif ($node -is [System.Management.Automation.Language.MemberExpressionAst]) {
            $node = $node.Expression
        } elseif ($node -is [System.Management.Automation.Language.IndexExpressionAst]) {
            $node = $node.Target
        } elseif ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) {
            $node = $node.Expression
        } elseif ($node -is [System.Management.Automation.Language.ParenExpressionAst]) {
            $node = $node.Pipeline
        } elseif ($node -is [System.Management.Automation.Language.PipelineAst] -and $node.PipelineElements.Count -eq 1) {
            $node = $node.PipelineElements[0]
        } elseif ($node -is [System.Management.Automation.Language.CommandExpressionAst]) {
            $node = $node.Expression
        } else {
            return $null
        }
    }
    return $null
}

function Get-TypeNames {
    param($Ast)
    $names = @()
    foreach ($t in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeExpressionAst] }, $true)) {
        $names += $t.TypeName.FullName
    }
    foreach ($c in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ConvertExpressionAst] }, $true)) {
        $names += $c.Type.TypeName.FullName
    }
    return $names
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
        # Full ordered element list: every parameter (named, incl. common
        # parameters like -OutVariable, with its switch colon value) and every
        # positional argument, so the closed-world inventory sees them all.
        $arguments = @()
        $elems = $node.CommandElements
        for ($ei = 1; $ei -lt $elems.Count; $ei++) {
            $el = $elems[$ei]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                $pv = $null
                if ($null -ne $el.Argument) {
                    $pv = Get-Text $el.Argument
                } elseif ($ei + 1 -lt $elems.Count -and
                    -not ($elems[$ei + 1] -is [System.Management.Automation.Language.CommandParameterAst])) {
                    $pv = Get-Text $elems[$ei + 1]
                    $ei++
                }
                $arguments += [pscustomobject][ordered]@{ parameter = $el.ParameterName; value = $pv }
            } else {
                $arguments += [pscustomobject][ordered]@{ parameter = $null; value = (Get-Text $el) }
            }
        }
        $record = [ordered]@{
            name = $name
            line = $node.Extent.StartLineNumber
            invocation = [string]$node.InvocationOperator
            text = $node.Extent.Text
            bound = (Get-BoundParameters $node)
            arguments = $arguments
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
            dynamic_member = ($null -eq $memberName)
            line = $node.Extent.StartLineNumber
            receiver = (Get-Text $node.Expression)
            receiver_var = (Get-RootVariable $node.Expression)
            receiver_types = @(Get-TypeNames $node.Expression)
            first_argument = if ($node.Arguments -and $node.Arguments.Count -gt 0) { Get-Text $node.Arguments[0] } else { $null }
            text = $node.Extent.Text
        }
    }

    # Assignments: member writes ($x.Prop = ...) and variable writes ($v = ...),
    # including compound (+=) and any scope ($script:, $global:). The test uses
    # the variable writes for write-root confinement (exactly one, documented).
    $memberAssignments = @()
    $variableAssignments = @()
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        $left = $node.Left
        while ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
        if ($left -is [System.Management.Automation.Language.MemberExpressionAst]) {
            $memberAssignments += [pscustomobject][ordered]@{
                line = $node.Extent.StartLineNumber
                target = $left.Extent.Text
                receiver_var = (Get-RootVariable $left.Expression)
                receiver_types = @(Get-TypeNames $left.Expression)
            }
        } elseif ($left -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $variableAssignments += [pscustomobject][ordered]@{
                name = $left.VariablePath.UserPath
                scope = [string]$left.VariablePath.DriveName
                operator = [string]$node.Operator
                line = $node.Extent.StartLineNumber
                rhs = (Get-Text $node.Right)
                rhs_types = @(Get-TypeNames $node.Right)
                kind = 'assign'
            }
        }
    }

    # Parameter declarations bind a variable to its default; a write root that is
    # a parameter has this as its single binding.
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true)) {
        $variableAssignments += [pscustomobject][ordered]@{
            name = $node.Name.VariablePath.UserPath
            scope = ''
            operator = 'param'
            line = $node.Extent.StartLineNumber
            rhs = (Get-Text $node.DefaultValue)
            rhs_types = @()
            kind = 'param'
        }
    }

    # foreach ($x in ...) binds $x; count it as an assignment so a write root can
    # never be silently rebound by a loop variable.
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
        $variableAssignments += [pscustomobject][ordered]@{
            name = $node.Variable.VariablePath.UserPath
            scope = [string]$node.Variable.VariablePath.DriveName
            operator = 'foreach'
            line = $node.Extent.StartLineNumber
            rhs = (Get-Text $node.Condition)
            rhs_types = @()
            kind = 'foreach'
        }
    }

    # Set-Variable / New-Variable / [ref] indirections name a variable in a
    # string, invisible to the assignment AST; record them as assignments too.
    $indirectWrites = @()
    foreach ($node in $commands) {
        if ($node.name -in @('Set-Variable', 'New-Variable', 'Set-Item', 'Tee-Object')) {
            $indirectWrites += [pscustomobject][ordered]@{ command = $node.name; line = $node.line; text = $node.text }
        }
    }

    $redirections = @()
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst] }, $true)) {
        $redirections += [pscustomobject][ordered]@{
            kind = 'file'
            from_stream = [string]$node.FromStream
            location = (Get-Text $node.Location)
            line = $node.Extent.StartLineNumber
            text = $node.Extent.Text
        }
    }
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MergingRedirectionAst] }, $true)) {
        $redirections += [pscustomobject][ordered]@{
            kind = 'merging'
            from_stream = [string]$node.FromStream
            location = [string]$node.ToStream
            line = $node.Extent.StartLineNumber
            text = $node.Extent.Text
        }
    }

    $usings = @()
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.UsingStatementAst] }, $true)) {
        $usings += [pscustomobject][ordered]@{
            kind = [string]$node.UsingStatementKind
            name = (Get-Text $node.Name)
            line = $node.Extent.StartLineNumber
            text = $node.Extent.Text
        }
    }

    $typeReferences = @()
    foreach ($n in (Get-TypeNames $ast)) {
        $typeReferences += $n
    }

    $files += [pscustomobject][ordered]@{
        path = $file
        parse_errors = @($parseErrors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" })
        functions = $functions
        commands = $commands
        members = $members
        member_assignments = $memberAssignments
        variable_assignments = $variableAssignments
        indirect_writes = $indirectWrites
        redirections = $redirections
        using_statements = $usings
        type_references = $typeReferences
    }
}
$sha.Dispose()
ConvertTo-Json -InputObject @($files) -Depth 10 -Compress
