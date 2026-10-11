<#
.SYNOPSIS
  Emit, as JSON, (1) a complete, order-preserving serialization of each
  script's PowerShell syntax tree and (2) the security-relevant projections the
  semantic gate reasons about (command invocations, .NET member calls with
  receiver and every argument, variable/member/index assignments and every
  other variable binding, redirections, using statements, type references, and
  the control-flow context of each call). Parses only; never executes the
  scripts it inspects.
.DESCRIPTION
  Consumed by tests/test_collector_readonly.py.

  The full-tree serialization (`ast_rows`) is driven by $NodeProperties, an
  explicit table of every concrete AST node type and the properties that carry
  its meaning. A node type that is not in the table is emitted as an
  UNSUPPORTED row (and rejected by the gate); `-Describe` prints the table next
  to the node types and properties this PowerShell build actually has, so a
  test can prove the table covers all of them.

  Uses the PowerShell language AST
  ([System.Management.Automation.Language.Parser]::ParseFile) and
  StaticParameterBinder, so parameters bind by name exactly as PowerShell would
  for commands available in this session (built-in cmdlets); for commands that
  are not available (AD/GroupPolicy/ScheduledTasks modules on a Linux runner)
  only the command name and raw argument text are recorded.
  Compatible with Windows PowerShell 5.1 and PowerShell 7.
#>
param(
    [Parameter(ValueFromRemainingArguments)][string[]]$Path,
    # Print the serializer table next to this runtime's AST reflection data.
    [switch]$Describe,
    # Emit only the source digest, parse errors and the full-tree rows.
    [switch]$AstOnly,
    # Emit mutation sites (tokens, sibling statements, conditions, blocks) for
    # the completeness meta-test.
    [switch]$Sites
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Full-tree serialization table: node type -> ordered properties. Every public
# property of every concrete Ast type must be either listed here or in
# $ExcludedProperties (tests/test_collector_readonly.py proves this against the
# running PowerShell's reflection data).
# ---------------------------------------------------------------------------
$InvokeMemberProps = @('Static', 'NullConditional', 'Expression', 'Member', 'GenericTypeArguments', 'Arguments')
$NodeProperties = @{
    'ArrayExpressionAst'                = @('SubExpression')
    'ArrayLiteralAst'                   = @('Elements')
    'AssignmentStatementAst'            = @('Operator', 'Left', 'Right')
    'AttributeAst'                      = @('TypeName', 'PositionalArguments', 'NamedArguments')
    'AttributedExpressionAst'           = @('Attribute', 'Child')
    'BaseCtorInvokeMemberExpressionAst' = $InvokeMemberProps
    'BinaryExpressionAst'               = @('Operator', 'Left', 'Right')
    'BlockStatementAst'                 = @('Kind', 'Body')
    'BreakStatementAst'                 = @('Label')
    'CatchClauseAst'                    = @('IsCatchAll', 'CatchTypes', 'Body')
    'CommandAst'                        = @('InvocationOperator', 'DefiningKeyword', 'CommandElements', 'Redirections')
    'CommandExpressionAst'              = @('Expression', 'Redirections')
    'CommandParameterAst'               = @('ParameterName', 'Argument')
    'ConfigurationDefinitionAst'        = @('ConfigurationType', 'InstanceName', 'Body')
    'ConstantExpressionAst'             = @('Value')
    'ContinueStatementAst'              = @('Label')
    'ConvertExpressionAst'              = @('Type', 'Child')
    'DataStatementAst'                  = @('Variable', 'CommandsAllowed', 'Body')
    'DoUntilStatementAst'               = @('Label', 'Body', 'Condition')
    'DoWhileStatementAst'               = @('Label', 'Body', 'Condition')
    'DynamicKeywordStatementAst'        = @('CommandElements')
    'ErrorExpressionAst'                = @('NestedAst')
    'ErrorStatementAst'                 = @('Kind', 'Flags', 'Conditions', 'Bodies', 'NestedAst')
    'ExitStatementAst'                  = @('Pipeline')
    'ExpandableStringExpressionAst'     = @('StringConstantType', 'Value', 'NestedExpressions')
    'FileRedirectionAst'                = @('FromStream', 'Append', 'Location')
    'ForEachStatementAst'               = @('Label', 'Flags', 'Variable', 'Condition', 'ThrottleLimit', 'Body')
    'ForStatementAst'                   = @('Label', 'Initializer', 'Condition', 'Iterator', 'Body')
    'FunctionDefinitionAst'             = @('IsFilter', 'IsWorkflow', 'Name', 'Parameters', 'Body')
    'FunctionMemberAst'                 = @('Name', 'MethodAttributes', 'IsPublic', 'IsPrivate', 'IsHidden', 'IsStatic',
        'IsConstructor', 'Attributes', 'ReturnType', 'Parameters', 'Body')
    'HashtableAst'                      = @('KeyValuePairs')
    'IfStatementAst'                    = @('Clauses', 'ElseClause')
    'IndexExpressionAst'                = @('NullConditional', 'Target', 'Index')
    'InvokeMemberExpressionAst'         = $InvokeMemberProps
    'MemberExpressionAst'               = @('Static', 'NullConditional', 'Expression', 'Member')
    'MergingRedirectionAst'             = @('FromStream', 'ToStream')
    'NamedAttributeArgumentAst'         = @('ArgumentName', 'ExpressionOmitted', 'Argument')
    'NamedBlockAst'                     = @('BlockKind', 'Unnamed', 'Statements', 'Traps')
    'ParamBlockAst'                     = @('Attributes', 'Parameters')
    'ParameterAst'                      = @('Attributes', 'Name', 'DefaultValue')
    'ParenExpressionAst'                = @('Pipeline')
    'PipelineAst'                       = @('Background', 'PipelineElements')
    'PipelineChainAst'                  = @('Operator', 'Background', 'LhsPipelineChain', 'RhsPipeline')
    'PropertyMemberAst'                 = @('Name', 'PropertyAttributes', 'IsPublic', 'IsPrivate', 'IsHidden', 'IsStatic',
        'PropertyType', 'Attributes', 'InitialValue')
    'ReturnStatementAst'                = @('Pipeline')
    'ScriptBlockAst'                    = @('ScriptRequirements', 'Attributes', 'UsingStatements', 'ParamBlock',
        'DynamicParamBlock', 'BeginBlock', 'ProcessBlock', 'EndBlock', 'CleanBlock')
    'ScriptBlockExpressionAst'          = @('ScriptBlock')
    'StatementBlockAst'                 = @('Statements', 'Traps')
    'StringConstantExpressionAst'       = @('StringConstantType', 'Value')
    'SubExpressionAst'                  = @('SubExpression')
    'SwitchStatementAst'                = @('Label', 'Flags', 'Condition', 'Clauses', 'Default')
    'TernaryExpressionAst'              = @('Condition', 'IfTrue', 'IfFalse')
    'ThrowStatementAst'                 = @('IsRethrow', 'Pipeline')
    'TrapStatementAst'                  = @('TrapType', 'Body')
    'TryStatementAst'                   = @('Body', 'CatchClauses', 'Finally')
    'TypeConstraintAst'                 = @('TypeName')
    'TypeDefinitionAst'                 = @('Name', 'TypeAttributes', 'IsEnum', 'IsClass', 'IsInterface', 'Attributes',
        'BaseTypes', 'Members')
    'TypeExpressionAst'                 = @('TypeName')
    'UnaryExpressionAst'                = @('TokenKind', 'Child')
    'UsingExpressionAst'                = @('SubExpression')
    'UsingStatementAst'                 = @('UsingStatementKind', 'Name', 'Alias', 'ModuleSpecification')
    'VariableExpressionAst'             = @('VariablePath', 'Splatted')
    'WhileStatementAst'                 = @('Label', 'Condition', 'Body')
}
# Properties deliberately not serialized, with the reason (checked by the test).
$ExcludedProperties = [ordered]@{
    '*.Parent'                   = 'back-reference to the enclosing node (structure is the row nesting)'
    '*.Extent'                   = 'source position/text; positions are not behaviour and the text is the children'
    '*.ErrorPosition'            = 'source position of an operator token (an IScriptExtent)'
    '*.StaticType'               = 'derived by the parser from the node type, constant value or cast type'
    'ConvertExpressionAst.Attribute' = 'the same object as ConvertExpressionAst.Type'
}
# Tuple-valued collections: friendly names for Item1/Item2.
$TupleRoles = @{
    'IfStatementAst.Clauses'      = @('Condition', 'Body')
    'SwitchStatementAst.Clauses'  = @('Pattern', 'Body')
    'HashtableAst.KeyValuePairs'  = @('Key', 'Value')
}

function Get-NormText {
    param([string]$Text)
    if ($null -eq $Text) { return $null }
    return (($Text -replace '\s+', ' ').Trim())
}

function ConvertTo-Lf {
    param([string]$Text)
    if ($null -eq $Text) { return $null }
    return $Text.Replace("`r`n", "`n")
}

function Format-ScalarValue {
    # Returns @($ok, $value). $value is a string, $true, or a string array.
    param($Value)
    if ($Value -is [string]) { return @($true, (ConvertTo-Lf $Value)) }
    if ($Value -is [bool]) { return @($true, $Value) }
    if ($Value -is [enum]) { return @($true, $Value.ToString()) }
    if ($Value -is [System.Management.Automation.Language.ITypeName]) { return @($true, $Value.FullName) }
    if ($Value -is [System.Management.Automation.VariablePath]) { return @($true, $Value.UserPath) }
    if ($Value -is [System.Management.Automation.Language.Token]) {
        return @($true, ('{0}:{1}' -f $Value.Kind, (ConvertTo-Lf $Value.Text)))
    }
    if ($Value -is [System.Management.Automation.Language.DynamicKeyword]) { return @($true, $Value.Keyword) }
    if ($Value -is [System.Management.Automation.Language.ScriptRequirements]) {
        $parts = @()
        foreach ($p in ($Value.GetType().GetProperties() | Sort-Object Name)) {
            $v = $p.GetValue($Value)
            if ($null -eq $v) { continue }
            if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
                $items = @($v | ForEach-Object {
                        if ($_.PSObject.Properties['Name'] -and -not ($_ -is [string])) { "$($_.Name) $($_.Version)" } else { [string]$_ }
                    })
                if ($items.Count -eq 0) { continue }
                $parts += ('{0}=[{1}]' -f $p.Name, ($items -join ', '))
            } elseif ($v -is [bool]) {
                if ($v) { $parts += $p.Name }
            } else {
                $parts += ('{0}={1}' -f $p.Name, [string]$v)
            }
        }
        return @($true, ($parts -join '; '))
    }
    if ($Value -is [ValueType]) {
        $text = if ($Value -is [System.IFormattable]) {
            $Value.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture)
        } else { [string]$Value }
        return @($true, ('{0}:{1}' -f $Value.GetType().Name, $text))
    }
    return @($false, $Value.GetType().FullName)
}

function Add-AstRows {
    param($Node, [int]$Depth, [string]$Role, $Rows, $Unsupported)
    $typeName = $Node.GetType().Name
    $props = $NodeProperties[$typeName]
    if ($null -eq $props) {
        $Unsupported.Add($typeName)
        $Rows.Add(@($Depth, $Role, "UNSUPPORTED:$typeName", @(), (Get-NormText $Node.Extent.Text)))
        return
    }
    $attrs = [System.Collections.Generic.List[object]]::new()
    $children = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $props) {
        $prop = $Node.PSObject.Properties[$p]
        if ($null -eq $prop) { continue }  # e.g. CleanBlock does not exist in 5.1
        $value = $prop.Value
        if ($null -eq $value) { continue }
        if ($value -is [System.Management.Automation.Language.Ast]) {
            $children.Add(@($p, $value))
            continue
        }
        if ($value -is [System.Collections.IDictionary]) {
            # ErrorStatementAst.Flags: name -> Tuple<Token, Ast>, emitted sorted.
            $names = @()
            foreach ($k in (@($value.Keys) | Sort-Object)) {
                $entry = $value[$k]
                $names += [string]$k
                if ($null -ne $entry.Item2) { $children.Add(@("$p[$k]", $entry.Item2)) }
            }
            $attrs.Add(@($p, [string[]]$names))
            continue
        }
        if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
            $scalars = @()
            foreach ($item in $value) {
                if ($null -eq $item) { continue }
                if ($item -is [System.Management.Automation.Language.Ast]) {
                    $children.Add(@($p, $item))
                } elseif ($item.GetType().Name -eq 'Tuple`2') {
                    $names = $TupleRoles["$typeName.$p"]
                    if ($null -eq $names) { $names = @('Item1', 'Item2') }
                    if ($null -ne $item.Item1) { $children.Add(@("$p.$($names[0])", $item.Item1)) }
                    if ($null -ne $item.Item2) { $children.Add(@("$p.$($names[1])", $item.Item2)) }
                } else {
                    $r = Format-ScalarValue $item
                    if (-not $r[0]) { $Unsupported.Add("$typeName.$p item $($r[1])") }
                    $scalars += [string]$r[1]
                }
            }
            if ($scalars.Count -gt 0) { $attrs.Add(@($p, [string[]]$scalars)) }
            continue
        }
        $r = Format-ScalarValue $value
        if (-not $r[0]) {
            $Unsupported.Add("$typeName.$p value $($r[1])")
            $attrs.Add(@($p, "UNSUPPORTED:$($r[1])"))
            continue
        }
        if ($r[1] -is [bool]) {
            if ($r[1]) { $attrs.Add(@($p, $true)) }  # false is the default; omitted
            continue
        }
        $attrs.Add(@($p, $r[1]))
    }
    $Rows.Add(@($Depth, $Role, $typeName, $attrs.ToArray()))
    foreach ($c in $children) {
        Add-AstRows -Node $c[1] -Depth ($Depth + 1) -Role $c[0] -Rows $Rows -Unsupported $Unsupported
    }
}

if ($Describe) {
    $asm = [System.Management.Automation.Language.Ast].Assembly
    $types = @()
    foreach ($t in ($asm.GetTypes() | Where-Object {
                $_.IsPublic -and -not $_.IsAbstract -and [System.Management.Automation.Language.Ast].IsAssignableFrom($_)
            } | Sort-Object Name)) {
        $types += [pscustomobject][ordered]@{
            name = $t.Name
            properties = @($t.GetProperties([Reflection.BindingFlags]'Public,Instance') |
                    ForEach-Object { $_.Name } | Sort-Object -Unique)
        }
    }
    $table = [ordered]@{}
    foreach ($k in ($NodeProperties.Keys | Sort-Object)) { $table[$k] = @($NodeProperties[$k]) }
    [pscustomobject][ordered]@{
        ps_version = $PSVersionTable.PSVersion.ToString()
        ast_types = $types
        table = [pscustomobject]$table
        excluded = @($ExcludedProperties.Keys)
        script_requirements_properties = @([System.Management.Automation.Language.ScriptRequirements].GetProperties() |
                ForEach-Object { $_.Name } | Sort-Object)
    } | ConvertTo-Json -Depth 6 -Compress
    return
}

# ---------------------------------------------------------------------------
# Projections used by the semantic layer.
# ---------------------------------------------------------------------------

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

function Get-AstKind {
    param($Ast)
    if ($null -eq $Ast) { return $null }
    return $Ast.GetType().Name
}

function Get-EnclosingFunction {
    param($Ast)
    $node = $Ast.Parent
    while ($null -ne $node) {
        if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $node.Name }
        $node = $node.Parent
    }
    return ''
}

# Exit statements directly in a block (not nested deeper).
function Get-BlockExits {
    param($Block)
    if ($null -eq $Block) { return @() }
    $kinds = @()
    foreach ($s in $Block.Statements) {
        if ($s -is [System.Management.Automation.Language.ThrowStatementAst]) { $kinds += 'throw' }
        elseif ($s -is [System.Management.Automation.Language.ReturnStatementAst]) { $kinds += 'return' }
        elseif ($s -is [System.Management.Automation.Language.ExitStatementAst]) { $kinds += 'exit' }
        elseif ($s -is [System.Management.Automation.Language.BreakStatementAst]) { $kinds += 'break' }
        elseif ($s -is [System.Management.Automation.Language.ContinueStatementAst]) { $kinds += 'continue' }
    }
    return $kinds
}

# A statement that can stop execution before a later sibling runs: an `if`
# whose clause exits, an `Assert-*` call, or a bare exit statement.
function Get-GuardText {
    param($Statement)
    if ($Statement -is [System.Management.Automation.Language.IfStatementAst]) {
        $parts = @()
        $exits = $false
        foreach ($clause in $Statement.Clauses) {
            $k = @(Get-BlockExits $clause.Item2)
            if ($k.Count -gt 0) { $exits = $true }
            $parts += ('({0}) -> {1}' -f (Get-NormText (Get-Text $clause.Item1)), $(if ($k.Count) { $k -join ',' } else { '...' }))
        }
        if ($null -ne $Statement.ElseClause) {
            $k = @(Get-BlockExits $Statement.ElseClause)
            if ($k.Count -gt 0) { $exits = $true }
            $parts += ('else -> {0}' -f $(if ($k.Count) { $k -join ',' } else { '...' }))
        }
        if ($exits) { return 'guard if ' + ($parts -join ' | ') }
        return $null
    }
    if ($Statement -is [System.Management.Automation.Language.PipelineAst] -and $Statement.PipelineElements.Count -eq 1 -and
        $Statement.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst]) {
        $name = $Statement.PipelineElements[0].GetCommandName()
        if ($name -and $name -like 'Assert-*') { return 'guard ' + (Get-NormText (Get-Text $Statement)) }
        return $null
    }
    foreach ($t in @('Throw', 'Return', 'Exit', 'Break', 'Continue')) {
        if ($Statement.GetType().Name -eq "${t}StatementAst") { return 'guard ' + (Get-NormText (Get-Text $Statement)) }
    }
    return $null
}

# Control-flow context of a node, outermost first: enclosing functions,
# conditions, loops, try/catch/finally, scriptblock arguments, and every guard
# statement that precedes it in each enclosing block.
function Get-NodeContext {
    param($Ast)
    $levels = [System.Collections.Generic.List[string]]::new()
    $child = $Ast
    $parent = $Ast.Parent
    while ($null -ne $parent) {
        $here = [System.Collections.Generic.List[string]]::new()
        if ($parent -is [System.Management.Automation.Language.StatementBlockAst] -or
            $parent -is [System.Management.Automation.Language.NamedBlockAst]) {
            if ($parent -is [System.Management.Automation.Language.NamedBlockAst] -and -not $parent.Unnamed) {
                $here.Add("block $($parent.BlockKind)")
            }
            foreach ($s in $parent.Statements) {
                if ([object]::ReferenceEquals($s, $child)) { break }
                $g = Get-GuardText $s
                if ($g) { $here.Add($g) }
            }
        } elseif ($parent -is [System.Management.Automation.Language.IfStatementAst]) {
            $conds = @()
            $placed = $false
            foreach ($clause in $parent.Clauses) {
                $c = Get-NormText (Get-Text $clause.Item1)
                if ([object]::ReferenceEquals($clause.Item1, $child)) { $here.Add("if-condition after [$($conds -join ' ; ')]"); $placed = $true; break }
                if ([object]::ReferenceEquals($clause.Item2, $child)) { $here.Add("if ($c) after [$($conds -join ' ; ')]"); $placed = $true; break }
                $conds += "($c)"
            }
            if (-not $placed) { $here.Add("else of [$($conds -join ' ; ')]") }
        } elseif ($parent -is [System.Management.Automation.Language.ForEachStatementAst]) {
            $here.Add("foreach (`$$($parent.Variable.VariablePath.UserPath) in $(Get-NormText (Get-Text $parent.Condition)))")
        } elseif ($parent -is [System.Management.Automation.Language.ForStatementAst]) {
            $here.Add("for ($(Get-NormText (Get-Text $parent.Initializer)); $(Get-NormText (Get-Text $parent.Condition)); $(Get-NormText (Get-Text $parent.Iterator)))")
        } elseif ($parent -is [System.Management.Automation.Language.LoopStatementAst]) {
            $here.Add("$($parent.GetType().Name -replace 'StatementAst$', '') ($(Get-NormText (Get-Text $parent.Condition)))")
        } elseif ($parent -is [System.Management.Automation.Language.SwitchStatementAst]) {
            $here.Add("switch ($(Get-NormText (Get-Text $parent.Condition)))")
        } elseif ($parent -is [System.Management.Automation.Language.TryStatementAst]) {
            if ([object]::ReferenceEquals($parent.Body, $child)) { $here.Add('try') }
            elseif ([object]::ReferenceEquals($parent.Finally, $child)) { $here.Add('finally') }
        } elseif ($parent -is [System.Management.Automation.Language.CatchClauseAst]) {
            $here.Add('catch [' + (@($parent.CatchTypes | ForEach-Object { $_.TypeName.FullName }) -join ', ') + ']')
        } elseif ($parent -is [System.Management.Automation.Language.TrapStatementAst]) {
            $here.Add('trap')
        } elseif ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            $here.Add("function $($parent.Name)")
        } elseif ($parent -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
            $owner = $parent.Parent
            if ($owner -is [System.Management.Automation.Language.CommandParameterAst]) {
                $here.Add("scriptblock -$($owner.ParameterName) of $($owner.Parent.GetCommandName())")
            } elseif ($owner -is [System.Management.Automation.Language.CommandAst]) {
                $elems = $owner.CommandElements
                $label = 'positional'
                for ($i = 1; $i -lt $elems.Count; $i++) {
                    if ([object]::ReferenceEquals($elems[$i], $parent)) {
                        $prev = $elems[$i - 1]
                        if ($prev -is [System.Management.Automation.Language.CommandParameterAst] -and $null -eq $prev.Argument -and $i -gt 1) {
                            $label = "-$($prev.ParameterName)"
                        }
                        break
                    }
                }
                $here.Add("scriptblock $label of $($owner.GetCommandName())")
            } else {
                $here.Add("scriptblock in $($owner.GetType().Name)")
            }
        }
        for ($i = $here.Count - 1; $i -ge 0; $i--) { $levels.Insert(0, $here[$i]) }
        $child = $parent
        $parent = $parent.Parent
    }
    return , $levels.ToArray()
}

function New-Binding {
    param($VariableAst, [string]$Kind, [string]$Operator, [string]$Rhs, $Node)
    $vp = $VariableAst.VariablePath
    return [pscustomobject][ordered]@{
        name = $vp.UserPath
        drive = [string]$vp.DriveName
        is_variable = [bool]$vp.IsVariable
        qualifier = $(if ($vp.IsUnqualified) { '' } elseif ($vp.IsScript) { 'script' } elseif ($vp.IsLocal) { 'local' }
            elseif ($vp.IsPrivate) { 'private' } elseif ($vp.IsGlobal) { 'global' } else { 'other' })
        kind = $Kind
        operator = $Operator
        rhs = $Rhs
        line = $Node.Extent.StartLineNumber
        function = (Get-EnclosingFunction $Node)
    }
}

function Get-SourceFacts {
    param([string]$File)
    $bytes = [System.IO.File]::ReadAllBytes($File)
    $nonAscii = 0
    foreach ($b in $bytes) { if ($b -gt 127) { $nonAscii++ } }
    $text = ConvertTo-Lf ([System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF))
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([System.BitConverter]::ToString($hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))) -replace '-', '').ToLowerInvariant()
    } finally { $hash.Dispose() }
    return @($digest, $nonAscii)
}

$sha = [System.Security.Cryptography.SHA256]::Create()
$files = @()
foreach ($file in $Path) {
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors)
    $facts = Get-SourceFacts $file

    $rows = [System.Collections.Generic.List[object]]::new()
    $unsupported = [System.Collections.Generic.List[string]]::new()
    Add-AstRows -Node $ast -Depth 0 -Role 'Script' -Rows $rows -Unsupported $unsupported
    $parseErrorText = @($parseErrors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" })
    if ($AstOnly) {
        $files += [pscustomobject][ordered]@{
            path = $file
            source_sha256 = $facts[0]
            parse_errors = $parseErrorText
            ast_rows = $rows.ToArray()
        }
        continue
    }
    if ($Sites) {
        $significant = @($tokens | Where-Object {
                $_.Kind -notin @('NewLine', 'LineContinuation', 'Comment', 'EndOfInput')
            } | ForEach-Object {
                [pscustomobject][ordered]@{
                    kind = [string]$_.Kind
                    start = $_.Extent.StartOffset
                    end = $_.Extent.EndOffset
                    text = $_.Text
                }
            })
        $siblings = @()
        foreach ($b in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StatementBlockAst] -or
                        $n -is [System.Management.Automation.Language.NamedBlockAst] }, $true)) {
            $st = @($b.Statements)
            for ($i = 0; $i + 1 -lt $st.Count; $i++) {
                $siblings += , @($st[$i].Extent.StartOffset, $st[$i].Extent.EndOffset,
                    $st[$i + 1].Extent.StartOffset, $st[$i + 1].Extent.EndOffset)
            }
        }
        $conditions = @()
        foreach ($n in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.IfStatementAst] }, $true)) {
            foreach ($clause in $n.Clauses) {
                $conditions += , @($clause.Item1.Extent.StartOffset, $clause.Item1.Extent.EndOffset)
            }
        }
        $blockStarts = @()
        foreach ($fd in $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            $end = $fd.Body.EndBlock
            if ($null -ne $end -and $end.Statements.Count -gt 0) { $blockStarts += $end.Statements[0].Extent.StartOffset }
        }
        $files += [pscustomobject][ordered]@{
            path = $file
            tokens = $significant
            siblings = $siblings
            conditions = $conditions
            block_starts = $blockStarts
        }
        continue
    }

    $functionDefs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
    $functions = @($functionDefs | ForEach-Object { $_.Name })
    $functionParams = @()
    foreach ($fd in $functionDefs) {
        $params = @()
        if ($fd.Parameters) { $params = @($fd.Parameters) }
        elseif ($fd.Body.ParamBlock) { $params = @($fd.Body.ParamBlock.Parameters) }
        $pipeline = @()
        foreach ($pa in $params) {
            foreach ($attr in $pa.Attributes) {
                if ($attr -is [System.Management.Automation.Language.AttributeAst]) {
                    foreach ($na in $attr.NamedArguments) {
                        if ($na.ArgumentName -like 'ValueFromPipeline*') { $pipeline += $pa.Name.VariablePath.UserPath }
                    }
                }
            }
        }
        $functionParams += [pscustomobject][ordered]@{
            name = $fd.Name
            params = @($params | ForEach-Object { $_.Name.VariablePath.UserPath })
            pipeline_params = @($pipeline | Sort-Object -Unique)
        }
    }

    $commands = @()
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        $name = $node.GetCommandName()
        # Full ordered element list: every parameter (named, incl. common
        # parameters like -OutVariable, with its switch colon value) and every
        # positional argument.
        $arguments = @()
        $elems = $node.CommandElements
        for ($ei = 1; $ei -lt $elems.Count; $ei++) {
            $el = $elems[$ei]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                $pv = $null
                $kind = 'switch'
                if ($null -ne $el.Argument) {
                    $pv = Get-Text $el.Argument
                    $kind = (Get-AstKind $el.Argument)
                } elseif ($ei + 1 -lt $elems.Count -and
                    -not ($elems[$ei + 1] -is [System.Management.Automation.Language.CommandParameterAst])) {
                    $pv = Get-Text $elems[$ei + 1]
                    $kind = (Get-AstKind $elems[$ei + 1])
                    $ei++
                }
                $arguments += [pscustomobject][ordered]@{ parameter = $el.ParameterName; value = $pv; value_kind = $kind }
            } else {
                $arguments += [pscustomobject][ordered]@{ parameter = $null; value = (Get-Text $el); value_kind = (Get-AstKind $el) }
            }
        }
        $record = [ordered]@{
            name = $name
            line = $node.Extent.StartLineNumber
            invocation = [string]$node.InvocationOperator
            text = $node.Extent.Text
            bound = (Get-BoundParameters $node)
            arguments = $arguments
            context = (Get-NodeContext $node)
            function = (Get-EnclosingFunction $node)
            type_definition_sha256 = $null
        }
        if ($name -eq 'Add-Type') {
            # Inline C# is invisible to the PowerShell AST; pin its exact bytes
            # so any change to the compiled code needs a reviewed allowlist edit.
            for ($i = 1; $i -lt $elems.Count; $i++) {
                $el = $elems[$i]
                if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and
                    $el.ParameterName -eq 'TypeDefinition') {
                    $arg = if ($el.Argument) { $el.Argument } elseif ($i + 1 -lt $elems.Count) { $elems[$i + 1] } else { $null }
                    $value = Get-StringValue $arg
                    if ($null -ne $value) {
                        $normalized = $value -replace "`r`n", "`n"
                        $b = [System.Text.Encoding]::UTF8.GetBytes($normalized)
                        $record.type_definition_sha256 = ([System.BitConverter]::ToString($sha.ComputeHash($b)) -replace '-', '').ToLowerInvariant()
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
            arguments = @($node.Arguments | ForEach-Object { Get-Text $_ })
            text = $node.Extent.Text
            context = (Get-NodeContext $node)
            function = (Get-EnclosingFunction $node)
        }
    }

    # Every way a variable is bound: `=`/compound assignments (incl. multiple
    # assignment and any scope/drive qualifier), parameters, foreach variables,
    # [ref] arguments, and ++/--. Member and index assignments are separate.
    $memberAssignments = @()
    $indexAssignments = @()
    $variableAssignments = @()
    $otherAssignments = @()
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
        $left = $node.Left
        while ($left -is [System.Management.Automation.Language.AttributedExpressionAst]) { $left = $left.Child }
        $rhs = Get-Text $node.Right
        if ($left -is [System.Management.Automation.Language.MemberExpressionAst]) {
            $memberAssignments += [pscustomobject][ordered]@{
                line = $node.Extent.StartLineNumber
                target = $left.Extent.Text
                receiver_var = (Get-RootVariable $left.Expression)
                receiver_types = @(Get-TypeNames $left.Expression)
            }
        } elseif ($left -is [System.Management.Automation.Language.IndexExpressionAst]) {
            $indexAssignments += [pscustomobject][ordered]@{
                line = $node.Extent.StartLineNumber
                target = $left.Extent.Text
                root_var = (Get-RootVariable $left)
                operator = [string]$node.Operator
                rhs = $rhs
            }
        } elseif ($left -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $variableAssignments += New-Binding $left 'assign' ([string]$node.Operator) $rhs $node
        } elseif ($left -is [System.Management.Automation.Language.ArrayLiteralAst]) {
            foreach ($el in $left.Elements) {
                $inner = $el
                while ($inner -is [System.Management.Automation.Language.AttributedExpressionAst]) { $inner = $inner.Child }
                if ($inner -is [System.Management.Automation.Language.VariableExpressionAst]) {
                    $variableAssignments += New-Binding $inner 'multi' ([string]$node.Operator) $rhs $node
                } else {
                    $otherAssignments += [pscustomobject][ordered]@{ line = $node.Extent.StartLineNumber; target = $el.Extent.Text }
                }
            }
        } else {
            $otherAssignments += [pscustomobject][ordered]@{ line = $node.Extent.StartLineNumber; target = $left.Extent.Text }
        }
    }

    # Parameter declarations bind a variable to its default.
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true)) {
        $variableAssignments += New-Binding $node.Name 'param' 'param' (Get-Text $node.DefaultValue) $node
    }

    # foreach ($x in ...) binds $x.
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
        $variableAssignments += New-Binding $node.Variable 'foreach' 'foreach' (Get-Text $node.Condition) $node
    }

    # [ref]$x hands the variable to a callee that may write it.
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ConvertExpressionAst] }, $true)) {
        if ($node.Type.TypeName.FullName -in @('ref', 'System.Management.Automation.PSReference')) {
            $inner = $node.Child
            if ($inner -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $owner = $node.Parent
                while ($null -ne $owner -and -not ($owner -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and
                    -not ($owner -is [System.Management.Automation.Language.CommandAst]) -and
                    -not ($owner -is [System.Management.Automation.Language.StatementAst])) { $owner = $owner.Parent }
                $variableAssignments += New-Binding $inner 'ref' 'ref' (Get-Text $owner) $node
            } else {
                $otherAssignments += [pscustomobject][ordered]@{ line = $node.Extent.StartLineNumber; target = $node.Extent.Text }
            }
        }
    }

    # ++ / -- rebind their operand.
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.UnaryExpressionAst] }, $true)) {
        if ([string]$node.TokenKind -in @('PlusPlus', 'MinusMinus', 'PostfixPlusPlus', 'PostfixMinusMinus')) {
            $inner = $node.Child
            if ($inner -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $variableAssignments += New-Binding $inner 'incdec' ([string]$node.TokenKind) '' $node
            } else {
                $otherAssignments += [pscustomobject][ordered]@{ line = $node.Extent.StartLineNumber; target = $node.Extent.Text }
            }
        }
    }

    $variableRefs = @()
    $seen = @{}
    foreach ($node in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
        $key = "$($node.VariablePath.UserPath)|$($node.Splatted)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $variableRefs += [pscustomobject][ordered]@{
            name = $node.VariablePath.UserPath
            drive = [string]$node.VariablePath.DriveName
            splatted = [bool]$node.Splatted
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
        source_sha256 = $facts[0]
        source_non_ascii_bytes = $facts[1]
        parse_errors = $parseErrorText
        ast_rows = $rows.ToArray()
        unsupported_nodes = @($unsupported | Sort-Object -Unique)
        script_requirements = ($null -ne $ast.ScriptRequirements)
        node_types = @($ast.FindAll({ $true }, $true) | ForEach-Object { $_.GetType().Name } | Sort-Object -Unique)
        background_pipelines = @($ast.FindAll({ param($n) ($n -is [System.Management.Automation.Language.PipelineAst] -or
                        $n -is [System.Management.Automation.Language.PipelineChainAst]) -and $n.Background }, $true) |
                ForEach-Object { $_.Extent.Text })
        functions = $functions
        function_params = $functionParams
        commands = $commands
        members = $members
        member_assignments = $memberAssignments
        index_assignments = $indexAssignments
        other_assignments = $otherAssignments
        variable_assignments = $variableAssignments
        variable_refs = $variableRefs
        indirect_writes = $indirectWrites
        redirections = $redirections
        using_statements = $usings
        type_references = $typeReferences
    }
}
$sha.Dispose()
ConvertTo-Json -InputObject @($files) -Depth 12 -Compress
