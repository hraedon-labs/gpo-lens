"""Collector read-only enforcement by PowerShell AST allowlist.

The collection scripts run on a domain controller or RSAT host with a domain
account. gpo-lens claims they are read-only against Active Directory, Group
Policy and SYSVOL. This test turns that claim from "by inspection" into a
mechanical check: it **parses** (never executes) each in-scope script with the
PowerShell language parser (``tests/powershell/Get-ScriptCallInventory.ps1``)
and fails on anything outside an explicit ALLOWLIST:

* every command invocation (cmdlet, function, external program);
* every dynamic invocation (``&`` / ``.`` with a computed target), pinned by
  its exact source text;
* every static .NET method call (``[Type]::Method``) by type and member;
* every instance .NET method call by member name (the receiver type is not
  statically known; see "Limits" below);
* every property assignment on an object (``$x.Prop = ...``);
* ``New-Object`` type names (``-ComObject`` is never allowed);
* ``Add-Type`` arguments: an assembly name, or an inline C# definition pinned
  by SHA-256 because its body is invisible to the PowerShell AST.

The allowlist is strict in both directions: an entry that a script no longer
uses also fails, so the list cannot rot into a permissive superset.

Local file writes are allowed only to the collection's own outputs. Each
file-writing command or method must target an expression built only from the
variables named in that script's ``write_roots`` (each documented below with
its derivation from ``-OutputRoot``, ``-OutputPath`` or ``-CopyTo``), and must
not contain an absolute path, UNC path or ``..`` literal. That the named
variables derive from those parameters is verified by inspection, recorded in
the ``write_roots`` descriptions; the AST check pins the variable names.

Scope:

* In scope (run on the DC/RSAT host): ``Export-GpoEstate.ps1``,
  ``Export-GroupMembers.ps1``, ``Export-Principals.ps1``,
  ``Run-GpoLensCollection.ps1``, ``GpoLensCollectionMarker.ps1``.
* ``Register-GpoLensCollection.ps1`` also runs on the DC/RSAT host but its job
  is to create a Windows scheduled task, which is a write to the host (not to
  AD). It has its own narrow allowlist that names the ScheduledTasks cmdlets.
* Out of scope: ``install-windows.ps1`` / ``uninstall-windows.ps1`` run on the
  *analysis* host (IIS install), never on a DC, and legitimately install
  software, write IIS configuration and firewall rules.

Limits (stated, not hidden):

* Instance methods are matched by name only. ``.Delete()`` on a ZIP entry and
  on a hypothetical directory object look the same; each allowlisted instance
  name is therefore per script and justified by the objects that script
  creates.
* ``& $CollectorPath`` in the runner executes the script path the operator
  registered. The default is ``Export-GpoEstate.ps1`` (checked here); a custom
  ``-CollectorPath`` is operator-supplied code and outside this guarantee.
* Read-only is about Active Directory, Group Policy and SYSVOL. The AD and
  GroupPolicy cmdlets in the allowlist are all ``Get-*`` cmdlets; Microsoft's
  documentation is the authority for those cmdlets not writing.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parent.parent
_SCRIPTS = _REPO / "scripts"
_DUMPER = _REPO / "tests" / "powershell" / "Get-ScriptCallInventory.ps1"


@dataclass(frozen=True)
class ScriptPolicy:
    commands: frozenset[str]
    static_methods: frozenset[str] = frozenset()
    instance_methods: frozenset[str] = frozenset()
    dynamic_invocations: frozenset[str] = frozenset()
    dot_sources: tuple[str, ...] = ()
    new_object_types: frozenset[str] = frozenset()
    add_type_assemblies: frozenset[str] = frozenset()
    add_type_definitions: frozenset[str] = frozenset()
    member_assignments: frozenset[str] = frozenset()
    write_roots: dict[str, str] = field(default_factory=dict)


# Console output and pure pipeline/data cmdlets; no state outside the process.
_CONSOLE_AND_PIPELINE = frozenset(
    {
        "ConvertFrom-Json",
        "ConvertTo-Json",
        "ForEach-Object",
        "Get-Date",
        "Join-Path",
        "Measure-Object",
        "Out-Null",
        "Out-String",
        "Select-Object",
        "Sort-Object",
        "Where-Object",
        "Write-Error",
        "Write-Host",
        "Write-Progress",
        "Write-Warning",
    }
)
# Local file-system reads.
_FS_READ = frozenset({"Get-ChildItem", "Get-Content", "Get-Item", "Resolve-Path", "Test-Path"})


def _cmds(*names: str, shared: frozenset[str]) -> frozenset[str]:
    """Script-specific commands plus the subset of *shared* the script uses.

    Every name must still be used (the exact-match check), so taking a subset
    of a shared group never widens what a script may call.
    """
    return frozenset(names) | shared


POLICIES: dict[str, ScriptPolicy] = {
    "Export-GpoEstate.ps1": ScriptPolicy(
        commands=_cmds(
            # AD / Group Policy reads.
            "Get-ADDomain",
            "Get-ADGroupMember",
            "Get-ADObject",
            "Get-ADOrganizationalUnit",
            "Get-ADRootDSE",
            "Get-GPInheritance",
            "Get-GPO",
            "Get-GPOReport",
            "Get-Module",
            # Assembly load for ZIP creation; New-Object for SID parsing.
            "Add-Type",
            "New-Object",
            # Local writes, constrained by write_roots.
            "Copy-Item",
            "New-Item",
            "Remove-Item",
            "Set-Content",
            shared=(_CONSOLE_AND_PIPELINE - {"ConvertFrom-Json", "Out-String"})
            | (_FS_READ - {"Resolve-Path"}),
        ),
        static_methods=frozenset(
            {
                "Collections.Generic.HashSet[string]::new",
                "Collections.Generic.List[object]::new",
                "Collections.Generic.List[string]::new",
                "IO.Compression.ZipFile::Open",
                "IO.Compression.ZipFileExtensions::CreateEntryFromFile",
                "IO.File::WriteAllText",
                "math::Round",
                "regex::Matches",
            }
        ),
        instance_methods=frozenset(
            # Collections, strings, ZIP dispose, SecurityIdentifier.Translate
            # (SID -> account name lookup, a read).
            {"Add", "Contains", "Dispose", "Replace", "Split", "Substring", "Translate", "Trim"}
        ),
        new_object_types=frozenset({"System.Security.Principal.SecurityIdentifier"}),
        add_type_assemblies=frozenset({"System.IO.Compression.FileSystem"}),
        write_roots={
            "OutputRoot": "the -OutputRoot parameter (created if absent)",
            "testFile": "Join-Path $OutputRoot '_writetest_.tmp' (writability probe, removed)",
            "out": "Join-Path $OutputRoot '<domain>-<stamp>' (this run's export folder)",
            "dest": "Join-Path $out 'SYSVOL-Policies' (the SYSVOL copy target)",
            "archive": '"$ExportPath.zip" where New-GpoExportZip receives -ExportPath $out',
        },
    ),
    "Export-GroupMembers.ps1": ScriptPolicy(
        commands=_cmds(
            "Get-ADGroupMember",
            "Get-Content",
            "Set-Content",
            shared=frozenset(
                {"ConvertFrom-Json", "ConvertTo-Json", "Get-Date", "Where-Object", "Write-Host"}
            ),
        ),
        # Splatting an optional -Credential into the AD read cmdlets.
        member_assignments=frozenset({"$adParams.Credential"}),
        write_roots={"OutputPath": "the -OutputPath parameter (default group-members.json)"},
    ),
    "Export-Principals.ps1": ScriptPolicy(
        commands=_cmds(
            "Get-ADDomain",
            "Get-ADObject",
            "New-Object",
            "Set-Content",
            shared=frozenset(
                {
                    "ConvertTo-Json",
                    "Get-ChildItem",
                    "Get-Content",
                    "Get-Date",
                    "Join-Path",
                    "Sort-Object",
                    "Test-Path",
                    "Where-Object",
                    "Write-Host",
                }
            ),
        ),
        static_methods=frozenset({"Collections.Generic.HashSet[string]::new", "regex::Matches"}),
        # RawSecurityDescriptor -> SDDL text and SID -> account name: reads.
        instance_methods=frozenset({"Add", "GetSecurityDescriptorSddlForm", "Translate"}),
        new_object_types=frozenset({"System.Security.Principal.SecurityIdentifier"}),
        member_assignments=frozenset({"$adParams.Credential"}),
        write_roots={"OutputPath": "the -OutputPath parameter (default principals.json)"},
    ),
    "Run-GpoLensCollection.ps1": ScriptPolicy(
        commands=_cmds(
            "Add-Type",
            "Copy-Item",
            "Move-Item",
            "New-Item",
            "Remove-Item",
            shared=(_CONSOLE_AND_PIPELINE - {"ConvertTo-Json", "Measure-Object", "Write-Progress"})
            | (_FS_READ - {"Get-Content"}),
        ),
        dynamic_invocations=frozenset(
            {
                # Runs the registered collector (default Export-GpoEstate.ps1).
                "& $CollectorPath -OutputRoot $OutputRoot *>&1",
                ". (Join-Path $PSScriptRoot 'GpoLensCollectionMarker.ps1')",
            }
        ),
        dot_sources=("GpoLensCollectionMarker.ps1",),
        static_methods=frozenset(
            {
                "Collections.Generic.HashSet[guid]::new",
                "Collections.Generic.Stack[string]::new",
                "IO.Compression.ZipFile::Open",
                "IO.Compression.ZipFile::OpenRead",
                "IO.File::AppendAllText",
                "IO.File::Open",
                "IO.File::ReadAllBytes",
                "IO.File::WriteAllBytes",
                "Text.UTF8Encoding::new",
                "guid::NewGuid",
                "guid::TryParse",
                "math::Max",
                "string::Equals",
                "string::IsNullOrWhiteSpace",
            }
        ),
        instance_methods=frozenset(
            {
                "Add",
                "ContainsKey",
                # ZipArchive.CreateEntry / ZipArchiveEntry.Delete+Open on the
                # ZIP this run just created (inventory overlay).
                "CreateEntry",
                "Delete",
                "Dispose",
                "GetByteCount",
                "GetEntry",
                "GetString",
                "Open",
                "Pop",
                "Push",
                "Substring",
                "ToString",
                "TrimEnd",
                "TrimStart",
                "Write",
            }
        ),
        add_type_assemblies=frozenset({"System.IO.Compression.FileSystem"}),
        write_roots={
            "OutputRoot": "the -OutputRoot parameter (owner-marker checked before any write)",
            "LogPath": "Join-Path $OutputRoot 'collection.log'",
            "old": "$LogPath or $LogPath.<n> (log rotation)",
            "next": "$LogPath.<n> (log rotation)",
            "newest": "the single new completed ZIP under $OutputRoot",
            "exportDir": "Join-Path $OutputRoot $newest.BaseName",
            "archive": "an expired completed export ZIP under $OutputRoot (retention)",
            "folder": "Join-Path $OutputRoot $archive.BaseName (retention)",
            "CopyTo": "the -CopyTo delivery directory",
            "partial": "<$delivery>.<guid>.partial inside -CopyTo",
            "delivery": "Join-Path $CopyTo $newest.Name",
        },
    ),
    "GpoLensCollectionMarker.ps1": ScriptPolicy(
        commands=_cmds(
            "Add-Type",
            # Linux-only test path: link count of the already-open marker inode.
            "stat",
            shared=frozenset({"Get-Item", "Join-Path", "Test-Path"}),
        ),
        static_methods=frozenset(
            {
                "GpoLens.MarkerFileInfo::LinkCount",
                "IO.File::Delete",
                "IO.File::Open",
                "IO.MemoryStream::new",
                "uint32::TryParse",
            }
        ),
        instance_methods=frozenset(
            {"CopyTo", "DangerousGetHandle", "Dispose", "ToArray", "ToInt64", "Write"}
        ),
        # GetFileInformationByHandle P/Invoke (read-only link-count query).
        add_type_definitions=frozenset(
            {"8e3d8b0b78dcf2319d6a1e414007e80fdb055c76715b83f81e94ba32d42c5f67"}
        ),
        write_roots={
            "Marker": "the owner marker path passed by callers (opened for read only)",
            "marker": "Join-Path <output root> '.gpo-lens-collection-owner'",
        },
    ),
    # Separate, narrow policy: registering the task is a deliberate write to the
    # host's Task Scheduler (not to AD). Nothing else here writes beyond the
    # output root's owner marker and lock file.
    "Register-GpoLensCollection.ps1": ScriptPolicy(
        commands=_cmds(
            "New-ScheduledTask",
            "New-ScheduledTaskAction",
            "New-ScheduledTaskPrincipal",
            "New-ScheduledTaskSettingsSet",
            "New-ScheduledTaskTrigger",
            "Register-ScheduledTask",
            "Unregister-ScheduledTask",
            # Service-account password prompt, handed only to Task Scheduler.
            "Get-Credential",
            "New-Item",
            shared=frozenset(
                {"Get-Item", "Join-Path", "Out-Null", "Resolve-Path", "Test-Path"}
                | {"Write-Host", "Write-Warning"}
            ),
        ),
        dynamic_invocations=frozenset(
            {
                # Invokes the in-file scriptblock literal passed to
                # Set-GpoLensCollectionOwner (its body is scanned here).
                "& $RegisterTask",
                ". (Join-Path $PSScriptRoot 'GpoLensCollectionMarker.ps1')",
            }
        ),
        dot_sources=("GpoLensCollectionMarker.ps1",),
        static_methods=frozenset(
            {
                "IO.File::Delete",
                "IO.File::Open",
                "IO.Path::GetFullPath",
                "Text.UTF8Encoding::new",
                "datetime::TryParseExact",
                "string::Equals",
                "string::IsNullOrWhiteSpace",
                "timespan::FromDays",
                "timespan::FromHours",
            }
        ),
        instance_methods=frozenset(
            {
                "Dispose",
                "GetBytes",
                "GetNetworkCredential",
                "GetString",
                "ShouldProcess",
                "TrimEnd",
                "TrimStart",
            }
        ),
        write_roots={
            "OutputRoot": "the -OutputRoot parameter (normalized with GetFullPath)",
            "marker": "Join-Path $OutputRoot '.gpo-lens-collection-owner'",
        },
    ),
}

OUT_OF_SCOPE = {
    "install-windows.ps1": "runs on the analysis host to install the IIS site, not on a DC",
    "uninstall-windows.ps1": "runs on the analysis host to remove the IIS site, not on a DC",
}

# File-writing commands and the bound parameters that name what they write.
# Move-Item removes its source, so both ends are write targets.
_WRITE_COMMANDS: dict[str, tuple[str, ...]] = {
    "Add-Content": ("Path", "LiteralPath"),
    "Copy-Item": ("Destination",),
    "Move-Item": ("Path", "LiteralPath", "Destination"),
    "New-Item": ("Path",),
    "Out-File": ("FilePath", "LiteralPath"),
    "Remove-Item": ("Path", "LiteralPath"),
    "Rename-Item": ("Path", "LiteralPath"),
    "Set-Content": ("Path", "LiteralPath"),
}
# Static methods whose first argument is a path that may be created/written/deleted.
_WRITE_STATIC = {
    "IO.File::AppendAllText",
    "IO.File::Delete",
    "IO.File::Open",
    "IO.File::WriteAllBytes",
    "IO.File::WriteAllText",
    "IO.Compression.ZipFile::Open",
}
_VARIABLE = re.compile(r"\$(?:\{([^}]+)\}|(?:script:|local:)?([A-Za-z_][A-Za-z0-9_]*))")
_ABSOLUTE_LITERAL = re.compile(r"[A-Za-z]:[\\/]|\\\\|(?:^|[\\/'\" ])\.\.(?:[\\/'\" ]|$)")


def _normalize_type(name: str) -> str:
    return name.removeprefix("System.")


def _pwsh() -> str:
    exe = shutil.which("pwsh")
    if exe is None:
        if os.environ.get("CI"):
            pytest.fail("pwsh is required in CI for the collector read-only gate")
        pytest.skip("pwsh not installed; CI runs this gate (ubuntu runners ship pwsh)")
    return exe


@cache
def _inventory_for(exe: str) -> dict[str, dict[str, Any]]:
    paths = [str(_SCRIPTS / name) for name in sorted(POLICIES)]
    result = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-File", str(_DUMPER), *paths],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return {Path(entry["path"]).name: entry for entry in json.loads(result.stdout)}


@pytest.fixture(scope="module")
def inventory() -> dict[str, dict[str, Any]]:
    return _inventory_for(_pwsh())


def _exact(kind: str, script: str, used: set[str], allowed: frozenset[str]) -> None:
    unexpected = sorted(used - allowed)
    unused = sorted(allowed - used)
    assert not unexpected, f"{script}: {kind} outside the read-only allowlist: {unexpected}"
    assert not unused, f"{script}: stale {kind} allowlist entries (remove them): {unused}"


def test_every_script_is_classified() -> None:
    on_disk = {p.name for p in _SCRIPTS.glob("*.ps1")}
    classified = set(POLICIES) | set(OUT_OF_SCOPE)
    assert on_disk == classified, (
        "Every scripts/*.ps1 must be in POLICIES or OUT_OF_SCOPE: "
        f"unclassified {sorted(on_disk - classified)}, missing {sorted(classified - on_disk)}"
    )


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_parses_without_errors(inventory: dict[str, dict[str, Any]], script: str) -> None:
    assert inventory[script]["parse_errors"] == []


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_commands_are_allowlisted(inventory: dict[str, dict[str, Any]], script: str) -> None:
    policy = POLICIES[script]
    entry = inventory[script]
    local = set(entry["functions"])
    for source in policy.dot_sources:
        local |= set(inventory[source]["functions"])
    named = {c["name"] for c in entry["commands"] if c["name"]}
    _exact("commands", script, named - local, policy.commands)
    dynamic = {c["text"] for c in entry["commands"] if not c["name"]}
    _exact("dynamic invocations", script, dynamic, policy.dynamic_invocations)


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_dotnet_calls_are_allowlisted(inventory: dict[str, dict[str, Any]], script: str) -> None:
    policy = POLICIES[script]
    members = inventory[script]["members"]
    dynamic = [m["text"] for m in members if m["member"] is None or (m["static"] and not m["type"])]
    assert not dynamic, f"{script}: computed member/type names cannot be verified: {dynamic}"
    static = {f"{_normalize_type(m['type'])}::{m['member']}" for m in members if m["static"]}
    _exact("static .NET methods", script, static, policy.static_methods)
    instance = {m["member"] for m in members if not m["static"]}
    _exact("instance .NET methods", script, instance, policy.instance_methods)
    assigned = {a["target"] for a in inventory[script]["member_assignments"]}
    _exact("property assignments", script, assigned, policy.member_assignments)


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_new_object_and_add_type(inventory: dict[str, dict[str, Any]], script: str) -> None:
    policy = POLICIES[script]
    types: set[str] = set()
    assemblies: set[str] = set()
    definitions: set[str] = set()
    for command in inventory[script]["commands"]:
        bound = command["bound"]
        if command["name"] == "New-Object":
            assert "ComObject" not in bound, f"{script}:{command['line']}: COM is not allowed"
            types.add(str(bound.get("TypeName")))
        elif command["name"] == "Add-Type":
            keys = set(bound) - {"ErrorAction"}
            if keys == {"AssemblyName"}:
                assemblies.add(bound["AssemblyName"])
            elif keys == {"TypeDefinition"} and command["type_definition_sha256"]:
                definitions.add(command["type_definition_sha256"])
            else:
                pytest.fail(f"{script}:{command['line']}: unsupported Add-Type form {sorted(keys)}")
    _exact("New-Object types", script, types, policy.new_object_types)
    _exact("Add-Type assemblies", script, assemblies, policy.add_type_assemblies)
    _exact("Add-Type inline definitions (sha256)", script, definitions, policy.add_type_definitions)


def _write_targets(entry: dict[str, Any]) -> list[tuple[int, str]]:
    targets: list[tuple[int, str]] = []
    for command in entry["commands"]:
        params = _WRITE_COMMANDS.get(command["name"] or "")
        if params is None:
            continue
        bound = [command["bound"][p] for p in params if isinstance(command["bound"].get(p), str)]
        assert bound, (
            f"line {command['line']}: cannot resolve the write target of {command['text']}"
        )
        targets.extend((command["line"], text) for text in bound)
    for member in entry["members"]:
        if member["static"] and f"{_normalize_type(member['type'])}::{member['member']}" in (
            _WRITE_STATIC
        ):
            targets.append((member["line"], member["first_argument"] or ""))
    return targets


@pytest.mark.parametrize("script", sorted(POLICIES))
def test_local_writes_stay_under_declared_roots(
    inventory: dict[str, dict[str, Any]], script: str
) -> None:
    policy = POLICIES[script]
    used_roots: set[str] = set()
    for line, text in _write_targets(inventory[script]):
        names = {a or b for a, b in _VARIABLE.findall(text)}
        names.discard("_")  # pipeline item; only ever a source here, never a target
        assert names, f"{script}:{line}: write target {text!r} is not built from a declared root"
        outside = names - set(policy.write_roots)
        assert not outside, f"{script}:{line}: write target {text!r} uses undeclared {outside}"
        assert not _ABSOLUTE_LITERAL.search(text), f"{script}:{line}: literal path in {text!r}"
        used_roots |= names
    _exact("write roots", script, used_roots, frozenset(policy.write_roots))


def test_ad_and_group_policy_cmdlets_are_reads_only() -> None:
    """Every AD/GroupPolicy/ScheduledTasks noun-verb in an allowlist is a Get-*,
    except the scheduled-task registration that only Register-* may use."""
    task_cmdlets = {
        "New-ScheduledTask",
        "New-ScheduledTaskAction",
        "New-ScheduledTaskPrincipal",
        "New-ScheduledTaskSettingsSet",
        "New-ScheduledTaskTrigger",
        "Register-ScheduledTask",
        "Unregister-ScheduledTask",
    }
    for script, policy in POLICIES.items():
        directory = {c for c in policy.commands if re.match(r"^\w+-(AD|GP)", c)}
        assert all(c.startswith("Get-") for c in directory), (script, sorted(directory))
        tasks = policy.commands & task_cmdlets
        if script != "Register-GpoLensCollection.ps1":
            assert not tasks, f"{script} must not touch Task Scheduler: {sorted(tasks)}"


def test_allowlist_rejects_a_planted_write(tmp_path: Path) -> None:
    """Mutation check: the inventory sees an AD write, an ADSI commit and an
    absolute-path file write, and none of them is allowlisted anywhere."""
    exe = _pwsh()
    planted = (
        "Get-ADObject -Filter * | Out-Null\n"
        "Set-ADObject -Identity 'x' -Replace @{description='y'}\n"
        "[System.IO.File]::WriteAllText('C:\\Windows\\x.txt', 'y')\n"
        "$entry.CommitChanges()\n"
    )
    script = tmp_path / "planted.ps1"
    script.write_text(planted, encoding="ascii")
    result = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-File", str(_DUMPER), str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    entry = json.loads(result.stdout)[0]
    commands = {c["name"] for c in entry["commands"]}
    assert "Set-ADObject" in commands
    assert not any("Set-ADObject" in p.commands for p in POLICIES.values())
    members = {(m["static"], m["member"]) for m in entry["members"]}
    assert (False, "CommitChanges") in members
    assert not any("CommitChanges" in p.instance_methods for p in POLICIES.values())
    targets = _write_targets(entry)
    assert any(_ABSOLUTE_LITERAL.search(text) for _, text in targets)
