<#
STYLE: Never embed single quotes inside double-quoted strings. PowerShell 5.1
reads this file via the system ANSI codepage when the UTF-8 BOM is missing
(e.g. GitHub zip download), and multi-byte UTF-8 sequences corrupt the
parser's quote-tracking state -- every subsequent ' inside "..." becomes a
fatal parse error. Use `" `"` (escaped double quotes) or restructure instead.

Also: this script must run on PowerShell 5.1 (the Windows default). Avoid
PS 7+ syntax: no ?? (null-coalescing), no ternary operator, no pipeline
chain operators (&& / ||). Use if/else and -or/-and instead.

.SYNOPSIS
    Bootstrap gpo-lens on Windows for hosting behind IIS.

.DESCRIPTION
    Creates the data directory, a virtualenv, and installs gpo-lens (with the
    [web] extra) into it. When -ConfigureIIS is passed, the script also
    creates/updates the IIS site, app pool, web.config, and TLS binding on the
    chosen port. Re-running is safe: the estate database is kept and IIS steps
    are idempotent. On a re-run against an existing site, any IIS binding
    parameter that is OMITTED (-Port, -HostName, -Sni, -TlsCertThumbprint) is
    preserved from the live configuration, so an upgrade-in-place to refresh
    the app does not force an SNI/port/certificate reconfigure. An explicitly
    passed parameter still wins (e.g. -Port 443 changes the port).

    gpo-lens has no per-user login. Behind IIS every request appears to come
    from 127.0.0.1, so the app trusts all callers as the local analyst. Restrict
    access at the IIS layer (Windows Auth / IP allow-list) or keep the site on an
    isolated network. See deploy\iis\README.md "Access control".

    When the detected Python is user-scoped (the default with the Python Install
    Manager), the script copies it to a shared location under InstallDir so the
    IIS app pool identity can access it without depending on a user profile. See
    deploy\iis\README.md "Why a shared Python install" for the full rationale.

.PARAMETER InstallDir
    Base directory for the estate database, venv, logs, and the shared Python
    install. Default: C:\ProgramData\gpo-lens

.PARAMETER AppPool
    IIS application pool name. Default: gpo-lens
    The pool identity ("IIS AppPool\<name>") is granted modify on the data dir
    and execute on the shared Python install.

.PARAMETER ConfigureIIS
    When passed, the script creates/updates the IIS site, app pool, web.config,
    and TLS binding. Omit to skip IIS setup.

.PARAMETER SitePath
    Physical path for the IIS site (where web.config lives).
    Default: C:\inetpub\gpo-lens

.PARAMETER Port
    HTTPS port for the IIS site. Default: 8443. (cert-watch typically owns 443
    on the same host; a distinct port lets gpo-lens run alongside it.)

.PARAMETER HostName
    Hostname for the HTTPS binding. Default: empty (any hostname).

.PARAMETER TlsCertThumbprint
    Thumbprint of the TLS certificate to bind to the HTTPS endpoint.
    When omitted, the binding is created without a certificate (a warning is
    written).

.PARAMETER Sni
    Use an SNI (Server Name Indication) TLS binding instead of a catch-all
    ipport binding. Requires -HostName (SNI selects a cert by hostname) and
    IIS 8+ (Windows Server 2012+). With -Sni the cert is bound via
    netsh hostnameport=HostName:Port and the IIS binding gets sslFlags=1,
    so multiple HTTPS sites can share a port (e.g. gpo-lens on 443 alongside
    cert-watch) keyed by hostname. The catch-all ipport binding is never
    touched in SNI mode, so a co-existing site's binding is safe.

.PARAMETER WindowsAuth
    Enable Windows Authentication on the IIS site and disable anonymous
    access, so only authenticated domain users can reach gpo-lens (the
    recommended access-control model behind IIS). Installs the
    Web-Windows-Auth role service if it is missing. Requires the server to
    be domain-joined (Kerberos/Negotiate does not work on a workgroup box).

.PARAMETER AllowAnonymousNetworkAccess
    Explicit opt-out for a fresh network site without Windows Authentication.
    Every reachable caller receives full analyst permissions. Existing sites
    preserve their authentication during upgrades and warn if anonymous.

.PARAMETER FirewallRemoteAddress
    Remote addresses for a NEW firewall rule. Default LocalSubnet, on Domain
    and Private profiles only. Existing rules are preserved during upgrades.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -ConfigureIIS -Port 8443 -HostName host.example.com -TlsCertThumbprint "ABCDEF123456..." -WindowsAuth

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -ConfigureIIS -Port 443 -HostName gpo-lens.example.com -TlsCertThumbprint "ABCDEF..." -Sni -WindowsAuth

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -ConfigureIIS -Port 8443 -HostName host.example.com -TlsCertThumbprint "ABCDEF..." -WindowsAuth

.NOTES
    This script is not signed. If your execution policy blocks unsigned scripts,
    either bypass it per-invocation (see example above) or sign the script with
    your organisation's code-signing certificate.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\ProgramData\gpo-lens",
    [string]$AppPool = "gpo-lens",
    [switch]$ConfigureIIS,
    [string]$SitePath = "C:\inetpub\gpo-lens",
    [int]$Port = 8443,
    [string]$HostName = "",
    [string]$TlsCertThumbprint = "",
    [switch]$Sni,
    [switch]$WindowsAuth,
    [switch]$AllowAnonymousNetworkAccess,
    [string[]]$FirewallRemoteAddress = @("LocalSubnet")
)

# --- IIS binding / SNI / cert helper functions (extracted for Pester testing) ---
# These are placed before the main execution body so the script can be dot-sourced
# to load the functions without running the install logic.

function Parse-BindingInformation {
    <#
    .SYNOPSIS
        Parse an IIS bindingInformation string into IP, port and host.
        bindingInformation is "IP:Port:HostHeader". The IP is "*", an IPv4
        literal, or a bracketed "[ipv6]" literal.
    #>
    param([string]$BindingInformation)
    $exIp = ""; $exPort = ""; $exHost = ""
    $bi = "$BindingInformation"
    if ($bi.StartsWith("[")) {
        # Bracketed IPv6 IP: "[addr]:port:host"
        $close = $bi.IndexOf("]")
        if ($close -gt 0 -and ($close + 1) -lt $bi.Length -and $bi.Substring($close + 1, 1) -eq ":") {
            $rest = $bi.Substring($close + 2)
            $c = $rest.IndexOf(":")
            if ($c -ge 0) { $exIp = $bi.Substring(0, $close + 1); $exPort = $rest.Substring(0, $c); $exHost = $rest.Substring($c + 1) }
        }
    } else {
        $i1 = $bi.IndexOf(":")
        $i2 = if ($i1 -ge 0) { $bi.IndexOf(":", $i1 + 1) } else { -1 }
        if ($i1 -ge 0 -and $i2 -gt $i1) {
            $exIp = $bi.Substring(0, $i1)
            $exPort = $bi.Substring($i1 + 1, $i2 - $i1 - 1)
            $exHost = $bi.Substring($i2 + 1)
        }
    }
    @{ Ip = $exIp; Port = $exPort; Host = $exHost }
}

function Get-ExistingBindingConfig {
    <#
    .SYNOPSIS
        Read the current IIS HTTPS binding and http.sys certificate binding for
        the gpo-lens site. Returns a hashtable with Port, Host, Sni and Cert keys,
        or $null when no usable binding exists.
    #>
    param([string]$SiteName)
    $existing = $null
    $httpsBind = $null
    foreach ($b in (Get-WebBinding -Name $SiteName -ErrorAction SilentlyContinue)) {
        if ($b.protocol -eq "https") { $httpsBind = $b; break }
    }
    if ($httpsBind) {
        $parsed = Parse-BindingInformation -BindingInformation "$($httpsBind.bindingInformation)"
        if ($parsed.Port -ne "") {
            # sslFlags is a bitmask: bit 0 (1) = SNI, bit 1 (2) = Central Cert Store, etc.
            # Some IIS provider versions return a string ("Sni"/"None") instead of an int;
            # fall back to string match for those.
            $rawFlags = "$($httpsBind.sslFlags)"
            $flagsVal = 0
            if ([int]::TryParse($rawFlags, [ref]$flagsVal)) {
                $exSni = ($flagsVal -band 1) -ne 0
            } else {
                $exSni = $rawFlags -match "Sni"
            }
            $existing = @{ Ip = $parsed.Ip; Port = $parsed.Port; Host = $parsed.Host; Sni = $exSni; Flags = $flagsVal; Cert = "" }
            # Read the currently bound cert hash. Try the IIS binding's
            # certificateHash first (most reliable), then fall back to netsh
            # http.sys queries (hostnameport for SNI/host bindings, ipport for
            # catch-all).  The netsh regex allows spaces before the colon
            # because Windows pads the label (e.g. "Certificate Hash     :").
            $existing.Cert = ""
            try { if ($httpsBind.certificateHash) { $existing.Cert = "$($httpsBind.certificateHash)" } } catch { }
            try { if (-not $existing.Cert -and $httpsBind.certHash) { $existing.Cert = "$($httpsBind.certHash)" } } catch { }
            if (-not $existing.Cert) {
                $show = ""
                if ($exSni -or $parsed.Host) {
                    $show = & netsh http show sslcert hostnameport="$($parsed.Host)`:$($parsed.Port)" 2>&1 | Out-String
                }
                if ($show -notmatch "(?m)^\s*Certificate Hash\s*:\s*([0-9A-Fa-f]+)") {
                    $certIp = if ($parsed.Ip -eq "*") { "0.0.0.0" } else { $parsed.Ip }
                    $show = & netsh http show sslcert ipport="$certIp`:$($parsed.Port)" 2>&1 | Out-String
                }
                if ($show -match "(?m)^\s*Certificate Hash\s*:\s*([0-9A-Fa-f]+)") {
                    $existing.Cert = $Matches[1]
                }
            }
        }
    }
    $existing
}

function Resolve-EffectiveBinding {
    <#
    .SYNOPSIS
        Resolve the effective value for one binding parameter.
        Explicit parameter wins, then an existing installation value, then the
        default value.

    .DESCRIPTION
        The caller pre-computes $ExistingValue from the live config:
        - For Port/Host/Sni: pass the value whenever $existing exists (existence-
          based, matching the original inline `elseif ($existing)`).
        - For Cert: pass the value only when $existing.Cert is non-empty
          (truthiness-based, matching the original `elseif ($existing -and
          $existing.Cert)`). An empty existing cert falls through to the default.
        This preserves the original script's per-parameter semantics without a
        per-parameter flag on the function itself.
    #>
    param(
        [bool]$IsExplicit,
        [object]$ExplicitValue,
        [object]$ExistingValue,
        [object]$DefaultValue
    )
    if ($IsExplicit) { $ExplicitValue }
    elseif ($null -ne $ExistingValue) { $ExistingValue }
    else { $DefaultValue }
}

function Test-SniConsistency {
    <#
    .SYNOPSIS
        Throw if SNI is requested without a hostname. SNI selects a certificate
        by hostname, so an empty host is invalid.
    #>
    param([bool]$Sni, [string]$HostName)
    # Checked after preservation so an existing SNI site upgraded with no flags
    # (host preserved) does not false-positive.
    if ($Sni -and -not $HostName) {
        throw "-Sni requires -HostName (SNI selects a certificate by hostname). Pass -HostName, or omit -Sni to keep the existing binding."
    }
}

function Test-BindingChanged {
    <#
    .SYNOPSIS
        Return $true when the existing binding differs from the effective port,
        host or SNI state and therefore needs to be updated.
    #>
    param(
        [hashtable]$Existing,
        [string]$EffectivePort,
        [string]$EffectiveHost,
        [bool]$EffectiveSni = [bool]$Existing.Sni
    )
    if (-not $Existing -or "$($Existing.Port)" -ne "$EffectivePort" -or "$($Existing.Host)" -ne "$EffectiveHost" -or [bool]$Existing.Sni -ne $EffectiveSni) {
        return $true
    }
    return $false
}

function Compare-CertThumbprint {
    <#
    .SYNOPSIS
        Compare two certificate thumbprints, ignoring whitespace differences.
    #>
    param([string]$Current, [string]$Desired)
    if (-not $Current -or -not $Desired) { return $false }
    ($Current -replace "\s","") -eq ("$Desired" -replace "\s","")
}

function Set-SniBinding {
    <#
    .SYNOPSIS
        Apply the effective IIS binding and SNI bit in either direction.
        Set sslFlags before the netsh certificate bind. Retain the previous
        IIS endpoint until Set-IisTlsEndpoint verifies the new certificate.
    #>
    param(
        [string]$SiteName,
        [string]$Port,
        [string]$HostName,
        [bool]$Sni,
        [hashtable]$Existing,
        [bool]$BindingAlreadyCreated = $false
    )
    if ($Existing -and -not (Test-BindingChanged -Existing $Existing -EffectivePort $Port -EffectiveHost $HostName -EffectiveSni $Sni)) {
        Write-Host "  HTTPS binding already configured; preserving."
        return
    }
    # A fresh site already has its binding from New-Item. Set its SNI bit
    # without attempting to create a duplicate binding.
    if (-not $Existing -and $BindingAlreadyCreated) {
        if ($Sni) {
            Set-WebBinding -Name $SiteName -BindingInformation "*:$Port`:$HostName" -PropertyName sslFlags -Value 1
        }
        return
    }
    $ip = if ($Existing -and $Existing.Ip) { "$($Existing.Ip)" } else { "*" }
    $flags = if ($Existing -and $Existing.Flags) { [int]$Existing.Flags } else { 0 }
    $flags = ($flags -band (-bnot 1)) -bor [int]$Sni
    if ($Existing -and "$($Existing.Port)" -eq "$Port" -and "$($Existing.Host)" -eq "$HostName") {
        # SNI can be enabled AND disabled. Keep unrelated sslFlags bits.
        Set-WebBinding -Name $SiteName -BindingInformation "$ip`:$Port`:$HostName" -PropertyName sslFlags -Value $flags
    } else {
        # Keep the old binding until the new certificate has been verified.
        New-WebBinding -Name $SiteName -Protocol https -IPAddress $ip -Port $Port -HostHeader $HostName -SslFlags $flags | Out-Null
    }
}

function Set-IisTlsEndpoint {
    <# Update the endpoint tuple and certificate together. Plain upgrades are no-ops. #>
    param(
        [string]$SiteName, [string]$Port, [string]$HostName, [bool]$Sni,
        [string]$CertThumbprint, [hashtable]$Existing,
        [bool]$BindingAlreadyCreated = $false
    )
    $changed = Test-BindingChanged -Existing $Existing -EffectivePort $Port -EffectiveHost $HostName -EffectiveSni $Sni
    $ip = if ($Existing -and $Existing.Ip) { "$($Existing.Ip)" } else { "*" }
    Set-SniBinding -SiteName $SiteName -Port $Port -HostName $HostName -Sni $Sni -Existing $Existing -BindingAlreadyCreated $BindingAlreadyCreated
    if (-not $CertThumbprint) {
        Write-Host "  [warn] No TLS certificate configured. Assign one via IIS Manager or -TlsCertThumbprint."
        return
    }
    $currentCert = if ($Existing) { "$($Existing.Cert)" } else { "" }
    if ($changed -or -not (Compare-CertThumbprint -Current $currentCert -Desired $CertThumbprint)) {
        try {
            Set-TlsCertBinding -CertThumbprint $CertThumbprint -Port $Port -HostName $HostName -Sni $Sni -IPAddress $ip
        } catch {
            # Restore the previous IIS tuple if the new certificate failed.
            if ($Existing -and $changed) {
                if ("$($Existing.Port)" -ne "$Port" -or "$($Existing.Host)" -ne "$HostName") {
                    Remove-WebBinding -Name $SiteName -Protocol https -BindingInformation "$ip`:$Port`:$HostName"
                } else {
                    $oldFlags = if ($Existing.Flags) { [int]$Existing.Flags } else { [int][bool]$Existing.Sni }
                    Set-WebBinding -Name $SiteName -BindingInformation "$ip`:$Port`:$HostName" -PropertyName sslFlags -Value $oldFlags
                }
            }
            throw
        }
    }
    if ($Existing -and $changed) {
        if ("$($Existing.Port)" -ne "$Port" -or "$($Existing.Host)" -ne "$HostName") {
            Remove-WebBinding -Name $SiteName -Protocol https -BindingInformation "$ip`:$($Existing.Port)`:$($Existing.Host)"
        }
        # Delete only an old http.sys endpoint that differs from the new one.
        # A host change on non-SNI keeps the same IP:port certificate endpoint.
        if (Test-TlsEndpointStillUsed -Existing $Existing) { return }
        if ($Existing.Sni -and (-not $Sni -or "$($Existing.Port)" -ne "$Port" -or "$($Existing.Host)" -ne "$HostName")) {
            & netsh http delete sslcert hostnameport="$($Existing.Host)`:$($Existing.Port)" 2>$null | Out-Null
        } elseif (-not $Existing.Sni -and ($Sni -or "$($Existing.Port)" -ne "$Port")) {
            $oldIp = if ($ip -eq "*") { "0.0.0.0" } else { $ip }
            & netsh http delete sslcert ipport="$oldIp`:$($Existing.Port)" 2>$null | Out-Null
        }
    }
}

function Test-TlsEndpointStillUsed {
    <# http.sys endpoints may be shared by sites. Never delete one still in use. #>
    param([hashtable]$Existing)
    $oldIp = if ($Existing.Ip) { "$($Existing.Ip)" } else { "*" }
    foreach ($binding in (Get-WebBinding -Protocol https -ErrorAction Stop)) {
        $parsed = Parse-BindingInformation -BindingInformation "$($binding.bindingInformation)"
        if ($parsed.Port -ne "$($Existing.Port)") { continue }
        $flags = 0
        $usesSni = if ([int]::TryParse("$($binding.sslFlags)", [ref]$flags)) { ($flags -band 1) -ne 0 } else { "$($binding.sslFlags)" -match "Sni" }
        if ($Existing.Sni) {
            if ($usesSni -and $parsed.Host -eq "$($Existing.Host)") { return $true }
        } elseif (-not $usesSni) {
            # Wildcard families can overlap (including IPv6 dual-stack).
            if ($oldIp -in @("*", "0.0.0.0", "[::]") -or $parsed.Ip -in @("*", "0.0.0.0", "[::]") -or $parsed.Ip -eq $oldIp) { return $true }
        }
    }
    return $false
}

function Set-TlsCertBinding {
    <#
    .SYNOPSIS
        Bind a TLS certificate to an http.sys endpoint. Uses the SNI hostnameport
        path when Sni is set, otherwise the catch-all ipport path.
    #>
    param(
        [string]$CertThumbprint,
        [string]$Port,
        [string]$HostName,
        [bool]$Sni,
        [string]$IPAddress = "*"
    )
    $bindPort = "$Port"
    $appId = "{B2C3D4E5-F6A7-8901-BCDE-F23456789012}"

    if ($Sni) {
        # SNI: cert is bound per-hostname via hostnameport. Do NOT touch the
        # catch-all ipport=0.0.0.0:Port binding.
        $hostnameport = "$HostName`:$bindPort"
        & netsh http delete sslcert hostnameport="$hostnameport" 2>$null | Out-Null
        $addOut = & netsh http add sslcert hostnameport="$hostnameport" certhash="$CertThumbprint" appid="$appId" certstorename=MY 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host ($addOut | Out-String)
            throw "Failed to bind TLS certificate (netsh exit $LASTEXITCODE). HTTPS will not work. Verify the thumbprint exists in LocalMachine\My with a private key, and that sslFlags=1 (SNI) is set on the IIS binding (the netsh hostnameport add fails with error 87 otherwise)."
        }
        $show = & netsh http show sslcert hostnameport="$hostnameport" 2>&1 | Out-String
        if ($show -notmatch [regex]::Escape($CertThumbprint)) {
            throw "TLS certificate binding verification failed for $hostnameport (cert hash not present after add)."
        }
        Write-Host "    TLS certificate bound to $hostnameport (SNI, store: MY)."
    } else {
        # Non-SNI catch-all: bind the cert to ipport=0.0.0.0:Port.
        $certIp = if ($IPAddress -eq "*") { "0.0.0.0" } else { $IPAddress }
        $ipport = "$certIp`:$bindPort"
        & netsh http delete sslcert ipport="$ipport" 2>$null | Out-Null
        $addOut = & netsh http add sslcert ipport="$ipport" certhash="$CertThumbprint" appid="$appId" certstorename=MY 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host ($addOut | Out-String)
            throw "Failed to bind TLS certificate (netsh exit $LASTEXITCODE). HTTPS will not work. Verify the thumbprint exists in LocalMachine\My and has a private key."
        }
        $show = & netsh http show sslcert ipport="$ipport" 2>&1 | Out-String
        if ($show -notmatch [regex]::Escape($CertThumbprint)) {
            throw "TLS certificate binding verification failed for $ipport (cert hash not present after add)."
        }
        Write-Host "    TLS certificate bound to $ipport (store: MY)."
    }
}


function Test-IisAccessChoice {
    param(
        [bool]$ExistingSite,
        [bool]$WindowsAuth,
        [bool]$AllowAnonymousNetworkAccess,
        [string]$SiteName = "gpo-lens",
        [string]$EnableAuthCommand = ".\scripts\install-windows.ps1 -ConfigureIIS -WindowsAuth"
    )
    if (-not $ExistingSite -and -not $WindowsAuth -and -not $AllowAnonymousNetworkAccess) {
        throw "Fresh -ConfigureIIS requires -WindowsAuth or the explicit -AllowAnonymousNetworkAccess opt-out."
    }
    if ($WindowsAuth) { return }
    if ($ExistingSite) {
        try {
            $anonymous = Get-WebConfigurationProperty -Filter system.webServer/security/authentication/anonymousAuthentication `
                -PSPath "IIS:\" -Location $SiteName -Name enabled -ErrorAction Stop
            if (-not [bool]$anonymous.Value) { return }
        } catch {
            Write-Warning "ACCESS CONTROL: Could not inspect existing IIS authentication; preserving access. Verify it in IIS Manager. To enable Windows Authentication deliberately: $EnableAuthCommand"
            return
        }
        Write-Warning "ANONYMOUS NETWORK ACCESS: Existing site access is preserved for this upgrade. Every reachable caller can view, ingest, delete, triage and narrate. To enable Windows Authentication deliberately: $EnableAuthCommand"
    } else {
        Write-Warning "ANONYMOUS NETWORK ACCESS explicitly allowed: Every reachable caller can view, ingest, delete, triage and narrate. Restrict the network/IIS IP rules before use."
    }
}

function Set-IisFirewallRule {
    param([string]$Port, [string[]]$RemoteAddress = @("LocalSubnet"))
    $rule = "gpo-lens HTTPS $Port"
    if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $Port -Profile Domain,Private -RemoteAddress $RemoteAddress | Out-Null
    } else {
        Write-Host "  Existing firewall rule preserved: $rule. Review its remote-address/profile scope separately."
    }
}

function Get-IisAllowedHosts {
    param(
        [string]$SiteName,
        [string]$MachineFqdn,
        [string]$MachineName = $env:COMPUTERNAME
    )
    if (-not $MachineName) { $MachineName = [System.Net.Dns]::GetHostName() }
    if (-not $MachineFqdn) {
        try { $MachineFqdn = [System.Net.Dns]::GetHostEntry($MachineName).HostName } catch { }
        if (-not $MachineFqdn -or $MachineFqdn -notmatch "\.") {
            # Resolve the machine domain, not the interactive operator's domain.
            try {
                $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
                if ($computer.PartOfDomain) { $MachineFqdn = "$MachineName.$($computer.Domain)" }
            } catch { }
        }
        if (-not $MachineFqdn) { $MachineFqdn = $MachineName }
    }
    $authorities = @($MachineFqdn, $MachineName)
    foreach ($binding in (Get-WebBinding -Name $SiteName -ErrorAction Stop)) {
        if ($binding.protocol -ne "https") { continue }
        $parsed = Parse-BindingInformation -BindingInformation "$($binding.bindingInformation)"
        if (-not $parsed.Port) { continue }
        $names = @($MachineFqdn, $MachineName)
        if ($parsed.Host) { $names += $parsed.Host }
        if ($parsed.Ip -and $parsed.Ip -notin @("*", "0.0.0.0", "[::]")) { $names += $parsed.Ip }
        foreach ($name in $names) {
            $authorities += $name
            $authorities += "$name`:$($parsed.Port)"
        }
    }
    (($authorities | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique) -join ",")
}

function Set-IisAllowedHosts {
    param([string]$WebConfigPath, [string]$AllowedHosts)
    $doc = New-Object System.Xml.XmlDocument
    $doc.PreserveWhitespace = $true
    $doc.Load($WebConfigPath)
    $platform = $doc.SelectSingleNode("/configuration/system.webServer/httpPlatform")
    if (-not $platform) {
        throw "Missing httpPlatform in $WebConfigPath; configure GPO_LENS_ALLOWED_HOSTS in the actual application environment."
    }
    $variables = $platform.SelectSingleNode("environmentVariables")
    if (-not $variables) {
        $variables = $doc.CreateElement("environmentVariables")
        $null = $platform.AppendChild($variables)
    }
    foreach ($variable in $variables.SelectNodes("environmentVariable")) {
        if ($variable.GetAttribute("name") -eq "GPO_LENS_ALLOWED_HOSTS") { return }
    }
    $variable = $doc.CreateElement("environmentVariable")
    $variable.SetAttribute("name", "GPO_LENS_ALLOWED_HOSTS")
    $variable.SetAttribute("value", $AllowedHosts)
    $null = $variables.AppendChild($variable)
    # Write only after validating, beside the original, then replace atomically.
    $temporary = "$WebConfigPath.gpo-lens-tmp"
    try {
        $settings = New-Object System.Xml.XmlWriterSettings
        $settings.Encoding = New-Object System.Text.UTF8Encoding $false
        $writer = [System.Xml.XmlWriter]::Create($temporary, $settings)
        try { $doc.Save($writer) } finally { $writer.Dispose() }
        [System.IO.File]::Replace($temporary, $WebConfigPath, [NullString]::Value)
    } finally {
        if (Test-Path $temporary) { Remove-Item $temporary -Force }
    }
    Write-Host "  Added GPO_LENS_ALLOWED_HOSTS=$AllowedHosts (other web.config settings preserved)."
}

# Guard: only run the main installation body when executed directly. Dot-sourcing
# loads the helper functions above so they can be unit-tested without touching
# IIS, http.sys, or the filesystem.
if ($MyInvocation.InvocationName -ne ".") {

    $ErrorActionPreference = "Stop"

    # --- Must be elevated (we write under ProgramData and set ACLs) ---
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run from an elevated (Administrator) PowerShell."
    }

    $repoRoot = (Resolve-Path "$PSScriptRoot\..").Path

# Inspect access before stopping a live pool or changing any installation files.
$siteName = "gpo-lens"
$sitePathIIS = "IIS:\Sites\$siteName"
$existingSite = $null
$iisModuleAvailable = [bool](Get-Module -ListAvailable WebAdministration -ErrorAction SilentlyContinue)
if ($iisModuleAvailable) {
    Import-Module WebAdministration
    $existingSite = Get-Item $sitePathIIS -ErrorAction SilentlyContinue
    # A custom physical path is part of the existing installation too.
    if ($existingSite -and -not $PSBoundParameters.ContainsKey("SitePath")) {
        $SitePath = [Environment]::ExpandEnvironmentVariables("$($existingSite.physicalPath)")
    }
    if ($ConfigureIIS -or $existingSite) {
        $enableAuthCommand = "powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ConfigureIIS -WindowsAuth -InstallDir `"$InstallDir`" -SitePath `"$SitePath`" -AppPool `"$AppPool`""
        Test-IisAccessChoice -ExistingSite ([bool]$existingSite) -WindowsAuth ([bool]$WindowsAuth) `
            -AllowAnonymousNetworkAccess ([bool]$AllowAnonymousNetworkAccess) -EnableAuthCommand $enableAuthCommand
    }
} elseif ($ConfigureIIS) {
    throw "-ConfigureIIS requires the WebAdministration module to inspect and configure site access. Install IIS management scripting tools first."
}

$venv     = Join-Path $InstallDir "venv"
$logs     = Join-Path $InstallDir "logs"

# --- Locate a Python 3.12+ launcher ---
# The Windows 'py' launcher works interactively but can fail through
# PowerShell's & operator (Windows Store stubs, argument mangling).
# Use cmd /c for probing, then resolve the real python.exe path so all
# subsequent calls go directly to the executable.
function Invoke-PyProbe {
    param([string]$Exe, [string[]]$Arguments)
    $argStr = ($Arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
    $tmp = Join-Path $env:TEMP "gpol-py-probe.txt"
    & cmd /c "`"$Exe`" $argStr > `"$tmp`" 2>&1"
    $exit = $LASTEXITCODE
    $out = ""
    if (Test-Path $tmp) {
        $out = (Get-Content $tmp -Raw)
        Remove-Item $tmp -Force
    }
    @{ ExitCode = $exit; Output = if ($out) { $out.Trim() } else { "" } }
}

# Candidate interpreters, in priority order. Fully-qualified python.exe paths
# come first because they work in non-interactive sessions (SSH / scheduled
# task / service); the bare `py` / `python` / `python3` PATH launchers come
# last and are skipped below when they resolve to a Windows Store
# execution-alias stub under WindowsApps -- those 0-byte reparse points fail
# with "cannot be accessed by the system" outside an interactive logon, which
# is exactly what broke a remote (SSH) re-install (WI-050).
$launchers = @()
# 1. The shared interpreter a prior install copied under InstallDir. Present on
#    every re-install/upgrade and guaranteed outside a user profile/WindowsApps.
$sharedCandidate = Join-Path $InstallDir "python\python.exe"
if (Test-Path $sharedCandidate) { $launchers += @{ Exe = $sharedCandidate; Args = @() } }
# 2. Python Install Manager per-user runtimes (full prefixes, real exes -- not
#    the Store aliases). Prefer the runtime dir over the bin\ shims so the
#    "ensure shared" copy below has a complete prefix to copy.
$imRoot = Join-Path $env:LOCALAPPDATA "Python"
foreach ($pc in (Get-ChildItem $imRoot -Filter "pythoncore-*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
    $p = Join-Path $pc.FullName "python.exe"
    if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
}
# 3. Per-machine Python installs.
foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if (-not $base) { continue }
    foreach ($d in (Get-ChildItem $base -Filter "Python3*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
        $p = Join-Path $d.FullName "python.exe"
        if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
    }
}
# 4. Install Manager bin shims, then the bare PATH launchers, as a last resort.
foreach ($n in @("python3.exe", "python.exe")) {
    $p = Join-Path (Join-Path $imRoot "bin") $n
    if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
}
$launchers += @(
    @{ Exe = "py";      Args = @("-3.14") },
    @{ Exe = "py";      Args = @("-3.12") },
    @{ Exe = "py";      Args = @("-3") },
    @{ Exe = "python";  Args = @() },
    @{ Exe = "python3"; Args = @() }
)
$python = $null
foreach ($l in $launchers) {
    $label = "$($l.Exe) $($l.Args -join `" `")"
    $cmd = Get-Command $l.Exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Write-Host "  [skip] $label -- exe not found on PATH"
        continue
    }
    # Skip Windows Store execution-alias stubs (WI-050): they resolve on PATH
    # but cannot be executed in a non-interactive session.
    if ($cmd.Source -and $cmd.Source -match "\\WindowsApps\\") {
        Write-Host "  [skip] $label -- Windows Store alias ($($cmd.Source)), unusable non-interactively"
        continue
    }
    $probeArgs = $l.Args + @("--version")
    $r = Invoke-PyProbe -Exe $l.Exe -Arguments $probeArgs
    if ($r.ExitCode -ne 0) {
        Write-Host "  [fail] $label -- exit code $($r.ExitCode)"
        continue
    }
    $ver = ($r.Output -split "`n" | Where-Object { $_ -match "^Python\s+\d" } | Select-Object -First 1).Trim()
    if ($ver -match "Python\s+(\d+)\.(\d+)") {
        $major = [int]$Matches[1]; $minor = [int]$Matches[2]
        if ($major -ge 3 -and $minor -ge 12) {
            # Resolve the real python.exe path so we bypass the launcher for
            # all subsequent calls (venv, pip).  Ask Python itself.
            $resolved = ""
            try {
                $selfProbe = Invoke-PyProbe -Exe $l.Exe -Arguments ($l.Args + @("-c", "import sys; print(sys.executable)"))
                if ($selfProbe.ExitCode -eq 0) {
                    $candidate = ($selfProbe.Output -split "`n" | Select-Object -First 1).Trim()
                    if ($candidate -and (Test-Path $candidate -ErrorAction SilentlyContinue)) {
                        $resolved = $candidate
                    }
                }
            } catch { }
            if ($resolved) {
                Write-Host "  [ok]   $label -- $ver (resolved: $resolved)"
                $python = @{ Exe = $resolved; Args = @() }
            } else {
                Write-Host "  [ok]   $label -- $ver (using launcher directly)"
                $python = $l
            }
            break
        }
        Write-Host "  [fail] $label -- version $major.$minor < 3.12"
    } else {
        Write-Host "  [fail] $label -- output not recognised: $ver"
    }
}
if (-not $python) {
    throw "Python 3.12+ not found. Install it (winget install Python.Python.3.14) and re-run."
}

# --- Ensure Python is in a shared (non-user-profile) location ---
# The Python Install Manager installs runtimes per-user only (under
# %LocalAppData%\Python).  The IIS app pool identity cannot access user
# profiles, so we copy the runtime to a shared directory under InstallDir.
# See deploy\iis\README.md "Why a shared Python install" for the rationale.
$sharedPyDir = Join-Path $InstallDir "python"
$sharedPyExe = Join-Path $sharedPyDir "python.exe"
$needsShared = $false
if ($python.Exe -like "*\AppData\*" -or $python.Exe -like "*\WindowsApps\*") {
    $needsShared = $true
}
if ($needsShared) {
    if (Test-Path $sharedPyExe) {
        Write-Host "Using existing shared Python at $sharedPyDir"
    } else {
        Write-Host "Python is user-scoped ($($python.Exe)); copying to shared location ..."
        Write-Host "  Installing to $sharedPyDir via py install --target ..."
        $tag = "$major.$minor"
        $r = Invoke-PyProbe -Exe "py" -Arguments @("install", "--target=$sharedPyDir", $tag)
        if ($r.ExitCode -ne 0) {
            # Fallback: manually copy the installation
            Write-Host "  py install --target failed (exit $($r.ExitCode)); copying manually ..."
            $pySrc = Split-Path $python.Exe
            # Copy the entire Python prefix (not just the exe -- we need stdlib)
            if (Test-Path $pySrc) {
                Copy-Item -Path $pySrc -Destination $sharedPyDir -Recurse -Force
            }
        }
        if (-not (Test-Path $sharedPyExe)) {
            # py install --target may extract to a subdirectory
            $nested = Get-ChildItem -Path $sharedPyDir -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($nested) {
                $sharedPyDir = Split-Path $nested.FullName
                $sharedPyExe = $nested.FullName
            }
        }
        if (-not (Test-Path $sharedPyExe)) {
            throw "Failed to create shared Python at $sharedPyDir. Copy $($python.Exe) manually."
        }
        # Python 3.14+ marks venvlauncher.exe as hidden/system. When we copy the
        # installation to a shared location, those attributes survive. The venv
        # module then cannot copy the launcher into the new venv, producing a
        # degraded wrapper instead of a proper launcher.
        $launcher = Join-Path $sharedPyDir "Lib\venv\scripts\nt\venvlauncher.exe"
        $wlauncher = Join-Path $sharedPyDir "Lib\venv\scripts\nt\venvwlauncher.exe"
        if (Test-Path $launcher) {
            attrib -H -S $launcher 2>$null | Out-Null
        }
        if (Test-Path $wlauncher) {
            attrib -H -S $wlauncher 2>$null | Out-Null
        }
        Write-Host "  Shared Python ready at $sharedPyExe"
    }
    $python = @{ Exe = $sharedPyExe; Args = @() }
}

Write-Host "Creating directories under $InstallDir ..."
foreach ($d in @($InstallDir, $logs)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

# Stop the IIS app pool (if it exists) BEFORE touching the venv so the running
# worker releases the files it holds (venv\Scripts\python.exe and loaded
# .pyd/.exe). On a re-install over a live site, leaving it running locks these
# files and both venv creation and pip install fail. appcmd is always present
# with IIS, so this avoids a hard dependency on the WebAdministration module.
$script:poolWasStopped = $false
$appcmdExe = "$env:windir\system32\inetsrv\appcmd.exe"
if (Test-Path $appcmdExe) {
    $poolExists = & $appcmdExe list apppool "$AppPool" 2>$null
    if ($poolExists) {
        Write-Host "Stopping app pool `"$AppPool`" to release files before install ..."
        & $appcmdExe stop apppool /apppool.name:"$AppPool" 2>$null | Out-Null
        Start-Sleep -Seconds 3
        $script:poolWasStopped = $true
    }
}

# Clear hidden/system attributes on the chosen interpreter's venv launchers
# before creating the venv. Python 3.14 marks venvlauncher.exe hidden+system;
# venv creation then fails with "Unable to copy ... venvlauncher.exe". The
# fresh-copy path above clears these, but when we reuse an existing shared
# Python (the common re-install case) the attributes survive, so clear them
# here unconditionally against whichever interpreter we resolved (WI-050).
$pyPrefix = Split-Path $python.Exe
foreach ($vl in @("Lib\venv\scripts\nt\venvlauncher.exe", "Lib\venv\scripts\nt\venvwlauncher.exe")) {
    $vlPath = Join-Path $pyPrefix $vl
    if (Test-Path $vlPath) { attrib -H -S $vlPath 2>$null | Out-Null }
}

Write-Host "Creating virtualenv at $venv ..."
# Capture venv output rather than letting it stream. Python 3.14 can emit a
# scary-looking "Unable to copy ... venvlauncher.exe" line while still producing
# a working venv via its fallback; we only want to show that noise if the venv
# actually fails to verify below.
$venvOut = & $python.Exe @($python.Args + @("-m", "venv", $venv)) 2>&1
if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
    if ($venvOut) { Write-Host ($venvOut | Out-String) }
    throw "Failed to create virtualenv at $venv using $($python.Exe)."
}

$venvPy = Join-Path $venv "Scripts\python.exe"
# Verify the venv is functional (not just that the file exists). In Python 3.14
# the venvlauncher copy may silently produce a broken wrapper when the source
# launcher has hidden/system attributes.
$venvProbe = & $venvPy -c "import sys; print(sys.executable)" 2>&1
if ($LASTEXITCODE -ne 0) {
    if ($venvOut) { Write-Host ($venvOut | Out-String) }
    throw "venv created but python.exe is not functional (exit $LASTEXITCODE): $venvProbe"
}
Write-Host "  venv verified: $venvProbe"
if ("$venvOut" -match "Unable to copy") {
    # The venv verified functional, so the launcher-copy message is cosmetic
    # (Python used its fallback wrapper). Say so, so it does not read as a failure.
    Write-Host "  Note: Python logged a benign `"Unable to copy venvlauncher.exe`" message during"
    Write-Host "        venv creation; the venv was created and verified working, so it is not an error."
}
Write-Host "Installing gpo-lens ..."
$requirements = Join-Path $repoRoot "deploy\iis\requirements-web.lock.txt"
& $venvPy -m pip install --require-hashes -r $requirements
if ($LASTEXITCODE -ne 0) {
    throw "Hash-pinned web dependency install failed (exit $LASTEXITCODE)."
}
# Install the complete locked build closure before disabling build isolation.
$buildRequirements = Join-Path $repoRoot "deploy\iis\requirements-build.lock.txt"
& $venvPy -m pip install --require-hashes -r $buildRequirements
if ($LASTEXITCODE -ne 0) {
    throw "Hash-pinned build dependency install failed (exit $LASTEXITCODE)."
}
# The [web] extra pulls fastapi/uvicorn/jinja2/python-multipart needed to serve.
$pkg = "$repoRoot[web]"
# --upgrade so an in-place re-install actually refreshes the package metadata.
# Without it pip could leave a prior version's dist-info in place, which is what
# the app reports as its version (the GUI then shows a stale version after an
# upgrade that otherwise appeared to succeed).
& $venvPy -m pip install --upgrade --no-deps --no-build-isolation $pkg
if ($LASTEXITCODE -ne 0) {
    throw "pip install of gpo-lens failed (exit $LASTEXITCODE)."
}
# Surface the version that actually landed in the venv, and flag drift from the
# source tree being installed. This closes the loop on "the GUI shows the wrong
# version after a deploy" by making the installed version visible at install time.
$installedVer = ((& $venvPy -m pip show gpo-lens 2>$null | Select-String "^Version:") -replace "^Version:\s*", "").Trim()
$sourceVer = ""
$pyprojectPath = Join-Path $repoRoot "pyproject.toml"
if (Test-Path $pyprojectPath) {
    $verLine = Get-Content $pyprojectPath | Select-String '^\s*version\s*=' | Select-Object -First 1
    if ($verLine) { $sourceVer = ($verLine.ToString() -replace '.*=\s*"?([^"]*)"?.*', '$1').Trim() }
}
Write-Host "  Installed gpo-lens version: $installedVer"
if ($sourceVer -and $installedVer -and ($installedVer -ne $sourceVer)) {
    Write-Host "  [warn] Installed version ($installedVer) does not match the source tree ($sourceVer)."
}

# gpo-lens stores no signing secrets -- the estate database is its only state,
# and it is created on first run under InstallDir.

$identity = "IIS AppPool\$AppPool"

function Test-AccountResolves {
    param([string]$Account)
    try {
        $null = (New-Object System.Security.Principal.NTAccount($Account)).Translate(
            [System.Security.Principal.SecurityIdentifier])
        return $true
    } catch {
        return $false
    }
}

function Grant-AppPoolAcls {
    Write-Host "Granting $identity access (data: modify, python: read+execute) ..."
    icacls $InstallDir /grant:r "${identity}:(OI)(CI)M" | Out-Null
    # The shared Python install lives under InstallDir, which already has
    # modify access.  Explicitly set RX on the python subdir to ensure
    # execute is inherited even if the parent's modify ACE is tightened later.
    if (Test-Path $sharedPyDir) {
        icacls $sharedPyDir /grant "${identity}:(OI)(CI)RX" | Out-Null
    }
}

# App-pool virtual accounts ("IIS AppPool\<name>") only exist once the pool
# does. Grant now if the pool is already there (upgrade-in-place); otherwise
# -ConfigureIIS grants right after creating the pool. A plain venv install
# (CI smoke, dev box) skips the grant -- icacls would fail with "No mapping
# between account names and security IDs" and poison the script's exit code.
if (Test-AccountResolves $identity) {
    Grant-AppPoolAcls
} elseif (-not $ConfigureIIS) {
    Write-Host "App pool `"$AppPool`" does not exist; skipping ACL grant (re-run with -ConfigureIIS for IIS hosting)."
}

$script:iisActuallyConfigured = $false

# --- IIS configuration ---
if ($ConfigureIIS) {
    Write-Host ""
    Write-Host "Configuring IIS ..."

    # Check prerequisites
    if (-not $iisModuleAvailable) {
        Write-Host "  [skip] WebAdministration module not available; skipping IIS config."
        Write-Host "  See deploy\iis\README.md for manual IIS setup."
    } else {
        Import-Module WebAdministration

        # 1. Create site directory and web.config
        if (-not (Test-Path $SitePath)) {
            Write-Host "  Creating site directory $SitePath ..."
            New-Item -ItemType Directory -Force -Path $SitePath | Out-Null
        } else {
            Write-Host "  Site directory exists: $SitePath"
        }

        $webConfigSrc = Join-Path $repoRoot "deploy\iis\web.config"
        $webConfigDst = Join-Path $SitePath "web.config"
        # Do NOT clobber an existing web.config. It may hold operator-set
        # environmentVariables (GPO_LENS_LLM_ENDPOINT / GPO_LENS_API_KEY for
        # narration) that the template ships commented out. Only lay the
        # template down on a fresh install; to reset, delete it and re-run.
        if (Test-Path $webConfigDst) {
            Write-Host "  Keeping existing web.config (preserving operator settings)."
            Write-Host "    To reset it to the template, delete `"$webConfigDst`" and re-run."
        } else {
            Write-Host "  Installing web.config from template ..."
            Copy-Item $webConfigSrc $webConfigDst -Force

            # Update paths in web.config to reflect InstallDir
            $defaultDir = "C:\ProgramData\gpo-lens"
            $wcContent = Get-Content $webConfigDst -Raw
            if ($InstallDir -ne $defaultDir) {
                $escapedInstallDir = [System.Security.SecurityElement]::Escape($InstallDir)
                $wcContent = $wcContent.Replace($defaultDir, $escapedInstallDir)
            }
            # Validate the result is well-formed XML before writing
            try {
                $null = [xml]$wcContent
            } catch {
                throw "web.config rewrite produced invalid XML"
            }
            # Write without BOM (Set-Content -Encoding UTF8 emits BOM on PS 5.1)
            [System.IO.File]::WriteAllText($webConfigDst, $wcContent, (New-Object System.Text.UTF8Encoding $false))
            Write-Host "    Wrote template web.config (paths -> $InstallDir)."
            Write-Host "    Optionally edit it to set GPO_LENS_LLM_ENDPOINT / GPO_LENS_API_KEY for the Ask page."
        }

        # 2. Unlock handlers section
        Write-Host "  Unlocking system.webServer/handlers ..."
        & "$env:windir\system32\inetsrv\appcmd.exe" unlock config -section:system.webServer/handlers
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to unlock system.webServer/handlers. Run manually: appcmd unlock config -section:system.webServer/handlers"
        }

        # 3. Create app pool
        $poolPath = "IIS:\AppPools\$AppPool"
        $existingPool = Get-Item $poolPath -ErrorAction SilentlyContinue
        if (-not $existingPool) {
            Write-Host "  Creating app pool `"$AppPool`" ..."
            New-Item $poolPath | Out-Null
            # Do not serve a fresh site until host policy and authentication are set.
            Stop-WebAppPool -Name $AppPool
        } else {
            Write-Host "  App pool `"$AppPool`" already exists."
        }
        Set-ItemProperty $poolPath -Name managedRuntimeVersion -Value ""
        Set-ItemProperty $poolPath -Name startMode -Value "AlwaysRunning"
        Set-ItemProperty $poolPath -Name processModel.idleTimeout -Value "00:00:00"
        Set-ItemProperty $poolPath -Name recycling.periodicRestart.time -Value "00:00:00"
        Write-Host "    App pool configured (No Managed Code, AlwaysRunning, no idle timeout, no periodic restart)."

        # The pool (and its virtual account) now exists -- apply the data/python
        # ACLs that were skipped earlier if it was missing.
        Grant-AppPoolAcls

        # 4. Detect an existing installation so an upgrade-in-place PRESERVES the
        # IIS binding/SNI/certificate instead of clobbering it with the parameter
        # defaults. Operators re-running the installer to refresh the app
        # typically omit -Port/-HostName/-Sni/-TlsCertThumbprint; without this,
        # the script would rewrite the binding to *:8443: (catch-all, non-SNI,
        # no cert) and force a full reconfigure. For any binding parameter the
        # caller did NOT explicitly pass ($PSBoundParameters), fall back to the
        # live IIS/http.sys value; an explicit argument still wins, so
        # -Port 443 on an existing site still changes the port.
        $siteName = "gpo-lens"
        $sitePathIIS = "IIS:\Sites\$siteName"
        $existingSite = Get-Item $sitePathIIS -ErrorAction SilentlyContinue
        $existing = $null
        if ($existingSite) {
            $existing = Get-ExistingBindingConfig -SiteName $siteName
        }

        # Resolve effective binding values: explicit parameter wins, else the
        # existing installation's value (preservation), else the default.
        # Port/Host/Sni are existence-based (pass the value whenever $existing
        # exists); Cert is truthiness-based (pass $null when existing cert is
        # empty, so it falls through to the default).
        $existingPort = if ($existing) { "$($existing.Port)" } else { $null }
        $existingHost = if ($existing) { $existing.Host } else { $null }
        $existingSni  = if ($existing) { [bool]$existing.Sni } else { $null }
        $existingCert = if ($existing -and $existing.Cert) { $existing.Cert } else { $null }
        # NOTE: [bool] casts must be parenthesized when used as parameter
        # arguments -- PS 5.1 parses bare -Param [bool]$var as the string
        # "[bool]False", not as a cast.  Pester (pwsh 7) does not catch this.
        $effPort = Resolve-EffectiveBinding -IsExplicit $PSBoundParameters.ContainsKey("Port") -ExplicitValue "$Port" -ExistingValue $existingPort -DefaultValue "$Port"
        $effHost = Resolve-EffectiveBinding -IsExplicit $PSBoundParameters.ContainsKey("HostName") -ExplicitValue $HostName -ExistingValue $existingHost -DefaultValue $HostName
        $effSni  = Resolve-EffectiveBinding -IsExplicit $PSBoundParameters.ContainsKey("Sni") -ExplicitValue ([bool]$Sni) -ExistingValue $existingSni -DefaultValue ([bool]$Sni)
        $effCert = Resolve-EffectiveBinding -IsExplicit $PSBoundParameters.ContainsKey("TlsCertThumbprint") -ExplicitValue $TlsCertThumbprint -ExistingValue $existingCert -DefaultValue $TlsCertThumbprint

        Test-SniConsistency -Sni $effSni -HostName $effHost

        # Expose effective values to the script epilogue (Browse: message).
        $script:effPort = $effPort
        $script:effHost = $effHost

        if ($existing) {
            Write-Host "  Existing IIS site detected -- preserving binding unless overridden:"
            $certLabel = if ($effCert) { $effCert } else { "<none>" }
            Write-Host "    port=$effPort host=`"$effHost`" sni=$effSni cert=$certLabel"
        }

        # 5. Create / update the IIS site.
        $bindingInfo = "*:$($effPort):$effHost"
        if (-not $existingSite) {
            Write-Host "  Creating IIS site `"$siteName`" on port $effPort ..."
            New-Item $sitePathIIS -bindings @{protocol="https"; bindingInformation=$bindingInfo} -physicalPath $SitePath | Out-Null
            Set-ItemProperty $sitePathIIS -Name applicationPool -Value $AppPool
        } else {
            Write-Host "  IIS site `"$siteName`" already exists."
            Set-ItemProperty $sitePathIIS -Name applicationPool -Value $AppPool
            Set-ItemProperty $sitePathIIS -Name physicalPath -Value $SitePath
        }

        # Rebind a preserved certificate whenever port/host/SNI changes. The
        # helper retains the old endpoint until the new certificate verifies.
        Set-IisTlsEndpoint -SiteName $siteName -Port $effPort -HostName $effHost -Sni $effSni -CertThumbprint $effCert -Existing $existing -BindingAlreadyCreated (-not $existingSite)

        # Merge the host policy after bindings are effective; preserve an operator's value.
        $allowedHosts = Get-IisAllowedHosts -SiteName $siteName
        Set-IisAllowedHosts -WebConfigPath $webConfigDst -AllowedHosts $allowedHosts

        # New firewall rules are management-subnet scoped. Existing rules stay intact.
        if (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) {
            Set-IisFirewallRule -Port $effPort -RemoteAddress $FirewallRemoteAddress
        } else {
            Write-Warning "New-NetFirewallRule unavailable; allow TCP $effPort from the intended management network manually."
        }

        # 9. Windows Authentication (optional - closes the access-control gap).
        if ($WindowsAuth) {
            Write-Host "  Configuring Windows Authentication ..."
            $waFeature = Get-WindowsFeature Web-Windows-Auth -ErrorAction SilentlyContinue
            if ($waFeature -and -not $waFeature.Installed) {
                Write-Host "    Installing Web-Windows-Auth role service ..."
                $waResult = Install-WindowsFeature Web-Windows-Auth
                if (-not $waResult.Success) {
                    throw "Install-WindowsFeature Web-Windows-Auth failed (exit $($waResult.ExitCode)). A reboot may be required."
                }
                if ($waResult.RestartNeeded -eq "Yes") {
                    Write-Host "    [warn] Web-Windows-Auth installed but a reboot is required before Windows Auth will work."
                }
            }
            Set-WebConfigurationProperty -Filter system.webServer/security/authentication/windowsAuthentication `
                -PSPath "IIS:\" -Location $siteName -Name enabled -Value $true
            Set-WebConfigurationProperty -Filter system.webServer/security/authentication/anonymousAuthentication `
                -PSPath "IIS:\" -Location $siteName -Name enabled -Value $false
            Write-Host "    Windows Auth enabled, anonymous disabled (domain users only)."
        }

        # 10. Grant app pool identity read access to site path
        Write-Host "  Granting $identity read access to $SitePath ..."
        icacls $SitePath /grant "${identity}:(OI)(CI)R" | Out-Null

        # 11. Start the app pool so the freshly installed code is the live code.
        # (It was stopped before pip install on a re-install; a fresh pool may
        # also be stopped depending on IIS state.) Verify it reaches Started so
        # a silent 503 does not slip through.
        Write-Host "  Starting app pool `"$AppPool`" ..."
        & $appcmdExe start apppool /apppool.name:"$AppPool" 2>$null | Out-Null
        Start-Sleep -Seconds 2
        $poolState = (& $appcmdExe list apppool "$AppPool" /text:state) 2>$null
        Write-Host "    App pool state: $poolState"
        if ("$poolState" -ne "Started") {
            Write-Host "    [warn] App pool `"$AppPool`" is not Started; the site will return HTTP 503 until it starts."
        }

        $script:iisActuallyConfigured = $true
    }
}

if (-not $ConfigureIIS -and $existingSite) {
    $installedWebConfig = Join-Path $SitePath "web.config"
    if (Test-Path $installedWebConfig) {
        Set-IisAllowedHosts -WebConfigPath $installedWebConfig -AllowedHosts (Get-IisAllowedHosts -SiteName $siteName)
    }
}

# If we stopped the pool to release locked files but did NOT run the IIS-config
# path (which restarts it), bring it back up now. Otherwise a plain
# upgrade-in-place (install without -ConfigureIIS) leaves the site stopped and
# serving HTTP 503.
if ($script:poolWasStopped -and -not $script:iisActuallyConfigured) {
    Write-Host ""
    Write-Host "Restarting app pool `"$AppPool`" (was stopped to release files) ..."
    & $appcmdExe start apppool /apppool.name:"$AppPool" 2>$null | Out-Null
    Start-Sleep -Seconds 2
    $poolState = (& $appcmdExe list apppool "$AppPool" /text:state) 2>$null
    Write-Host "  App pool state: $poolState"
    if ("$poolState" -ne "Started") {
        Write-Host "  [warn] App pool `"$AppPool`" is not Started; the site will return HTTP 503 until it starts."
    }
}

Write-Host ""
Write-Host "Done. gpo-lens installed to $venv"
Write-Host "Data dir: $InstallDir   DB: $InstallDir\gpo-lens.sqlite3"
if ($script:iisActuallyConfigured) {
    # Use the effective (possibly preserved) binding values so the printed
    # URL matches what the operator actually hits after an upgrade-in-place.
    $epPort = if ($script:effPort) { $script:effPort } else { $Port }
    $epHost = if ($script:effHost) { $script:effHost } else { $HostName }
    Write-Host "IIS site: $SitePath   App pool: $AppPool   Port: $epPort"
    $hn = if ($epHost) { $epHost } else { "<hostname>" }
    Write-Host "Browse: https://$hn`:$epPort/"
}
Write-Host ""
Write-Host "The estate starts empty -- open the site and use Ingest to upload a"
Write-Host "collector export, or copy a gpo-lens.sqlite3 into the data dir."
Write-Host ""
Write-Host "ACCESS CONTROL: gpo-lens has no per-user login. Behind IIS every caller"
Write-Host "is treated as the trusted local analyst. Restrict the site at the IIS"
Write-Host "layer (Windows Auth / IP allow-list) or keep it on an isolated network."
Write-Host "See deploy\iis\README.md."

} # end dot-source guard
