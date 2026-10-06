# Pester 5 tests for the IIS binding/SNI/cert helper functions extracted from
# scripts/install-windows.ps1.
#
# The script is dot-sourced to load the functions without executing the install
# body. IIS/http.sys commands used by those functions are mocked/stubbed below
# so tests run on non-Windows hosts.

# netsh is a native Windows executable, so native-command mocking in Pester does
# not work reliably from a function loaded via dot-sourcing. A global function
# stub records every invocation and returns a controlled "show sslcert" output.
function global:netsh {
    $global:NetshCalls += ,@($Args)
    $global:LASTEXITCODE = $global:NetshExit
    $cmd = $Args -join " "
    if ($cmd -match 'show sslcert') {
        if ($global:NetshCertHash) {
            "    Certificate Hash:        $($global:NetshCertHash)"
        }
    }
}

Describe "install-windows.ps1" {
    BeforeAll {
        $script:SourcePath = "$PSScriptRoot/../../scripts/install-windows.ps1"
        . $script:SourcePath
    }

    BeforeEach {
        $global:NetshCalls = @()
        $global:NetshExit = 0
        $global:NetshCertHash = "ABCDEF123456"
    }

    Describe "Parse-BindingInformation" {
        It "parses IPv4 wildcard *:8443:" {
            $r = Parse-BindingInformation -BindingInformation "*:8443:"
            $r.Port | Should -Be "8443"
            $r.Host | Should -Be ""
        }

        It "parses IPv4 wildcard with a hostname" {
            $r = Parse-BindingInformation -BindingInformation "*:8443:host.example.com"
            $r.Port | Should -Be "8443"
            $r.Host | Should -Be "host.example.com"
        }

        It "parses an IPv4 literal IP with a hostname" {
            $r = Parse-BindingInformation -BindingInformation "192.168.1.1:8443:gpo-lens.local"
            $r.Port | Should -Be "8443"
            $r.Host | Should -Be "gpo-lens.local"
        }

        It "parses bracketed IPv6 [::]:8443:" {
            $r = Parse-BindingInformation -BindingInformation "[::]:8443:"
            $r.Port | Should -Be "8443"
            $r.Host | Should -Be ""
        }

        It "parses bracketed IPv6 with a hostname" {
            $r = Parse-BindingInformation -BindingInformation "[::]:8443:gpo-lens.local"
            $r.Port | Should -Be "8443"
            $r.Host | Should -Be "gpo-lens.local"
        }

        It "returns empty values for a malformed string" {
            $r = Parse-BindingInformation -BindingInformation "not-a-binding"
            $r.Port | Should -Be ""
            $r.Host | Should -Be ""
        }

        It "returns empty values for an empty string" {
            $r = Parse-BindingInformation -BindingInformation ""
            $r.Port | Should -Be ""
            $r.Host | Should -Be ""
        }
    }

    Describe "Resolve-EffectiveBinding" {
        It "prefer explicit value over existing and default" {
            $r = Resolve-EffectiveBinding -IsExplicit $true -ExplicitValue "8443" -ExistingValue "443" -DefaultValue "8443"
            $r | Should -Be "8443"
        }

        It "preserves existing value when no explicit value is supplied" {
            $r = Resolve-EffectiveBinding -IsExplicit $false -ExplicitValue "8443" -ExistingValue "443" -DefaultValue "8443"
            $r | Should -Be "443"
        }

        It "falls back to default when there is no existing config" {
            $r = Resolve-EffectiveBinding -IsExplicit $false -ExplicitValue "8443" -ExistingValue $null -DefaultValue "8443"
            $r | Should -Be "8443"
        }

        It "preserves existing Sni=`$true" {
            $r = Resolve-EffectiveBinding -IsExplicit $false -ExplicitValue $false -ExistingValue $true -DefaultValue $false
            $r | Should -Be $true
        }

        It "preserves existing Sni=`$false over a `$true default" {
            $r = Resolve-EffectiveBinding -IsExplicit $false -ExplicitValue $false -ExistingValue $false -DefaultValue $true
            $r | Should -Be $false
        }

        It "uses default when the existing value is `$null (key absent)" {
            $r = Resolve-EffectiveBinding -IsExplicit $false -ExplicitValue "" -ExistingValue $null -DefaultValue "default.example.com"
            $r | Should -Be "default.example.com"
        }

        It "explicit false Sni wins over existing true" {
            $r = Resolve-EffectiveBinding -IsExplicit $true -ExplicitValue $false -ExistingValue $true -DefaultValue $false
            $r | Should -Be $false
        }

        It "falls to default when existing cert is empty (truthiness semantics)" {
            $r = Resolve-EffectiveBinding -IsExplicit $false -ExplicitValue "" -ExistingValue $null -DefaultValue ""
            $r | Should -Be ""
        }

        It "preserves a non-empty existing cert" {
            $r = Resolve-EffectiveBinding -IsExplicit $false -ExplicitValue "" -ExistingValue "ABCDEF123456" -DefaultValue ""
            $r | Should -Be "ABCDEF123456"
        }
    }

    Describe "Test-SniConsistency" {
        It "throws when Sni is requested without a hostname" {
            { Test-SniConsistency -Sni $true -HostName "" } | Should -Throw
        }

        It "passes when Sni is requested with a hostname" {
            { Test-SniConsistency -Sni $true -HostName "gpo-lens.local" } | Should -Not -Throw
        }

        It "passes when Sni is false and hostname is empty" {
            { Test-SniConsistency -Sni $false -HostName "" } | Should -Not -Throw
        }

        It "passes when Sni is false and hostname is set" {
            { Test-SniConsistency -Sni $false -HostName "gpo-lens.local" } | Should -Not -Throw
        }
    }

    Describe "Test-BindingChanged" {
        It "returns `$true when there is no existing binding" {
            Test-BindingChanged -Existing $null -EffectivePort "8443" -EffectiveHost "" | Should -Be $true
        }

        It "returns `$false when port and host both match" {
            $existing = @{ Port = "8443"; Host = "gpo-lens.local" }
            Test-BindingChanged -Existing $existing -EffectivePort "8443" -EffectiveHost "gpo-lens.local" | Should -Be $false
        }

        It "returns `$true when the port differs" {
            $existing = @{ Port = "8443"; Host = "gpo-lens.local" }
            Test-BindingChanged -Existing $existing -EffectivePort "443" -EffectiveHost "gpo-lens.local" | Should -Be $true
        }

        It "returns `$true when the host differs" {
            $existing = @{ Port = "8443"; Host = "old.example.com" }
            Test-BindingChanged -Existing $existing -EffectivePort "8443" -EffectiveHost "gpo-lens.local" | Should -Be $true
        }

        It "returns `$false when both existing and effective hosts are empty" {
            $existing = @{ Port = "8443"; Host = "" }
            Test-BindingChanged -Existing $existing -EffectivePort "8443" -EffectiveHost "" | Should -Be $false
        }
    }

    Describe "Compare-CertThumbprint" {
        It "returns `$true for identical thumbprints" {
            Compare-CertThumbprint -Current "ABCDEF123456" -Desired "ABCDEF123456" | Should -Be $true
        }

        It "ignores whitespace differences in the current thumbprint" {
            Compare-CertThumbprint -Current "AB CD EF 12 34 56" -Desired "ABCDEF123456" | Should -Be $true
        }

        It "ignores whitespace differences in the desired thumbprint" {
            Compare-CertThumbprint -Current "ABCDEF123456" -Desired "AB CD EF 12 34 56" | Should -Be $true
        }

        It "ignores case differences (PowerShell default equality)" {
            Compare-CertThumbprint -Current "abcdef123456" -Desired "ABCDEF123456" | Should -Be $true
        }

        It "returns `$false when the current thumbprint is empty" {
            Compare-CertThumbprint -Current "" -Desired "ABCDEF123456" | Should -Be $false
        }

        It "returns `$false when the desired thumbprint is empty" {
            Compare-CertThumbprint -Current "ABCDEF123456" -Desired "" | Should -Be $false
        }
    }

    Describe "Get-ExistingBindingConfig" {
        BeforeAll {
            function Get-WebBinding { }
        }

        It "retains concrete binding IP and reads its certificate" -ForEach @(
            @{IP="192.0.2.10"}, @{IP="[2001:db8::10]"}
        ) {
            Mock Get-WebBinding {
                @([pscustomobject]@{protocol="https"; bindingInformation="$IP`:8443:"; sslFlags=0})
            }
            $r = Get-ExistingBindingConfig -SiteName gpo-lens
            $r.IP | Should -Be $IP
            $r.Cert | Should -Be "ABCDEF123456"
            $global:NetshCalls | Where-Object { ($_ -join " ") -eq "http show sslcert ipport=$IP`:8443" } | Should -Not -Be $null
        }

        It "reads non-SNI host-header certificate from IP rather than stale hostnameport" {
            Mock Get-WebBinding { @([pscustomobject]@{protocol="https"; bindingInformation="192.0.2.10:8443:lens.lab.example.com"; sslFlags=0}) }
            $r = Get-ExistingBindingConfig -SiteName gpo-lens
            $r.Cert | Should -Be "ABCDEF123456"
            $global:NetshCalls | Where-Object { ($_ -join " ") -match 'hostnameport=' } | Should -Be $null
            $global:NetshCalls | Where-Object { ($_ -join " ") -eq 'http show sslcert ipport=192.0.2.10:8443' } | Should -Not -Be $null
        }

        It "returns `$null when there is no https binding" {
            Mock Get-WebBinding {
                @(
                    [pscustomobject]@{ protocol = "http"; bindingInformation = "*:80:"; sslFlags = 0 }
                )
            }

            $r = Get-ExistingBindingConfig -SiteName "gpo-lens"
            $r | Should -Be $null
            $global:NetshCalls | Should -Be @()
        }

        It "detects an IPv4 catch-all binding and reads the ipport cert" {
            Mock Get-WebBinding {
                @(
                    [pscustomobject]@{ protocol = "https"; bindingInformation = "*:8443:"; sslFlags = 0 }
                )
            }
            $global:NetshCertHash = "ABCD1234"

            $r = Get-ExistingBindingConfig -SiteName "gpo-lens"
            $r.Port | Should -Be "8443"
            $r.Host | Should -Be ""
            $r.Sni | Should -Be $false
            $r.Cert | Should -Be "ABCD1234"

            $ipportShow = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'show sslcert ipport=0\.0\.0\.0:8443' }
            $ipportShow | Should -Not -Be $null
        }

        It "detects an IPv6 binding with a hostname" {
            Mock Get-WebBinding {
                @(
                    [pscustomobject]@{ protocol = "https"; bindingInformation = "[::]:8443:gpo-lens.local"; sslFlags = 0 }
                )
            }
            $global:NetshCertHash = "ABCD5678"

            $r = Get-ExistingBindingConfig -SiteName "gpo-lens"
            $r.Port | Should -Be "8443"
            $r.Host | Should -Be "gpo-lens.local"
            $r.Sni | Should -Be $false
            $r.Cert | Should -Be "ABCD5678"

            $ipportShow = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'show sslcert ipport=\[::\]:8443' }
            $ipportShow | Should -Not -Be $null
        }

        It "detects SNI from sslFlags string and reads the hostnameport cert" {
            Mock Get-WebBinding {
                @(
                    [pscustomobject]@{ protocol = "https"; bindingInformation = "*:8443:gpo-lens.local"; sslFlags = "Sni" }
                )
            }
            $global:NetshCertHash = "ABCD9ABC"

            $r = Get-ExistingBindingConfig -SiteName "gpo-lens"
            $r.Port | Should -Be "8443"
            $r.Host | Should -Be "gpo-lens.local"
            $r.Sni | Should -Be $true
            $r.Cert | Should -Be "ABCD9ABC"

            $hostnameportShow = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'show sslcert hostnameport=gpo-lens.local:8443' }
            $hostnameportShow | Should -Not -Be $null
        }

        It "detects SNI from numeric sslFlags bitmask (bit 0 = SNI)" {
            Mock Get-WebBinding {
                @(
                    [pscustomobject]@{ protocol = "https"; bindingInformation = "*:8443:gpo-lens.local"; sslFlags = 1 }
                )
            }
            $global:NetshCertHash = "ABCDDEF0"

            $r = Get-ExistingBindingConfig -SiteName "gpo-lens"
            $r.Sni | Should -Be $true
            $r.Cert | Should -Be "ABCDDEF0"

            # Because the binding has a hostname, the script first tries
            # hostnameport and only falls back to ipport on a miss.
            $hostnameportShow = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'show sslcert hostnameport=gpo-lens.local:8443' }
            $hostnameportShow | Should -Not -Be $null
        }

        It "detects SNI from sslFlags bitmask with combined flags (3 = SNI + CCS)" {
            Mock Get-WebBinding {
                @(
                    [pscustomobject]@{ protocol = "https"; bindingInformation = "*:8443:gpo-lens.local"; sslFlags = 3 }
                )
            }
            $global:NetshCertHash = "ABCD1122"

            $r = Get-ExistingBindingConfig -SiteName "gpo-lens"
            $r.Sni | Should -Be $true
            $r.Cert | Should -Be "ABCD1122"
        }

        It "returns `$null when bindingInformation is malformed" {
            Mock Get-WebBinding {
                @(
                    [pscustomobject]@{ protocol = "https"; bindingInformation = "not-a-binding"; sslFlags = 0 }
                )
            }

            $r = Get-ExistingBindingConfig -SiteName "gpo-lens"
            $r | Should -Be $null
            $global:NetshCalls | Should -Be @()
        }

        It "reads cert from IIS binding certificateHash (no netsh needed)" {
            $skip = $PSVersionTable.PSVersion.Major -lt 6
            if ($skip) {
                Set-ItResult -Skipped -Because "PS 5.1 Mock does not expose certificateHash on pscustomobject"
            } else {
                Mock Get-WebBinding {
                    @(
                        [pscustomobject]@{ protocol = "https"; bindingInformation = "*:8443:"; sslFlags = 0; certificateHash = "AABBCCDDEEFF" }
                    )
                }

                $r = Get-ExistingBindingConfig -SiteName "gpo-lens"
                $r.Port | Should -Be "8443"
                $r.Cert | Should -Be "AABBCCDDEEFF"
                $global:NetshCalls | Should -Be @()
            }
        }

        It "falls back to netsh when IIS binding has no certificateHash" {
            Mock Get-WebBinding {
                @(
                    [pscustomobject]@{ protocol = "https"; bindingInformation = "*:8443:"; sslFlags = 0; certificateHash = $null }
                )
            }
            $global:NetshCertHash = "DEADBEEF"

            $r = Get-ExistingBindingConfig -SiteName "gpo-lens"
            $r.Cert | Should -Be "DEADBEEF"
            $global:NetshCalls.Count | Should -BeGreaterThan 0
        }
    }

    Describe "Set-SniBinding" {
        BeforeAll {
            function Clear-WebBinding { }
            function New-WebBinding { }
        }

        It "applies the SNI binding when there is no existing config" {
            Mock Clear-WebBinding { }
            Mock New-WebBinding { }
            Set-SniBinding -SiteName "gpo-lens" -Port "8443" -HostName "gpo-lens.local" -Sni $true -Existing $null
            Should -Invoke Clear-WebBinding -Exactly 1
            Should -Invoke New-WebBinding -Exactly 1
        }

        It "re-applies the SNI binding when the current binding is not SNI" {
            Mock Clear-WebBinding { }
            Mock New-WebBinding { }
            Set-SniBinding -SiteName "gpo-lens" -Port "8443" -HostName "gpo-lens.local" -Sni $true -Existing @{ Port = "8443"; Host = "gpo-lens.local"; Sni = $false }
            Should -Invoke Clear-WebBinding -Exactly 1
            Should -Invoke New-WebBinding -Exactly 1
        }

        It "preserves the SNI binding when it already matches" {
            Mock Clear-WebBinding { }
            Mock New-WebBinding { }
            Set-SniBinding -SiteName "gpo-lens" -Port "8443" -HostName "gpo-lens.local" -Sni $true -Existing @{ Port = "8443"; Host = "gpo-lens.local"; Sni = $true }
            Should -Invoke Clear-WebBinding -Exactly 0
            Should -Invoke New-WebBinding -Exactly 0
        }

        It "does nothing when Sni is `$false" {
            Mock Clear-WebBinding { }
            Mock New-WebBinding { }
            Set-SniBinding -SiteName "gpo-lens" -Port "8443" -HostName "" -Sni $false -Existing $null
            Should -Invoke Clear-WebBinding -Exactly 0
            Should -Invoke New-WebBinding -Exactly 0
        }
    }

    Describe "Set-TlsCertBinding" {
        It "targets the preserved concrete IP for non-SNI certificates" -ForEach @(
            @{IP="192.0.2.10"}, @{IP="[2001:db8::10]"}
        ) {
            Set-TlsCertBinding -CertThumbprint "ABCDEF123456" -Port "8443" -HostName "" -Sni $false -IPAddress $IP
            $global:NetshCalls | Where-Object { ($_ -join " ") -like "*add sslcert ipport=$([WildcardPattern]::Escape($IP))`:8443*" } | Should -Not -Be $null
            $global:NetshCalls | Where-Object { ($_ -join " ") -match 'ipport=0\.0\.0\.0' } | Should -Be $null
        }

        It "uses hostnameport for an SNI binding" {
            Set-TlsCertBinding -CertThumbprint "ABCDEF123456" -Port "8443" -HostName "gpo-lens.local" -Sni $true

            $delete = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'delete sslcert hostnameport=gpo-lens.local:8443' }
            $add    = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'add sslcert hostnameport=gpo-lens.local:8443' }
            $show   = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'show sslcert hostnameport=gpo-lens.local:8443' }
            $ipport = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'ipport=' }

            $delete | Should -Not -Be $null
            $add    | Should -Not -Be $null
            $show   | Should -Not -Be $null
            $ipport | Should -Be $null
        }

        It "uses ipport=0.0.0.0:Port for a non-SNI catch-all binding" {
            Set-TlsCertBinding -CertThumbprint "ABCDEF123456" -Port "8443" -HostName "" -Sni $false

            $delete = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'delete sslcert ipport=0\.0\.0\.0:8443' }
            $add    = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'add sslcert ipport=0\.0\.0\.0:8443' }
            $show   = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'show sslcert ipport=0\.0\.0\.0:8443' }
            $hn     = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'hostnameport=' }

            $delete | Should -Not -Be $null
            $add    | Should -Not -Be $null
            $show   | Should -Not -Be $null
            $hn     | Should -Be $null
        }

        It "leaves hostnameport cleanup to the endpoint transition after successful binding" {
            Set-TlsCertBinding -CertThumbprint "ABCDEF123456" -Port "8443" -HostName "gpo-lens.local" -Sni $false

            $deleteIp    = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'delete sslcert ipport=0\.0\.0\.0:8443' }
            $deleteHost  = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'delete sslcert hostnameport=gpo-lens.local:8443' }
            $add         = $global:NetshCalls | Where-Object { ($_ -join " ") -match 'add sslcert ipport=0\.0\.0\.0:8443' }

            $deleteIp   | Should -Not -Be $null
            $deleteHost | Should -Be $null
            $add        | Should -Not -Be $null
        }

        It "throws when netsh add returns a non-zero exit code" {
            $global:NetshExit = 1

            { Set-TlsCertBinding -CertThumbprint "ABCDEF123456" -Port "8443" -HostName "gpo-lens.local" -Sni $true } | Should -Throw
        }

        It "throws when the show sslcert verification does not contain the thumbprint" {
            $global:NetshCertHash = "111111111111"

            { Set-TlsCertBinding -CertThumbprint "ABCDEF123456" -Port "8443" -HostName "gpo-lens.local" -Sni $true } | Should -Throw
        }

        It "does not throw on a successful binding" {
            { Set-TlsCertBinding -CertThumbprint "ABCDEF123456" -Port "8443" -HostName "gpo-lens.local" -Sni $false } | Should -Not -Throw
        }
    }
}
