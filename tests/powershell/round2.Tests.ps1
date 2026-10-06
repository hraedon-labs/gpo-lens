# glv2's endpoint and concrete-IP helper probes, exercised through the helper
# used by the installer so preserved thumbprints still bind a changed endpoint.
Describe "Round 2 IIS upgrade regressions" {
    BeforeAll {
        . "$PSScriptRoot/../../scripts/install-windows.ps1"
        function Clear-WebBinding { }
        function New-WebBinding { param($Name, $Protocol, $Port, $HostHeader, $SslFlags, $IPAddress) }
        function Get-WebBinding { }
        function netsh { }
    }
    BeforeEach {
        Mock Clear-WebBinding { }
        Mock New-WebBinding { }
        Mock Set-TlsCertBinding { }
        Mock netsh { }
    }
    It "rebinds the preserved certificate for an explicit port change" {
        $old = @{Port="8443"; Host="lens.lab.example.com"; Sni=$false; Cert="ABCDEF"}
        Set-IisEndpoint -SiteName gpo-lens -Port 443 -HostName $old.Host -Sni $false -CertThumbprint $old.Cert -Existing $old
        Should -Invoke Set-TlsCertBinding -Exactly 1 -ParameterFilter { $Port -eq "443" -and $CertThumbprint -eq "ABCDEF" }
        Should -Invoke New-WebBinding -Exactly 1 -ParameterFilter { $Port -eq "443" -and $SslFlags -eq 0 }
    }
    It "rebinds a preserved certificate for an SNI hostname change" {
        $old = @{Port="8443"; Host="old.lab.example.com"; Sni=$true; Cert="ABCDEF"}
        Set-IisEndpoint -SiteName gpo-lens -Port 8443 -HostName new.lab.example.com -Sni $true -CertThumbprint $old.Cert -Existing $old
        Should -Invoke Set-TlsCertBinding -Exactly 1 -ParameterFilter { $HostName -eq "new.lab.example.com" -and $Sni }
        Should -Invoke New-WebBinding -Exactly 1 -ParameterFilter { $SslFlags -eq 1 }
    }
    It "explicitly disables SNI at the same host and port" {
        $old = @{Port="8443"; Host="lens.lab.example.com"; Sni=$true; Cert="ABCDEF"}
        Test-BindingChanged -Existing $old -EffectivePort 8443 -EffectiveHost $old.Host -EffectiveSni $false | Should -BeTrue
        Set-IisEndpoint -SiteName gpo-lens -Port 8443 -HostName $old.Host -Sni $false -CertThumbprint $old.Cert -Existing $old
        Should -Invoke New-WebBinding -Exactly 1 -ParameterFilter { $SslFlags -eq 0 }
        Should -Invoke Set-TlsCertBinding -Exactly 1 -ParameterFilter { -not $Sni }
    }
    It "preserves a no-override endpoint for both anonymous and Windows Auth upgrades" -ForEach @(@{Sni=$false}, @{Sni=$true}) {
        $old = @{Port="9443"; Host="lens.lab.example.com"; Sni=$Sni; Cert="ABCDEF"}
        Set-IisEndpoint -SiteName gpo-lens -Port $old.Port -HostName $old.Host -Sni $old.Sni -CertThumbprint $old.Cert -Existing $old
        Should -Invoke Clear-WebBinding -Exactly 0
        Should -Invoke New-WebBinding -Exactly 0
        Should -Invoke Set-TlsCertBinding -Exactly 0
        Should -Invoke netsh -Exactly 0
    }
    It "does not delete the old TLS endpoint when new certificate binding fails" {
        Mock Set-TlsCertBinding { throw "synthetic bind failure" }
        $old = @{Port="8443"; Host="old.lab.example.com"; Sni=$true; Cert="ABCDEF"}
        { Set-IisEndpoint -SiteName gpo-lens -Port 9443 -HostName $old.Host -Sni $true -CertThumbprint $old.Cert -Existing $old } | Should -Throw "*synthetic bind failure*"
        Should -Invoke netsh -Exactly 0
        Should -Invoke New-WebBinding -Exactly 1 -ParameterFilter { $Port -eq "8443" -and $SslFlags -eq 1 }
    }
    It "restores a concrete-IP binding after failed replacement without widening scope" {
        Mock Set-TlsCertBinding { throw "synthetic bind failure" }
        $old = @{IP="192.0.2.10"; Port="8443"; Host=""; Sni=$false; Cert="ABCDEF"}
        { Set-IisEndpoint -SiteName gpo-lens -Port 9443 -HostName "" -Sni $false -CertThumbprint $old.Cert -Existing $old } | Should -Throw
        Should -Invoke New-WebBinding -Exactly 1 -ParameterFilter { $Port -eq "9443" -and $IPAddress -eq "192.0.2.10" }
        Should -Invoke New-WebBinding -Exactly 1 -ParameterFilter { $Port -eq "8443" -and $IPAddress -eq "192.0.2.10" }
    }
    It "preserves a concrete-IP listener on a successful port change" {
        $old = @{IP="[2001:db8::10]"; Port="8443"; Host=""; Sni=$false; Cert="ABCDEF"}
        Set-IisEndpoint -SiteName gpo-lens -Port 9443 -HostName "" -Sni $false -CertThumbprint $old.Cert -Existing $old
        Should -Invoke New-WebBinding -Exactly 1 -ParameterFilter { $IPAddress -eq "2001:db8::10" }
        Should -Invoke Set-TlsCertBinding -Exactly 1 -ParameterFilter { $IPAddress -eq "[2001:db8::10]" }
    }
    It "restores the old certificate when certificate-only rotation fails" {
        $script:CertCalls = @()
        Mock Set-TlsCertBinding {
            $script:CertCalls += $CertThumbprint
            if ($CertThumbprint -eq "BADBAD") { throw "synthetic rotation failure" }
        }
        $old = @{IP="192.0.2.10"; Port="8443"; Host=""; Sni=$false; Cert="ABCDEF"}
        { Set-IisEndpoint -SiteName gpo-lens -Port 8443 -HostName "" -Sni $false -CertThumbprint BADBAD -Existing $old } | Should -Throw "*synthetic rotation failure*"
        ($script:CertCalls -join ",") | Should -Be "BADBAD,ABCDEF"
        Should -Invoke Clear-WebBinding -Exactly 0
        Should -Invoke Set-TlsCertBinding -Exactly 1 -ParameterFilter { $CertThumbprint -eq "ABCDEF" -and $IPAddress -eq "192.0.2.10" }
    }
    It "keeps the healthy old certificate untouched when a new target bind fails" {
        Mock Set-TlsCertBinding { if ($Port -eq "9443") { throw "synthetic bind failure" } }
        $old = @{IP="192.0.2.10"; Port="8443"; Host=""; Sni=$false; Cert="ABCDEF"}
        { Set-IisEndpoint -SiteName gpo-lens -Port 9443 -HostName "" -Sni $false -CertThumbprint $old.Cert -Existing $old } | Should -Throw
        Should -Invoke Set-TlsCertBinding -Exactly 0 -ParameterFilter { $Port -eq "8443" }
        Should -Invoke New-WebBinding -Exactly 1 -ParameterFilter { $Port -eq "8443" }
    }
    It "keeps the old certificate untouched when binding creation fails before TLS" {
        Mock New-WebBinding { if ($Port -eq "9443") { throw "synthetic IIS failure" } }
        $old = @{IP="192.0.2.10"; Port="8443"; Host=""; Sni=$false; Cert="ABCDEF"}
        { Set-IisEndpoint -SiteName gpo-lens -Port 9443 -HostName "" -Sni $false -CertThumbprint $old.Cert -Existing $old } | Should -Throw
        Should -Invoke Set-TlsCertBinding -Exactly 0
        Should -Invoke New-WebBinding -Exactly 1 -ParameterFilter { $Port -eq "8443" }
    }
    It "deletes only the old SNI endpoint after the new certificate succeeds" {
        $script:Bound = $false
        Mock Set-TlsCertBinding { $script:Bound = $true }
        Mock netsh { $script:Bound | Should -BeTrue }
        $old = @{Port="8443"; Host="old.lab.example.com"; Sni=$true; Cert="ABCDEF"}
        Set-IisEndpoint -SiteName gpo-lens -Port 9443 -HostName $old.Host -Sni $true -CertThumbprint $old.Cert -Existing $old
        Should -Invoke netsh -Exactly 1 -ParameterFilter { ($args -join " ") -eq "http delete sslcert hostnameport=old.lab.example.com:8443" }
    }
    It "derives concrete IPv4 and IPv6 authorities without accepting wildcard addresses" {
        Mock Get-WebBinding { @(
            [pscustomobject]@{protocol="https"; bindingInformation="192.0.2.10:8443:"},
            [pscustomobject]@{protocol="https"; bindingInformation="[2001:db8::10]:9443:"},
            [pscustomobject]@{protocol="https"; bindingInformation="0.0.0.0:443:"},
            [pscustomobject]@{protocol="https"; bindingInformation="[::]:443:"}
        ) }
        $policy = (Get-IisAllowedHosts -SiteName gpo-lens -MachineFqdn lens.lab.example.com -MachineName LENS).Split(",")
        $policy | Should -Contain "192.0.2.10"
        $policy | Should -Contain "192.0.2.10:8443"
        $policy | Should -Contain "[2001:db8::10]"
        $policy | Should -Contain "[2001:db8::10]:9443"
        $policy | Should -Not -Contain "0.0.0.0"
        $policy | Should -Not -Contain "[::]"
    }
    It "returns the concrete IP from the binding parser" {
        (Parse-BindingInformation "192.0.2.10:8443:").IP | Should -Be "192.0.2.10"
        (Parse-BindingInformation "[2001:db8::10]:9443:").IP | Should -Be "[2001:db8::10]"
    }
}
