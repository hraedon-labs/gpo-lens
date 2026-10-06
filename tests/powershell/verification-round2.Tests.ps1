Describe "Daybreak Blue round-two IIS probes" {
    BeforeAll {
        . "$PSScriptRoot/../../scripts/install-windows.ps1"
        function Get-WebBinding { }
        function Clear-WebBinding { }
        function New-WebBinding { param($Name, $Protocol, $Port, $HostHeader, $SslFlags, $IPAddress) }
        function Set-WebBinding { param($Name, $BindingInformation, $PropertyName, $Value) }
        function Remove-WebBinding { param($Name, $Protocol, $BindingInformation) }
        function netsh { }
    }
    BeforeEach {
        Mock Get-WebBinding { }
        Mock New-WebBinding { }
        Mock Set-WebBinding { }
        Mock Remove-WebBinding { }
        Mock Set-TlsCertBinding { }
        Mock netsh { }
    }

    It "detects explicit SNI disable on an unchanged host and port" {
        $existing = @{ Port="8443"; Host="lens.example"; Sni=$true; Cert="ABCDEF" }
        Test-BindingChanged -Existing $existing -EffectivePort "8443" -EffectiveHost "lens.example" -EffectiveSni $false | Should -BeTrue
        Set-SniBinding -SiteName "gpo-lens" -Port "8443" -HostName "lens.example" -Sni $false -Existing $existing
        Should -Invoke Set-WebBinding -Exactly 1 -ParameterFilter { $PropertyName -eq "sslFlags" -and $Value -eq 0 }
    }

    It "rebinds a preserved certificate on a changed endpoint: <Port>, <HostName>, <Sni>" -TestCases @(
        @{ Port="443"; HostName="lens.example"; Sni=$true },
        @{ Port="8443"; HostName="new.example"; Sni=$true },
        @{ Port="8443"; HostName="lens.example"; Sni=$false }
    ) {
        param($Port, $HostName, $Sni)
        $existing = @{ Port="8443"; Host="lens.example"; Sni=$true; Cert="ABCDEF" }
        $script:ExpectedPort = $Port
        $script:ExpectedHost = $HostName
        $script:ExpectedSni = $Sni
        Set-IisTlsEndpoint -SiteName "gpo-lens" -Port $Port -HostName $HostName -Sni $Sni -CertThumbprint "ABCDEF" -Existing $existing
        Should -Invoke Set-TlsCertBinding -Exactly 1 -ParameterFilter {
            $CertThumbprint -eq "ABCDEF" -and $Port -eq $script:ExpectedPort -and $HostName -eq $script:ExpectedHost -and $Sni -eq $script:ExpectedSni
        }
    }

    It "preserves the endpoint and certificate on a plain upgrade: SNI=<Sni>" -TestCases @(@{Sni=$true}, @{Sni=$false}) {
        param($Sni)
        $existing = @{ Port="8443"; Host="lens.example"; Sni=$Sni; Cert="ABCDEF" }
        Set-IisTlsEndpoint -SiteName "gpo-lens" -Port "8443" -HostName "lens.example" -Sni $Sni -CertThumbprint "ABCDEF" -Existing $existing
        Should -Invoke New-WebBinding -Exactly 0
        Should -Invoke Set-WebBinding -Exactly 0
        Should -Invoke Remove-WebBinding -Exactly 0
        Should -Invoke Set-TlsCertBinding -Exactly 0
        Should -Invoke netsh -Exactly 0
    }

    It "leaves the old endpoint until the new certificate is verified" {
        Mock Set-TlsCertBinding { throw "synthetic binding failure" }
        $existing = @{ Port="8443"; Host="lens.example"; Sni=$true; Cert="ABCDEF" }
        { Set-IisTlsEndpoint -SiteName "gpo-lens" -Port "443" -HostName "lens.example" -Sni $true -CertThumbprint "ABCDEF" -Existing $existing } | Should -Throw "*synthetic binding failure*"
        Should -Invoke Remove-WebBinding -Exactly 0 -ParameterFilter { $BindingInformation -eq "*:8443:lens.example" }
        Should -Invoke netsh -Exactly 0
    }

    It "removes the old endpoint only after a successful certificate bind" {
        $script:Sequence = @()
        Mock Set-TlsCertBinding { $script:Sequence += "bind" }
        Mock netsh { $script:Sequence += "remove-cert" }
        Mock Remove-WebBinding { $script:Sequence += "remove-binding" }
        $existing = @{ Port="8443"; Host="lens.example"; Sni=$true; Cert="ABCDEF" }
        Set-IisTlsEndpoint -SiteName "gpo-lens" -Port "443" -HostName "lens.example" -Sni $true -CertThumbprint "ABCDEF" -Existing $existing
        $script:Sequence[0] | Should -Be "bind"
        $script:Sequence | Should -Contain "remove-cert"
        $script:Sequence | Should -Contain "remove-binding"
    }

    It "keeps concrete IP authorities in the generated policy" {
        Mock Get-WebBinding { @(
            [pscustomobject]@{protocol="https"; bindingInformation="192.0.2.10:8443:"},
            [pscustomobject]@{protocol="https"; bindingInformation="[2001:db8::10]:9443:"},
            [pscustomobject]@{protocol="https"; bindingInformation="*:443:"},
            [pscustomobject]@{protocol="https"; bindingInformation="[::]:443:"}
        ) }
        $hosts = (Get-IisAllowedHosts -SiteName "gpo-lens" -MachineFqdn "lens.lab.example.com" -MachineName "LENS").Split(",")
        foreach ($authority in @("192.0.2.10", "192.0.2.10:8443", "[2001:db8::10]", "[2001:db8::10]:9443", "lens:443")) {
            $hosts | Should -Contain $authority
        }
        $hosts | Should -Not -Contain "*"
        $hosts | Should -Not -Contain "[::]"
    }
    It 'creates HTTPS when an existing site has no usable HTTPS binding' {
        Set-IisTlsEndpoint -SiteName lens -Port 8443 -HostName lens.example -Sni $false -CertThumbprint ABCDEF -Existing $null
        Should -Invoke New-WebBinding -Exactly 1
    }
    It 'preserves a shared non-SNI endpoint when one site switches to SNI' {
        Mock Get-WebBinding { @([pscustomobject]@{protocol='https';bindingInformation='*:8443:other.example';sslFlags=0}) }
        $existing=@{Port='8443';Host='lens.example';Sni=$false;Cert='ABCDEF'}
        Set-IisTlsEndpoint -SiteName lens -Port 8443 -HostName lens.example -Sni $true -CertThumbprint ABCDEF -Existing $existing
        Should -Invoke netsh -Exactly 0
    }

    It "does not recreate the HTTPS binding of a fresh site: SNI=<Sni>" -TestCases @(@{Sni=$true}, @{Sni=$false}) {
        param($Sni)
        Set-IisTlsEndpoint -SiteName lens -Port 8443 -HostName lens.example -Sni $Sni -CertThumbprint ABCDEF -Existing $null -BindingAlreadyCreated $true
        Should -Invoke New-WebBinding -Exactly 0
        Should -Invoke Set-WebBinding -Exactly ([int]$Sni)
        Should -Invoke Set-TlsCertBinding -Exactly 1
    }
}
