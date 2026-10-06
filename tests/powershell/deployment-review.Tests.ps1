Describe "Daybreak deployment regressions" {
    BeforeAll {
        $script:Installer = "$PSScriptRoot/../../scripts/install-windows.ps1"
        . $script:Installer
        function Get-WebConfigurationProperty { }
        function Get-NetFirewallRule { }
        function New-NetFirewallRule { param($DisplayName, $Direction, $Action, $Protocol, $LocalPort, $Profile, $RemoteAddress) }
        function Get-WebBinding { }
        function Set-WebConfigurationProperty { }
    }

    It "refuses a fresh anonymous network site" {
        { Test-IisAccessChoice -ExistingSite $false -WindowsAuth $false -AllowAnonymousNetworkAccess $false } |
            Should -Throw "*AllowAnonymousNetworkAccess*"
    }
    It "allows a fresh Windows Auth site" {
        { Test-IisAccessChoice -ExistingSite $false -WindowsAuth $true -AllowAnonymousNetworkAccess $false } |
            Should -Not -Throw
    }
    It "allows the explicit anonymous opt-out with a prominent consequence warning" {
        Mock Write-Warning { }
        Mock Set-WebConfigurationProperty { }
        Test-IisAccessChoice -ExistingSite $false -WindowsAuth $false -AllowAnonymousNetworkAccess $true
        Should -Invoke Write-Warning -Exactly 1 -ParameterFilter { $Message -match "ANONYMOUS.*ingest.*delete.*triage" }
    }
    It "warns and continues an anonymous upgrade without changing authentication" {
        Mock Get-WebConfigurationProperty { [pscustomobject]@{ Value = $true } }
        Mock Write-Warning { }
        { Test-IisAccessChoice -ExistingSite $true -WindowsAuth $false -AllowAnonymousNetworkAccess $false -EnableAuthCommand "powershell -File install-windows.ps1 -ConfigureIIS -WindowsAuth" } |
            Should -Not -Throw
        Should -Invoke Write-Warning -Exactly 1 -ParameterFilter { $Message -match "ANONYMOUS.*preserv" -and $Message -match "-ConfigureIIS -WindowsAuth" }
    }
    It "does not warn on a protected upgrade" {
        Mock Get-WebConfigurationProperty { [pscustomobject]@{ Value = $false } }
        Mock Write-Warning { }
        Test-IisAccessChoice -ExistingSite $true -WindowsAuth $false -AllowAnonymousNetworkAccess $false
        Should -Invoke Write-Warning -Exactly 0
    }
    It "does not fail an upgrade if auth inspection is unavailable" {
        Mock Get-WebConfigurationProperty { throw "module locked" }
        Mock Write-Warning { }
        { Test-IisAccessChoice -ExistingSite $true -WindowsAuth $false -AllowAnonymousNetworkAccess $false } | Should -Not -Throw
        Should -Invoke Write-Warning -Exactly 1
    }
    It "checks access before stopping the pool or installing" {
        $source = Get-Content $script:Installer -Raw
        $source.IndexOf("Test-IisAccessChoice -ExistingSite") | Should -BeGreaterThan 0
        $source.IndexOf("Test-IisAccessChoice -ExistingSite") | Should -BeLessThan $source.IndexOf('stop apppool /apppool.name:')
        $source.IndexOf("Test-IisAccessChoice -ExistingSite") | Should -BeLessThan $source.IndexOf('pip install --require-hashes')
    }
    It "only changes IIS authentication when WindowsAuth is explicitly requested" {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Installer, [ref]$null, [ref]$null)
        $setters = $ast.FindAll({ param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq "Set-WebConfigurationProperty"
        }, $true)
        @($setters).Count | Should -Be 2
        foreach ($setter in $setters) {
            $parent = $setter.Parent
            while ($parent -and $parent -isnot [System.Management.Automation.Language.IfStatementAst]) { $parent = $parent.Parent }
            $parent.Clauses[0].Item1.Extent.Text | Should -Be '$WindowsAuth'
        }
    }
    It "wires host migration into both configured and plain upgrades" {
        $source = Get-Content $script:Installer -Raw
        ([regex]::Matches($source, 'Set-IisAllowedHosts -WebConfigPath')).Count | Should -Be 2
        $source | Should -Match 'Set-IisFirewallRule -Port \$effPort -RemoteAddress \$FirewallRemoteAddress'
    }
    It "scopes a new firewall rule to LocalSubnet by default" {
        Mock Get-NetFirewallRule { $null }
        Mock New-NetFirewallRule { }
        Set-IisFirewallRule -Port "8443"
        Should -Invoke New-NetFirewallRule -Exactly 1 -ParameterFilter { $RemoteAddress -eq "LocalSubnet" -and ($Profile -join ",") -eq "Domain,Private" }
    }
    It "uses the operator's explicit firewall remote addresses" {
        Mock Get-NetFirewallRule { $null }
        Mock New-NetFirewallRule { }
        Set-IisFirewallRule -Port "8443" -RemoteAddress @("192.0.2.0/24")
        Should -Invoke New-NetFirewallRule -Exactly 1 -ParameterFilter { $RemoteAddress -eq "192.0.2.0/24" }
    }
    It "preserves an existing firewall rule during upgrade" {
        Mock Get-NetFirewallRule { [pscustomobject]@{ DisplayName = "existing" } }
        Mock New-NetFirewallRule { }
        Set-IisFirewallRule -Port "8443"
        Should -Invoke New-NetFirewallRule -Exactly 0
    }
    It "derives all HTTPS hostnames plus machine names and excludes HTTP" {
        Mock Get-WebBinding {
            @([pscustomobject]@{ protocol="https"; bindingInformation="*:8443:Portal.LAB.example.com" },
              [pscustomobject]@{ protocol="https"; bindingInformation="*:443:other.lab.example.com" },
              [pscustomobject]@{ protocol="http"; bindingInformation="*:80:ignore.lab.example.com" })
        }
        $hosts = Get-IisAllowedHosts -SiteName "gpo-lens" -MachineFqdn "lens.lab.example.com" -MachineName "LENS"
        $hosts.Split(",") | Should -Contain "portal.lab.example.com:8443"
        $hosts.Split(",") | Should -Contain "other.lab.example.com:443"
        $hosts.Split(",") | Should -Contain "lens.lab.example.com:8443"
        $hosts.Split(",") | Should -Contain "lens:443"
        $hosts | Should -Not -Match "ignore"
    }
    It "uses machine names for a catch-all HTTPS binding" {
        Mock Get-WebBinding { @([pscustomobject]@{ protocol="https"; bindingInformation="[::]:8443:" }) }
        $hosts = Get-IisAllowedHosts -SiteName "gpo-lens" -MachineFqdn "lens.lab.example.com" -MachineName "LENS"
        $hosts.Split(",") | Should -Contain "lens.lab.example.com:8443"
        $hosts.Split(",") | Should -Contain "lens:8443"
    }
    It "merges missing allowed hosts preserving every existing variable and config" {
        $path = Join-Path $TestDrive "web.config"
        $xml = '<configuration><system.webServer><httpPlatform processPath="custom"><environmentVariables><environmentVariable name="GPO_LENS_API_KEY" value="synthetic"/><environmentVariable name="OTHER" value="keep"/></environmentVariables></httpPlatform></system.webServer></configuration>'
        [IO.File]::WriteAllText($path, $xml)
        Set-IisAllowedHosts -WebConfigPath $path -AllowedHosts "lens.lab.example.com:8443,lens:8443"
        $first = [IO.File]::ReadAllText($path)
        Set-IisAllowedHosts -WebConfigPath $path -AllowedHosts "different.lab.example.com"
        [IO.File]::ReadAllText($path) | Should -BeExactly $first
        $doc = [xml]$first
        $doc.configuration.'system.webServer'.httpPlatform.processPath | Should -Be "custom"
        $vars = $doc.configuration.'system.webServer'.httpPlatform.environmentVariables.environmentVariable
        ($vars | Where-Object name -eq "OTHER").value | Should -Be "keep"
        ($vars | Where-Object name -eq "GPO_LENS_API_KEY").value | Should -Be "synthetic"
        ($vars | Where-Object name -eq "GPO_LENS_ALLOWED_HOSTS").value | Should -Be "lens.lab.example.com:8443,lens:8443"
    }
    It "keeps an existing host policy byte-for-byte including case and empty value" {
        foreach ($value in @("CUSTOM.lab.example.com", "")) {
            $path = Join-Path $TestDrive "existing.config"
            $xml = '<configuration><system.webServer><httpPlatform><environmentVariables><environmentVariable name="GPO_LENS_ALLOWED_HOSTS" value="' + $value + '"/></environmentVariables></httpPlatform></system.webServer></configuration>'
            [IO.File]::WriteAllText($path, $xml)
            Set-IisAllowedHosts -WebConfigPath $path -AllowedHosts "lens.lab.example.com:8443"
            [IO.File]::ReadAllText($path) | Should -BeExactly $xml
        }
    }
    It "merges the fresh template and creates a missing variables block" {
        foreach ($content in @([IO.File]::ReadAllText("$PSScriptRoot/../../deploy/iis/web.config"), '<configuration><system.webServer><httpPlatform/></system.webServer></configuration>')) {
            $path = Join-Path $TestDrive "fresh.config"
            [IO.File]::WriteAllText($path, $content)
            Set-IisAllowedHosts -WebConfigPath $path -AllowedHosts "lens.lab.example.com:8443"
            ([xml][IO.File]::ReadAllText($path)).SelectSingleNode('//environmentVariable[@name="GPO_LENS_ALLOWED_HOSTS"]').value | Should -Be "lens.lab.example.com:8443"
        }
    }
}
