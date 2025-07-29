package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// RemediationRequest represents a request to fix a security issue
type RemediationRequest struct {
	ID int `json:"id"`
}

// RemediationResponse represents the result of a remediation attempt
type RemediationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	ID      int    `json:"id"`
}

// SecurityCheckInfo represents information about a security check
type SecurityCheckInfo struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Automated   bool   `json:"automated"`
	Description string `json:"description,omitempty"`
}

// PowerShell remediation mappings based on the Veeam Security & Compliance script
var remediationMappings = map[int]string{
	1:  "Remote Desktop Services (TermService) should be disabled",
	2:  "Remote Registry service (RemoteRegistry) should be disabled",
	3:  "Windows Remote Management (WinRM) service should be disabled",
	4:  "Windows Firewall should be enabled",
	5:  "WDigest credentials caching should be disabled",
	6:  "Web Proxy Auto-Discovery service (WinHttpAutoProxySvc) should be disabled",
	7:  "Deprecated versions of SSL and TLS should be disabled",
	8:  "Windows Script Host should be disabled",
	9:  "SMBv1 protocol should be disabled",
	10: "Link-Local Multicast Name Resolution (LLMNR) should be disabled",
	11: "SMBv3 signing and encryption should be enabled",
	19: "Unknown Linux servers should not be trusted automatically",
	21: "Host to proxy traffic encryption should be enabled for the Network transport mode",
	32: "PostgreSQL server should be configured with recommended settings",
	34: "Local Security Authority Server Service (LSASS) should be set to run as a protected process",
	35: "NetBIOS protocol should be disabled on all network interfaces",
}

// GetAllSecurityChecks returns information about all 35 Veeam security checks
func GetAllSecurityChecks() []SecurityCheckInfo {
	return []SecurityCheckInfo{
		// Automated checks (16 total)
		{ID: 1, Name: "Remote Desktop Services (TermService) should be disabled", Automated: true},
		{ID: 2, Name: "Remote Registry service (RemoteRegistry) should be disabled", Automated: true},
		{ID: 3, Name: "Windows Remote Management (WinRM) service should be disabled", Automated: true},
		{ID: 4, Name: "Windows Firewall should be enabled", Automated: true},
		{ID: 5, Name: "WDigest credentials caching should be disabled", Automated: true},
		{ID: 6, Name: "Web Proxy Auto-Discovery service (WinHttpAutoProxySvc) should be disabled", Automated: true},
		{ID: 7, Name: "Deprecated versions of SSL and TLS should be disabled", Automated: true},
		{ID: 8, Name: "Windows Script Host should be disabled", Automated: true},
		{ID: 9, Name: "SMBv1 protocol should be disabled", Automated: true},
		{ID: 10, Name: "Link-Local Multicast Name Resolution (LLMNR) should be disabled", Automated: true},
		{ID: 11, Name: "SMBv3 signing and encryption should be enabled", Automated: true},
		{ID: 19, Name: "Unknown Linux servers should not be trusted automatically", Automated: true},
		{ID: 21, Name: "Host to proxy traffic encryption should be enabled for the Network transport mode", Automated: true},
		{ID: 32, Name: "PostgreSQL server should be configured with recommended settings", Automated: true},
		{ID: 34, Name: "Local Security Authority Server Service (LSASS) should be set to run as a protected process", Automated: true},
		{ID: 35, Name: "NetBIOS protocol should be disabled on all network interfaces", Automated: true},

		// Manual checks (19 total)
		{ID: 12, Name: "MFA for the backup console should be enabled", Automated: false, Description: "Configure multi-factor authentication in Veeam console"},
		{ID: 13, Name: "Immutable or offline (air gapped) media should be used", Automated: false, Description: "Configure immutable backup repositories or offline storage"},
		{ID: 14, Name: "Password loss protection should be enabled", Automated: false, Description: "Enable password hints or recovery mechanisms"},
		{ID: 15, Name: "Backup server should not be a part of the production domain", Automated: false, Description: "Deploy backup server in separate, isolated domain"},
		{ID: 16, Name: "Email notifications should be enabled", Automated: false, Description: "Configure SMTP settings and email notifications"},
		{ID: 17, Name: "All backups should have at least one copy (the 3-2-1 backup rule)", Automated: false, Description: "Create backup copy jobs for offsite storage"},
		{ID: 18, Name: "Reverse incremental backup mode is deprecated and should be avoided", Automated: false, Description: "Migrate backup jobs to forward incremental mode"},
		{ID: 20, Name: "The configuration backup must not be stored on the backup server", Automated: false, Description: "Configure remote location for configuration backups"},
		{ID: 22, Name: "Hardened repositories should not be hosted in virtual machines", Automated: false, Description: "Deploy hardened repositories on physical servers"},
		{ID: 23, Name: "Network traffic encryption should be enabled in the backup network", Automated: false, Description: "Enable network-level encryption for backup traffic"},
		{ID: 24, Name: "Linux servers should have password-based authentication disabled", Automated: false, Description: "Configure SSH key-based authentication for Linux servers"},
		{ID: 25, Name: "Backup services should be running under the LocalSystem account", Automated: false, Description: "Configure Veeam services to run under LocalSystem"},
		{ID: 26, Name: "Configuration backup should be enabled and use encryption", Automated: false, Description: "Enable and encrypt configuration database backups"},
		{ID: 27, Name: "Credentials and encryption passwords should be rotated at least annually", Automated: false, Description: "Implement password rotation policy for backup credentials"},
		{ID: 28, Name: "Hardened repositories should have the SSH Server disabled", Automated: false, Description: "Disable SSH on hardened repository servers"},
		{ID: 29, Name: "S3 Object Lock in the Governance mode does not provide true immutability", Automated: false, Description: "Configure S3 Object Lock in Compliance mode instead"},
		{ID: 30, Name: "Backup jobs to cloud repositories should use encryption", Automated: false, Description: "Enable encryption for jobs targeting cloud storage"},
		{ID: 31, Name: "Latest product updates should be installed", Automated: false, Description: "Apply latest Veeam updates and patches"},
		{ID: 33, Name: "Hardened repositories should not be used as backup proxy servers", Automated: false, Description: "Separate hardened repositories from proxy server roles"},
	}
}

// HandleRemediation handles PowerShell-based security remediation requests
func HandleRemediation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RemediationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check if remediation ID is supported
	description, exists := remediationMappings[req.ID]
	if !exists {
		response := RemediationResponse{
			Success: false,
			Message: "Remediation ID not supported or requires manual intervention",
			ID:      req.ID,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Generate PowerShell script for the specific remediation
	script := generateRemediationScript(req.ID)
	if script == "" {
		response := RemediationResponse{
			Success: false,
			Message: "Failed to generate remediation script",
			ID:      req.ID,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}

	// Return the script to be executed by the client
	response := RemediationResponse{
		Success: true,
		Message: fmt.Sprintf("Remediation script generated for: %s. Execute the returned PowerShell script on the Veeam server.", description),
		ID:      req.ID,
	}

	// Add the script as a custom field
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-PowerShell-Script", script)
	json.NewEncoder(w).Encode(response)
}

// generateRemediationScript generates the PowerShell script for a specific remediation
func generateRemediationScript(id int) string {
	switch id {
	case 1:
		return `
# Disable Remote Desktop Services (WARNING: This will disable RDP access!)
try {
    Set-Service "TermService" -StartupType "Disabled" -ErrorAction Stop
    Write-Output "✓ Remote Desktop Services disabled successfully (Reboot required)"
} catch {
    Write-Error "✗ Failed to disable Remote Desktop Services: $_"
}`

	case 2:
		return `
# Disable Remote Registry service
try {
    Stop-Service "RemoteRegistry" -Force -ErrorAction Stop
    Set-Service "RemoteRegistry" -StartupType "Disabled" -ErrorAction Stop
    Write-Output "✓ Remote Registry service disabled successfully"
} catch {
    Write-Error "✗ Failed to disable Remote Registry service: $_"
}`

	case 3:
		return `
# Disable Windows Remote Management (WinRM) service
try {
    Set-Service "WinRM" -StartupType "Disabled" -ErrorAction Stop
    Write-Output "✓ Windows Remote Management disabled successfully (Reboot required)"
} catch {
    Write-Error "✗ Failed to disable Windows Remote Management: $_"
}`

	case 4:
		return `
# Enable Windows Firewall
try {
    Set-NetFirewallProfile -All -Enabled "True" -ErrorAction Stop
    Write-Output "✓ Windows Firewall enabled successfully"
} catch {
    Write-Error "✗ Failed to enable Windows Firewall: $_"
}`

	case 5:
		return `
# Disable WDigest credentials caching
try {
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction Ignore
    Write-Output "✓ WDigest credentials caching disabled successfully (Reboot required)"
} catch {
    Write-Error "✗ Failed to disable WDigest credentials caching: $_"
}`

	case 6:
		return `
# Disable Web Proxy Auto-Discovery service
try {
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc -Name Start -Value 4 -ErrorAction Stop
    Write-Output "✓ Web Proxy Auto-Discovery service disabled successfully (Reboot required)"
} catch {
    Write-Error "✗ Failed to disable Web Proxy Auto-Discovery service: $_"
}`

	case 7:
		return `
# Disable deprecated SSL/TLS versions
try {
    # SSL 2.0
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWORD' -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWORD' -Force -ErrorAction SilentlyContinue | Out-Null
    
    # SSL 3.0
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWORD' -Force -ErrorAction SilentlyContinue | Out-Null
    
    # TLS 1.0
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWORD' -Force -ErrorAction SilentlyContinue | Out-Null
    
    # TLS 1.1
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWORD' -Force -ErrorAction SilentlyContinue | Out-Null
    
    Write-Output "✓ Deprecated SSL/TLS versions disabled successfully (Reboot required)"
} catch {
    Write-Error "✗ Failed to disable deprecated SSL/TLS versions: $_"
}`

	case 8:
		return `
# Disable Windows Script Host
try {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -PropertyType "DWORD" -Value "0" -Force -ErrorAction Stop | Out-Null
    Write-Output "✓ Windows Script Host disabled successfully"
} catch {
    Write-Error "✗ Failed to disable Windows Script Host: $_"
}`

	case 9:
		return `
# Disable SMBv1 protocol
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Write-Output "✓ SMBv1 protocol disabled successfully (Reboot required)"
} catch {
    Write-Error "✗ Failed to disable SMBv1 protocol: $_"
}`

	case 10:
		return `
# Disable Link-Local Multicast Name Resolution (LLMNR)
try {
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT" -Name "DNSClient" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMultiCast" -Value "0" -PropertyType "DWORD" -Force -ErrorAction Stop | Out-Null
    Write-Output "✓ LLMNR disabled successfully (Reboot required)"
} catch {
    Write-Error "✗ Failed to disable LLMNR: $_"
}`

	case 11:
		return `
# Enable SMBv3 signing and encryption
try {
    Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction Stop
    Set-SmbServerConfiguration -EnableSecuritySignature $true -Force -ErrorAction Stop
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop
    Write-Output "✓ SMBv3 signing and encryption enabled successfully"
} catch {
    Write-Error "✗ Failed to enable SMBv3 signing and encryption: $_"
}`

	case 19:
		return `
# Set unknown Linux servers trust settings
try {
    Import-Module Veeam.Backup.PowerShell -DisableNameChecking
    Set-VBRLinuxTrustedHostPolicy -Type "KnownHosts"
    Write-Output "✓ Linux trusted host policy configured successfully"
} catch {
    Write-Error "✗ Failed to configure Linux trusted host policy: $_"
}`

	case 21:
		return `
# Enable host to proxy traffic encryption in Network transport mode
try {
    Import-Module Veeam.Backup.PowerShell -DisableNameChecking
    Get-VBRViProxy | Where-Object {$_.UseSSL -ne $True} | Set-VBRViProxy -EnableHostToProxyEncryption -ErrorAction Stop
    Write-Output "✓ Host to proxy traffic encryption enabled successfully"
} catch {
    Write-Error "✗ Failed to enable host to proxy traffic encryption: $_"
}`

	case 32:
		return `
# Configure recommended PostgreSQL settings
try {
    Import-Module Veeam.Backup.PowerShell -DisableNameChecking
    Set-VBRPSQLDatabaseServerLimits -WA 0
    Write-Output "✓ PostgreSQL settings configured successfully (Reboot required)"
} catch {
    Write-Error "✗ Failed to configure PostgreSQL settings: $_"
}`

	case 34:
		return `
# Make LSASS run as a protected process
try {
    if ($env:firmware_type -eq "UEFI") { 
        Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -ErrorAction Stop
    } else { 
        Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 2 -ErrorAction Stop
    }
    Write-Output "✓ LSASS configured to run as protected process successfully"
} catch {
    Write-Error "✗ Failed to configure LSASS as protected process: $_"
}`

	case 35:
		return `
# Disable NetBIOS on all network interfaces
try {
    $interfaces = Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | Select -ExpandProperty PSChildName
    Foreach($interface in $interfaces) { 
        Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$interface" -Name "NetbiosOptions" -Value 2 -ErrorAction Stop
    }
    Write-Output "✓ NetBIOS disabled on all network interfaces successfully"
} catch {
    Write-Error "✗ Failed to disable NetBIOS: $_"
}`

	default:
		return ""
	}
}

// HandleSecurityChecksInfo provides information about all security checks
func HandleSecurityChecksInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	checks := GetAllSecurityChecks()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(checks); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// GetAvailableRemediations returns a list of all available remediation actions
func GetAvailableRemediations() map[int]string {
	return remediationMappings
}
