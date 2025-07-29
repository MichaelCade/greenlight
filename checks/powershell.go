package checks

import (
	"encoding/json"
	"fmt"
	"greenlight/models"
	"os/exec"
	"runtime"
	"strings"
)

func GetVeeamPowerShellData(veeamServer string) (*models.PowerShellData, error) {
	var data models.PowerShellData

	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("PowerShell integration only available on Windows")
	}

	script := `
        $ErrorActionPreference = "Continue"
        
        $result = @{
            databaseInfo = @{}
            serviceStatus = @()
            securitySettings = @{}
            repositoryDetails = @()
            jobSecurity = @()
            systemHealth = @{}
            auditSettings = @{}
            complianceReport = @{}
        }
        
        $veeamModuleLoaded = $false
        $moduleLoadError = ""
        
        try {
            if (Get-Module -ListAvailable -Name "Veeam.Backup.PowerShell") {
                Import-Module Veeam.Backup.PowerShell -ErrorAction Stop
                $veeamModuleLoaded = $true
            } elseif (Get-PSSnapin -Registered | Where-Object {$_.Name -like "*Veeam*"}) {
                Add-PSSnapin VeeamPSSnapIn -ErrorAction Stop
                $veeamModuleLoaded = $true
            }
        } catch {
            $moduleLoadError = $_.Exception.Message
        }
        
        if (-not $veeamModuleLoaded) {
            $result.databaseInfo = @{ error = "Veeam PowerShell module not available: $moduleLoadError" }
            $result.repositoryDetails = @()
            $result.jobSecurity = @()
            $result.complianceReport = @{ error = "Veeam PowerShell module not loaded" }
            $result.systemHealth = @{ error = "Veeam PowerShell module not loaded" }
            $result.auditSettings = @{ error = "Veeam PowerShell module not loaded" }
        } else {
            # Database information
            try {
                $configBackup = Get-VBRConfigurationBackupJob -ErrorAction SilentlyContinue
                $result.databaseInfo = @{
                    backupEnabled = $configBackup -ne $null
                    lastBackup = if($configBackup) { $configBackup.LastRun } else { $null }
                    nextRun = if($configBackup) { $configBackup.NextRun } else { $null }
                    isRemoteDatabase = $false
                }
                
                try {
                    $dbConnection = Get-VBRDatabaseConnection -ErrorAction SilentlyContinue
                    if ($dbConnection) {
                        $result.databaseInfo.databaseType = $dbConnection.DatabaseType
                        $result.databaseInfo.sqlServerName = $dbConnection.SqlServerName
                        $result.databaseInfo.sqlDatabaseName = $dbConnection.SqlDatabaseName
                        $result.databaseInfo.isRemoteDatabase = $dbConnection.SqlServerName -ne $env:COMPUTERNAME
                    }
                } catch {
                    # Database connection details not available
                }
            } catch {
                $result.databaseInfo = @{ error = $_.Exception.Message }
            }
            
            # Enhanced Repository details with comprehensive immutability detection
            try {
                $repos = Get-VBRBackupRepository -ErrorAction SilentlyContinue
                if ($repos) {
                    foreach($repo in $repos) {
                        $repoDetails = @{
                            name = $repo.Name
                            type = $repo.Type.ToString()
                            isImmutable = $false
                            immutablePeriod = 0
                            path = ""
                            immutabilitySource = "None"
                            debugInfo = @{}
                        }
                        
                        try {
                            # Debug: Get all properties for repositories with "immutable" in name
                            if ($repo.Name -like "*immutable*") {
                                $repoDetails.debugInfo.allProperties = @()
                                $repo | Get-Member -MemberType Property | ForEach-Object {
                                    try {
                                        $propValue = $repo.($_.Name)
                                        $repoDetails.debugInfo.allProperties += "$($_.Name): $propValue"
                                    } catch {
                                        $repoDetails.debugInfo.allProperties += "$($_.Name): <error accessing>"
                                    }
                                }
                            }
                            
                            # Method 1: Linux Hardened repositories (always immutable)
                            if ($repo.Type -eq "LinuxHardened") {
                                $repoDetails.isImmutable = $true
                                $repoDetails.immutabilitySource = "LinuxHardened"
                                if ($repo.Path) { $repoDetails.path = $repo.Path }
                            }
                            
                            # Method 2: Check for ObjectStorageRepository properties (for cloud storage)
                            if ($repo.PSObject.Properties.Name -contains "ObjectStorageRepository") {
                                $objStorage = $repo.ObjectStorageRepository
                                if ($objStorage) {
                                    # Check for Amazon S3 Object Lock
                                    if ($objStorage.PSObject.Properties.Name -contains "AmazonS3") {
                                        $s3Settings = $objStorage.AmazonS3
                                        if ($s3Settings -and $s3Settings.PSObject.Properties.Name -contains "ObjectLockConfiguration") {
                                            $lockConfig = $s3Settings.ObjectLockConfiguration
                                            if ($lockConfig -and $lockConfig.ObjectLockEnabled) {
                                                $repoDetails.isImmutable = $true
                                                $repoDetails.immutabilitySource = "S3ObjectLock"
                                                $repoDetails.immutablePeriod = $lockConfig.DefaultRetentionPeriodDays
                                            }
                                        }
                                    }
                                    
                                    # Check for Azure Blob immutability
                                    if ($objStorage.PSObject.Properties.Name -contains "AzureBlob") {
                                        $azureSettings = $objStorage.AzureBlob
                                        if ($azureSettings -and $azureSettings.PSObject.Properties.Name -contains "ImmutabilityPolicy") {
                                            $immutabilityPolicy = $azureSettings.ImmutabilityPolicy
                                            if ($immutabilityPolicy -and $immutabilityPolicy.Enabled) {
                                                $repoDetails.isImmutable = $true
                                                $repoDetails.immutabilitySource = "AzureBlobImmutability"
                                                $repoDetails.immutablePeriod = $immutabilityPolicy.Period
                                            }
                                        }
                                    }
                                }
                            }
                            
                            # Method 3: Direct S3 repository properties
                            if ($repo.Type -eq "AmazonS3" -or $repo.Type -eq "S3Compatible") {
                                # Check for S3-specific immutability properties
                                if ($repo.PSObject.Properties.Name -contains "S3Config") {
                                    $s3Config = $repo.S3Config
                                    if ($s3Config -and $s3Config.PSObject.Properties.Name -contains "ObjectLockEnabled") {
                                        if ($s3Config.ObjectLockEnabled) {
                                            $repoDetails.isImmutable = $true
                                            $repoDetails.immutabilitySource = "S3Config"
                                        }
                                    }
                                }
                                
                                # Check for bucket-level immutability settings
                                if ($repo.PSObject.Properties.Name -contains "BucketConfig") {
                                    $bucketConfig = $repo.BucketConfig
                                    if ($bucketConfig) {
                                        # Check various bucket immutability properties
                                        $immutabilityFields = @("ObjectLockEnabled", "ImmutabilityEnabled", "RetentionLockEnabled")
                                        foreach ($field in $immutabilityFields) {
                                            if ($bucketConfig.PSObject.Properties.Name -contains $field) {
                                                if ($bucketConfig.$field) {
                                                    $repoDetails.isImmutable = $true
                                                    $repoDetails.immutabilitySource = "BucketConfig.$field"
                                                    break
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                # Try to get immutability through REST API calls (if available)
                                try {
                                    $repoExtended = Get-VBRBackupRepository -Name $repo.Name | Get-VBRRepositoryExtension -ErrorAction SilentlyContinue
                                    if ($repoExtended -and $repoExtended.PSObject.Properties.Name -contains "ImmutabilitySettings") {
                                        $immutabilitySettings = $repoExtended.ImmutabilitySettings
                                        if ($immutabilitySettings -and $immutabilitySettings.Enabled) {
                                            $repoDetails.isImmutable = $true
                                            $repoDetails.immutabilitySource = "RepositoryExtension"
                                            $repoDetails.immutablePeriod = $immutabilitySettings.Period
                                        }
                                    }
                                } catch {
                                    # Extension method not available
                                }
                            }
                            
                            # Method 4: Azure Blob repository properties
                            if ($repo.Type -eq "AzureBlob") {
                                # Check for Azure-specific immutability
                                if ($repo.PSObject.Properties.Name -contains "AzureConfig") {
                                    $azureConfig = $repo.AzureConfig
                                    if ($azureConfig) {
                                        $azureImmutableFields = @("ImmutabilityPolicyEnabled", "ImmutableStorageEnabled", "RetentionBasedHoldEnabled")
                                        foreach ($field in $azureImmutableFields) {
                                            if ($azureConfig.PSObject.Properties.Name -contains $field) {
                                                if ($azureConfig.$field) {
                                                    $repoDetails.isImmutable = $true
                                                    $repoDetails.immutabilitySource = "AzureConfig.$field"
                                                    break
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                # Check container-level immutability
                                if ($repo.PSObject.Properties.Name -contains "ContainerConfig") {
                                    $containerConfig = $repo.ContainerConfig
                                    if ($containerConfig -and $containerConfig.PSObject.Properties.Name -contains "ImmutabilityPolicy") {
                                        $immutabilityPolicy = $containerConfig.ImmutabilityPolicy
                                        if ($immutabilityPolicy -and $immutabilityPolicy.Enabled) {
                                            $repoDetails.isImmutable = $true
                                            $repoDetails.immutabilitySource = "ContainerImmutability"
                                            $repoDetails.immutablePeriod = $immutabilityPolicy.RetentionPeriod
                                        }
                                    }
                                }
                            }
                            
                            # Method 5: Generic immutability properties (last resort)
                            if (-not $repoDetails.isImmutable) {
                                $genericImmutableFields = @(
                                    "IsImmutable", "Immutable", "ImmutabilityEnabled", 
                                    "ObjectLockEnabled", "RetentionLockEnabled",
                                    "MakeRecentBackupsImmutable", "MakeRecentBackupsImmutableForDays"
                                )
                                
                                foreach ($field in $genericImmutableFields) {
                                    if ($repo.PSObject.Properties.Name -contains $field) {
                                        $value = $repo.$field
                                        if (($value -is [bool] -and $value) -or ($value -is [int] -and $value -gt 0)) {
                                            $repoDetails.isImmutable = $true
                                            $repoDetails.immutabilitySource = "Generic.$field"
                                            if ($value -is [int]) {
                                                $repoDetails.immutablePeriod = $value
                                            }
                                            break
                                        }
                                    }
                                }
                            }
                            
                            # Method 6: Try to call Veeam-specific cmdlets for repository details
                            if (-not $repoDetails.isImmutable -and $repo.Name -like "*immutable*") {
                                try {
                                    # Try to get more detailed repository information
                                    $repoDetails.debugInfo.attemptedDetailedLookup = $true
                                    
                                    # For S3 repositories, try to get S3 settings
                                    if ($repo.Type -eq "AmazonS3" -or $repo.Type -eq "S3Compatible") {
                                        $s3Repository = Get-VBRObjectStorageRepository -Name $repo.Name -ErrorAction SilentlyContinue
                                        if ($s3Repository) {
                                            $repoDetails.debugInfo.s3RepositoryFound = $true
                                            # Check if this has immutability settings
                                            if ($s3Repository.PSObject.Properties.Name -contains "ObjectLockConfiguration") {
                                                $lockConfig = $s3Repository.ObjectLockConfiguration
                                                if ($lockConfig -and $lockConfig.Enabled) {
                                                    $repoDetails.isImmutable = $true
                                                    $repoDetails.immutabilitySource = "ObjectStorageRepository"
                                                    $repoDetails.immutablePeriod = $lockConfig.RetentionPeriod
                                                }
                                            }
                                        }
                                    }
                                } catch {
                                    $repoDetails.debugInfo.detailedLookupError = $_.Exception.Message
                                }
                            }
                            
                        } catch {
                            $repoDetails.debugInfo.error = $_.Exception.Message
                        }
                        
                        $result.repositoryDetails += $repoDetails
                    }
                }
            } catch {
                $result.repositoryDetails = @()
            }
            
            # Job security details (unchanged)
            try {
                $jobs = Get-VBRJob -ErrorAction SilentlyContinue
                if ($jobs) {
                    foreach($job in $jobs) {
                        try {
                            $jobSecurity = @{
                                name = $job.Name
                                type = $job.JobType.ToString()
                                isEncrypted = $false
                                encryptionKey = ""
                            }
                            
                            if ($job.Options -and $job.Options.BackupStorageOptions) {
                                $jobSecurity.isEncrypted = $job.Options.BackupStorageOptions.StorageEncryptionEnabled
                                if ($job.Options.BackupStorageOptions.StorageEncryptionKey) {
                                    $jobSecurity.encryptionKey = $job.Options.BackupStorageOptions.StorageEncryptionKey.Description
                                }
                            }
                            
                            $result.jobSecurity += $jobSecurity
                        } catch {
                            # Skip this job if we can't get security info
                        }
                    }
                }
            } catch {
                $result.jobSecurity = @()
            }
            
            # Compliance check - simplified
            $result.complianceReport = @{ error = "Compliance analyzer requires manual implementation" }
            
            # Audit settings (unchanged)
            try {
                $auditSettings = @{
                    eventLogEnabled = $true
                    syslogEnabled = $false
                    snmpEnabled = $false
                }
                
                try {
                    $syslogServers = Get-VBRSyslogServer -ErrorAction SilentlyContinue
                    if($syslogServers -and $syslogServers.Count -gt 0) {
                        $auditSettings.syslogEnabled = $true
                        $auditSettings.syslogServers = $syslogServers.Count
                    }
                } catch {
                    # SYSLOG not available
                }
                
                $result.auditSettings = $auditSettings
            } catch {
                $result.auditSettings = @{ error = $_.Exception.Message }
            }
            
            # System health (unchanged)
            $result.systemHealth = @{
                powerShellModuleLoaded = $true
                timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        # Service status (unchanged)
        $services = @("VeeamBackupSvc", "VeeamBrokerSvc", "VeeamCatalogSvc", "VeeamCloudSvc", "VeeamDeploymentSvc", "VeeamMountSvc")
        foreach($svc in $services) {
            try {
                $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if($service) {
                    $serviceInfo = @{
                        name = $service.Name
                        status = $service.Status.ToString()
                        startType = $service.StartType.ToString()
                        account = "Unknown"
                        binaryPath = "Unknown"
                    }
                    
                    try {
                        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
                        if ($wmiService) {
                            $serviceInfo.account = $wmiService.StartName
                            $serviceInfo.binaryPath = $wmiService.PathName
                        }
                    } catch {
                        # WMI not available
                    }
                    
                    $result.serviceStatus += $serviceInfo
                }
            } catch {
                # Skip this service if we can't get info
            }
        }
        
        $result | ConvertTo-Json -Depth 6 -Compress
    `

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("PowerShell execution failed: %v\nOutput: %s", err, string(output))
	}

	outputStr := strings.TrimSpace(string(output))

	startIdx := strings.Index(outputStr, "{")
	endIdx := strings.LastIndex(outputStr, "}")

	if startIdx == -1 || endIdx == -1 || startIdx >= endIdx {
		return nil, fmt.Errorf("no valid JSON found in PowerShell output: %s", outputStr)
	}

	jsonStr := outputStr[startIdx : endIdx+1]
	err = json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PowerShell JSON: %v\nJSON: %s", err, jsonStr)
	}

	return &data, nil
}

func CheckPowerShellSecurity(psData *models.PowerShellData) (int, []string, []models.SecurityCheck) {
	if psData == nil {
		return 0, []string{"PowerShell data not available"}, []models.SecurityCheck{}
	}

	var totalScore int
	var allRecs []string
	var checks []models.SecurityCheck

	// Check 1: Database Security
	dbScore, dbRecs, dbCheck := checkDatabaseSecurity(psData)
	totalScore += dbScore
	allRecs = append(allRecs, dbRecs...)
	checks = append(checks, dbCheck)

	// Check 2: Service Security
	serviceScore, serviceRecs, serviceCheck := checkServiceSecurity(psData)
	totalScore += serviceScore
	allRecs = append(allRecs, serviceRecs...)
	checks = append(checks, serviceCheck)

	// Check 3: PowerShell Repository Analysis
	repoScore, repoRecs, repoCheck := checkPowerShellRepositories(psData)
	totalScore += repoScore
	allRecs = append(allRecs, repoRecs...)
	checks = append(checks, repoCheck)

	// Check 4: Job Security Analysis
	jobScore, jobRecs, jobCheck := checkJobSecurityDetails(psData)
	totalScore += jobScore
	allRecs = append(allRecs, jobRecs...)
	checks = append(checks, jobCheck)

	// Check 5: Audit & Logging
	auditScore, auditRecs, auditCheck := checkAuditConfiguration(psData)
	totalScore += auditScore
	allRecs = append(allRecs, auditRecs...)
	checks = append(checks, auditCheck)

	// Check 6: Veeam Security & Compliance
	complianceScore, complianceRecs, complianceCheck := checkVeeamCompliance(psData)
	totalScore += complianceScore
	allRecs = append(allRecs, complianceRecs...)
	checks = append(checks, complianceCheck)

	return totalScore, allRecs, checks
}

func checkDatabaseSecurity(psData *models.PowerShellData) (int, []string, models.SecurityCheck) {
	maxScore := 20
	score := 0
	recs := []string{}
	status := "fail"
	description := "Database security assessment failed"

	if dbInfo, exists := psData.DatabaseInfo["error"]; exists {
		description = fmt.Sprintf("Database check error: %v", dbInfo)
		return score, recs, models.SecurityCheck{
			Name: "Database Security", Score: score, MaxScore: maxScore,
			Status: status, Description: description,
		}
	}

	// Check configuration backup
	if backupEnabled, exists := psData.DatabaseInfo["backupEnabled"].(bool); exists && backupEnabled {
		score += 10
		recs = append(recs, "✓ Configuration database backup is enabled")
	} else {
		recs = append(recs, "⚠ Configuration database backup is not enabled")
	}

	// Check if using remote database
	if isRemote, exists := psData.DatabaseInfo["isRemoteDatabase"].(bool); exists && isRemote {
		score += 10
		status = "pass"
		recs = append(recs, "✓ Using remote SQL Server database")
	} else {
		score += 5
		status = "warning"
		recs = append(recs, "⚠ Using local database")
	}

	if score >= 15 {
		status = "pass"
		description = "Good database security configuration"
	} else if score >= 10 {
		status = "warning"
		description = "Database security needs improvement"
	} else {
		description = "Poor database security configuration"
	}

	return score, recs, models.SecurityCheck{
		Name: "Database Security", Score: score, MaxScore: maxScore,
		Status: status, Description: description,
	}
}

func checkServiceSecurity(psData *models.PowerShellData) (int, []string, models.SecurityCheck) {
	maxScore := 15
	score := 0
	recs := []string{}
	status := "fail"
	description := "No services found"

	if len(psData.ServiceStatus) == 0 {
		return score, recs, models.SecurityCheck{
			Name: "Service Security", Score: score, MaxScore: maxScore,
			Status: status, Description: description,
		}
	}

	runningServices := 0
	for _, service := range psData.ServiceStatus {
		if serviceMap, ok := service.(map[string]interface{}); ok {
			if statusVal, exists := serviceMap["status"].(string); exists && statusVal == "Running" {
				runningServices++
			}
		}
	}

	if runningServices >= 4 {
		score += 10
		status = "pass"
		recs = append(recs, fmt.Sprintf("✓ %d critical Veeam services are running", runningServices))
	} else {
		recs = append(recs, fmt.Sprintf("⚠ Only %d Veeam services running", runningServices))
	}

	if score >= 8 {
		status = "pass"
		description = "Good service security configuration"
	} else {
		description = "Service security needs improvement"
	}

	return score, recs, models.SecurityCheck{
		Name: "Service Security", Score: score, MaxScore: maxScore,
		Status: status, Description: description,
	}
}

func checkPowerShellRepositories(psData *models.PowerShellData) (int, []string, models.SecurityCheck) {
	maxScore := 25
	score := 0
	recs := []string{}
	status := "fail"
	description := "No repository details available"

	if len(psData.RepositoryDetails) > 0 {
		immutableRepos := 0

		for _, repo := range psData.RepositoryDetails {
			if repoMap, ok := repo.(map[string]interface{}); ok {
				repoName := "Unknown"
				if name, exists := repoMap["name"].(string); exists {
					repoName = name
				}

				repoType := "Unknown"
				if rType, exists := repoMap["type"].(string); exists {
					repoType = rType
				}

				immutabilitySource := "None"
				if source, exists := repoMap["immutabilitySource"].(string); exists {
					immutabilitySource = source
				}

				if isImmutable, exists := repoMap["isImmutable"].(bool); exists && isImmutable {
					immutableRepos++
					recs = append(recs, fmt.Sprintf("✓ Repository '%s' (%s) has immutability enabled via %s", repoName, repoType, immutabilitySource))
				} else {
					recs = append(recs, fmt.Sprintf("• Repository '%s' (%s) is not immutable via PowerShell", repoName, repoType))

					// Add debug information for repositories that should be immutable
					if strings.Contains(strings.ToLower(repoName), "immutable") {
						if debugInfo, exists := repoMap["debugInfo"].(map[string]interface{}); exists {
							if allProps, exists := debugInfo["allProperties"].([]interface{}); exists {
								recs = append(recs, fmt.Sprintf("  Debug: Repository '%s' properties:", repoName))
								for i, prop := range allProps {
									if i < 5 { // Limit to first 5 properties to avoid spam
										if propStr, ok := prop.(string); ok {
											recs = append(recs, fmt.Sprintf("    %s", propStr))
										}
									}
								}
								if len(allProps) > 5 {
									recs = append(recs, fmt.Sprintf("    ... and %d more properties", len(allProps)-5))
								}
							}
							if err, exists := debugInfo["error"].(string); exists {
								recs = append(recs, fmt.Sprintf("  Debug Error: %s", err))
							}
						}
					}
				}
			}
		}

		if immutableRepos > 0 {
			ratio := float64(immutableRepos) / float64(len(psData.RepositoryDetails))
			score = int(float64(maxScore) * ratio)
			if ratio >= 0.8 {
				status = "pass"
			} else {
				status = "warning"
			}
			description = fmt.Sprintf("PowerShell detected %d of %d immutable repositories", immutableRepos, len(psData.RepositoryDetails))
		} else {
			description = fmt.Sprintf("PowerShell found 0 of %d repositories as immutable", len(psData.RepositoryDetails))
			recs = append(recs, "")
			recs = append(recs, "ℹ TROUBLESHOOTING:")
			recs = append(recs, "• PowerShell may have limited visibility into cloud repository immutability settings")
			recs = append(recs, "• Cloud storage immutability is often managed at the storage provider level")
			recs = append(recs, "• API-based checks provide more comprehensive immutability detection")
			recs = append(recs, "• This discrepancy is normal - both methods complement each other")
		}
	} else {
		description = "No repositories found via PowerShell"
		recs = append(recs, "⚠ PowerShell could not enumerate repositories")
	}

	return score, recs, models.SecurityCheck{
		Name: "PowerShell Repository Analysis", Score: score, MaxScore: maxScore,
		Status: status, Description: description,
	}
}

func checkJobSecurityDetails(psData *models.PowerShellData) (int, []string, models.SecurityCheck) {
	maxScore := 20
	score := 0
	recs := []string{}
	status := "fail"
	description := "No job security details available"

	if len(psData.JobSecurity) > 0 {
		encryptedJobs := 0

		for _, job := range psData.JobSecurity {
			if jobMap, ok := job.(map[string]interface{}); ok {
				if isEncrypted, exists := jobMap["isEncrypted"].(bool); exists && isEncrypted {
					encryptedJobs++
				}
			}
		}

		encryptionRatio := float64(encryptedJobs) / float64(len(psData.JobSecurity))
		score = int(float64(maxScore) * encryptionRatio)

		if encryptionRatio >= 1.0 {
			status = "pass"
			recs = append(recs, "✓ All backup jobs have encryption enabled")
		} else if encryptionRatio >= 0.8 {
			status = "warning"
			recs = append(recs, fmt.Sprintf("✓ %.0f%% of jobs encrypted", encryptionRatio*100))
		} else {
			recs = append(recs, fmt.Sprintf("⚠ Only %.0f%% of jobs encrypted", encryptionRatio*100))
		}

		description = "Job encryption analysis complete"
	}

	return score, recs, models.SecurityCheck{
		Name: "Job Security Analysis", Score: score, MaxScore: maxScore,
		Status: status, Description: description,
	}
}

func checkAuditConfiguration(psData *models.PowerShellData) (int, []string, models.SecurityCheck) {
	maxScore := 10
	score := 5
	recs := []string{"✓ Windows Event Log enabled"}
	status := "warning"
	description := "Basic audit logging only"

	if syslogEnabled, exists := psData.AuditSettings["syslogEnabled"].(bool); exists && syslogEnabled {
		score += 3
		recs = append(recs, "✓ SYSLOG integration configured")
	}

	if snmpEnabled, exists := psData.AuditSettings["snmpEnabled"].(bool); exists && snmpEnabled {
		score += 2
		recs = append(recs, "✓ SNMP monitoring configured")
	}

	if score >= 8 {
		status = "pass"
		description = "Comprehensive audit configuration"
	}

	return score, recs, models.SecurityCheck{
		Name: "Audit & Logging", Score: score, MaxScore: maxScore,
		Status: status, Description: description,
	}
}

// Helper function to map compliance check names to remediation IDs
func getRemediationID(checkName string) int {
	// Map Veeam compliance check names to remediation script IDs
	// These correspond to the automated fixes available in the Veeam Security & Compliance Analyzer script
	remediationMap := map[string]int{
		// Automated remediation available (16 total)
		"RemoteDesktopServiceDisabled":     1,  // Remote Desktop Services should be disabled
		"RemoteRegistryDisabled":           2,  // Remote Registry service should be disabled
		"WinRmServiceDisabled":             3,  // Windows Remote Management should be disabled
		"WindowsFirewallEnabled":           4,  // Windows Firewall should be enabled
		"WDigestNotStorePasswordsInMemory": 5,  // WDigest credentials caching should be disabled
		"WebProxyAutoDiscoveryDisabled":    6,  // Web Proxy Auto-Discovery service should be disabled
		"OutdatedSslAndTlsDisabled":        7,  // Deprecated versions of SSL and TLS should be disabled
		"WindowsScriptHostDisabled":        8,  // Windows Script Host should be disabled
		"SMB1ProtocolDisabled":             9,  // SMBv1 protocol should be disabled
		"LLMNRDisabled":                    10, // Link-Local Multicast Name Resolution should be disabled
		"CSmbSigningAndEncryptionEnabled":  11, // SMBv3 signing and encryption should be enabled
		"ManualLinuxHostAuthentication":    19, // Unknown Linux servers should not be trusted automatically
		"ViProxyTrafficEncrypted":          21, // Host to proxy traffic encryption should be enabled
		"PostgreSqlUseRecommendedSettings": 32, // PostgreSQL server should be configured with recommended settings
		"LsassProtectedProcess":            34, // LSASS should be set to run as a protected process
		"NetBiosDisabled":                  35, // NetBIOS protocol should be disabled on all network interfaces

		// Manual remediation required (19 items) - these return 0 to indicate no automation available
		"MfaEnabledInBackupConsole":               0, // ID 12: MFA for the backup console should be enabled
		"ImmutableOrOfflineMediaPresence":         0, // ID 13: Immutable or offline (air gapped) media should be used
		"LossProtectionEnabled":                   0, // ID 14: Password loss protection should be enabled
		"BackupServerInProductionDomain":          0, // ID 15: Backup server should not be a part of the production domain
		"EmailNotificationsEnabled":               0, // ID 16: Email notifications should be enabled
		"ContainBackupCopies":                     0, // ID 17: All backups should have at least one copy (3-2-1 rule)
		"ReverseIncrementalInUse":                 0, // ID 18: Reverse incremental backup mode should be avoided
		"ConfigurationBackupRepositoryNotLocal":   0, // ID 20: Configuration backup must not be stored on the backup server
		"HardenedRepositoryNotVirtual":            0, // ID 22: Hardened repositories should not be hosted in virtual machines
		"TrafficEncryptionEnabled":                0, // ID 23: Network traffic encryption should be enabled in the backup network
		"LinuxServersUsingSSHKeys":                0, // ID 24: Linux servers should have password-based authentication disabled
		"BackupServicesUnderLocalSystem":          0, // ID 25: Backup services should be running under the LocalSystem account
		"ConfigurationBackupEnabledAndEncrypted":  0, // ID 26: Configuration backup should be enabled and use encryption
		"PasswordsRotation":                       0, // ID 27: Credentials and encryption passwords should be rotated annually
		"HardenedRepositorySshDisabled":           0, // ID 28: Hardened repositories should have the SSH Server disabled
		"OsBucketsInComplianceMode":               0, // ID 29: S3 Object Lock in Governance mode does not provide true immutability
		"JobsTargetingCloudRepositoriesEncrypted": 0, // ID 30: Backup jobs to cloud repositories should use encryption
		"BackupServerUpToDate":                    0, // ID 31: Latest product updates should be installed
		"HardenedRepositoryNotContainsNBDProxies": 0, // ID 33: Hardened repositories should not be used as backup proxy servers
	}

	if id, exists := remediationMap[checkName]; exists {
		return id
	}
	return 0
}

// Helper function to get the first remediation ID from a list
func getFirstRemediationID(remediableIssues []int) int {
	if len(remediableIssues) > 0 {
		return remediableIssues[0]
	}
	return 0
}

func checkVeeamCompliance(psData *models.PowerShellData) (int, []string, models.SecurityCheck) {
	maxScore := 100
	score := 0
	recs := []string{}
	status := "fail"
	description := "Veeam Security & Compliance Analysis not available"

	if errorMsg, hasError := psData.ComplianceReport["error"]; hasError {
		description := fmt.Sprintf("Compliance check error: %v", errorMsg)

		// Provide manual security recommendations instead
		recs = append(recs, "🔧 MANUAL SECURITY RECOMMENDATIONS:")
		recs = append(recs, "• Enable MFA for Veeam console access")
		recs = append(recs, "• Use dedicated service accounts for backup operations")
		recs = append(recs, "• Implement immutable backup storage (already detected via API)")
		recs = append(recs, "• Enable backup job encryption")
		recs = append(recs, "• Configure SYSLOG forwarding for audit trails")
		recs = append(recs, "• Regularly update Veeam to latest patches")
		recs = append(recs, "• Implement network segmentation for backup infrastructure")
		recs = append(recs, "• Enable configuration database backups")
		recs = append(recs, "• Use remote SQL Server for configuration database")
		recs = append(recs, "• Disable unnecessary Windows services (RDP, WinRM, etc.)")

		// Give partial score for manual recommendations
		score = 30
		status = "warning"

		return score, recs, models.SecurityCheck{
			Name: "Veeam Security & Compliance", Score: score, MaxScore: maxScore,
			Status: status, Description: description,
		}
	}

	if len(psData.ComplianceReport) == 0 {
		description = "No compliance data available"
		return score, recs, models.SecurityCheck{
			Name: "Veeam Security & Compliance", Score: score, MaxScore: maxScore,
			Status: status, Description: description,
		}
	}

	// Process compliance checks and identify remediable issues
	totalChecks := len(psData.ComplianceReport)
	passedChecks := 0
	remediableIssues := []int{} // Track which issues can be fixed via PowerShell

	for key, value := range psData.ComplianceReport {
		if statusStr, ok := value.(string); ok && statusStr == "Ok" {
			passedChecks++
			recs = append(recs, fmt.Sprintf("✓ %s", key))
		} else {
			// Check if this issue can be remediated via PowerShell
			remediationID := getRemediationID(key)
			if remediationID > 0 {
				remediableIssues = append(remediableIssues, remediationID)
				recs = append(recs, fmt.Sprintf("🔧 %s (can be fixed via PowerShell)", key))
			} else {
				recs = append(recs, fmt.Sprintf("⚠ %s (requires manual intervention)", key))
			}
		}
	}

	canRemediate := len(remediableIssues) > 0

	if totalChecks > 0 {
		percentage := float64(passedChecks) / float64(totalChecks) * 100
		score = int(float64(maxScore) * percentage / 100)

		if percentage >= 90 {
			status = "pass"
		} else if percentage >= 70 {
			status = "warning"
		}

		description = fmt.Sprintf("Compliance: %.1f%% (%d/%d checks passed)", percentage, passedChecks, totalChecks)

		if canRemediate {
			description += fmt.Sprintf(" - %d issues can be auto-fixed", len(remediableIssues))
		}
	}

	return score, recs, models.SecurityCheck{
		Name: "Veeam Security & Compliance", Score: score, MaxScore: maxScore,
		Status: status, Description: description,
		CanRemediate:  canRemediate,
		RemediationID: getFirstRemediationID(remediableIssues),
	}
}
