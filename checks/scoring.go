package checks

import (
	"fmt"
	"greenlight/models"
	"strings"
)

func RunAllChecks(data models.VeeamData) models.CheckResult {
	maxScore := 200 // Increased to accommodate PowerShell checks
	score := 0
	recs := []string{}
	securityChecks := make(map[string]models.SecurityCheck)

	// Existing API-based checks (100 points total)
	// Check 1: Backup Jobs Existence (10 points)
	jobScore, jobRecs, jobCheck := checkBackupJobs(data.BackupJobs)
	score += jobScore
	recs = append(recs, jobRecs...)
	securityChecks["backup_jobs"] = jobCheck

	// Check 2: Repository Immutability (25 points)
	immutableScore, immutableRecs, immutableCheck := checkRepositoryImmutability(data.Repositories)
	score += immutableScore
	recs = append(recs, immutableRecs...)
	securityChecks["immutable_repos"] = immutableCheck

	// Check 3: Encryption (20 points)
	encryptionScore, encryptionRecs, encryptionCheck := checkEncryption(data.BackupJobs)
	score += encryptionScore
	recs = append(recs, encryptionRecs...)
	securityChecks["encryption"] = encryptionCheck

	// Check 4: Credential Security (15 points)
	credentialScore, credentialRecs, credentialCheck := checkCredentialSecurity(data.Credentials)
	score += credentialScore
	recs = append(recs, credentialRecs...)
	securityChecks["credentials"] = credentialCheck

	// Check 5: Network Security (15 points)
	networkScore, networkRecs, networkCheck := checkNetworkSecurity(data.Proxies)
	score += networkScore
	recs = append(recs, networkRecs...)
	securityChecks["network"] = networkCheck

	// Check 6: KMS Integration (15 points)
	kmsScore, kmsRecs, kmsCheck := checkKMSIntegration(data.KMSServers)
	score += kmsScore
	recs = append(recs, kmsRecs...)
	securityChecks["kms"] = kmsCheck

	// Enhanced PowerShell-based checks (100 points total)
	if data.PowerShellData != nil {
		psScore, psRecs, psChecks := CheckPowerShellSecurity(data.PowerShellData)
		score += psScore
		recs = append(recs, psRecs...)

		// Add PowerShell checks to the security checks map with correct keys
		for _, check := range psChecks {
			switch check.Name {
			case "Database Security":
				securityChecks["database_security"] = check
			case "Service Security":
				securityChecks["service_security"] = check
			case "PowerShell Repository Analysis":
				securityChecks["powershell_repository_analysis"] = check
			case "Job Security Analysis":
				securityChecks["job_security_analysis"] = check
			case "Audit & Logging":
				securityChecks["audit_&_logging"] = check
			case "Veeam Security & Compliance":
				securityChecks["veeam_security_&_compliance"] = check
			default:
				// Fallback for any other checks
				key := strings.ToLower(strings.ReplaceAll(check.Name, " ", "_"))
				key = strings.ReplaceAll(key, "&", "&")
				securityChecks[key] = check
			}
		}
	} else {
		recs = append(recs, "⚠ PowerShell checks not available - run on Windows Veeam server for enhanced analysis")

		// Add placeholder PowerShell checks to show what would be available
		placeholderChecks := []models.SecurityCheck{
			{Name: "Database Security", Score: 0, MaxScore: 20, Status: "fail", Description: "PowerShell not available"},
			{Name: "Service Security", Score: 0, MaxScore: 15, Status: "fail", Description: "PowerShell not available"},
			{Name: "PowerShell Repository Analysis", Score: 0, MaxScore: 25, Status: "fail", Description: "PowerShell not available"},
			{Name: "Job Security Analysis", Score: 0, MaxScore: 20, Status: "fail", Description: "PowerShell not available"},
			{Name: "Audit & Logging", Score: 0, MaxScore: 10, Status: "fail", Description: "PowerShell not available"},
			{Name: "Veeam Security & Compliance", Score: 0, MaxScore: 100, Status: "fail", Description: "PowerShell not available"},
		}

		securityChecks["database_security"] = placeholderChecks[0]
		securityChecks["service_security"] = placeholderChecks[1]
		securityChecks["powershell_repository_analysis"] = placeholderChecks[2]
		securityChecks["job_security_analysis"] = placeholderChecks[3]
		securityChecks["audit_&_logging"] = placeholderChecks[4]
		securityChecks["veeam_security_&_compliance"] = placeholderChecks[5]
	}

	return models.CheckResult{
		JobsCount:       len(data.BackupJobs),
		ReposCount:      len(data.Repositories),
		Score:           score,
		MaxScore:        maxScore,
		Recommendations: recs,
		SecurityChecks:  securityChecks,
	}
}

func checkBackupJobs(jobs []map[string]interface{}) (int, []string, models.SecurityCheck) {
	maxScore := 10
	score := 0
	recs := []string{}
	status := "fail"
	description := "No backup jobs configured"

	if len(jobs) > 0 {
		score = maxScore
		status = "pass"
		description = fmt.Sprintf("Found %d backup jobs", len(jobs))
		recs = append(recs, description)
	} else {
		recs = append(recs, "No backup jobs found. Configure backup jobs to protect your data.")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Backup Jobs",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

func checkRepositoryImmutability(repositories []interface{}) (int, []string, models.SecurityCheck) {
	maxScore := 25
	score := 0
	recs := []string{}
	immutable := 0

	for i, repo := range repositories {
		if repoMap, ok := repo.(map[string]interface{}); ok {
			isImmutable := false
			repoName := "Unknown"

			// Get repository name for debugging
			if name, exists := repoMap["name"].(string); exists {
				repoName = name
			}

			// Enhanced debugging for all repositories with "immutable" in name
			if strings.Contains(strings.ToLower(repoName), "immutable") {
				fmt.Printf("\n=== DETAILED DEBUG: Repository %d (%s) ===\n", i, repoName)
				printNestedStructure(repoMap, "")
				fmt.Printf("=== END DETAILED DEBUG ===\n\n")

				// Check ALL possible immutability-related fields
				isImmutable = checkAllImmutabilityFields(repoMap, i, repoName)
			} else {
				// For non-immutable named repos, do standard checks
				isImmutable = checkStandardImmutabilityFields(repoMap, i, repoName)
			}

			// Check for LinuxHardened type (these are immutable by design)
			if repoType, exists := repoMap["type"].(string); exists && repoType == "LinuxHardened" {
				isImmutable = true
				fmt.Printf("Repository %d (%s): LinuxHardened type detected\n", i, repoName)
			}

			if isImmutable {
				immutable++
				fmt.Printf("✓ Repository %d (%s) is immutable\n", i, repoName)
			} else {
				fmt.Printf("✗ Repository %d (%s) is NOT immutable\n", i, repoName)
			}
		}
	}

	status := "fail"
	description := "No immutable repositories found"

	if len(repositories) == 0 {
		description = "No repositories configured"
	} else if immutable > 0 {
		ratio := float64(immutable) / float64(len(repositories))
		if ratio >= 0.8 {
			score = maxScore
			status = "pass"
		} else if ratio >= 0.5 {
			score = int(float64(maxScore) * 0.7)
			status = "warning"
		} else {
			score = int(float64(maxScore) * 0.3)
			status = "warning"
		}
		description = fmt.Sprintf("Found %d of %d immutable repositories (%.0f%%)", immutable, len(repositories), ratio*100)
		recs = append(recs, description)
	} else {
		recs = append(recs, "No immutable repositories found. Enable immutability for ransomware protection.")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Repository Immutability",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// Comprehensive check for repositories that should be immutable
func checkAllImmutabilityFields(repoMap map[string]interface{}, i int, repoName string) bool {
	fmt.Printf("Repository %d (%s): Performing comprehensive immutability check\n", i, repoName)

	// Check every field recursively for immutability indicators
	return searchForImmutabilityFields(repoMap, "", i, repoName)
}

// Standard checks for other repositories
func checkStandardImmutabilityFields(repoMap map[string]interface{}, i int, repoName string) bool {
	// Top-level checks
	if checkBoolField(repoMap, "isImmutable") ||
		checkBoolField(repoMap, "immutable") ||
		checkBoolField(repoMap, "linuxHardeningEnabled") ||
		checkBoolField(repoMap, "objectLockEnabled") ||
		checkBoolField(repoMap, "isObjectLockEnabled") ||
		checkPositiveNumericField(repoMap, "makeRecentBackupsImmutableForDays") ||
		checkPositiveNumericField(repoMap, "immutableDays") {
		fmt.Printf("Repository %d (%s): Found top-level immutability\n", i, repoName)
		return true
	}

	// Nested bucket/container checks
	if bucket, exists := repoMap["bucket"].(map[string]interface{}); exists {
		if checkNestedImmutability(bucket, "bucket", i, repoName) {
			return true
		}
	}

	if container, exists := repoMap["container"].(map[string]interface{}); exists {
		if checkNestedImmutability(container, "container", i, repoName) {
			return true
		}
	}

	if repository, exists := repoMap["repository"].(map[string]interface{}); exists {
		if checkNestedImmutability(repository, "repository", i, repoName) {
			return true
		}
	}

	return false
}

// Recursively search for any immutability-related fields
func searchForImmutabilityFields(data interface{}, path string, i int, repoName string) bool {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			currentPath := path
			if currentPath != "" {
				currentPath += "."
			}
			currentPath += key

			lowerKey := strings.ToLower(key)

			// Check if this field name suggests immutability
			if strings.Contains(lowerKey, "immutable") ||
				strings.Contains(lowerKey, "objectlock") ||
				strings.Contains(lowerKey, "lock") ||
				strings.Contains(lowerKey, "retention") ||
				strings.Contains(lowerKey, "makerecent") {

				fmt.Printf("Repository %d (%s): Found potential field %s: %+v\n", i, repoName, currentPath, value)

				// Check if the value indicates immutability is enabled
				if checkBoolField(v, key) || checkPositiveNumericField(v, key) {
					fmt.Printf("Repository %d (%s): Confirmed immutability via %s\n", i, repoName, currentPath)
					return true
				}
			}

			// Special handling for immutability maps
			if key == "immutability" {
				if immutabilityMap, ok := value.(map[string]interface{}); ok {
					fmt.Printf("Repository %d (%s): Found immutability config at %s: %+v\n", i, repoName, currentPath, immutabilityMap)

					// ONLY consider immutable if isEnabled is explicitly true
					if isEnabled, exists := immutabilityMap["isEnabled"]; exists {
						if enabled, ok := isEnabled.(bool); ok && enabled {
							fmt.Printf("Repository %d (%s): Confirmed immutability enabled at %s\n", i, repoName, currentPath)
							return true
						} else {
							fmt.Printf("Repository %d (%s): Found immutability config but isEnabled=false at %s\n", i, repoName, currentPath)
							// Do not return true - having daysCount but isEnabled=false means NOT immutable
						}
					}
				}
			}

			// Recursively check nested structures
			if searchForImmutabilityFields(value, currentPath, i, repoName) {
				return true
			}
		}
	case []interface{}:
		for idx, item := range v {
			currentPath := fmt.Sprintf("%s[%d]", path, idx)
			if searchForImmutabilityFields(item, currentPath, i, repoName) {
				return true
			}
		}
	}

	return false
}

func checkNestedImmutability(nested map[string]interface{}, structType string, i int, repoName string) bool {
	// Check for standard immutability configuration
	if immutabilityMap, exists := nested["immutability"].(map[string]interface{}); exists {
		fmt.Printf("Repository %d (%s): Found %s immutability config: %+v\n", i, repoName, structType, immutabilityMap)

		// Check if explicitly enabled - this is the ONLY way to confirm immutability
		if isEnabled, exists := immutabilityMap["isEnabled"]; exists {
			if enabled, ok := isEnabled.(bool); ok && enabled {
				fmt.Printf("Repository %d (%s): Found %s immutability explicitly enabled\n", i, repoName, structType)
				return true
			} else {
				fmt.Printf("Repository %d (%s): Found %s immutability config but isEnabled=false\n", i, repoName, structType)
				return false
			}
		}
	}

	// Check for Azure-specific immutability fields
	azureImmutableFields := []string{
		"makeRecentBackupsImmutable",
		"makeRecentBackupsImmutableForDays",
		"immutableForDays",
		"recentBackupsImmutable",
		"immutableBackups",
		"backupImmutability",
	}

	for _, field := range azureImmutableFields {
		if checkBoolField(nested, field) || checkPositiveNumericField(nested, field) {
			fmt.Printf("Repository %d (%s): Found %s immutability via Azure field %s\n", i, repoName, structType, field)
			return true
		}
	}

	// Check for any field containing "immutable" or "lock" in the name
	for key := range nested {
		lowerKey := strings.ToLower(key)
		if (strings.Contains(lowerKey, "immutable") || strings.Contains(lowerKey, "lock")) &&
			(checkBoolField(nested, key) || checkPositiveNumericField(nested, key)) {
			fmt.Printf("Repository %d (%s): Found %s immutability via %s\n", i, repoName, structType, key)
			return true
		}
	}

	// Print all container fields for Azure Blob debugging
	if structType == "container" && strings.Contains(strings.ToLower(repoName), "azure") {
		fmt.Printf("Repository %d (%s): Azure container fields for debugging:\n", i, repoName)
		for key, value := range nested {
			fmt.Printf("  %s: %+v (type: %T)\n", key, value, value)
		}
	}

	return false
}

// Helper function to recursively print nested structure
func printNestedStructure(data interface{}, indent string) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fmt.Printf("%s%s: ", indent, key)
			switch val := value.(type) {
			case map[string]interface{}:
				fmt.Printf("(map)\n")
				printNestedStructure(val, indent+"  ")
			case []interface{}:
				fmt.Printf("(array with %d items)\n", len(val))
				if len(val) > 0 {
					printNestedStructure(val[0], indent+"  [0]: ")
				}
			default:
				fmt.Printf("%v (type: %T)\n", value, value)
			}
		}
	case []interface{}:
		for i, item := range v {
			fmt.Printf("%s[%d]: ", indent, i)
			printNestedStructure(item, indent+"  ")
		}
	default:
		fmt.Printf("%s%v (type: %T)\n", indent, data, data)
	}
}

// Helper function to check boolean fields with flexible type handling
func checkBoolField(repoMap map[string]interface{}, fieldName string) bool {
	if val, exists := repoMap[fieldName]; exists {
		switch v := val.(type) {
		case bool:
			return v
		case string:
			return v == "true" || v == "True" || v == "TRUE"
		case float64:
			return v > 0
		case int:
			return v > 0
		}
	}
	return false
}

// Helper function to check numeric fields that should be positive
func checkPositiveNumericField(repoMap map[string]interface{}, fieldName string) bool {
	if val, exists := repoMap[fieldName]; exists {
		switch v := val.(type) {
		case float64:
			return v > 0
		case int:
			return v > 0
		case string:
			return v != "" && v != "0"
		}
	}
	return false
}
