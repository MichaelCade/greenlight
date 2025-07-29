package checks

import (
	"fmt"
	"greenlight/models"
	"strings"
)

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func RunAllChecks(data models.VeeamData) models.CheckResult {
	recs := []string{}
	securityChecks := make(map[string]models.SecurityCheck)
	featureChecks := make(map[string]models.SecurityCheck)

	// Core Security Checks (70 points total)
	coreScore := 0

	// Check 1: Repository Immutability (25 points)
	immutableScore, immutableRecs, immutableCheck := checkRepositoryImmutability(data.Repositories)
	coreScore += immutableScore
	recs = append(recs, immutableRecs...)
	securityChecks["immutable_repos"] = immutableCheck

	// Check 2: Encryption (20 points)
	encryptionScore, encryptionRecs, encryptionCheck := checkEncryption(data.BackupJobs)
	coreScore += encryptionScore
	recs = append(recs, encryptionRecs...)
	securityChecks["encryption"] = encryptionCheck

	// Check 3: Credential Security (15 points)
	credentialScore, credentialRecs, credentialCheck := checkCredentialSecurity(data.Credentials)
	coreScore += credentialScore
	recs = append(recs, credentialRecs...)
	securityChecks["credentials"] = credentialCheck

	// Check 4: Network Security (10 points)
	networkScore, networkRecs, networkCheck := checkNetworkSecurity(data.Proxies)
	coreScore += networkScore
	recs = append(recs, networkRecs...)
	securityChecks["network"] = networkCheck

	// Feature Checks (30 points total)
	featureScore := 0

	// Feature 1: 3-2-1 Backup Compliance (15 points)
	compliance321Score, compliance321Recs, compliance321Check := check321Compliance(data)
	featureScore += compliance321Score
	recs = append(recs, compliance321Recs...)
	featureChecks["321_compliance"] = compliance321Check

	// Feature 2: SureBackup Implementation (10 points)
	surebackupScore, surebackupRecs, surebackupCheck := checkSureBackupImplementation(data)
	featureScore += surebackupScore
	recs = append(recs, surebackupRecs...)
	featureChecks["surebackup"] = surebackupCheck

	// Feature 3: Suspicious Activity Detection (5 points)
	suspiciousScore, suspiciousRecs, suspiciousCheck := checkSuspiciousActivity(data)
	featureScore += suspiciousScore
	recs = append(recs, suspiciousRecs...)
	featureChecks["suspicious_activity"] = suspiciousCheck

	// Advanced Security Checks (add to feature score for comprehensive assessment)
	// Feature 4: Backup Copy Compliance (15 points)
	backupCopyScore, backupCopyRecs, backupCopyCheck := checkBackupCopyCompliance(data)
	featureScore += backupCopyScore
	recs = append(recs, backupCopyRecs...)
	featureChecks["backup_copy_compliance"] = backupCopyCheck

	// Feature 5: Retention Policy Compliance (10 points)
	retentionScore, retentionRecs, retentionCheck := checkRetentionPolicyCompliance(data)
	featureScore += retentionScore
	recs = append(recs, retentionRecs...)
	featureChecks["retention_compliance"] = retentionCheck

	// Feature 6: Cloud Tier Security (10 points)
	cloudTierScore, cloudTierRecs, cloudTierCheck := checkCloudTierCompliance(data)
	featureScore += cloudTierScore
	recs = append(recs, cloudTierRecs...)
	featureChecks["cloud_tier_security"] = cloudTierCheck

	// Feature 7: Tape Security (10 points)
	tapeScore, tapeRecs, tapeCheck := checkTapeSecurityCompliance(data)
	featureScore += tapeScore
	recs = append(recs, tapeRecs...)
	featureChecks["tape_security"] = tapeCheck

	// Feature 8: Replication Security (10 points)
	replicationScore, replicationRecs, replicationCheck := checkReplicationCompliance(data)
	featureScore += replicationScore
	recs = append(recs, replicationRecs...)
	featureChecks["replication_security"] = replicationCheck

	// Operational Security Checks (additional features for comprehensive assessment)
	// Feature 9: License Compliance (5 points)
	licenseScore, licenseRecs, licenseCheck := checkLicenseCompliance(data.LicenseInfo)
	featureScore += licenseScore
	recs = append(recs, licenseRecs...)
	featureChecks["license_compliance"] = licenseCheck

	// Feature 10: Security Alarms (10 points)
	alarmScore, alarmRecs, alarmCheck := checkSecurityAlarms(data.Alarms)
	featureScore += alarmScore
	recs = append(recs, alarmRecs...)
	featureChecks["security_alarms"] = alarmCheck

	// Feature 11: Backup Success Rate (10 points)
	successScore, successRecs, successCheck := checkBackupSuccessRate(data.Sessions)
	featureScore += successScore
	recs = append(recs, successRecs...)
	featureChecks["backup_success_rate"] = successCheck

	// Feature 12: Audit Logging (10 points)
	auditScore, auditRecs, auditCheck := checkAuditingCompliance(data.AuditItems)
	featureScore += auditScore
	recs = append(recs, auditRecs...)
	featureChecks["audit_logging"] = auditCheck
	// Normalize the total score to 100 points
	// Core security checks: 70 points maximum
	// Essential features (first 30 points of featureScore): 30 points maximum
	// Total base score: 100 points maximum
	baseScore := coreScore + min(featureScore, 30)

	// PowerShell enhances the base score but final score is always normalized to 100
	finalScore := baseScore
	if data.PowerShellData != nil {
		psScore, psRecs, psChecks := CheckPowerShellSecurity(data.PowerShellData)

		// PowerShell can boost the score up to 100, but not exceed it
		psBoostPotential := (psScore * 30) / 100 // Up to 30 point boost
		maxPossibleBoost := 100 - baseScore      // How much room for improvement

		actualBoost := min(psBoostPotential, maxPossibleBoost)
		finalScore = baseScore + actualBoost

		// Ensure final score never exceeds 100
		if finalScore > 100 {
			finalScore = 100
		}

		if actualBoost > 0 {
			recs = append(recs, fmt.Sprintf("✓ PowerShell analysis provided +%d security enhancement points", actualBoost))
		}

		// Report on additional features beyond the core 100-point scale
		bonusFeaturePoints := max(0, featureScore-30)
		if bonusFeaturePoints > 0 {
			recs = append(recs, fmt.Sprintf("✓ Advanced features detected (+%d points beyond standard assessment)", bonusFeaturePoints))
		}

		recs = append(recs, psRecs...)

		// Add PowerShell checks as additional security insights
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
				key := strings.ToLower(strings.ReplaceAll(check.Name, " ", "_"))
				key = strings.ReplaceAll(key, "&", "&")
				securityChecks[key] = check
			}
		}
	} else {
		recs = append(recs, "⚠ PowerShell analysis not available - run on Windows Veeam server for enhanced insights")

		// Report on additional features beyond the core 100-point scale
		bonusFeaturePoints := max(0, featureScore-30)
		if bonusFeaturePoints > 0 {
			recs = append(recs, fmt.Sprintf("✓ Advanced features detected (+%d points beyond standard assessment)", bonusFeaturePoints))
		}
	}

	// Max score is always 100 for consistency across platforms
	dynamicMaxScore := 100

	return models.CheckResult{
		JobsCount:       len(data.BackupJobs),
		ReposCount:      len(data.Repositories),
		Score:           finalScore,
		MaxScore:        dynamicMaxScore,
		Recommendations: recs,
		SecurityChecks:  securityChecks,
		FeatureChecks:   featureChecks,
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
				// Debug output removed for cleaner console
				// fmt.Printf("\n=== DETAILED DEBUG: Repository %d (%s) ===\n", i, repoName)
				// printNestedStructure(repoMap, "")
				// fmt.Printf("=== END DETAILED DEBUG ===\n\n")

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

// check321Compliance performs a comprehensive 3-2-1 backup compliance check
func check321Compliance(data models.VeeamData) (int, []string, models.SecurityCheck) {
	maxScore := 15 // Adjusted for 100-point scale
	score := 0
	recs := []string{}
	status := "fail"

	if len(data.BackupJobs) == 0 {
		return score, []string{"No backup jobs found for 3-2-1 compliance analysis"}, models.SecurityCheck{
			Name:        "3-2-1 Backup Compliance",
			Score:       score,
			MaxScore:    maxScore,
			Status:      status,
			Description: "No backup jobs configured",
		}
	}

	// Analyze job compliance
	compliantJobs := 0
	totalJobs := len(data.BackupJobs)
	complianceDetails := []string{}

	for _, job := range data.BackupJobs {
		jobName := "Unknown Job"
		if name, exists := job["name"].(string); exists {
			jobName = name
		}

		compliance := analyze321JobCompliance(job, data.Repositories, data.ScaleOutRepositories)
		if compliance.IsCompliant {
			compliantJobs++
			complianceDetails = append(complianceDetails, fmt.Sprintf("✅ %s: %s", jobName, compliance.Summary))
		} else {
			complianceDetails = append(complianceDetails, fmt.Sprintf("❌ %s: %s", jobName, compliance.Summary))
			recs = append(recs, fmt.Sprintf("Job '%s' needs: %s", jobName, strings.Join(compliance.MissingElements, ", ")))
		}
	}

	// Calculate score based on compliance ratio
	complianceRatio := float64(compliantJobs) / float64(totalJobs)

	if complianceRatio >= 0.9 {
		score = maxScore
		status = "pass"
	} else if complianceRatio >= 0.7 {
		score = int(float64(maxScore) * 0.8)
		status = "warning"
	} else if complianceRatio >= 0.5 {
		score = int(float64(maxScore) * 0.5)
		status = "warning"
	} else {
		score = int(float64(maxScore) * 0.2)
		status = "fail"
	}

	description := fmt.Sprintf("%d of %d jobs (%.0f%%) follow 3-2-1 rule", compliantJobs, totalJobs, complianceRatio*100)

	// Add detailed breakdown to recommendations
	recs = append(recs, "=== 3-2-1 Compliance Analysis ===")
	recs = append(recs, complianceDetails...)
	recs = append(recs, fmt.Sprintf("Overall Compliance: %.0f%% (%d/%d jobs)", complianceRatio*100, compliantJobs, totalJobs))

	return score, recs, models.SecurityCheck{
		Name:        "3-2-1 Backup Compliance",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// JobComplianceResult represents the 3-2-1 compliance status of a job
type JobComplianceResult struct {
	IsCompliant     bool
	Summary         string
	MissingElements []string
	CopyCount       int
	MediaTypes      []string
	OffsiteCount    int
}

// analyze321JobCompliance analyzes a single job for 3-2-1 compliance
func analyze321JobCompliance(job map[string]interface{}, repositories []interface{}, scaleOutRepos []interface{}) JobComplianceResult {
	result := JobComplianceResult{
		IsCompliant:     false,
		MediaTypes:      []string{},
		MissingElements: []string{},
	}

	// Track copies and media types
	mediaTypeMap := make(map[string]bool)
	offsiteCount := 0
	totalCopies := 1 // Main backup counts as first copy

	// Analyze backup copy jobs (if any are configured)
	if copyJobs, exists := job["backupCopyJobs"].([]interface{}); exists {
		for _, copyJobInterface := range copyJobs {
			if copyJob, ok := copyJobInterface.(map[string]interface{}); ok {
				totalCopies++

				// Analyze target repository for this copy
				if targetRepoId, exists := copyJob["targetRepositoryId"].(string); exists {
					repoInfo := findRepositoryInfo(targetRepoId, repositories, scaleOutRepos)
					if repoInfo != nil {
						// Determine media type
						mediaType := determineMediaType(repoInfo)
						mediaTypeMap[mediaType] = true

						// Check if offsite
						if isOffsiteRepository(repoInfo) {
							offsiteCount++
						}
					}
				}
			}
		}
	}

	// Also check if job itself targets multiple repositories (scale-out scenarios)
	if repoId, exists := job["repositoryId"].(string); exists {
		repoInfo := findRepositoryInfo(repoId, repositories, scaleOutRepos)
		if repoInfo != nil {
			mediaType := determineMediaType(repoInfo)
			mediaTypeMap[mediaType] = true

			if isOffsiteRepository(repoInfo) {
				offsiteCount++
			}
		}
	}

	// Convert media types map to slice
	for mediaType := range mediaTypeMap {
		result.MediaTypes = append(result.MediaTypes, mediaType)
	}

	result.CopyCount = totalCopies
	result.OffsiteCount = offsiteCount

	// Check 3-2-1 compliance
	// 3 copies (including original)
	if totalCopies < 3 {
		result.MissingElements = append(result.MissingElements, fmt.Sprintf("Need %d more copies", 3-totalCopies))
	}

	// 2 different media types
	if len(result.MediaTypes) < 2 {
		result.MissingElements = append(result.MissingElements, "Need 2+ different media types")
	}

	// 1 offsite copy
	if offsiteCount < 1 {
		result.MissingElements = append(result.MissingElements, "Need 1+ offsite copy")
	}

	result.IsCompliant = len(result.MissingElements) == 0

	if result.IsCompliant {
		result.Summary = fmt.Sprintf("Compliant (%d copies, %d media types, %d offsite)", totalCopies, len(result.MediaTypes), offsiteCount)
	} else {
		result.Summary = fmt.Sprintf("Non-compliant (%d copies, %d media types, %d offsite)", totalCopies, len(result.MediaTypes), offsiteCount)
	}

	return result
}

// findRepositoryInfo finds repository information by ID
func findRepositoryInfo(repoId string, repositories []interface{}, scaleOutRepos []interface{}) map[string]interface{} {
	// Search in regular repositories
	for _, repo := range repositories {
		if repoMap, ok := repo.(map[string]interface{}); ok {
			if id, exists := repoMap["id"].(string); exists && id == repoId {
				return repoMap
			}
		}
	}

	// Search in scale-out repositories
	for _, repo := range scaleOutRepos {
		if repoMap, ok := repo.(map[string]interface{}); ok {
			if id, exists := repoMap["id"].(string); exists && id == repoId {
				return repoMap
			}
		}
	}

	return nil
}

// determineMediaType determines the media type of a repository
func determineMediaType(repo map[string]interface{}) string {
	if repoType, exists := repo["type"].(string); exists {
		switch strings.ToLower(repoType) {
		case "linuxhardened", "hardened":
			return "Hardened Storage"
		case "cloud", "s3", "azure", "gcp":
			return "Cloud Storage"
		case "tape":
			return "Tape"
		case "dedup":
			return "Deduplication Appliance"
		default:
			return "Local Disk"
		}
	}

	// Check for cloud indicators
	if name, exists := repo["name"].(string); exists {
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, "cloud") || strings.Contains(nameLower, "s3") ||
			strings.Contains(nameLower, "azure") || strings.Contains(nameLower, "aws") {
			return "Cloud Storage"
		}
		if strings.Contains(nameLower, "tape") {
			return "Tape"
		}
		if strings.Contains(nameLower, "hardened") || strings.Contains(nameLower, "immutable") {
			return "Hardened Storage"
		}
	}

	return "Local Disk"
}

// isOffsiteRepository determines if a repository is considered offsite
func isOffsiteRepository(repo map[string]interface{}) bool {
	if repoType, exists := repo["type"].(string); exists {
		switch strings.ToLower(repoType) {
		case "cloud", "s3", "azure", "gcp":
			return true
		case "tape":
			return true // Tapes are typically stored offsite
		}
	}

	// Check for cloud/offsite indicators in name
	if name, exists := repo["name"].(string); exists {
		nameLower := strings.ToLower(name)
		if strings.Contains(nameLower, "cloud") || strings.Contains(nameLower, "offsite") ||
			strings.Contains(nameLower, "remote") || strings.Contains(nameLower, "s3") ||
			strings.Contains(nameLower, "azure") || strings.Contains(nameLower, "aws") ||
			strings.Contains(nameLower, "tape") {
			return true
		}
	}

	// Check for remote server indicators
	if host, exists := repo["host"].(string); exists {
		// If host is not localhost/127.0.0.1, consider it offsite
		if !strings.Contains(strings.ToLower(host), "localhost") &&
			!strings.Contains(host, "127.0.0.1") {
			return true
		}
	}

	return false
}

// checkSureBackupImplementation checks if SureBackup is configured for backup verification
func checkSureBackupImplementation(data models.VeeamData) (int, []string, models.SecurityCheck) {
	maxScore := 10
	score := 0
	recs := []string{}
	status := "fail"
	description := "SureBackup verification not implemented"

	// Check for SureBackup jobs in backup jobs or dedicated endpoint
	sureBackupJobs := 0

	for _, job := range data.BackupJobs {
		if jobType, exists := job["type"].(string); exists {
			if strings.Contains(strings.ToLower(jobType), "surebackup") {
				sureBackupJobs++
			}
		}
		// Also check for verification settings in regular backup jobs
		if jobName, exists := job["name"].(string); exists {
			if strings.Contains(strings.ToLower(jobName), "surebackup") ||
				strings.Contains(strings.ToLower(jobName), "verification") {
				sureBackupJobs++
			}
		}
	}

	if sureBackupJobs > 0 {
		score = maxScore
		status = "pass"
		description = fmt.Sprintf("SureBackup verification active (%d jobs found)", sureBackupJobs)
		recs = append(recs, fmt.Sprintf("✓ SureBackup verification is configured with %d jobs", sureBackupJobs))
	} else {
		// Check if any backup jobs have verification enabled
		verificationEnabled := false
		for _, job := range data.BackupJobs {
			if settings, exists := job["settings"].(map[string]interface{}); exists {
				if verification, exists := settings["verification"]; exists {
					if enabled, ok := verification.(bool); ok && enabled {
						verificationEnabled = true
						break
					}
				}
			}
		}

		if verificationEnabled {
			score = maxScore / 2 // Partial credit for basic verification
			status = "warning"
			description = "Basic backup verification enabled, but SureBackup not configured"
			recs = append(recs, "⚠ Consider implementing SureBackup for comprehensive backup verification")
		} else {
			recs = append(recs, "🚨 Critical: No backup verification configured - implement SureBackup to ensure backup integrity")
		}
	}

	return score, recs, models.SecurityCheck{
		Name:        "SureBackup Verification",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// checkSuspiciousActivity looks for indicators of potential security issues
func checkSuspiciousActivity(data models.VeeamData) (int, []string, models.SecurityCheck) {
	maxScore := 5
	score := maxScore // Start with full score and deduct for issues
	recs := []string{}
	status := "pass"
	description := "No suspicious activity detected"
	issues := []string{}

	// Check for unusual credential configurations
	if len(data.Credentials) > 10 {
		score -= 1
		issues = append(issues, fmt.Sprintf("High number of stored credentials (%d)", len(data.Credentials)))
		recs = append(recs, "⚠ Review stored credentials - consider credential consolidation")
	}

	// Check for repositories without encryption
	unencryptedRepos := 0
	for _, repo := range data.Repositories {
		repoMap, ok := repo.(map[string]interface{})
		if !ok {
			continue
		}

		isEncrypted := false

		// Check various encryption fields
		if encryption, exists := repoMap["encryption"]; exists {
			if encMap, ok := encryption.(map[string]interface{}); ok {
				if enabled, exists := encMap["enabled"].(bool); exists && enabled {
					isEncrypted = true
				}
			}
		}

		if !isEncrypted {
			unencryptedRepos++
		}
	}

	if unencryptedRepos > 0 {
		score -= 2
		issues = append(issues, fmt.Sprintf("%d repositories without encryption", unencryptedRepos))
		recs = append(recs, "🚨 Enable encryption for all repositories to protect against data theft")
	}

	// Check for jobs without immutability
	vulnerableJobs := 0
	for _, job := range data.BackupJobs {
		// Look for repository assignment
		if repoId, exists := job["repositoryId"].(string); exists {
			// Find the repository and check immutability
			for _, repo := range data.Repositories {
				if repoMap, ok := repo.(map[string]interface{}); ok {
					if id, exists := repoMap["id"].(string); exists && id == repoId {
						if !isSingleRepositoryImmutable(repoMap) {
							vulnerableJobs++
							break
						}
					}
				}
			}
		}
	}

	if vulnerableJobs > 0 {
		score -= 2
		issues = append(issues, fmt.Sprintf("%d jobs backing up to non-immutable storage", vulnerableJobs))
		recs = append(recs, "🛡️ Ensure critical backups use immutable repositories for ransomware protection")
	}

	// Update status and description based on findings
	if len(issues) > 0 {
		if score <= 2 {
			status = "fail"
			description = fmt.Sprintf("Multiple security concerns: %s", strings.Join(issues, ", "))
		} else {
			status = "warning"
			description = fmt.Sprintf("Some security concerns: %s", strings.Join(issues, ", "))
		}
	} else {
		recs = append(recs, "✓ No obvious security concerns detected")
	}

	if score < 0 {
		score = 0
	}

	return score, recs, models.SecurityCheck{
		Name:        "Suspicious Activity Detection",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// isSingleRepositoryImmutable checks if a single repository is immutable
func isSingleRepositoryImmutable(repo map[string]interface{}) bool {
	// Check for Linux Hardened repository type
	if repoType, exists := repo["type"].(string); exists {
		if strings.Contains(strings.ToLower(repoType), "linuxhardened") {
			return true
		}
	}

	// Check for immutability settings in cloud repositories (AWS S3, Azure Blob, etc.)
	if bucket, exists := repo["bucket"].(map[string]interface{}); exists {
		if immutability, exists := bucket["immutability"].(map[string]interface{}); exists {
			if isEnabled, exists := immutability["isEnabled"].(bool); exists && isEnabled {
				return true
			}
		}
	}

	if container, exists := repo["container"].(map[string]interface{}); exists {
		if immutability, exists := container["immutability"].(map[string]interface{}); exists {
			if isEnabled, exists := immutability["isEnabled"].(bool); exists && isEnabled {
				return true
			}
		}
	}

	// Check for makeRecentBackupsImmutableDays (Linux hardened repos)
	if _, exists := repo["makeRecentBackupsImmutableDays"]; exists {
		return true
	}

	return false
}
