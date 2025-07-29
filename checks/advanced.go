package checks

import (
	"fmt"
	"greenlight/models"
	"strings"
)

// checkTapeSecurityCompliance checks for proper tape backup security
func checkTapeSecurityCompliance(data models.VeeamData) (int, []string, models.SecurityCheck) {
	maxScore := 10
	score := 0
	recs := []string{}
	status := "warning"
	description := "No tape infrastructure found"

	tapeJobs := 0
	encryptedTapeJobs := 0

	// Check for tape-related repositories or jobs
	for _, repo := range data.Repositories {
		if repoMap, ok := repo.(map[string]interface{}); ok {
			if repoType, exists := repoMap["type"].(string); exists {
				if strings.Contains(strings.ToLower(repoType), "tape") {
					tapeJobs++
					// Check if tape encryption is enabled
					if checkTapeEncryption(repoMap) {
						encryptedTapeJobs++
					}
				}
			}
		}
	}

	if tapeJobs > 0 {
		if encryptedTapeJobs == tapeJobs {
			score = maxScore
			status = "pass"
			description = fmt.Sprintf("All %d tape repositories encrypted", tapeJobs)
			recs = append(recs, "✓ Excellent: All tape backups are encrypted for secure offsite storage")
		} else {
			score = maxScore / 2
			status = "warning"
			description = fmt.Sprintf("%d of %d tape repositories encrypted", encryptedTapeJobs, tapeJobs)
			recs = append(recs, "⚠ Some tape repositories lack encryption - secure all tapes for offsite storage")
		}
	} else {
		score = 0
		recs = append(recs, "💡 Consider implementing tape backups for long-term archival and air-gapped storage")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Tape Security Compliance",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// checkCloudTierCompliance checks for proper cloud tier configuration
func checkCloudTierCompliance(data models.VeeamData) (int, []string, models.SecurityCheck) {
	maxScore := 10
	score := 0
	recs := []string{}
	status := "warning"
	description := "No cloud tier configured"

	cloudRepos := 0
	secureCloudRepos := 0

	for _, repo := range data.Repositories {
		if repoMap, ok := repo.(map[string]interface{}); ok {
			if isCloudRepository(repoMap) {
				cloudRepos++
				if checkCloudSecurity(repoMap) {
					secureCloudRepos++
				}
			}
		}
	}

	if cloudRepos > 0 {
		securityRatio := float64(secureCloudRepos) / float64(cloudRepos)
		if securityRatio >= 0.8 {
			score = maxScore
			status = "pass"
			description = fmt.Sprintf("%d of %d cloud repositories properly secured", secureCloudRepos, cloudRepos)
			recs = append(recs, "✓ Cloud repositories are properly configured with security controls")
		} else {
			score = int(float64(maxScore) * securityRatio)
			status = "warning"
			description = fmt.Sprintf("%d of %d cloud repositories properly secured", secureCloudRepos, cloudRepos)
			recs = append(recs, "⚠ Review cloud repository security settings (encryption, access controls)")
		}
	} else {
		score = 0
		recs = append(recs, "💡 Consider cloud tiering for cost-effective long-term storage")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Cloud Tier Security",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// checkBackupCopyCompliance checks for proper backup copy job configuration
func checkBackupCopyCompliance(data models.VeeamData) (int, []string, models.SecurityCheck) {
	maxScore := 15
	score := 0
	recs := []string{}
	status := "fail"
	description := "No backup copy jobs found"

	backupCopyJobs := 0
	encryptedCopyJobs := 0
	offsiteCopyJobs := 0

	for _, job := range data.BackupJobs {
		if jobType, exists := job["type"].(string); exists {
			if strings.Contains(strings.ToLower(jobType), "copy") {
				backupCopyJobs++

				// Check if copy job uses encryption
				if checkJobEncryption(job) {
					encryptedCopyJobs++
				}

				// Check if copy job targets offsite repository
				if checkJobOffsiteTarget(job, data.Repositories) {
					offsiteCopyJobs++
				}
			}
		}
	}

	if backupCopyJobs > 0 {
		// Calculate score based on encryption and offsite ratios
		encryptionRatio := float64(encryptedCopyJobs) / float64(backupCopyJobs)
		offsiteRatio := float64(offsiteCopyJobs) / float64(backupCopyJobs)

		totalRatio := (encryptionRatio + offsiteRatio) / 2

		if totalRatio >= 0.8 {
			score = maxScore
			status = "pass"
			description = fmt.Sprintf("%d backup copy jobs with good security", backupCopyJobs)
			recs = append(recs, "✓ Backup copy jobs properly configured for security and offsite storage")
		} else if totalRatio >= 0.5 {
			score = int(float64(maxScore) * 0.7)
			status = "warning"
			description = fmt.Sprintf("%d backup copy jobs need security improvements", backupCopyJobs)
			recs = append(recs, "⚠ Improve backup copy job security (encryption and offsite targets)")
		} else {
			score = int(float64(maxScore) * 0.3)
			status = "warning"
			description = fmt.Sprintf("%d backup copy jobs with poor security", backupCopyJobs)
			recs = append(recs, "🚨 Critical: Backup copy jobs lack proper encryption and offsite configuration")
		}
	} else {
		recs = append(recs, "🚨 Critical: No backup copy jobs found - implement for 3-2-1 compliance")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Backup Copy Compliance",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// checkRetentionPolicyCompliance checks for proper retention policies
func checkRetentionPolicyCompliance(data models.VeeamData) (int, []string, models.SecurityCheck) {
	maxScore := 10
	score := 0
	recs := []string{}
	status := "warning"
	description := "Retention policies need review"

	jobsWithGoodRetention := 0
	totalJobs := len(data.BackupJobs)

	for _, job := range data.BackupJobs {
		if hasProperRetention(job) {
			jobsWithGoodRetention++
		}
	}

	if totalJobs > 0 {
		retentionRatio := float64(jobsWithGoodRetention) / float64(totalJobs)

		if retentionRatio >= 0.9 {
			score = maxScore
			status = "pass"
			description = fmt.Sprintf("%d of %d jobs have proper retention", jobsWithGoodRetention, totalJobs)
			recs = append(recs, "✓ Good retention policies configured across backup jobs")
		} else if retentionRatio >= 0.7 {
			score = int(float64(maxScore) * 0.8)
			status = "warning"
			description = fmt.Sprintf("%d of %d jobs have proper retention", jobsWithGoodRetention, totalJobs)
			recs = append(recs, "⚠ Some jobs need better retention policies")
		} else {
			score = int(float64(maxScore) * 0.4)
			status = "fail"
			description = fmt.Sprintf("Only %d of %d jobs have proper retention", jobsWithGoodRetention, totalJobs)
			recs = append(recs, "🚨 Many jobs lack proper retention policies - review for compliance")
		}
	}

	return score, recs, models.SecurityCheck{
		Name:        "Retention Policy Compliance",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// checkReplicationCompliance checks for proper replication configuration
func checkReplicationCompliance(data models.VeeamData) (int, []string, models.SecurityCheck) {
	maxScore := 10
	score := 0
	recs := []string{}
	status := "warning"
	description := "No replication jobs found"

	replicationJobs := 0
	encryptedReplicationJobs := 0

	for _, job := range data.BackupJobs {
		if jobType, exists := job["type"].(string); exists {
			if strings.Contains(strings.ToLower(jobType), "replication") {
				replicationJobs++
				if checkJobEncryption(job) {
					encryptedReplicationJobs++
				}
			}
		}
	}

	if replicationJobs > 0 {
		encryptionRatio := float64(encryptedReplicationJobs) / float64(replicationJobs)

		if encryptionRatio >= 0.8 {
			score = maxScore
			status = "pass"
			description = fmt.Sprintf("%d replication jobs properly secured", replicationJobs)
			recs = append(recs, "✓ Replication jobs properly encrypted for secure DR")
		} else {
			score = int(float64(maxScore) * encryptionRatio)
			status = "warning"
			description = fmt.Sprintf("%d of %d replication jobs encrypted", encryptedReplicationJobs, replicationJobs)
			recs = append(recs, "⚠ Enable encryption for all replication jobs")
		}
	} else {
		score = 0
		recs = append(recs, "💡 Consider VM replication for faster disaster recovery")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Replication Security",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// checkLicenseCompliance checks for proper Veeam licensing
func checkLicenseCompliance(licenseInfo map[string]interface{}) (int, []string, models.SecurityCheck) {
	maxScore := 5
	score := 0
	recs := []string{}
	status := "warning"
	description := "License information unavailable"

	if licenseInfo == nil || licenseInfo["status"] == "unavailable" {
		recs = append(recs, "💡 License information not accessible via API")
		return score, recs, models.SecurityCheck{
			Name:        "License Compliance",
			Score:       score,
			MaxScore:    maxScore,
			Status:      status,
			Description: description,
		}
	}

	// Check license validity and features
	if licenseData, exists := licenseInfo["data"].([]interface{}); exists && len(licenseData) > 0 {
		validLicenses := 0
		totalLicenses := len(licenseData)

		for _, license := range licenseData {
			if licenseMap, ok := license.(map[string]interface{}); ok {
				if status, exists := licenseMap["status"].(string); exists {
					if strings.ToLower(status) == "valid" || strings.ToLower(status) == "active" {
						validLicenses++
					}
				}
			}
		}

		if validLicenses == totalLicenses {
			score = maxScore
			status = "pass"
			description = fmt.Sprintf("All %d licenses valid", totalLicenses)
			recs = append(recs, "✓ All Veeam licenses are valid and active")
		} else {
			score = maxScore / 2
			status = "warning"
			description = fmt.Sprintf("%d of %d licenses valid", validLicenses, totalLicenses)
			recs = append(recs, "⚠ Some Veeam licenses may be expired or invalid")
		}
	}

	return score, recs, models.SecurityCheck{
		Name:        "License Compliance",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// checkSecurityAlarms analyzes current security-related alarms
func checkSecurityAlarms(alarms []interface{}) (int, []string, models.SecurityCheck) {
	maxScore := 10
	score := maxScore // Start with full score, deduct for issues
	recs := []string{}
	status := "pass"
	description := "No security alarms detected"

	securityAlarms := 0
	criticalAlarms := 0

	for _, alarm := range alarms {
		if alarmMap, ok := alarm.(map[string]interface{}); ok {
			alarmType := ""
			severity := ""

			if aType, exists := alarmMap["type"].(string); exists {
				alarmType = strings.ToLower(aType)
			}

			if sev, exists := alarmMap["severity"].(string); exists {
				severity = strings.ToLower(sev)
			}

			// Check for security-related alarms
			if strings.Contains(alarmType, "security") ||
				strings.Contains(alarmType, "encryption") ||
				strings.Contains(alarmType, "credential") ||
				strings.Contains(alarmType, "authentication") {
				securityAlarms++

				if severity == "critical" || severity == "error" {
					criticalAlarms++
				}
			}
		}
	}

	if securityAlarms > 0 {
		if criticalAlarms > 0 {
			score = 0
			status = "fail"
			description = fmt.Sprintf("%d security alarms (%d critical)", securityAlarms, criticalAlarms)
			recs = append(recs, fmt.Sprintf("🚨 Critical: %d critical security alarms need immediate attention", criticalAlarms))
		} else {
			score = maxScore / 2
			status = "warning"
			description = fmt.Sprintf("%d non-critical security alarms", securityAlarms)
			recs = append(recs, fmt.Sprintf("⚠ %d security-related alarms detected", securityAlarms))
		}
	} else {
		recs = append(recs, "✓ No security-related alarms detected")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Security Alarms",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// checkBackupSuccessRate analyzes recent backup success rates
func checkBackupSuccessRate(sessions []interface{}) (int, []string, models.SecurityCheck) {
	maxScore := 10
	score := 0
	recs := []string{}
	status := "warning"
	description := "Unable to analyze backup sessions"

	if len(sessions) == 0 {
		recs = append(recs, "💡 No recent backup sessions found for analysis")
		return score, recs, models.SecurityCheck{
			Name:        "Backup Success Rate",
			Score:       score,
			MaxScore:    maxScore,
			Status:      status,
			Description: description,
		}
	}

	successfulSessions := 0
	failedSessions := 0
	warningSessions := 0

	// Analyze recent sessions (limit to last 50 for performance)
	sessionLimit := min(len(sessions), 50)

	for i := 0; i < sessionLimit; i++ {
		if sessionMap, ok := sessions[i].(map[string]interface{}); ok {
			if result, exists := sessionMap["result"].(string); exists {
				switch strings.ToLower(result) {
				case "success":
					successfulSessions++
				case "warning":
					warningSessions++
				case "failed", "error":
					failedSessions++
				}
			}
		}
	}

	totalSessions := successfulSessions + warningSessions + failedSessions
	if totalSessions > 0 {
		successRate := float64(successfulSessions) / float64(totalSessions)

		if successRate >= 0.95 {
			score = maxScore
			status = "pass"
			description = fmt.Sprintf("%.1f%% success rate (%d/%d sessions)", successRate*100, successfulSessions, totalSessions)
			recs = append(recs, "✓ Excellent backup success rate")
		} else if successRate >= 0.80 {
			score = int(float64(maxScore) * 0.8)
			status = "warning"
			description = fmt.Sprintf("%.1f%% success rate (%d/%d sessions)", successRate*100, successfulSessions, totalSessions)
			recs = append(recs, "⚠ Some backup failures detected - review failed jobs")
		} else {
			score = int(float64(maxScore) * 0.4)
			status = "fail"
			description = fmt.Sprintf("%.1f%% success rate (%d/%d sessions)", successRate*100, successfulSessions, totalSessions)
			recs = append(recs, "🚨 Poor backup success rate - immediate attention required")
		}

		if failedSessions > 0 {
			recs = append(recs, fmt.Sprintf("📊 Recent sessions: %d successful, %d warnings, %d failed", successfulSessions, warningSessions, failedSessions))
		}
	}

	return score, recs, models.SecurityCheck{
		Name:        "Backup Success Rate",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// checkAuditingCompliance checks for proper audit logging
func checkAuditingCompliance(auditItems []interface{}) (int, []string, models.SecurityCheck) {
	maxScore := 10
	score := 0
	recs := []string{}
	status := "warning"
	description := "Audit logging assessment"

	if len(auditItems) == 0 {
		score = 0
		status = "fail"
		description = "No audit items found"
		recs = append(recs, "🚨 No audit logging detected - enable audit logging for security compliance")
		return score, recs, models.SecurityCheck{
			Name:        "Audit Logging",
			Score:       score,
			MaxScore:    maxScore,
			Status:      status,
			Description: description,
		}
	}

	// Check for comprehensive audit coverage
	securityEvents := 0
	adminEvents := 0

	// Analyze recent audit items (limit for performance)
	auditLimit := min(len(auditItems), 100)

	for i := 0; i < auditLimit; i++ {
		if auditMap, ok := auditItems[i].(map[string]interface{}); ok {
			if eventType, exists := auditMap["type"].(string); exists {
				eventTypeLower := strings.ToLower(eventType)

				if strings.Contains(eventTypeLower, "security") ||
					strings.Contains(eventTypeLower, "authentication") ||
					strings.Contains(eventTypeLower, "authorization") {
					securityEvents++
				}

				if strings.Contains(eventTypeLower, "admin") ||
					strings.Contains(eventTypeLower, "configuration") ||
					strings.Contains(eventTypeLower, "settings") {
					adminEvents++
				}
			}
		}
	}

	// Score based on audit coverage
	if securityEvents > 5 && adminEvents > 5 {
		score = maxScore
		status = "pass"
		description = "Comprehensive audit logging active"
		recs = append(recs, "✓ Good audit logging coverage for security and administrative events")
	} else if securityEvents > 0 || adminEvents > 0 {
		score = maxScore / 2
		status = "warning"
		description = "Limited audit logging detected"
		recs = append(recs, "⚠ Audit logging present but may need expanded coverage")
	} else {
		score = maxScore / 4
		status = "warning"
		description = "Basic audit logging only"
		recs = append(recs, "💡 Consider expanding audit logging for better security visibility")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Audit Logging",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

// Helper functions
func checkTapeEncryption(repo map[string]interface{}) bool {
	// Check for tape encryption settings
	if encryption, exists := repo["encryption"]; exists {
		if encMap, ok := encryption.(map[string]interface{}); ok {
			if enabled, exists := encMap["enabled"].(bool); exists && enabled {
				return true
			}
		}
	}
	return false
}

func isCloudRepository(repo map[string]interface{}) bool {
	if repoType, exists := repo["type"].(string); exists {
		lowerType := strings.ToLower(repoType)
		return strings.Contains(lowerType, "cloud") ||
			strings.Contains(lowerType, "s3") ||
			strings.Contains(lowerType, "azure") ||
			strings.Contains(lowerType, "gcp")
	}

	if name, exists := repo["name"].(string); exists {
		lowerName := strings.ToLower(name)
		return strings.Contains(lowerName, "cloud") ||
			strings.Contains(lowerName, "s3") ||
			strings.Contains(lowerName, "azure") ||
			strings.Contains(lowerName, "aws")
	}

	return false
}

func checkCloudSecurity(repo map[string]interface{}) bool {
	// Check for encryption and immutability
	hasEncryption := false
	hasImmutability := false

	// Check encryption
	if encryption, exists := repo["encryption"]; exists {
		if encMap, ok := encryption.(map[string]interface{}); ok {
			if enabled, exists := encMap["enabled"].(bool); exists && enabled {
				hasEncryption = true
			}
		}
	}

	// Check immutability for cloud repos
	if bucket, exists := repo["bucket"].(map[string]interface{}); exists {
		if immutability, exists := bucket["immutability"].(map[string]interface{}); exists {
			if isEnabled, exists := immutability["isEnabled"].(bool); exists && isEnabled {
				hasImmutability = true
			}
		}
	}

	return hasEncryption && hasImmutability
}

func checkJobEncryption(job map[string]interface{}) bool {
	// Check for job-level encryption settings
	if settings, exists := job["settings"].(map[string]interface{}); exists {
		if encryption, exists := settings["encryption"]; exists {
			if encMap, ok := encryption.(map[string]interface{}); ok {
				if enabled, exists := encMap["enabled"].(bool); exists && enabled {
					return true
				}
			}
		}
	}
	return false
}

func checkJobOffsiteTarget(job map[string]interface{}, repositories []interface{}) bool {
	if repoId, exists := job["repositoryId"].(string); exists {
		for _, repo := range repositories {
			if repoMap, ok := repo.(map[string]interface{}); ok {
				if id, exists := repoMap["id"].(string); exists && id == repoId {
					return isOffsiteRepository(repoMap)
				}
			}
		}
	}
	return false
}

func hasProperRetention(job map[string]interface{}) bool {
	if settings, exists := job["settings"].(map[string]interface{}); exists {
		if retention, exists := settings["retention"]; exists {
			if retMap, ok := retention.(map[string]interface{}); ok {
				// Check for reasonable retention periods (at least 30 days)
				if days, exists := retMap["days"].(float64); exists && days >= 30 {
					return true
				}
				if restorePoints, exists := retMap["restorePoints"].(float64); exists && restorePoints >= 14 {
					return true
				}
			}
		}
	}
	return false
}

// Note: isOffsiteRepository is defined in scoring.go
