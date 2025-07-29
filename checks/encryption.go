package checks

import (
	"fmt"
	"greenlight/models"
)

func checkEncryption(jobs []map[string]interface{}) (int, []string, models.SecurityCheck) {
	maxScore := 20
	score := 0
	recs := []string{}
	encryptedJobs := 0
	encryptionDetails := []string{}

	for i, job := range jobs {
		jobName := fmt.Sprintf("Job %d", i+1)
		if name, exists := job["name"].(string); exists {
			jobName = name
		}

		isEncrypted := false
		encryptionMethod := "None"

		// Check various encryption fields
		if checkBoolField(job, "encryptionEnabled") {
			isEncrypted = true
			encryptionMethod = "Enabled"
		} else if checkBoolField(job, "isEncrypted") {
			isEncrypted = true
			encryptionMethod = "Enabled"
		} else if checkBoolField(job, "encrypted") {
			isEncrypted = true
			encryptionMethod = "Enabled"
		}

		// Check for specific encryption settings
		if encSettings, exists := job["encryptionSettings"].(map[string]interface{}); exists {
			if enabled, ok := encSettings["enabled"].(bool); ok && enabled {
				isEncrypted = true
				if algorithm, ok := encSettings["algorithm"].(string); ok {
					encryptionMethod = fmt.Sprintf("Enabled (%s)", algorithm)
				}
			}
		}

		if isEncrypted {
			encryptedJobs++
			encryptionDetails = append(encryptionDetails, fmt.Sprintf("✅ %s: %s", jobName, encryptionMethod))
		} else {
			encryptionDetails = append(encryptionDetails, fmt.Sprintf("❌ %s: No encryption", jobName))
		}
	}

	status := "fail"
	description := "No encryption configured"

	if len(jobs) == 0 {
		description = "No backup jobs to evaluate"
	} else {
		encryptionRatio := float64(encryptedJobs) / float64(len(jobs))

		if encryptionRatio >= 1.0 {
			score = maxScore
			status = "pass"
			description = fmt.Sprintf("All %d backup jobs have encryption enabled", len(jobs))
			recs = append(recs, "🔒 All backup jobs properly encrypted")
		} else if encryptionRatio >= 0.8 {
			score = int(float64(maxScore) * 0.8)
			status = "warning"
			description = fmt.Sprintf("%d of %d jobs (%.0f%%) have encryption enabled", encryptedJobs, len(jobs), encryptionRatio*100)
			recs = append(recs, fmt.Sprintf("⚠️ %d jobs still need encryption enabled", len(jobs)-encryptedJobs))
		} else if encryptionRatio >= 0.5 {
			score = int(float64(maxScore) * 0.5)
			status = "warning"
			description = fmt.Sprintf("%d of %d jobs (%.0f%%) have encryption enabled", encryptedJobs, len(jobs), encryptionRatio*100)
			recs = append(recs, fmt.Sprintf("🚨 URGENT: %d jobs without encryption - vulnerable to data theft", len(jobs)-encryptedJobs))
		} else {
			description = fmt.Sprintf("Critical: Only %d of %d jobs encrypted", encryptedJobs, len(jobs))
			recs = append(recs, fmt.Sprintf("🚨 CRITICAL: %d jobs completely unencrypted - immediate security risk", len(jobs)-encryptedJobs))
		}

		// Add detailed breakdown
		recs = append(recs, "=== Encryption Status by Job ===")
		recs = append(recs, encryptionDetails...)
		recs = append(recs, "📋 Recommendation: Enable AES-256 encryption on all backup jobs")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Backup Encryption",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}
