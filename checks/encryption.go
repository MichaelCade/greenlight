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

	for _, job := range jobs {
		if checkBoolField(job, "encryptionEnabled") ||
			checkBoolField(job, "isEncrypted") ||
			checkBoolField(job, "encrypted") {
			encryptedJobs++
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
			description = "All backup jobs have encryption enabled"
			recs = append(recs, description)
		} else if encryptionRatio >= 0.8 {
			score = int(float64(maxScore) * 0.8)
			status = "warning"
			description = fmt.Sprintf("%.0f%% of backup jobs have encryption enabled", encryptionRatio*100)
			recs = append(recs, description+". Consider encrypting all jobs for better security.")
		} else if encryptionRatio >= 0.5 {
			score = int(float64(maxScore) * 0.5)
			status = "warning"
			description = fmt.Sprintf("%.0f%% of backup jobs have encryption enabled", encryptionRatio*100)
			recs = append(recs, description+". Increase encryption coverage for better protection.")
		} else {
			description = "Low encryption coverage detected"
			recs = append(recs, "Low encryption coverage. Encrypt backup jobs for better security.")
		}
	}

	return score, recs, models.SecurityCheck{
		Name:        "Backup Encryption",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}
