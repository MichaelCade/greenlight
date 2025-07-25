package checks

import (
	"fmt"
	"greenlight/models"
	"strings"
)

func checkCredentialSecurity(credentials []interface{}) (int, []string, models.SecurityCheck) {
	maxScore := 15
	score := 0
	recs := []string{}
	status := "fail"
	description := "No credentials configured"

	if len(credentials) == 0 {
		recs = append(recs, "No credentials configured.")
		return score, recs, models.SecurityCheck{
			Name:        "Credential Security",
			Score:       score,
			MaxScore:    maxScore,
			Status:      status,
			Description: description,
		}
	}

	serviceAccounts := 0
	for _, cred := range credentials {
		if credMap, ok := cred.(map[string]interface{}); ok {
			if username, exists := credMap["username"].(string); exists {
				if isServiceAccount(username) {
					serviceAccounts++
				}
			}
		}
	}

	serviceAccountRatio := float64(serviceAccounts) / float64(len(credentials))

	if serviceAccountRatio >= 0.8 {
		score = maxScore
		status = "pass"
		description = "Most credentials are service accounts"
		recs = append(recs, "Good credential hygiene: most credentials appear to be service accounts.")
	} else if serviceAccountRatio >= 0.5 {
		score = int(float64(maxScore) * 0.7)
		status = "warning"
		description = fmt.Sprintf("%.0f%% credentials are service accounts", serviceAccountRatio*100)
		recs = append(recs, "Consider using more dedicated service accounts for backup operations.")
	} else {
		score = int(float64(maxScore) * 0.3)
		status = "warning"
		description = "Few service accounts detected"
		recs = append(recs, "Consider using dedicated service accounts instead of personal accounts for backup operations.")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Credential Security",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

func isServiceAccount(username string) bool {
	serviceIndicators := []string{"svc", "service", "backup", "veeam", "sa-", "srv", "admin"}
	username = strings.ToLower(username)

	for _, indicator := range serviceIndicators {
		if strings.Contains(username, indicator) {
			return true
		}
	}
	return false
}
