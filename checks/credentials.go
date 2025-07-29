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
	adminAccounts := 0
	credentialDetails := []string{}
	securityIssues := []string{}

	for i, cred := range credentials {
		if credMap, ok := cred.(map[string]interface{}); ok {
			credName := fmt.Sprintf("Credential %d", i+1)
			username := "Unknown"

			if name, exists := credMap["name"].(string); exists {
				credName = name
			}
			if user, exists := credMap["username"].(string); exists {
				username = user
			}

			// Analyze credential type and security
			isServiceAcc := isServiceAccount(username)
			isAdmin := isAdminAccount(username)

			if isServiceAcc {
				serviceAccounts++
				credentialDetails = append(credentialDetails, fmt.Sprintf("✅ %s: Service account (%s)", credName, username))
			} else if isAdmin {
				adminAccounts++
				credentialDetails = append(credentialDetails, fmt.Sprintf("⚠️ %s: Admin account (%s)", credName, username))
				securityIssues = append(securityIssues, fmt.Sprintf("Admin account '%s' should be replaced with dedicated service account", username))
			} else {
				credentialDetails = append(credentialDetails, fmt.Sprintf("❌ %s: Regular user account (%s)", credName, username))
				securityIssues = append(securityIssues, fmt.Sprintf("User account '%s' should be replaced with dedicated service account", username))
			}

			// Check for other security indicators
			if description, exists := credMap["description"].(string); exists {
				if strings.Contains(strings.ToLower(description), "test") ||
					strings.Contains(strings.ToLower(description), "temp") {
					securityIssues = append(securityIssues, fmt.Sprintf("Credential '%s' appears to be temporary - review and clean up", credName))
				}
			}
		}
	}

	serviceAccountRatio := float64(serviceAccounts) / float64(len(credentials))

	if serviceAccountRatio >= 0.8 {
		score = maxScore
		status = "pass"
		description = fmt.Sprintf("%d of %d credentials are service accounts (%.0f%%)", serviceAccounts, len(credentials), serviceAccountRatio*100)
		recs = append(recs, "🔒 Excellent credential hygiene: majority are dedicated service accounts")
	} else if serviceAccountRatio >= 0.5 {
		score = int(float64(maxScore) * 0.7)
		status = "warning"
		description = fmt.Sprintf("%d of %d credentials are service accounts (%.0f%%)", serviceAccounts, len(credentials), serviceAccountRatio*100)
		recs = append(recs, fmt.Sprintf("⚠️ Consider converting %d user/admin accounts to dedicated service accounts", len(credentials)-serviceAccounts))
	} else {
		score = int(float64(maxScore) * 0.3)
		status = "fail"
		description = fmt.Sprintf("Poor credential security: only %d of %d are service accounts", serviceAccounts, len(credentials))
		recs = append(recs, fmt.Sprintf("🚨 SECURITY RISK: %d accounts need to be converted to service accounts", len(credentials)-serviceAccounts))
	}

	// Add detailed recommendations
	recs = append(recs, "=== Credential Analysis ===")
	recs = append(recs, credentialDetails...)

	if len(securityIssues) > 0 {
		recs = append(recs, "=== Security Issues Found ===")
		recs = append(recs, securityIssues...)
	}

	recs = append(recs, "📋 Best Practice: Use dedicated service accounts with minimal required permissions")

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

func isAdminAccount(username string) bool {
	adminIndicators := []string{"admin", "administrator", "root", "sa", "sysadmin"}
	username = strings.ToLower(username)

	for _, indicator := range adminIndicators {
		if strings.Contains(username, indicator) {
			return true
		}
	}
	return false
}
