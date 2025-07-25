package checks

import (
	"fmt"
	"greenlight/models"
)

func checkNetworkSecurity(proxies []interface{}) (int, []string, models.SecurityCheck) {
	maxScore := 15
	score := 0
	recs := []string{}
	status := "warning"
	description := "No dedicated backup proxies found"

	if len(proxies) > 0 {
		score = maxScore
		status = "pass"
		description = fmt.Sprintf("Found %d backup proxies", len(proxies))
		recs = append(recs, fmt.Sprintf("Good network architecture: found %d backup proxies for distributed processing.", len(proxies)))
	} else {
		recs = append(recs, "No dedicated backup proxies found. Consider adding proxies for better performance and security.")
	}

	return score, recs, models.SecurityCheck{
		Name:        "Network Security",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}

func checkKMSIntegration(kmsServers []interface{}) (int, []string, models.SecurityCheck) {
	maxScore := 15
	score := 0
	recs := []string{}
	status := "warning"
	description := "No KMS integration configured"

	if len(kmsServers) > 0 {
		score = maxScore
		status = "pass"
		description = fmt.Sprintf("Found %d KMS servers", len(kmsServers))
		recs = append(recs, fmt.Sprintf("Excellent security: found %d KMS servers for enterprise key management.", len(kmsServers)))
	} else {
		recs = append(recs, "No KMS integration found. Consider implementing enterprise key management for enhanced security.")
	}

	return score, recs, models.SecurityCheck{
		Name:        "KMS Integration",
		Score:       score,
		MaxScore:    maxScore,
		Status:      status,
		Description: description,
	}
}
