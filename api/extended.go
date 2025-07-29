package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// GetVeeamServerHealth checks the overall health of the Veeam server
func GetVeeamServerHealth(baseURL, token string, client *http.Client) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/serverHealthAnalyzer", baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("x-api-version", "1.1-rev2")
	req.Header.Add("accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return map[string]interface{}{
			"status":  "unavailable",
			"message": "Health analyzer endpoint not available",
		}, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var health map[string]interface{}
	if err := json.Unmarshal(body, &health); err != nil {
		return nil, err
	}

	return health, nil
}

// GetVeeamLicenseInfo retrieves license information
func GetVeeamLicenseInfo(baseURL, token string, client *http.Client) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/licenses", baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("x-api-version", "1.1-rev2")
	req.Header.Add("accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return map[string]interface{}{
			"status":  "unavailable",
			"message": "License endpoint not available",
		}, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var license map[string]interface{}
	if err := json.Unmarshal(body, &license); err != nil {
		return nil, err
	}

	return license, nil
}

// GetVeeamAuditItems retrieves audit/security events
func GetVeeamAuditItems(baseURL, token string, client *http.Client) ([]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/auditItems", baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("x-api-version", "1.1-rev2")
	req.Header.Add("accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []interface{}{}, nil // Return empty array if not available
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var auditItems struct {
		Data []interface{} `json:"data"`
	}

	if err := json.Unmarshal(body, &auditItems); err != nil {
		return nil, err
	}

	return auditItems.Data, nil
}

// GetVeeamAlarms retrieves current alarms/alerts
func GetVeeamAlarms(baseURL, token string, client *http.Client) ([]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/alarms", baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("x-api-version", "1.1-rev2")
	req.Header.Add("accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []interface{}{}, nil // Return empty array if not available
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var alarms struct {
		Data []interface{} `json:"data"`
	}

	if err := json.Unmarshal(body, &alarms); err != nil {
		return nil, err
	}

	return alarms.Data, nil
}

// GetVeeamSessions retrieves recent backup sessions for analysis
func GetVeeamSessions(baseURL, token string, client *http.Client) ([]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/sessions", baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("x-api-version", "1.1-rev2")
	req.Header.Add("accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []interface{}{}, nil // Return empty array if not available
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var sessions struct {
		Data []interface{} `json:"data"`
	}

	if err := json.Unmarshal(body, &sessions); err != nil {
		return nil, err
	}

	return sessions.Data, nil
}
