package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"greenlight/models"
	"io"
	"net/http"
	"strings"
	"time"
)

func CollectVeeamData(ctx context.Context, baseURL, username, password string, ignoreSSL ...bool) (models.VeeamData, error) {
	var data models.VeeamData

	skipTLS := len(ignoreSSL) > 0 && ignoreSSL[0]
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS},
		},
	}

	// Authenticate and get token
	token, err := authenticate(baseURL, username, password, client)
	if err != nil {
		return data, fmt.Errorf("authentication failed: %v", err)
	}

	// Collect data from various endpoints
	data.ServerInfo, _ = getServerInfo(baseURL, token, client)

	// Get enhanced server information including database details
	if serverInfo, err := getEnhancedServerInfo(baseURL, token, client); err == nil {
		// Merge enhanced info with basic server info
		if data.ServerInfo == nil {
			data.ServerInfo = make(map[string]interface{})
		}
		for key, value := range serverInfo {
			data.ServerInfo[key] = value
		}
	}

	// Collect extended information for comprehensive analysis
	data.HealthInfo, _ = GetVeeamServerHealth(baseURL, token, client)
	data.LicenseInfo, _ = GetVeeamLicenseInfo(baseURL, token, client)
	data.AuditItems, _ = GetVeeamAuditItems(baseURL, token, client)
	data.Alarms, _ = GetVeeamAlarms(baseURL, token, client)
	data.Sessions, _ = GetVeeamSessions(baseURL, token, client)

	data.Credentials, _ = getCredentials(baseURL, token, client)
	data.CloudCredentials, _ = getCloudCredentials(baseURL, token, client)
	data.KMSServers, _ = getKMSServers(baseURL, token, client)
	data.ManagedServers, _ = getManagedServers(baseURL, token, client)
	data.Repositories, _ = getRepositories(baseURL, token, client)
	data.ScaleOutRepositories, _ = getScaleOutRepositories(baseURL, token, client)
	data.Proxies, _ = getProxies(baseURL, token, client)
	data.BackupJobs, _ = getBackupJobs(baseURL, token, client)

	return data, nil
}

func authenticate(baseURL, username, password string, client *http.Client) (string, error) {
	authURL := fmt.Sprintf("%s/api/oauth2/token", baseURL)

	payload := strings.NewReader(fmt.Sprintf("grant_type=password&username=%s&password=%s", username, password))

	req, err := http.NewRequest("POST", authURL, payload)
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("x-api-version", "1.1-rev2")
	req.Header.Add("accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var authResp struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", err
	}

	return authResp.AccessToken, nil
}

func getAPIList(url, token string, client *http.Client) ([]interface{}, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("x-api-version", "1.1-rev2")
	req.Header.Add("accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data []interface{} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.Data, nil
}

func getAPIObject(url, token string, client *http.Client) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("x-api-version", "1.1-rev2")
	req.Header.Add("accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// getEnhancedServerInfo collects detailed server information including database details
func getEnhancedServerInfo(baseURL, token string, client *http.Client) (map[string]interface{}, error) {
	enhancedInfo := make(map[string]interface{})

	// Get basic server info
	serverInfo, err := getAPIObject(fmt.Sprintf("%s/api/v1/serverInfo", baseURL), token, client)
	if err != nil {
		return enhancedInfo, err
	}

	// Extract server details from the response
	if name, exists := serverInfo["name"]; exists {
		enhancedInfo["serverName"] = name
	}
	if buildVersion, exists := serverInfo["buildVersion"]; exists {
		enhancedInfo["buildVersion"] = buildVersion
	}
	if vbrId, exists := serverInfo["vbrId"]; exists {
		enhancedInfo["vbrId"] = vbrId
	}

	// Extract database information
	if databaseVendor, exists := serverInfo["databaseVendor"]; exists {
		enhancedInfo["databaseVendor"] = databaseVendor
	}
	if sqlServerVersion, exists := serverInfo["sqlServerVersion"]; exists {
		enhancedInfo["sqlServerVersion"] = sqlServerVersion
	}
	if sqlServerEdition, exists := serverInfo["sqlServerEdition"]; exists && sqlServerEdition != "" {
		enhancedInfo["sqlServerEdition"] = sqlServerEdition
	}

	// Add additional database metadata if available
	if databaseContentVersion, exists := serverInfo["databaseContentVersion"]; exists {
		enhancedInfo["databaseContentVersion"] = databaseContentVersion
	}
	if databaseSchemaVersion, exists := serverInfo["databaseSchemaVersion"]; exists {
		enhancedInfo["databaseSchemaVersion"] = databaseSchemaVersion
	}

	return enhancedInfo, nil
}

// getDatabaseInfo attempts to get database configuration details
func getServerInfo(baseURL, token string, client *http.Client) (map[string]interface{}, error) {
	return getAPIObject(fmt.Sprintf("%s/api/v1/serverInfo", baseURL), token, client)
}

func getCredentials(baseURL, token string, client *http.Client) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/credentials", baseURL), token, client)
}

func getCloudCredentials(baseURL, token string, client *http.Client) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/cloudCredentials", baseURL), token, client)
}

func getKMSServers(baseURL, token string, client *http.Client) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/kmsServers", baseURL), token, client)
}

func getManagedServers(baseURL, token string, client *http.Client) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/managedServers", baseURL), token, client)
}

func getRepositories(baseURL, token string, client *http.Client) ([]interface{}, error) {
	// First get the list of repositories
	repositories, err := getAPIList(fmt.Sprintf("%s/api/v1/backupInfrastructure/repositories", baseURL), token, client)
	if err != nil {
		return nil, err
	}

	// Then get detailed info for each repository
	detailedRepos := make([]interface{}, 0, len(repositories))

	for _, repo := range repositories {
		if repoMap, ok := repo.(map[string]interface{}); ok {
			if id, exists := repoMap["id"].(string); exists {
				// Get detailed repository information
				detailedRepo, err := getRepositoryDetails(baseURL, id, token, client)
				if err != nil {
					fmt.Printf("Warning: Could not get details for repository %s: %v\n", id, err)
					// Use basic info if detailed fetch fails
					detailedRepos = append(detailedRepos, repo)
				} else {
					detailedRepos = append(detailedRepos, detailedRepo)
				}
			}
		}
	}

	return detailedRepos, nil
}

func getRepositoryDetails(baseURL, repoID, token string, client *http.Client) (map[string]interface{}, error) {
	return getAPIObject(fmt.Sprintf("%s/api/v1/backupInfrastructure/repositories/%s", baseURL, repoID), token, client)
}

func getScaleOutRepositories(baseURL, token string, client *http.Client) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/backupInfrastructure/scaleOutRepositories", baseURL), token, client)
}

func getProxies(baseURL, token string, client *http.Client) ([]interface{}, error) {
	return getAPIList(fmt.Sprintf("%s/api/v1/backupInfrastructure/proxies", baseURL), token, client)
}

func getBackupJobs(baseURL, token string, client *http.Client) ([]map[string]interface{}, error) {
	data, err := getAPIList(fmt.Sprintf("%s/api/v1/jobs", baseURL), token, client)
	if err != nil {
		return nil, err
	}

	// Convert to []map[string]interface{}
	result := make([]map[string]interface{}, len(data))
	for i, item := range data {
		if itemMap, ok := item.(map[string]interface{}); ok {
			result[i] = itemMap
		}
	}

	return result, nil
}
