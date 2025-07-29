package models

// VeeamData represents the data collected from Veeam API
type VeeamData struct {
	ServerInfo           map[string]interface{}   `json:"serverInfo"`
	HealthInfo           map[string]interface{}   `json:"healthInfo"`
	LicenseInfo          map[string]interface{}   `json:"licenseInfo"`
	AuditItems           []interface{}            `json:"auditItems"`
	Alarms               []interface{}            `json:"alarms"`
	Sessions             []interface{}            `json:"sessions"`
	Credentials          []interface{}            `json:"credentials"`
	CloudCredentials     []interface{}            `json:"cloudCredentials"`
	KMSServers           []interface{}            `json:"kmsServers"`
	ManagedServers       []interface{}            `json:"managedServers"`
	Repositories         []interface{}            `json:"repositories"`
	ScaleOutRepositories []interface{}            `json:"scaleOutRepositories"`
	Proxies              []interface{}            `json:"proxies"`
	BackupJobs           []map[string]interface{} `json:"backupJobs"`
	PowerShellData       *PowerShellData          `json:"powershellData,omitempty"`
}

// CheckResult represents the result of running all security checks
type CheckResult struct {
	JobsCount       int                      `json:"jobsCount"`
	ReposCount      int                      `json:"reposCount"`
	Score           int                      `json:"score"`
	MaxScore        int                      `json:"maxScore"`
	Recommendations []string                 `json:"recommendations"`
	SecurityChecks  map[string]SecurityCheck `json:"securityChecks"`
	FeatureChecks   map[string]SecurityCheck `json:"featureChecks"`
}

// SecurityCheck represents an individual security check result
type SecurityCheck struct {
	Name          string `json:"name"`
	Score         int    `json:"score"`
	MaxScore      int    `json:"maxScore"`
	Status        string `json:"status"` // "pass", "warning", "fail"
	Description   string `json:"description"`
	CanRemediate  bool   `json:"canRemediate"`            // Whether this can be fixed via PowerShell
	RemediationID int    `json:"remediationId,omitempty"` // ID for PowerShell remediation
}

type PowerShellData struct {
	DatabaseInfo      map[string]interface{} `json:"databaseInfo"`
	ServiceStatus     []interface{}          `json:"serviceStatus"`
	SecuritySettings  map[string]interface{} `json:"securitySettings"`
	RepositoryDetails []interface{}          `json:"repositoryDetails"`
	JobSecurity       []interface{}          `json:"jobSecurity"`
	SystemHealth      map[string]interface{} `json:"systemHealth"`
	AuditSettings     map[string]interface{} `json:"auditSettings"`
	ComplianceReport  map[string]interface{} `json:"complianceReport"` // New field
}
