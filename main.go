package main

import (
	"context"
	"fmt"
	"greenlight/api"
	"greenlight/checks"
	"greenlight/web"
	"log"
	"os"
	"runtime"
)

func main() {
	// Configuration - get from environment variables
	veeamURL := os.Getenv("VEEAM_SERVER")
	if veeamURL == "" {
		veeamURL = os.Getenv("VEEAM_URL") // Fallback to VEEAM_URL
	}
	if veeamURL == "" {
		log.Fatal("Please set VEEAM_SERVER or VEEAM_URL environment variable")
	}

	username := os.Getenv("VEEAM_USERNAME")
	if username == "" {
		log.Fatal("Please set VEEAM_USERNAME environment variable")
	}

	password := os.Getenv("VEEAM_PASSWORD")
	if password == "" {
		log.Fatal("Please set VEEAM_PASSWORD environment variable")
	}

	fmt.Printf("Collecting data from Veeam Backup & Replication API: %s\n", veeamURL)

	// Collect data from Veeam API
	data, err := api.CollectVeeamData(context.Background(), veeamURL, username, password, true)
	if err != nil {
		log.Fatalf("Failed to collect Veeam data: %v", err)
	}

	if runtime.GOOS == "windows" {
		fmt.Println("Collecting enhanced PowerShell data...")
		psData, err := checks.GetVeeamPowerShellData(veeamURL)
		if err != nil {
			fmt.Printf("Warning: PowerShell data collection failed: %v\n", err)
		} else {
			data.PowerShellData = psData
			fmt.Println("✓ PowerShell data collected successfully")
		}
	} else {
		fmt.Println("Note: PowerShell checks not available on non-Windows platforms")
	}

	// Run security checks
	result := checks.RunAllChecks(data)

	fmt.Printf("Total security checks found: %d\n", len(result.SecurityChecks))
	fmt.Printf("PowerShell data available: %v\n", data.PowerShellData != nil)
	if data.PowerShellData != nil {
		fmt.Printf("PowerShell repositories found: %d\n", len(data.PowerShellData.RepositoryDetails))
		fmt.Printf("API repositories found: %d\n", len(data.Repositories))
	}

	for key, check := range result.SecurityChecks {
		fmt.Printf("- %s: %s (%d/%d points)\n", key, check.Name, check.Score, check.MaxScore)
	}

	// Start web server
	server := web.NewServer(result)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start web server: %v", err)
	}
}
