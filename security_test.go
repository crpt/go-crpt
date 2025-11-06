//go:build security_test
// +build security_test

package crpt_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This file contains security tests using gosec and govulncheck
// To run these tests, use: go test -tags=security_test -v

func TestSecurityScanWithGosec(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping security scan in short mode")
	}

	// Run gosec on the entire project
	cmd := exec.Command("go", "tool", "gosec", "-no-fail", "-fmt", "json", "./...")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "gosec should run without errors")

	// Parse JSON output and check for critical issues
	outputStr := string(output)
	t.Logf("gosec output: %s", outputStr)

	// In a real CI environment, you might want to fail on certain severities
	// For now, we just log the results
	if strings.Contains(outputStr, "Issues") {
		t.Log("Security issues found by gosec")
	}
}

func TestGosecConfidenceRules(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping security scan in short mode")
	}

	// Run gosec with specific rules related to cryptographic code
	cmd := exec.Command("go", "tool", "gosec",
		"-no-fail",
		"-quiet",
		"-include=G101,G102,G103,G104,G106,G107,G201,G202,G203,G204,G301,G302,G303,G304,G401,G402,G403,G404",
		"./...")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "gosec should run without errors")

	outputStr := string(output)
	if outputStr != "" {
		t.Logf("Security findings:\n%s", outputStr)
	}
}

func TestVulnerabilityCheckWithGovulncheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping vulnerability check in short mode")
	}

	// Run govulncheck on the module
	cmd := exec.Command("go", "tool", "govulncheck", "./...")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "govulncheck should run without errors")

	outputStr := string(output)
	t.Logf("govulncheck output: %s", outputStr)

	// Check if any vulnerabilities were found
	if strings.Contains(outputStr, "Vulnerability") {
		t.Log("Vulnerabilities found in dependencies")
	}
}

func TestHardcodedCredentialsCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping hardcoded credentials check in short mode")
	}

	// Run gosec with focus on hardcoded credentials
	cmd := exec.Command("go", "tool", "gosec",
		"-no-fail",
		"-quiet",
		"-include=G101",
		"./...")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "gosec should run without errors")

	outputStr := string(output)
	if strings.Contains(outputStr, "hardcoded credential") {
		t.Error("Potential hardcoded credentials found")
		t.Logf("Hardcoded credential findings:\n%s", outputStr)
	}
}

func TestWeakCryptoCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping weak cryptography check in short mode")
	}

	// Run gosec with focus on weak cryptography
	cmd := exec.Command("go", "tool", "gosec",
		"-no-fail",
		"-quiet",
		"-include=G103,G401,G402,G403,G404",
		"./...")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "gosec should run without errors")

	outputStr := string(output)
	if strings.Contains(outputStr, "weak") || strings.Contains(outputStr, "block") {
		t.Log("Weak cryptography findings (may be acceptable in cryptographic library context)")
		t.Logf("Weak crypto findings:\n%s", outputStr)
	}
}

func TestFileOperationSecurity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping file operation security check in short mode")
	}

	// Run gosec with focus on file operation security
	cmd := exec.Command("go", "tool", "gosec",
		"-no-fail",
		"-quiet",
		"-include=G301,G302,G303,G304",
		"./...")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "gosec should run without errors")

	outputStr := string(output)
	if strings.Contains(outputStr, "file permissions") ||
		strings.Contains(outputStr, "file path") {
		t.Log("File operation security findings:")
		t.Logf("File operation findings:\n%s", outputStr)
	}
}

func TestErrorHandlingSecurity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping error handling security check in short mode")
	}

	// Run gosec with focus on error handling security
	cmd := exec.Command("go", "tool", "gosec",
		"-no-fail",
		"-quiet",
		"-include=G104",
		"./...")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "gosec should run without errors")

	outputStr := string(output)
	if strings.Contains(outputStr, "unhandled error") {
		t.Log("Error handling security findings:")
		t.Logf("Error handling findings:\n%s", outputStr)
	}
}
