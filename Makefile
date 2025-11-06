# Makefile for go-crpt cryptographic library
.PHONY: help test test-all test-bench security-scan vuln-check security-test install-tools clean build lint fmt

# Default target
help:
	@echo "Available targets:"
	@echo "  test          - Run basic tests"
	@echo "  test-all      - Run all tests including security tests"
	@echo "  test-bench    - Run benchmarks"
	@echo "  security-scan - Run gosec security scanner"
	@echo "  vuln-check    - Run govulncheck vulnerability scanner"
	@echo "  security-test - Run comprehensive security tests"
	@echo "  install-tools - Install development tools"
	@echo "  clean         - Clean build artifacts"
	@echo "  build         - Build the project"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"

# Basic tests
test:
	go test -v ./...

# Comprehensive tests including security tests
test-all:
	go test -v -tags=security_test ./...

# Benchmark tests
test-bench:
	go test -bench=. -benchmem ./...

# Security scan with gosec
security-scan:
	@echo "Running gosec security scanner..."
	go tool gosec -no-fail ./...

# Vulnerability check with govulncheck
vuln-check:
	@echo "Running govulncheck vulnerability scanner..."
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Comprehensive security tests
security-test:
	@echo "Running comprehensive security tests..."
	go test -v -tags=security_test -run TestSecurity ./...

# Install development tools (tools are available via go tool and go run)
install-tools:
	@echo "Development tools are available via go tool gosec and go run govulncheck"

# Clean build artifacts
clean:
	go clean -testcache
	go clean -cache
	rm -f coverage.out coverage.html

# Build the project
build:
	go build ./...

# Run linter (if available)
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, skipping lint"; \
	fi

# Format code
fmt:
	go fmt ./...

# Security audit - runs all security checks
security-audit: security-scan vuln-check security-test
	@echo "Security audit complete!"

# Continuous integration target
ci: fmt build lint test security-audit
	@echo "CI pipeline complete!"

# Development setup
dev-setup: install-tools
	@echo "Development environment setup complete!"

# Check for common security issues
security-quick:
	@echo "Quick security check..."
	go tool gosec -quiet -no-fail ./...
	@echo "Quick vulnerability check..."
	go run golang.org/x/vuln/cmd/govulncheck@latest ./... 2>/dev/null || true