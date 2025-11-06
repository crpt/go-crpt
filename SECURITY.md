# Security Testing

This project includes comprehensive security testing using industry-standard tools.

## Security Tools

### gosec

[gosec](https://github.com/securego/gosec) is a Go security scanner that inspects source code for security problems.

**Usage:**
```bash
# Quick security scan
go tool gosec -quiet -no-fail ./...

# Detailed security scan with JSON output
go tool gosec -fmt=json ./...

# Scan for specific security rules
go tool gosec -include=G101,G103,G401 ./...
```

### govulncheck

[govulncheck](https://go.dev/security/vuln/check) is Go's official vulnerability scanner that checks for known vulnerabilities in dependencies.

**Usage:**
```bash
# Check for vulnerabilities in dependencies
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Check with JSON output
go run golang.org/x/vuln/cmd/govulncheck@latest -format=json ./...
```

## Security Tests

The project includes comprehensive security tests that can be run with:

```bash
# Run all security tests
go test -v -tags=security_test -run TestSecurity ./...

# Run specific security test categories
go test -v -tags=security_test -run TestHardcodedCredentialsCheck ./...
go test -v -tags=security_test -run TestWeakCryptoCheck ./...
go test -v -tags=security_test -run TestSQLInjectionCheck ./...
go test -v -tags=security_test -run TestFileOperationSecurity ./...
go test -v -tags=security_test -run TestNetworkSecurity ./...
go test -v -tags=security_test -run TestErrorHandlingSecurity ./...
```

## Makefile Targets

The project provides convenient Makefile targets for security testing:

```bash
# Quick security check
make security-quick

# Comprehensive security scan
make security-scan

# Vulnerability check
make vuln-check

# Full security tests
make security-test

# Complete security audit
make security-audit
```

## Security Best Practices Implemented

1. **Constant-time comparisons** for sensitive cryptographic operations
2. **Memory safety** in signature handling and key operations
3. **Proper random number generation** using crypto/rand
4. **Safe error handling** in cryptographic operations
5. **Input validation** for all cryptographic inputs

## Running Security Tests in CI

For continuous integration, use:

```bash
# Complete CI security pipeline
make ci

# Or individual security steps
make security-audit
```

## Security Configuration

Security tools are configured in:
- `go.mod` - Tool dependencies in the `tool` section
- `Makefile` - Security testing targets
- `security_test.go` - Comprehensive security test suite

## Notes

- Security tests use build tags (`security_test`) to separate them from regular tests
- Tests can be skipped in short mode using `go test -short`
