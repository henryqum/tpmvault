# TPM Vault

TPM Vault is a Go package that provides TPM-based authentication and certificate management for HashiCorp Vault. It handles TPM key generation, certificate signing requests (CSR), and mutual TLS authentication with Vault.

## Features

- TPM key generation and management
- Certificate Signing Request (CSR) generation
- Automated certificate retrieval from Vault
- TPM-based authentication to Vault
- Secure key storage and handling
- Automatic CA certificate management
- Retry mechanisms for TPM operations

## Prerequisites

- Go 1.16 or later
- TPM 2.0 device or simulator
- HashiCorp Vault server with PKI and TLS certificate authentication enabled
- TPM Resource Manager (tpm2-abrmd) service

## Installation

```bash
go get github.com/yourusername/tpmvault
```

## Usage

### Basic Setup

```go
package main

import (
    "context"
    "log"
    "time"
    "github.com/henryqum/tpmvault"
)

func main() {
    // Get default configuration
    config := tpmvault.DefaultConfig()

    // Set required Vault token for setup
    config.VaultToken = "your-vault-token"

    // Custom configuration (optional)
    config.VaultAddr = "https://your-vault-server:8201"
    config.CertPath = "/custom/path/cert.pem"
    config.HandlePath = "/custom/path/handle"

    // Setup TPM and get certificate (only needed once)
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    err := tpmvault.SetupTPMVault(ctx, config)
    if err != nil {
        log.Fatalf("Failed to setup TPM-Vault: %v", err)
    }
}
```

### Authentication

```go
package main

import (
    "log"
    "github.com/yourusername/tpmvault"
)

func main() {
    config := tpmvault.DefaultConfig()

    // Authenticate to Vault using TPM
    client, err := tpmvault.AuthenticateTPMVault(config)
    if err != nil {
        log.Fatalf("Failed to authenticate: %v", err)
    }

    // Use the authenticated Vault client
    secret, err := client.Logical().Read("secret/data/myapp")
    // ...
}
```

## Configuration

The `Config` struct supports the following options:

```go
type Config struct {
    VaultToken string // Required for setup, not for auth
    VaultAddr  string // Vault server address
    CertPath   string // Path to save/load certificate
    HandlePath string // Path to save/load TPM handle
    TPMDevice  string // Path to TPM device
}
```

Default values can be obtained using `DefaultConfig()`:

- VaultAddr: "https://your-vault-addr.com"
- CertPath: "/etc/device/cert.pem"
- HandlePath: "/etc/device/handle"
- TPMDevice: "/dev/tpm0"

## Security Considerations

1. The VaultToken is only required for initial setup and should be kept secure
2. Certificate and handle files are created with 0600 permissions
3. TPM keys are generated with appropriate security attributes
4. TLS is enforced with modern cipher suites
5. CA certificates are validated during authentication

## Testing

To run unit tests:

```bash
go test -v ./...
```

To run integration tests (requires TPM and Vault):

```bash
INTEGRATION_TEST=true VAULT_TOKEN=your-token go test -v ./...
```

## Error Handling

The package includes comprehensive error handling and retries for TPM operations:

- TPM device busy conditions
- Service availability checks
- Network timeouts
- Certificate validation
- Key matching verification

## License

MIT License - see LICENSE file for details
