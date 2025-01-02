package main

import (
	"context"
	"log"
	"os"
	"time"

	tpmvault "github.com/henryqum/tpmvault/pkg/tpmvault"
)

func main() {
	// Get default config and customize it
	config := &tpmvault.Config{
		CertPath:     "/tmp/test/cert.pem",
		HandlePath:   "/tmp/test/handle",
		TPMDevice:    "/dev/tpm0",
		VaultAddr:    "http://127.0.0.1:8200",
		VaultToken:   os.Getenv("VAULT_TOKEN"),
		CommonName:   "test.device",
		Organization: []string{"Test Org"},
		Country:      []string{"US"},
		ServerName:   "vault",
	}
	config.VaultToken = "your-vault-token" // Required for setup only
	config.VaultAddr = "https://your-vault-server:8201"

	// Setup TPM and get certificate (only needed once)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := tpmvault.SetupTPMVault(ctx, config); err != nil {
		log.Fatalf("Failed to setup TPM-Vault: %v", err)
	}
	log.Println("TPM setup completed successfully!")

	// Later, authenticate using TPM (can be called multiple times)
	client, err := tpmvault.AuthenticateTPMVault(config)
	if err != nil {
		log.Fatalf("Failed to authenticate: %v", err)
	}
	log.Println("Successfully authenticated to Vault!")

	// Use the authenticated Vault client
	client.Logical().Read("path/to/secret")
}
