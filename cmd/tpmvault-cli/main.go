package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	tpmvault "github.com/henryqum/tpmvault/pkg/tpmvault"
)

func main() {
	setupCmd := flag.NewFlagSet("setup", flag.ExitOnError)
	authCmd := flag.NewFlagSet("auth", flag.ExitOnError)

	// Setup command flags
	vaultToken := setupCmd.String("token", "", "Vault token (required)")
	vaultAddrSetup := setupCmd.String("vault-addr", "", "Vault address")
	certPathSetup := setupCmd.String("cert-path", "", "Certificate path")
	handlePathSetup := setupCmd.String("handle-path", "", "Handle path")
	tpmDeviceSetup := setupCmd.String("tpm-device", "", "TPM device path")

	// Auth command flags
	vaultAddrAuth := authCmd.String("vault-addr", "", "Vault address")
	certPathAuth := authCmd.String("cert-path", "", "Certificate path")
	handlePathAuth := authCmd.String("handle-path", "", "Handle path")
	tpmDeviceAuth := authCmd.String("tpm-device", "", "TPM device path")

	if len(os.Args) < 2 {
		fmt.Println("Expected 'setup' or 'auth' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "setup":
		setupCmd.Parse(os.Args[2:])
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

		if *vaultToken == "" {
			log.Fatal("Vault token is required for setup")
		}
		config.VaultToken = *vaultToken

		if *vaultAddrSetup != "" {
			config.VaultAddr = *vaultAddrSetup
		}
		if *certPathSetup != "" {
			config.CertPath = *certPathSetup
		}
		if *handlePathSetup != "" {
			config.HandlePath = *handlePathSetup
		}
		if *tpmDeviceSetup != "" {
			config.TPMDevice = *tpmDeviceSetup
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := tpmvault.SetupTPMVault(ctx, config); err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
		fmt.Println("Setup completed successfully")

	case "auth":
		authCmd.Parse(os.Args[2:])
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

		if *vaultAddrAuth != "" {
			config.VaultAddr = *vaultAddrAuth
		}
		if *certPathAuth != "" {
			config.CertPath = *certPathAuth
		}
		if *handlePathAuth != "" {
			config.HandlePath = *handlePathAuth
		}
		if *tpmDeviceAuth != "" {
			config.TPMDevice = *tpmDeviceAuth
		}

		client, err := tpmvault.AuthenticateTPMVault(config)
		if err != nil {
			log.Fatalf("Authentication failed: %v", err)
		}

		// Test authentication by checking Vault's health
		health, err := client.Sys().Health()
		if err != nil {
			log.Fatalf("Health check failed: %v", err)
		}
		fmt.Printf("Successfully authenticated to Vault (sealed: %v, initialized: %v)\n",
			health.Sealed, health.Initialized)

	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
