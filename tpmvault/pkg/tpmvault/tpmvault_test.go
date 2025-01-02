package tpmvault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpmutil"
)

// mockTPM implements a mock TPM for testing
type mockTPM struct {
	key     *ecdsa.PrivateKey
	handle  tpmutil.Handle
	fails   bool
	readBuf []byte
}

func (m *mockTPM) Read(p []byte) (int, error) {
	if m.fails {
		return 0, fmt.Errorf("mock TPM read failure")
	}
	return copy(p, m.readBuf), nil
}

func (m *mockTPM) Write(p []byte) (int, error) {
	if m.fails {
		return 0, fmt.Errorf("mock TPM write failure")
	}
	return len(p), nil
}

func (m *mockTPM) Close() error {
	return nil
}

// setupMockTPM creates a mock TPM with a test key
func setupMockTPM(t *testing.T) *mockTPM {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	return &mockTPM{
		key:    key,
		handle: tpmutil.Handle(0x81000000),
	}
}

// Mock server for Vault responses
func setupMockVaultServer(t *testing.T) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pki/sign/pki-role":
			// Mock certificate signing
			if r.Method != http.MethodPost {
				t.Errorf("Expected POST request, got %s", r.Method)
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			resp := `{
				"data": {
					"certificate": "-----BEGIN CERTIFICATE-----\nMIIBxDCCAWugAwIBAgIUJpY9HxrJ...-----END CERTIFICATE-----\n"
				}
			}`
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(resp))

		case "/v1/pki/ca/pem":
			// Mock CA certificate
			cert := `-----BEGIN CERTIFICATE-----\nMIIBxDCCAWugAwIBAgIUJpY9HxrJ...-----END CERTIFICATE-----\n`
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write([]byte(cert))

		case "/v1/auth/cert/login":
			// Mock certificate login
			resp := `{
				"auth": {
					"client_token": "mock-token",
					"policies": ["default"],
					"lease_duration": 3600,
					"renewable": true
				}
			}`
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(resp))

		default:
			t.Errorf("Unexpected request to %s", r.URL.Path)
			http.Error(w, "Not found", http.StatusNotFound)
		}
	}))
}

func TestCreateDirectories(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &Config{
		CertPath:   filepath.Join(tempDir, "certs", "cert.pem"),
		HandlePath: filepath.Join(tempDir, "handles", "handle"),
	}

	err := createDirectories(cfg)
	if err != nil {
		t.Fatalf("createDirectories failed: %v", err)
	}

	// Verify directories were created
	dirs := []string{
		filepath.Dir(cfg.CertPath),
		filepath.Dir(cfg.HandlePath),
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Directory %s was not created", dir)
		}
	}
}

func TestSetupTPMVault(t *testing.T) {
	mockServer := setupMockVaultServer(t)
	defer mockServer.Close()

	tempDir := t.TempDir()
	cfg := &Config{
		VaultToken: "mock-token",
		VaultAddr:  mockServer.URL,
		CertPath:   filepath.Join(tempDir, "cert.pem"),
		HandlePath: filepath.Join(tempDir, "handle"),
		TPMDevice:  "mock",
	}

	ctx := context.Background()
	err := SetupTPMVault(ctx, cfg)
	if err != nil {
		t.Fatalf("SetupTPMVault failed: %v", err)
	}

	// Verify files were created
	files := []string{
		cfg.CertPath,
		cfg.HandlePath,
		filepath.Join(filepath.Dir(cfg.CertPath), "ca.pem"),
	}
	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			t.Errorf("Expected file %s was not created", file)
		}
	}
}

func TestAuthenticateTPMVault(t *testing.T) {
	mockServer := setupMockVaultServer(t)
	defer mockServer.Close()

	tempDir := t.TempDir()
	cfg := &Config{
		VaultAddr:  mockServer.URL,
		CertPath:   filepath.Join(tempDir, "cert.pem"),
		HandlePath: filepath.Join(tempDir, "handle"),
		TPMDevice:  "mock",
	}

	// Setup mock certificate and handle
	mockKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate mock key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.device",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &mockKey.PublicKey, mockKey)
	if err != nil {
		t.Fatalf("Failed to create mock certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := os.WriteFile(cfg.CertPath, certPEM, 0600); err != nil {
		t.Fatalf("Failed to write mock certificate: %v", err)
	}

	if err := os.WriteFile(cfg.HandlePath, []byte("0x81000000"), 0600); err != nil {
		t.Fatalf("Failed to write mock handle: %v", err)
	}

	client, err := AuthenticateTPMVault(cfg)
	if err != nil {
		t.Fatalf("AuthenticateTPMVault failed: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}
}

// Integration tests that require actual TPM hardware
func TestIntegrationSetup(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	cfg := &Config{
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
	cfg.VaultToken = os.Getenv("VAULT_TOKEN")
	if cfg.VaultToken == "" {
		t.Fatal("VAULT_TOKEN environment variable required for integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := SetupTPMVault(ctx, cfg)
	if err != nil {
		t.Fatalf("Integration setup failed: %v", err)
	}

	// Verify files
	files := []string{
		cfg.CertPath,
		cfg.HandlePath,
		filepath.Join(filepath.Dir(cfg.CertPath), "ca.pem"),
	}
	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			t.Errorf("Expected file %s was not created", file)
		}
	}
}

func TestIntegrationAuth(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test")
	}

	cfg := &Config{
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

	client, err := AuthenticateTPMVault(cfg)
	if err != nil {
		t.Fatalf("Integration auth failed: %v", err)
	}

	// Test authentication by checking health
	health, err := client.Sys().Health()
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	if health == nil {
		t.Fatal("Expected non-nil health response")
	}
}
