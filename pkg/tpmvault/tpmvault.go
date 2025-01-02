package tpmvault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
)

const (
	defaultTPMDevice  = "/dev/tpm0"
	defaultTimeout    = 30 * time.Second
	pkiRole           = "pki-role"
	maxRetries        = 3
	retryDelay        = 1 * time.Second
	deviceBusyTimeout = 5 * time.Second
)

// Config holds the configuration for TPM and Vault interaction
type Config struct {
	VaultToken   string // Required for setup, not for auth
	VaultAddr    string
	CertPath     string
	HandlePath   string
	TPMDevice    string
	CommonName   string
	Organization []string
	Country      []string
	ServerName   string
}

// Private types

// ecdsaSignature represents an ECDSA signature for ASN.1 encoding
type ecdsaSignature struct {
	R, S *big.Int
}

type tpmManager struct {
	rwc    io.ReadWriteCloser
	config *Config
}

type tpmAuth struct {
	rwc    io.ReadWriteCloser
	config *Config
}

type tpmPrivateKey struct {
	rwc    io.ReadWriteCloser
	handle tpmutil.Handle
	pubKey *ecdsa.PublicKey
}

type tpmSigner struct {
	rwc    io.ReadWriteCloser
	handle tpmutil.Handle
	public crypto.PublicKey
	cert   *x509.Certificate
}

// SetupTPMVault initializes TPM, generates keys and CSR, and obtains a certificate from Vault
func SetupTPMVault(ctx context.Context, config *Config) error {

	if config.CertPath == "" {
		config.CertPath = "/etc/device/cert.pem"
	}
	if config.HandlePath == "" {
		config.HandlePath = "/etc/device/handle"
	}
	if config.TPMDevice == "" {
		config.TPMDevice = defaultTPMDevice
	}

	requiredFields := []struct {
		name  string
		value string
	}{
		{"VaultToken", config.VaultToken},
		{"VaultAddr", config.VaultAddr},
		{"CommonName", config.CommonName},
		{"ServerName", config.ServerName},
	}

	for _, field := range requiredFields {
		if field.value == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}

	tm, err := newTPMManager(config)
	if err != nil {
		return errors.Wrap(err, "initializing TPM")
	}
	defer tm.Close()

	if err := tm.downloadCACert(); err != nil {
		return errors.Wrap(err, "downloading CA cert")
	}

	if err := tm.flushContexts(); err != nil {
		return errors.Wrap(err, "flushing contexts")
	}

	handle, pubKey, err := tm.createTPMKey()
	if err != nil {
		return errors.Wrap(err, "creating TPM key")
	}

	if err := os.WriteFile(config.HandlePath, []byte(fmt.Sprintf("%d", handle)), 0600); err != nil {
		return errors.Wrap(err, "saving handle")
	}

	csr, err := tm.generateCSR(handle, pubKey)
	if err != nil {
		return errors.Wrap(err, "generating CSR")
	}

	cert, err := tm.submitToVault(ctx, csr)
	if err != nil {
		return errors.Wrap(err, "submitting to vault")
	}

	if err := os.WriteFile(config.CertPath, cert, 0600); err != nil {
		return errors.Wrap(err, "saving certificate")
	}

	return nil
}

// AuthenticateTPMVault performs TPM-based authentication to Vault and returns a client
func AuthenticateTPMVault(config *Config) (*api.Client, error) {
	if config.CertPath == "" {
		config.CertPath = "/etc/device/cert.pem"
	}
	if config.HandlePath == "" {
		config.HandlePath = "/etc/device/handle"
	}
	if config.TPMDevice == "" {
		config.TPMDevice = defaultTPMDevice
	}

	requiredFields := []struct {
		name  string
		value string
	}{
		{"VaultToken", config.VaultToken},
		{"VaultAddr", config.VaultAddr},
		{"CommonName", config.CommonName},
		{"ServerName", config.ServerName},
	}

	for _, field := range requiredFields {
		if field.value == "" {
			return nil, fmt.Errorf("%s is required", field.name)
		}
	}

	auth, err := newTPMAuth(config)
	if err != nil {
		return nil, errors.Wrap(err, "initializing TPM authentication")
	}
	defer auth.Close()

	client, err := auth.setupVaultClient()
	if err != nil {
		return nil, errors.Wrap(err, "setting up Vault client")
	}

	if err := auth.testAuth(client); err != nil {
		return nil, errors.Wrap(err, "testing authentication")
	}

	return client, nil
}

// Helper functions
func createDirectories(config *Config) error {
	dirs := []string{
		filepath.Dir(config.CertPath),
		filepath.Dir(config.HandlePath),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errors.Wrapf(err, "creating directory %s", dir)
		}
	}
	return nil
}

func checkTPMService() error {
	cmd := exec.Command("systemctl", "is-active", "tpm2-abrmd")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 3 {
			if _, err := os.Stat("/dev/tpmrm0"); err == nil {
				return nil
			}
		}
		return fmt.Errorf("TPM resource manager service check failed: %v", err)
	}

	status := strings.TrimSpace(string(output))
	if status != "active" {
		return fmt.Errorf("TPM resource manager service is not active (status: %s)", status)
	}
	return nil
}

func openTPM() (io.ReadWriteCloser, error) {
	var rwc io.ReadWriteCloser
	var lastErr error

	ctx, cancel := context.WithTimeout(context.Background(), deviceBusyTimeout)
	defer cancel()

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			time.Sleep(retryDelay)
		}

		done := make(chan struct{})
		var err error

		go func() {
			rwc, err = tpm2.OpenTPM("mssim:host=localhost,port=2321")
			if err != nil {
				rwc, err = tpm2.OpenTPM("/dev/tpmrm0")
			}
			close(done)
		}()

		select {
		case <-ctx.Done():
			lastErr = fmt.Errorf("timeout waiting for TPM")
			continue
		case <-done:
			if err == nil {
				return rwc, nil
			}
			lastErr = err
		}
	}

	return nil, fmt.Errorf("failed to initialize TPM after %d attempts: %v", maxRetries, lastErr)
}

// TPM Manager implementation
func newTPMManager(config *Config) (*tpmManager, error) {
	if err := createDirectories(config); err != nil {
		return nil, errors.Wrap(err, "creating directories")
	}

	if err := checkTPMService(); err != nil {
		return nil, fmt.Errorf("TPM resource manager not available: %v", err)
	}

	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}

	return &tpmManager{rwc: rwc, config: config}, nil
}

func (tm *tpmManager) Close() error {
	if tm.rwc != nil {
		return tm.rwc.Close()
	}
	return nil
}

func (tm *tpmManager) flushContexts() error {
	handles, _, err := tpm2.GetCapability(tm.rwc, tpm2.CapabilityHandles, 0xFF, uint32(0x80000000))
	if err != nil {
		return errors.Wrap(err, "getting transient handles")
	}

	for _, handleInt := range handles {
		handle, ok := handleInt.(tpmutil.Handle)
		if !ok {
			return errors.Errorf("invalid handle type: %T", handleInt)
		}
		if uint32(handle)&0xFF000000 == uint32(0x80000000) {
			if err := tpm2.FlushContext(tm.rwc, handle); err != nil {
				return errors.Wrapf(err, "flushing handle 0x%x", handle)
			}
		}
	}
	return nil
}

func (tm *tpmManager) flushPersistentHandle(handle tpmutil.Handle) error {
	err := tpm2.EvictControl(tm.rwc, "", tpm2.HandleOwner, handle, handle)
	if err != nil && !strings.Contains(err.Error(), "handle does not exist") {
		return errors.Wrap(err, "flushing persistent handle")
	}
	return nil
}

func (tm *tpmManager) createTPMKey() (tpmutil.Handle, *ecdsa.PublicKey, error) {
	template := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth |
			tpm2.FlagSign,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}

	handle, pub, err := tpm2.CreatePrimary(tm.rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", template)
	if err != nil {
		return 0, nil, errors.Wrap(err, "creating primary key")
	}

	pHandle := tpmutil.Handle(0x81000000)
	if err := tm.flushPersistentHandle(pHandle); err != nil {
		return 0, nil, err
	}

	if err := tpm2.EvictControl(tm.rwc, "", tpm2.HandleOwner, handle, pHandle); err != nil {
		return 0, nil, errors.Wrap(err, "making key persistent")
	}

	pubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return 0, nil, errors.New("created key is not ECDSA")
	}

	return pHandle, pubKey, nil
}

func (tm *tpmManager) generateCSR(handle tpmutil.Handle, pubKey *ecdsa.PublicKey) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   tm.config.CommonName,
			Organization: tm.config.Organization,
			Country:      tm.config.Country,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       []int{2, 5, 29, 15},
				Critical: true,
				Value:    []byte{0x03, 0x02, 0x05, 0xa0},
			},
			{
				Id:    []int{2, 5, 29, 37},
				Value: []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02},
			},
		},
	}

	privKey := &tpmPrivateKey{
		rwc:    tm.rwc,
		handle: handle,
		pubKey: pubKey,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, errors.Wrap(err, "creating certificate request")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}), nil
}

func (tm *tpmManager) submitToVault(ctx context.Context, csr []byte) ([]byte, error) {
	signData := map[string]interface{}{
		"csr":    string(csr),
		"ttl":    "720h",
		"format": "pem",
	}

	signJSON, err := json.Marshal(signData)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling sign request")
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/v1/pki/sign/%s", tm.config.VaultAddr, pkiRole),
		bytes.NewBuffer(signJSON))
	if err != nil {
		return nil, errors.Wrap(err, "creating sign request")
	}
	req.Header.Set("X-Vault-Token", tm.config.VaultToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "sending sign request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to sign CSR: status=%d, body=%s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, errors.Wrap(err, "decoding response")
	}

	if result.Data.Certificate == "" {
		return nil, errors.New("no certificate in response")
	}

	return []byte(result.Data.Certificate), nil
}

func (tm *tpmManager) downloadCACert() error {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/v1/pki/ca/pem", tm.config.VaultAddr), nil)
	if err != nil {
		return errors.Wrap(err, "creating request")
	}
	req.Header.Set("Accept", "application/x-pem-file")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "getting CA cert")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "reading CA cert")
	}

	caPath := filepath.Join(filepath.Dir(tm.config.CertPath), "ca.pem")
	return os.WriteFile(caPath, body, 0644)
}

// TPM Auth implementation
func newTPMAuth(config *Config) (*tpmAuth, error) {
	if err := createDirectories(config); err != nil {
		return nil, errors.Wrap(err, "creating directories")
	}

	if err := checkTPMService(); err != nil {
		return nil, fmt.Errorf("TPM resource manager not available: %v", err)
	}

	rwc, err := openTPM()
	if err != nil {
		return nil, err
	}

	return &tpmAuth{rwc: rwc, config: config}, nil
}

func (ta *tpmAuth) Close() error {
	if ta.rwc != nil {
		return ta.rwc.Close()
	}
	return nil
}

func (ta *tpmAuth) readSavedHandle() (tpmutil.Handle, error) {
	handleBytes, err := os.ReadFile(ta.config.HandlePath)
	if err != nil {
		return 0, errors.Wrap(err, "reading handle file")
	}

	var handle uint32
	if _, err := fmt.Sscanf(string(handleBytes), "%d", &handle); err != nil {
		return 0, errors.Wrap(err, "parsing handle value")
	}

	return tpmutil.Handle(handle), nil
}

func (ta *tpmAuth) setupVaultClient() (*api.Client, error) {
	certPEM, err := os.ReadFile(ta.config.CertPath)
	if err != nil {
		return nil, errors.Wrap(err, "reading certificate file")
	}

	caPath := filepath.Join(filepath.Dir(ta.config.CertPath), "ca.pem")
	caCertPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, errors.Wrap(err, "reading CA cert")
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caCertPEM) {
		return nil, errors.New("failed to parse CA certificate")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parsing x509 certificate")
	}

	handle, err := ta.readSavedHandle()
	if err != nil {
		return nil, errors.Wrap(err, "reading handle")
	}

	pub, _, _, err := tpm2.ReadPublic(ta.rwc, handle)
	if err != nil {
		return nil, errors.Wrap(err, "reading public key from TPM")
	}

	pubKey, err := pub.Key()
	if err != nil {
		return nil, errors.Wrap(err, "extracting public key")
	}

	signer := &tpmSigner{
		rwc:    ta.rwc,
		handle: handle,
		public: pubKey,
		cert:   cert,
	}

	certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate public key is not ECDSA")
	}
	tpmPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("TPM public key is not ECDSA")
	}
	if certPubKey.X.Cmp(tpmPubKey.X) != 0 || certPubKey.Y.Cmp(tpmPubKey.Y) != 0 {
		return nil, errors.New("TPM public key does not match certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: signer, Leaf: cert}},
		MinVersion:   tls.VersionTLS12,
		ServerName:   ta.config.ServerName,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tls.Dial(network, addr, tlsConfig)
		},
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	vaultConfig := &api.Config{
		Address:    ta.config.VaultAddr,
		HttpClient: httpClient,
	}

	return api.NewClient(vaultConfig)
}

func (ta *tpmAuth) login(client *api.Client) error {
	data := map[string]interface{}{"name": "web"}
	r := client.NewRequest("POST", "/v1/auth/cert/login")
	r.SetJSONBody(data)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFunc()

	resp, err := client.RawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	secret, err := api.ParseSecret(bytes.NewReader(body))
	if err != nil {
		return err
	}

	if secret == nil || secret.Auth == nil {
		return errors.New("no auth info in response")
	}

	client.SetToken(secret.Auth.ClientToken)
	return nil
}

func (ta *tpmAuth) testAuth(client *api.Client) error {
	if err := ta.login(client); err != nil {
		health, healthErr := client.Sys().Health()
		if healthErr != nil {
			return errors.Wrap(err, "authentication and health check failed")
		}
		return errors.Wrap(err, fmt.Sprintf("authentication failed (vault sealed: %v, initialized: %v)",
			health.Sealed, health.Initialized))
	}
	return nil
}

// TPM Key implementations
func (k *tpmPrivateKey) Public() crypto.PublicKey {
	return k.pubKey
}

func (k *tpmPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}

	sig, err := tpm2.Sign(k.rwc, k.handle, "", digest, nil, scheme)
	if err != nil {
		return nil, errors.Wrap(err, "signing with TPM")
	}

	signature := ecdsaSignature{
		R: sig.ECC.R,
		S: sig.ECC.S,
	}

	return asn1.Marshal(signature)
}

func (t *tpmSigner) Public() crypto.PublicKey {
	return t.public
}

func (t *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}

	sig, err := tpm2.Sign(t.rwc, t.handle, "", digest, nil, scheme)
	if err != nil {
		return nil, fmt.Errorf("signing with TPM: %v", err)
	}

	if sig.ECC == nil {
		return nil, errors.New("got nil ECDSA signature")
	}

	signature := struct {
		R, S *big.Int
	}{
		R: sig.ECC.R,
		S: sig.ECC.S,
	}

	return asn1.Marshal(signature)
}
