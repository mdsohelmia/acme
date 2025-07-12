package acme

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	// Live and staging URLs
	DirectoryLive    = "https://acme-v02.api.letsencrypt.org/directory"
	DirectoryStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// Modes
	ModeLive    = "live"
	ModeStaging = "staging"

	// Directory endpoints
	DirectoryNewAccount = "newAccount"
	DirectoryNewNonce   = "newNonce"
	DirectoryNewOrder   = "newOrder"

	// Validation types - DNS only
	ValidationDNS = "dns-01"
)

// ClientConfig holds configuration for the ACME client
type ClientConfig struct {
	Username  string
	Mode      string
	KeyLength int
	BasePath  string
	SourceIP  string
}

// Client represents the ACME client
type Client struct {
	config        *ClientConfig
	httpClient    *retryablehttp.Client
	directories   map[string]string
	nonce         string
	account       *Account
	privateKey    *rsa.PrivateKey
	privateKeyPEM string
	digest        string
	accountURL    string
}

// DirectoryResponse represents the ACME directory structure
type DirectoryResponse struct {
	NewAccount string `json:"newAccount"`
	NewNonce   string `json:"newNonce"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

// JWKHeader represents the JSON Web Key header
type JWKHeader struct {
	Alg   string `json:"alg"`
	JWK   *JWK   `json:"jwk,omitempty"`
	KID   string `json:"kid,omitempty"`
	Nonce string `json:"nonce"`
	URL   string `json:"url"`
}

// JWK represents a JSON Web Key
type JWK struct {
	E   string `json:"e"`
	Kty string `json:"kty"`
	N   string `json:"n"`
}

// JWS represents a JSON Web Signature
type JWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// NewClient creates a new ACME client
func NewClient(config *ClientConfig) (*Client, error) {
	if config.Username == "" {
		return nil, fmt.Errorf("username is required")
	}

	if config.Mode == "" {
		config.Mode = ModeLive
	}

	if config.KeyLength == 0 {
		config.KeyLength = 4096
	}

	if config.BasePath == "" {
		config.BasePath = "le"
	}

	// Create retryable HTTP client
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.RetryWaitMin = 1 * time.Second
	retryClient.RetryWaitMax = 5 * time.Second
	retryClient.HTTPClient.Timeout = 30 * time.Second

	// Disable logging by default (can be enabled if needed)
	retryClient.Logger = nil

	client := &Client{
		config:     config,
		httpClient: retryClient,
	}

	if err := client.init(); err != nil {
		return nil, fmt.Errorf("failed to initialize client: %w", err)
	}

	return client, nil
}

// Close cleans up the client
func (c *Client) Close() error {
	return nil
}

// init initializes the client by loading directories, keys, and account
func (c *Client) init() error {
	// Load directories from Let's Encrypt API
	if err := c.loadDirectories(); err != nil {
		return fmt.Errorf("failed to load directories: %w", err)
	}

	// Load or create private key
	if err := c.loadKeys(); err != nil {
		return fmt.Errorf("failed to load keys: %w", err)
	}

	// Agree to terms of service and get account
	if err := c.tosAgree(); err != nil {
		return fmt.Errorf("failed to agree to TOS: %w", err)
	}

	// Get account information
	account, err := c.getAccount()
	if err != nil {
		return fmt.Errorf("failed to get account: %w", err)
	}
	c.account = account

	return nil
}

// loadDirectories loads the ACME directory from Let's Encrypt
func (c *Client) loadDirectories() error {
	var directoryURL string
	if c.config.Mode == ModeLive {
		directoryURL = DirectoryLive
	} else {
		directoryURL = DirectoryStaging
	}

	fmt.Printf("Loading ACME directory from: %s\n", directoryURL)

	req, err := retryablehttp.NewRequest("GET", directoryURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to ACME server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d from ACME server: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Validate JSON before unmarshaling
	if !json.Valid(body) {
		return fmt.Errorf("invalid JSON response from ACME server")
	}

	var dir DirectoryResponse
	if err := json.Unmarshal(body, &dir); err != nil {
		return fmt.Errorf("failed to parse directory response: %w", err)
	}

	// Validate required fields
	if dir.NewAccount == "" || dir.NewNonce == "" || dir.NewOrder == "" {
		return fmt.Errorf("missing required fields in directory response")
	}

	c.directories = map[string]string{
		DirectoryNewAccount: dir.NewAccount,
		DirectoryNewNonce:   dir.NewNonce,
		DirectoryNewOrder:   dir.NewOrder,
	}

	fmt.Printf("Successfully loaded ACME directories\n")
	return nil
}

// loadKeys loads or creates the account private key
func (c *Client) loadKeys() error {
	keyPath := c.getPath("account.pem")

	// Check if key file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		// Create new key
		privateKey, err := rsa.GenerateKey(rand.Reader, c.config.KeyLength)
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}

		// Save key to file
		keyPEM := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}

		if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		keyFile, err := os.Create(keyPath)
		if err != nil {
			return fmt.Errorf("failed to create key file: %w", err)
		}
		defer keyFile.Close()

		if err := pem.Encode(keyFile, keyPEM); err != nil {
			return fmt.Errorf("failed to encode key: %w", err)
		}

		c.privateKey = privateKey
	} else {
		// Load existing key
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to read key file: %w", err)
		}

		block, _ := pem.Decode(keyData)
		if block == nil {
			return fmt.Errorf("failed to decode PEM block")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}

		c.privateKey = privateKey
	}

	// Store PEM format for later use
	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.privateKey),
	}
	c.privateKeyPEM = string(pem.EncodeToMemory(keyPEM))

	return nil
}

// getPath returns a formatted path for the given filename
func (c *Client) getPath(filename string) string {
	// Create a safe directory name from username
	userDir := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(c.config.Username), "-")
	return filepath.Join(c.config.BasePath, userDir, filename)
}

// tosAgree agrees to the terms of service
func (c *Client) tosAgree() error {
	payload := map[string]interface{}{
		"contact":              []string{"mailto:" + c.config.Username},
		"termsOfServiceAgreed": true,
	}

	url := c.directories[DirectoryNewAccount]
	jws, err := c.signPayloadJWK(payload, url)
	if err != nil {
		return err
	}

	resp, err := c.request("POST", url, jws)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Store account URL from Location header
	c.accountURL = resp.Header.Get("Location")

	return nil
}

// request sends an HTTP request to the ACME server using retryable HTTP
func (c *Client) request(method, url string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := retryablehttp.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/jose+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Update nonce from response
	if nonce := resp.Header.Get("Replay-Nonce"); nonce != "" {
		c.nonce = nonce
	}

	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return resp, nil
}

// getNonce gets a fresh nonce from the ACME server
func (c *Client) getNonce() error {
	if c.nonce != "" {
		return nil
	}

	req, err := retryablehttp.NewRequest("HEAD", c.directories[DirectoryNewNonce], nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	c.nonce = resp.Header.Get("Replay-Nonce")
	if c.nonce == "" {
		return fmt.Errorf("no nonce received")
	}

	return nil
}

// getJWK returns the JSON Web Key for the account
func (c *Client) getJWK() (*JWK, error) {
	publicKey := &c.privateKey.PublicKey

	nBytes := publicKey.N.Bytes()
	eBytes := make([]byte, 4)
	eBytes[0] = byte(publicKey.E >> 24)
	eBytes[1] = byte(publicKey.E >> 16)
	eBytes[2] = byte(publicKey.E >> 8)
	eBytes[3] = byte(publicKey.E)

	// Remove leading zeros from E
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}

	return &JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}, nil
}

// getDigest returns the thumbprint of the account key
func (c *Client) getDigest() (string, error) {
	if c.digest != "" {
		return c.digest, nil
	}

	jwk, err := c.getJWK()
	if err != nil {
		return "", err
	}

	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(jwkJSON)
	c.digest = base64.RawURLEncoding.EncodeToString(hash[:])
	return c.digest, nil
}

// signPayloadJWK signs a payload using JWK format
func (c *Client) signPayloadJWK(payload interface{}, url string) (*JWS, error) {
	if err := c.getNonce(); err != nil {
		return nil, err
	}

	jwk, err := c.getJWK()
	if err != nil {
		return nil, err
	}

	header := &JWKHeader{
		Alg:   "RS256",
		JWK:   jwk,
		Nonce: c.nonce,
		URL:   url,
	}

	return c.signPayload(header, payload)
}

// signPayloadKID signs a payload using KID format
func (c *Client) signPayloadKID(payload interface{}, url string) (*JWS, error) {
	if err := c.getNonce(); err != nil {
		return nil, err
	}

	header := &JWKHeader{
		Alg:   "RS256",
		KID:   c.accountURL,
		Nonce: c.nonce,
		URL:   url,
	}

	return c.signPayload(header, payload)
}

// signPayload signs a payload with the given header
func (c *Client) signPayload(header *JWKHeader, payload interface{}) (*JWS, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}

	var payloadJSON []byte
	if payload != nil {
		payloadJSON, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	protectedEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := protectedEncoded + "." + payloadEncoded

	hash := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}

	signatureEncoded := base64.RawURLEncoding.EncodeToString(signature)

	return &JWS{
		Protected: protectedEncoded,
		Payload:   payloadEncoded,
		Signature: signatureEncoded,
	}, nil
}

// getAccount retrieves account information (internal method)
func (c *Client) getAccount() (*Account, error) {
	payload := map[string]any{
		"onlyReturnExisting": true,
	}

	url := c.directories[DirectoryNewAccount]

	jws, err := c.signPayloadJWK(payload, url)
	if err != nil {
		return nil, err
	}

	resp, err := c.request("POST", url, jws)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var accountResp struct {
		Contact   []string `json:"contact"`
		CreatedAt string   `json:"createdAt"`
		Status    string   `json:"status"`
	}

	if err := json.Unmarshal(body, &accountResp); err != nil {
		return nil, err
	}

	accountURL := resp.Header.Get("Location")
	createdAt, err := time.Parse(time.RFC3339, accountResp.CreatedAt)
	if err != nil {
		return nil, err
	}

	return NewAccount(
		accountResp.Contact,
		createdAt,
		accountResp.Status == "valid",
		accountURL,
	), nil
}
