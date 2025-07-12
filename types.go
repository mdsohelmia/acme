package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// Account represents a Let's Encrypt account
type Account struct {
	contact    []string
	createdAt  time.Time
	isValid    bool
	accountURL string
}

// NewAccount creates a new Account
func NewAccount(contact []string, createdAt time.Time, isValid bool, accountURL string) *Account {
	return &Account{
		contact:    contact,
		createdAt:  createdAt,
		isValid:    isValid,
		accountURL: accountURL,
	}
}

// GetID returns the account ID from the URL
func (a *Account) GetID() string {
	parts := strings.Split(a.accountURL, "/")
	return parts[len(parts)-1]
}

// GetCreatedAt returns the account creation date
func (a *Account) GetCreatedAt() time.Time {
	return a.createdAt
}

// GetAccountURL returns the account URL
func (a *Account) GetAccountURL() string {
	return a.accountURL
}

// GetContact returns the contact information
func (a *Account) GetContact() []string {
	return a.contact
}

// IsValid returns whether the account is valid
func (a *Account) IsValid() bool {
	return a.isValid
}

// Order represents an ACME order
type Order struct {
	domains        []string
	url            string
	status         string
	expiresAt      time.Time
	identifiers    []map[string]string
	authorizations []string
	finalizeURL    string
}

// NewOrder creates a new Order
func NewOrder(domains []string, url, status, expiresAt string, identifiers []map[string]string, authorizations []string, finalizeURL string) (*Order, error) {
	// Handle microtime date format
	if strings.Contains(expiresAt, ".") {
		expiresAt = expiresAt[:strings.Index(expiresAt, ".")] + "Z"
	}

	expires, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expiry date: %w", err)
	}

	return &Order{
		domains:        domains,
		url:            url,
		status:         status,
		expiresAt:      expires,
		identifiers:    identifiers,
		authorizations: authorizations,
		finalizeURL:    finalizeURL,
	}, nil
}

// GetID returns the order ID
func (o *Order) GetID() string {
	parts := strings.Split(o.url, "/")
	return parts[len(parts)-1]
}

// GetURL returns the order URL
func (o *Order) GetURL() string {
	return o.url
}

// GetAuthorizationURLs returns the authorization URLs
func (o *Order) GetAuthorizationURLs() []string {
	return o.authorizations
}

// GetStatus returns the order status
func (o *Order) GetStatus() string {
	return o.status
}

// GetExpiresAt returns the expiry time
func (o *Order) GetExpiresAt() time.Time {
	return o.expiresAt
}

// GetIdentifiers returns the identifiers
func (o *Order) GetIdentifiers() []map[string]string {
	return o.identifiers
}

// GetFinalizeURL returns the finalize URL
func (o *Order) GetFinalizeURL() string {
	return o.finalizeURL
}

// GetDomains returns the domains
func (o *Order) GetDomains() []string {
	return o.domains
}

// Challenge represents an ACME challenge
type Challenge struct {
	authorizationURL string
	challengeType    string
	status           string
	url              string
	token            string
}

// NewChallenge creates a new Challenge
func NewChallenge(authorizationURL, challengeType, status, url, token string) *Challenge {
	return &Challenge{
		authorizationURL: authorizationURL,
		challengeType:    challengeType,
		status:           status,
		url:              url,
		token:            token,
	}
}

// GetURL returns the challenge URL
func (c *Challenge) GetURL() string {
	return c.url
}

// GetType returns the challenge type
func (c *Challenge) GetType() string {
	return c.challengeType
}

// GetToken returns the challenge token
func (c *Challenge) GetToken() string {
	return c.token
}

// GetStatus returns the challenge status
func (c *Challenge) GetStatus() string {
	return c.status
}

// GetAuthorizationURL returns the authorization URL
func (c *Challenge) GetAuthorizationURL() string {
	return c.authorizationURL
}

// Authorization represents an ACME authorization
type Authorization struct {
	domain     string
	expires    time.Time
	challenges []*Challenge
	digest     string
}

// NewAuthorization creates a new Authorization
func NewAuthorization(domain, expires, digest string) (*Authorization, error) {
	expiryTime, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expiry date: %w", err)
	}

	return &Authorization{
		domain:  domain,
		expires: expiryTime,
		digest:  digest,
	}, nil
}

// AddChallenge adds a challenge to the authorization
func (a *Authorization) AddChallenge(challenge *Challenge) {
	a.challenges = append(a.challenges, challenge)
}

// GetDomain returns the domain being authorized
func (a *Authorization) GetDomain() string {
	return a.domain
}

// GetExpires returns the expiry time
func (a *Authorization) GetExpires() time.Time {
	return a.expires
}

// GetChallenges returns all challenges
func (a *Authorization) GetChallenges() []*Challenge {
	return a.challenges
}

// GetDNSChallenge returns the DNS challenge (only DNS validation supported)
func (a *Authorization) GetDNSChallenge() *Challenge {
	for _, challenge := range a.challenges {
		if challenge.GetType() == ValidationDNS {
			return challenge
		}
	}
	return nil
}

// GetTxtRecord returns the TXT record for DNS validation
func (a *Authorization) GetTxtRecord() *Record {
	challenge := a.GetDNSChallenge()
	if challenge != nil {
		keyAuth := challenge.GetToken() + "." + a.digest
		hash := sha256.Sum256([]byte(keyAuth))
		value := base64.RawURLEncoding.EncodeToString(hash[:])
		name := "_acme-challenge." + a.GetDomain()
		return NewRecord(name, value)
	}
	return nil
}

// Record represents a DNS TXT record for DNS validation
type Record struct {
	name  string
	value string
}

// NewRecord creates a new Record
func NewRecord(name, value string) *Record {
	return &Record{
		name:  name,
		value: value,
	}
}

// GetName returns the record name
func (r *Record) GetName() string {
	return r.name
}

// GetValue returns the record value
func (r *Record) GetValue() string {
	return r.value
}

// Certificate represents an issued certificate
type Certificate struct {
	privateKey              string
	csr                     string
	chain                   string
	certificate             string
	intermediateCertificate string
	expiryDate              time.Time
}

// NewCertificate creates a new Certificate
func NewCertificate(privateKeyPEM, csr, chain string) (*Certificate, error) {
	cert, intermediate, err := splitCertificate(chain)
	if err != nil {
		return nil, err
	}

	expiryDate, err := getCertExpiryDate(chain)
	if err != nil {
		return nil, err
	}

	return &Certificate{
		privateKey:              privateKeyPEM,
		csr:                     csr,
		chain:                   chain,
		certificate:             cert,
		intermediateCertificate: intermediate,
		expiryDate:              expiryDate,
	}, nil
}

// GetCSR returns the certificate signing request
func (c *Certificate) GetCSR() string {
	return c.csr
}

// GetExpiryDate returns the certificate expiry date
func (c *Certificate) GetExpiryDate() time.Time {
	return c.expiryDate
}

// GetCertificate returns the certificate, optionally as a chain
func (c *Certificate) GetCertificate(asChain ...bool) string {
	if len(asChain) > 0 && !asChain[0] {
		return c.certificate
	}
	return c.chain
}

// GetIntermediate returns the intermediate certificate
func (c *Certificate) GetIntermediate() string {
	return c.intermediateCertificate
}

// GetPrivateKey returns the private key
func (c *Certificate) GetPrivateKey() string {
	return c.privateKey
}

// Helper functions

// generateNewKey generates a new RSA private key
func generateNewKey(keyLength int) (*rsa.PrivateKey, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return nil, "", err
	}

	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	return privateKey, string(pem.EncodeToMemory(keyPEM)), nil
}

// generateCSR generates a certificate signing request
func generateCSR(domains []string, privateKey *rsa.PrivateKey) (string, error) {
	if len(domains) == 0 {
		return "", fmt.Errorf("no domains provided")
	}

	primaryDomain := domains[0]

	// Create subject
	subject := pkix.Name{
		Country:    []string{"US"},
		CommonName: primaryDomain,
	}

	// Create CSR template
	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Add SANs for all domains
	for _, domain := range domains {
		template.DNSNames = append(template.DNSNames, domain)
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %w", err)
	}

	// Encode to PEM
	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}

	return string(pem.EncodeToMemory(csrPEM)), nil
}

// toDER converts PEM to DER format
func toDER(pemData string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return block.Bytes, nil
}

// getCertExpiryDate extracts the expiry date from a certificate
func getCertExpiryDate(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotAfter, nil
}

// splitCertificate splits a certificate chain into domain and intermediate certificates
func splitCertificate(chain string) (string, string, error) {
	var domainCert, intermediateCert strings.Builder
	var currentCert strings.Builder
	var inCert bool
	var certCount int

	lines := strings.Split(chain, "\n")
	for _, line := range lines {
		if strings.Contains(line, "-----BEGIN CERTIFICATE-----") {
			inCert = true
			certCount++
			currentCert.WriteString(line + "\n")
		} else if strings.Contains(line, "-----END CERTIFICATE-----") {
			currentCert.WriteString(line + "\n")
			inCert = false

			if certCount == 1 {
				domainCert = currentCert
			} else if certCount == 2 {
				intermediateCert = currentCert
			}
			currentCert.Reset()
		} else if inCert {
			currentCert.WriteString(line + "\n")
		}
	}

	if domainCert.Len() == 0 || intermediateCert.Len() == 0 {
		return "", "", fmt.Errorf("could not parse certificate chain")
	}

	return domainCert.String(), intermediateCert.String(), nil
}
